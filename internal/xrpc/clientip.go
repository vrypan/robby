package xrpc

import (
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// clientAddr returns the effective client IP for policy decisions
// (admin allowlisting, rate limiting), or the zero Addr if it cannot be
// determined.
//
// Behind the intended Cloudflare Tunnel deployment every request reaches
// us from cloudflared on loopback, so the TCP peer address alone can't
// distinguish the local admin CLI from an arbitrary internet client. In
// that case Cloudflare's CF-Connecting-IP header carries the real client
// address, and cloudflared/Cloudflare always set it — a tunnel client
// cannot strip or override it. The header is only trusted when the
// direct peer is loopback: for a connection arriving on a LAN interface
// it is attacker-controlled and ignored, so a LAN client can't spoof its
// way into an allowlist by sending a forged header.
func clientAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if cf := r.Header.Get("CF-Connecting-IP"); peer.IsLoopback() && cf != "" {
		addr, err := netip.ParseAddr(cf)
		if err != nil {
			return netip.Addr{}
		}
		return addr.Unmap()
	}
	return peer
}

func addrInPrefixes(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ipRateLimiter keeps a token bucket per client IP. IPv6 clients are
// bucketed by /64 so a single host can't dodge the limit by rotating
// through its interface identifiers. Unusable client addresses (the zero
// Addr) all share one bucket rather than bypassing the limit.
type ipRateLimiter struct {
	mu        sync.Mutex
	buckets   map[netip.Addr]*ipBucket
	limit     rate.Limit
	burst     int
	lastSweep time.Time
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const ipBucketIdleTTL = 15 * time.Minute

func newIPRateLimiter(limit rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		buckets:   make(map[netip.Addr]*ipBucket),
		limit:     limit,
		burst:     burst,
		lastSweep: time.Now(),
	}
}

func (l *ipRateLimiter) Allow(addr netip.Addr) bool {
	if addr.Is6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	// Drop idle buckets at most once per TTL so the map stays bounded by
	// one TTL window of distinct clients without an O(n) walk per request.
	if now.Sub(l.lastSweep) > ipBucketIdleTTL {
		for k, v := range l.buckets {
			if now.Sub(v.lastSeen) > ipBucketIdleTTL {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}

	b, ok := l.buckets[addr]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[addr] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}

// rateLimited wraps a handler with the per-IP login limiter, refusing
// excess requests before the handler does any work — password
// verification is deliberately expensive (scrypt), so unauthenticated
// attempts are both a brute-force and a CPU-exhaustion vector.
func (s *Server) rateLimited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.loginLimiter.Allow(clientAddr(r)) {
			writeXRPCError(w, http.StatusTooManyRequests, "RateLimitExceeded", "too many attempts, try again later")
			return
		}
		next(w, r)
	}
}
