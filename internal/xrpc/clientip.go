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
// (admin allowlisting, rate limiting).
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
func clientAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	peer = peer.Unmap()
	if peer.IsLoopback() {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			if addr, err := netip.ParseAddr(cf); err == nil {
				return addr.Unmap(), true
			}
			return netip.Addr{}, false
		}
	}
	return peer, true
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
// through its interface identifiers.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*ipBucket
	limit   rate.Limit
	burst   int
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const ipBucketIdleTTL = 15 * time.Minute

func newIPRateLimiter(limit rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		buckets: make(map[netip.Addr]*ipBucket),
		limit:   limit,
		burst:   burst,
	}
}

func (l *ipRateLimiter) Allow(addr netip.Addr) bool {
	if addr.Is6() && !addr.Is4In6() {
		addr = netip.PrefixFrom(addr, 64).Masked().Addr()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[addr]
	if !ok {
		// Piggyback stale-bucket cleanup on new-key insertion so the map
		// can't grow without bound under an address-rotating client.
		for k, v := range l.buckets {
			if now.Sub(v.lastSeen) > ipBucketIdleTTL {
				delete(l.buckets, k)
			}
		}
		b = &ipBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.buckets[addr] = b
	}
	b.lastSeen = now
	return b.limiter.Allow()
}
