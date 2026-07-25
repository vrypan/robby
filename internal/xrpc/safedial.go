package xrpc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// proxyHTTPClient is the HTTP client used for outbound service-proxy
// requests. It uses safeDialContext so that a request can never be
// directed (e.g. via a malicious atproto-proxy target DID whose service
// endpoint resolves to an internal address) at loopback, link-local,
// private, or otherwise non-public IPs — an SSRF guard.
var proxyHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DialContext:           safeDialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Resolve the host and verify every candidate address is public,
	// then dial the resolved IP directly so there's no TOCTOU gap
	// between the check and the connection.
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for host %q", host)
	}

	var dialer net.Dialer
	var lastErr error
	for _, ip := range ips {
		if !isPublicIP(ip.IP) {
			lastErr = fmt.Errorf("refusing to connect to non-public address %s", ip.IP)
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}
	return nil, lastErr
}

// isPublicIP reports whether ip is a globally-routable public address,
// excluding loopback, link-local, private (RFC1918/ULA), multicast,
// unspecified, and IPv4-mapped-into-private ranges.
func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return false
	}
	// Explicitly reject the cloud-metadata address (defense in depth; it
	// is link-local and already covered, but make the intent clear) and
	// IPv4/IPv6 shared/reserved ranges not covered above.
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 (CGNAT), 192.0.0.0/24, 198.18.0.0/15 (benchmarking)
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64:
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0:
			return false
		case v4[0] == 198 && (v4[1] == 18 || v4[1] == 19):
			return false
		}
	}
	return true
}
