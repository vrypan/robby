package xrpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	untrustedResolutionTimeout = 10 * time.Second
	maxDIDDocumentBytes        = 1 << 20
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

// newUntrustedResolutionHTTPClient is used for client-selected did:web and
// handle lookups. Direct IP dialing preserves the URL hostname for TLS SNI
// and certificate verification while preventing DNS rebinding.
func newUntrustedResolutionHTTPClient() *http.Client {
	return &http.Client{
		Timeout: untrustedResolutionTimeout,
		Transport: maxResponseBodyTransport{
			base:  newSafeTransport(),
			limit: maxDIDDocumentBytes,
		},
		CheckRedirect: sameHTTPSOriginRedirect,
	}
}

func newSafeTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

func sameHTTPSOriginRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || len(via) == 0 || req.URL.Host != via[0].URL.Host {
		return http.ErrUseLastResponse
	}
	return nil
}

type maxResponseBodyTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t maxResponseBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	if resp.ContentLength > t.limit {
		resp.Body.Close()
		return nil, fmt.Errorf("response body exceeds %d byte limit", t.limit)
	}
	resp.Body = &maxReadCloser{ReadCloser: resp.Body, remaining: t.limit}
	return resp, nil
}

type maxReadCloser struct {
	io.ReadCloser
	remaining int64
}

func (r *maxReadCloser) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var extra [1]byte
		n, err := r.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, fmt.Errorf("response body exceeds limit")
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	return n, err
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
var nonPublicPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64",
	"2001:2::/48", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func isPublicIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
