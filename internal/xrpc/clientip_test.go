package xrpc

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/vrypan/robby/internal/config"
)

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		cfHeader   string
		want       string // "" means the zero (invalid) Addr
	}{
		{"direct LAN peer", "192.168.1.7:51234", "", "192.168.1.7"},
		{"loopback, no header", "127.0.0.1:51234", "", "127.0.0.1"},
		{"tunnel client via loopback", "127.0.0.1:51234", "203.0.113.9", "203.0.113.9"},
		// A non-loopback peer must not be able to spoof its identity with
		// a forged Cloudflare header.
		{"LAN peer with forged header", "192.168.1.7:51234", "127.0.0.1", "192.168.1.7"},
		{"loopback with garbage header", "127.0.0.1:51234", "not-an-ip", ""},
		{"unparseable remote addr", "garbage", "", ""},
		{"ipv6 loopback with header", "[::1]:51234", "2001:4860::1", "2001:4860::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/xrpc/_health", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.cfHeader != "" {
				r.Header.Set("CF-Connecting-IP", tt.cfHeader)
			}
			var want netip.Addr
			if tt.want != "" {
				want = netip.MustParseAddr(tt.want)
			}
			if addr := clientAddr(r); addr != want {
				t.Fatalf("addr = %v, want %v", addr, want)
			}
		})
	}
}

// Address extraction is covered by TestClientAddr; this exercises only the
// gate policy layered on top of it.
func TestRequireAdminNetworkGate(t *testing.T) {
	s := &Server{
		cfg: &config.Config{AdminPassword: "sekrit"},
		adminNets: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("192.168.1.0/24"),
		},
		log: slog.New(slog.DiscardHandler),
	}
	handler := s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		remoteAddr string
		cfHeader   string
		password   string
		wantStatus int
	}{
		{"allowed network with password", "192.168.1.20:1", "", "sekrit", http.StatusOK},
		{"allowed network, bad password", "192.168.1.20:1", "", "wrong", http.StatusUnauthorized},
		{"disallowed network", "192.168.2.20:1", "", "sekrit", http.StatusForbidden},
		// Through the tunnel the peer is loopback but the real client is
		// whatever CF-Connecting-IP says — public clients must be refused
		// even with the right password.
		{"tunnel client, public IP", "127.0.0.1:1", "203.0.113.9", "sekrit", http.StatusForbidden},
		{"tunnel client, allowed IP", "127.0.0.1:1", "192.168.1.20", "sekrit", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/xrpc/net.vrypan.robby.admin.listAccounts", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.cfHeader != "" {
				r.Header.Set("CF-Connecting-IP", tt.cfHeader)
			}
			r.SetBasicAuth("admin", tt.password)
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func TestIPRateLimiter(t *testing.T) {
	l := newIPRateLimiter(rate.Every(time.Hour), 3)

	a := netip.MustParseAddr("203.0.113.9")
	for i := 0; i < 3; i++ {
		if !l.Allow(a) {
			t.Fatalf("attempt %d unexpectedly limited", i)
		}
	}
	if l.Allow(a) {
		t.Fatal("burst exhausted but attempt allowed")
	}

	// A different client gets its own bucket.
	if !l.Allow(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("independent client was limited")
	}

	// IPv6 addresses in the same /64 share a bucket.
	if !l.Allow(netip.MustParseAddr("2001:db8:1:2::1")) {
		t.Fatal("first v6 attempt limited")
	}
	l.Allow(netip.MustParseAddr("2001:db8:1:2::2"))
	l.Allow(netip.MustParseAddr("2001:db8:1:2::3"))
	if l.Allow(netip.MustParseAddr("2001:db8:1:2::4")) {
		t.Fatal("rotating within a /64 bypassed the limit")
	}
}
