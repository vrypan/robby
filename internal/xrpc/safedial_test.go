package xrpc

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/identity"

	"github.com/vrypan/robby/internal/store"
)

func TestIsPublicIP(t *testing.T) {
	tests := map[string]bool{
		"8.8.8.8":              true,
		"1.1.1.1":              true,
		"127.0.0.1":            false,
		"10.0.0.1":             false,
		"100.64.0.1":           false,
		"169.254.169.254":      false,
		"192.0.2.1":            false,
		"198.18.0.1":           false,
		"203.0.113.1":          false,
		"::1":                  false,
		"fc00::1":              false,
		"2001:db8::1":          false,
		"2606:4700:4700::1111": true,
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := isPublicIP(net.ParseIP(input)); got != want {
				t.Fatalf("isPublicIP(%s) = %v, want %v", input, got, want)
			}
		})
	}
}

func TestSameHTTPSOriginRedirect(t *testing.T) {
	first := httptest.NewRequest(http.MethodGet, "https://example.com/.well-known/did.json", nil)
	for _, target := range []string{
		"http://example.com/.well-known/did.json",
		"https://other.example/.well-known/did.json",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if err := sameHTTPSOriginRedirect(req, []*http.Request{first}); err == nil {
			t.Fatalf("redirect to %s was accepted", target)
		}
	}
	valid := httptest.NewRequest(http.MethodGet, "https://example.com/elsewhere", nil)
	if err := sameHTTPSOriginRedirect(valid, []*http.Request{first}); err != nil {
		t.Fatalf("same-origin HTTPS redirect rejected: %v", err)
	}
}

func TestMaxResponseBodyTransportRejectsOversize(t *testing.T) {
	transport := maxResponseBodyTransport{
		base: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("12345"))}, nil
		}),
		limit: 4,
	}
	resp, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "https://example.com", nil))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("oversized streamed body error = %v, want limit error", err)
	}
}

func TestSafeDialContextRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := safeDialContext(ctx, "tcp", "example.com:443"); err == nil {
		t.Fatal("canceled context unexpectedly permitted a dial")
	}
}

func TestResolveProxyTargetUsesUntrustedDirectoryForDIDWeb(t *testing.T) {
	const did = "did:web:example.com"
	doc := `{"id":"` + did + `","service":[{"id":"#atproto_pds","serviceEndpoint":"https://pds.example"}]}`
	s := &Server{
		dir: &identity.BaseDirectory{},
		untrustedDir: &identity.BaseDirectory{HTTPClient: http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://example.com/.well-known/did.json" {
				t.Fatalf("unexpected URL %s", req.URL)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(doc))}, nil
		})}},
	}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/app.bsky.feed.getTimeline", nil)
	req.Header.Set("atproto-proxy", did)
	target, err := s.resolveProxyTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if target.url != "https://pds.example" || target.trusted {
		t.Fatalf("unexpected target: %#v", target)
	}
}

func TestResolveProxyTargetKeepsPLCOnTrustedDirectory(t *testing.T) {
	const did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
	doc := `{"id":"` + did + `","service":[{"id":"#atproto_pds","serviceEndpoint":"https://pds.example"}]}`
	s := &Server{
		dir: &identity.BaseDirectory{PLCURL: "https://plc.example", HTTPClient: http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://plc.example/"+did {
				t.Fatalf("unexpected PLC URL %s", req.URL)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(doc))}, nil
		})}},
		untrustedDir: &identity.BaseDirectory{},
	}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/app.bsky.feed.getTimeline", nil)
	req.Header.Set("atproto-proxy", did)
	if _, err := s.resolveProxyTarget(req); err != nil {
		t.Fatal(err)
	}
}

func TestResolveHandleUsesBoundedDirectory(t *testing.T) {
	const did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"
	st, err := store.Open(t.TempDir() + "/accounts.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{untrustedDir: &identity.BaseDirectory{
		SkipDNSDomainSuffixes: []string{""},
		HTTPClient: http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(did))}, nil
		})},
	}, store: st}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.identity.resolveHandle?handle=example.com", nil).WithContext(context.Background())
	response := httptest.NewRecorder()
	s.handleResolveHandle(response, req)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), did) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
