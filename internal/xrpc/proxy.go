package xrpc

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	indigoauth "github.com/bluesky-social/indigo/atproto/auth"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/pds-light/internal/auth"
)

const proxyServiceAuthTTL = 60 * time.Second

type proxyTarget struct {
	did string // service DID, used as the service-auth "aud"
	url string // base URL to forward the request to
}

// resolveProxyTarget picks where to forward an unhandled /xrpc/* request:
// the configured AppView by default, or an explicit "atproto-proxy"
// header ("did[#serviceId]"), resolved via that DID's document.
func (s *Server) resolveProxyTarget(r *http.Request) (*proxyTarget, error) {
	header := r.Header.Get("atproto-proxy")
	if header == "" {
		return &proxyTarget{did: s.cfg.AppviewDID, url: s.cfg.AppviewURL}, nil
	}

	did, fragment, _ := strings.Cut(header, "#")
	parsedDID, err := syntax.ParseDID(did)
	if err != nil {
		return nil, fmt.Errorf("invalid atproto-proxy DID: %w", err)
	}
	if fragment == "" {
		fragment = "atproto_pds"
	}

	doc, err := s.dir.ResolveDID(r.Context(), parsedDID)
	if err != nil {
		return nil, fmt.Errorf("resolving proxy target DID: %w", err)
	}
	serviceID := "#" + fragment
	for _, svc := range doc.Service {
		if svc.ID == serviceID || svc.ID == did+serviceID {
			return &proxyTarget{did: did, url: svc.ServiceEndpoint}, nil
		}
	}
	return nil, fmt.Errorf("no matching service %q in DID document for %s", serviceID, did)
}

// handleServiceProxy forwards any /xrpc/* request not handled by a
// locally-registered route (i.e. anything under app.bsky.* and other
// unknown NSIDs) to the resolved target service, attaching a per-request
// service-auth JWT signed with the caller's own signing key when the
// request is authenticated.
func (s *Server) handleServiceProxy(w http.ResponseWriter, r *http.Request) {
	nsidStr := strings.TrimPrefix(r.URL.Path, "/xrpc/")
	if nsidStr == "" || strings.Contains(nsidStr, "/") {
		writeXRPCError(w, http.StatusNotFound, "XRPCNotSupported", "unknown method")
		return
	}
	if _, err := syntax.ParseNSID(nsidStr); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid method NSID")
		return
	}

	target, err := s.resolveProxyTarget(r)
	if err != nil {
		writeXRPCError(w, http.StatusBadGateway, "UpstreamFailure", "failed to resolve proxy target: "+err.Error())
		return
	}

	outURL := strings.TrimRight(target.url, "/") + "/xrpc/" + nsidStr
	if r.URL.RawQuery != "" {
		outURL += "?" + r.URL.RawQuery
	}

	var body io.Reader
	if r.Method == http.MethodPost {
		body = r.Body
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, body)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to build proxied request")
		return
	}
	copyProxyHeaders(outReq.Header, r.Header)
	outReq.Header.Set("User-Agent", "pds-light-proxy")

	if callerDID, ok := s.optionalAccessToken(r); ok {
		signingKey, err := s.signingKeyFor(r.Context(), callerDID)
		if err == nil {
			nsid, _ := syntax.ParseNSID(nsidStr)
			token, err := indigoauth.SignServiceAuth(syntax.DID(callerDID), target.did, proxyServiceAuthTTL, &nsid, signingKey)
			if err == nil {
				outReq.Header.Set("Authorization", "Bearer "+token)
			}
		}
	}

	resp, err := http.DefaultClient.Do(outReq)
	if err != nil {
		writeXRPCError(w, http.StatusBadGateway, "UpstreamFailure", "proxied request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// hopByHopHeaders are per-RFC-7230 connection-scoped headers that must
// not be forwarded by a proxy, plus Authorization and Content-Length,
// which we set explicitly ourselves on the outbound request.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
	"Authorization":       {},
	"Content-Length":      {},
}

// copyProxyHeaders forwards everything the client sent (Accept-Language,
// Content-Type, CF-IPCountry/CF-Connecting-IP for geolocation-dependent
// AppView features, atproto-accept-labelers, etc.) except hop-by-hop and
// auth headers we handle separately.
func copyProxyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if _, skip := hopByHopHeaders[k]; skip {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// optionalAccessToken validates a bearer access token if present, but
// (unlike requireAccessToken) doesn't write an error response or reject
// the request when absent/invalid — proxied reads are often anonymous.
func (s *Server) optionalAccessToken(r *http.Request) (string, bool) {
	tokenString, ok := bearerToken(r)
	if !ok {
		return "", false
	}
	parsed, err := auth.ParseAccessToken(s.cfg.JWTSecret, tokenString)
	if err != nil {
		return "", false
	}
	return parsed.DID, true
}
