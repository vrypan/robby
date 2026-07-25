package xrpc

import (
	"net/http"
	"strconv"
	"time"

	indigoauth "github.com/bluesky-social/indigo/atproto/auth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

const (
	defaultServiceAuthTTL = 60 * time.Second
	maxServiceAuthTTL     = 10 * time.Minute
)

// handleGetServiceAuth implements com.atproto.server.getServiceAuth: a
// short-lived, ES256K-signed token proving the caller's DID, scoped to a
// target audience (and optionally one Lexicon method), for the caller to
// present directly to that other service.
func (s *Server) handleGetServiceAuth(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requirePrivilegedAccessToken(w, r)
	if !ok {
		return
	}

	q := r.URL.Query()
	aud := q.Get("aud")
	if aud == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "aud is required")
		return
	}
	if _, err := syntax.ParseDID(aud); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid aud")
		return
	}

	ttl := defaultServiceAuthTTL
	if expStr := q.Get("exp"); expStr != "" {
		expSec, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid exp")
			return
		}
		ttl = time.Until(time.Unix(expSec, 0))
		if ttl <= 0 {
			writeXRPCError(w, http.StatusBadRequest, "BadExpiration", "exp must be in the future")
			return
		}
		if ttl > maxServiceAuthTTL {
			writeXRPCError(w, http.StatusBadRequest, "BadExpiration", "exp is too far in the future")
			return
		}
	}

	var lexMethod *syntax.NSID
	if lxm := q.Get("lxm"); lxm != "" {
		nsid, err := syntax.ParseNSID(lxm)
		if err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid lxm")
			return
		}
		lexMethod = &nsid
	}

	signingKey, err := s.signingKeyFor(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load signing key")
		return
	}

	token, err := indigoauth.SignServiceAuth(syntax.DID(did), aud, ttl, lexMethod, signingKey)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sign service auth token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
