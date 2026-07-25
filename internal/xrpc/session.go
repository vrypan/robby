package xrpc

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/pds-light/internal/auth"
	"github.com/vrypan/pds-light/internal/store"
)

func (s *Server) handleDescribeServer(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"did":                  ServiceDID(s.cfg),
		"availableUserDomains": []string{},
		"inviteCodeRequired":   false,
		"phoneVerificationReq": false,
		"links":                map[string]any{},
		"contact":              map[string]any{},
	})
}

type createSessionInput struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type sessionOutput struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	Handle     string `json:"handle"`
	DID        string `json:"did"`
	Active     bool   `json:"active"`
	Status     string `json:"status,omitempty"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var in createSessionInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.Identifier == "" || in.Password == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "identifier and password are required")
		return
	}

	acct, err := s.store.GetAccountByIdentifier(r.Context(), strings.TrimPrefix(in.Identifier, "at://"))
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid identifier or password")
		return
	}

	if ok, err := auth.VerifyPassword(in.Password, acct.PasswordHash); err != nil || !ok {
		if !s.verifyAppPassword(r.Context(), acct.DID, in.Password) {
			writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid identifier or password")
			return
		}
	}

	if acct.Status == store.StatusTakenDown {
		writeXRPCError(w, http.StatusUnauthorized, "AccountTakedown", "account has been taken down")
		return
	}

	s.issueSession(w, acct)
}

func (s *Server) issueSession(w http.ResponseWriter, acct *store.Account) {
	serviceDID := ServiceDID(s.cfg)

	accessJwt, _, err := auth.IssueAccessToken(s.cfg.JWTSecret, acct.DID, serviceDID)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to issue session")
		return
	}

	refreshJwt, jti, expiresAt, err := auth.IssueRefreshToken(s.cfg.JWTSecret, acct.DID, serviceDID)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to issue session")
		return
	}

	if err := s.store.CreateRefreshToken(context.Background(), store.RefreshToken{
		TokenHash: auth.HashToken(jti),
		DID:       acct.DID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to issue session")
		return
	}

	writeJSON(w, http.StatusOK, sessionOutput{
		AccessJwt:  accessJwt,
		RefreshJwt: refreshJwt,
		Handle:     acct.Handle,
		DID:        acct.DID,
		Active:     acct.Status == store.StatusActive,
		Status:     statusOrEmpty(acct.Status),
	})
}

func statusOrEmpty(status string) string {
	if status == store.StatusActive {
		return ""
	}
	return status
}

func (s *Server) handleRefreshSession(w http.ResponseWriter, r *http.Request) {
	tokenString, ok := bearerToken(r)
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "missing bearer token")
		return
	}

	parsed, err := auth.ParseRefreshToken(s.cfg.JWTSecret, tokenString)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "invalid or expired refresh token")
		return
	}

	tokenHash := auth.HashToken(parsed.JTI)
	stored, err := s.store.GetRefreshToken(r.Context(), tokenHash)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "refresh token has been revoked")
		return
	}
	if time.Now().After(stored.ExpiresAt) {
		_ = s.store.DeleteRefreshToken(r.Context(), tokenHash)
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "refresh token has expired")
		return
	}

	acct, err := s.store.GetAccountByDID(r.Context(), parsed.DID)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "account not found")
		return
	}

	// Rotate: consume the old refresh token, issue a new session.
	_ = s.store.DeleteRefreshToken(r.Context(), tokenHash)
	s.issueSession(w, acct)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	tokenString, ok := bearerToken(r)
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "missing bearer token")
		return
	}
	parsed, err := auth.ParseRefreshToken(s.cfg.JWTSecret, tokenString)
	if err != nil {
		// Already invalid/expired: deleting a session is idempotent.
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	_ = s.store.DeleteRefreshToken(r.Context(), auth.HashToken(parsed.JTI))
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"handle": acct.Handle,
		"did":    acct.DID,
		"active": acct.Status == store.StatusActive,
		"status": statusOrEmpty(acct.Status),
	})
}

func (s *Server) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "handle is required")
		return
	}

	if acct, err := s.store.GetAccountByHandle(r.Context(), handle); err == nil {
		writeJSON(w, http.StatusOK, map[string]string{"did": acct.DID})
		return
	}

	parsed, err := syntax.ParseHandle(handle)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid handle")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), untrustedResolutionTimeout)
	defer cancel()
	did, err := s.untrustedDir.ResolveHandle(ctx, parsed)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "UnableToResolveHandle", "could not resolve handle")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"did": did.String()})
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}

// requireAccessToken validates the bearer access token and returns the
// authenticated DID. On failure it writes the error response itself.
func (s *Server) requireAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	tokenString, ok := bearerToken(r)
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "missing bearer token")
		return "", false
	}
	parsed, err := auth.ParseAccessToken(s.cfg.JWTSecret, tokenString)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "invalid or expired access token")
		return "", false
	}
	return parsed.DID, true
}
