package xrpc

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/robby/internal/auth"
	"github.com/vrypan/robby/internal/store"
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
	// Rate-limit before touching the body or the store: every attempt
	// below this point costs an scrypt verification. Unparseable client
	// addresses all share the zero-Addr bucket rather than bypassing the
	// limit.
	addr, _ := clientAddr(r)
	if !s.loginLimiter.Allow(addr) {
		writeXRPCError(w, http.StatusTooManyRequests, "RateLimitExceeded", "too many login attempts, try again later")
		return
	}

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

	credential := auth.Credential{Kind: auth.CredentialPrimary}
	if ok, err := auth.VerifyPassword(in.Password, acct.PasswordHash); err != nil || !ok {
		ap, ok := s.verifyAppPassword(r.Context(), acct.DID, in.Password)
		if !ok {
			writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid identifier or password")
			return
		}
		credential = auth.Credential{Kind: auth.CredentialAppPassword, AppPasswordName: ap.Name}
		if ap.Privileged {
			credential.Kind = auth.CredentialPrivilegedAppPassword
		}
	}

	if acct.Status == store.StatusTakenDown {
		writeXRPCError(w, http.StatusUnauthorized, "AccountTakedown", "account has been taken down")
		return
	}

	s.issueSession(w, acct, credential)
}

func (s *Server) issueSession(w http.ResponseWriter, acct *store.Account, credential auth.Credential) {
	serviceDID := ServiceDID(s.cfg)

	accessJwt, _, err := auth.IssueAccessToken(s.cfg.JWTSecret, acct.DID, serviceDID, acct.AuthVersion, credential)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to issue session")
		return
	}

	refreshJwt, jti, expiresAt, err := auth.IssueRefreshToken(s.cfg.JWTSecret, acct.DID, serviceDID, acct.AuthVersion, credential)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to issue session")
		return
	}

	if err := s.store.CreateRefreshToken(context.Background(), store.RefreshToken{
		TokenHash:   auth.HashToken(jti),
		DID:         acct.DID,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
		AuthVersion: acct.AuthVersion, CredentialKind: credential.Kind, AppPasswordName: credential.AppPasswordName,
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
	acct, err := s.store.GetAccountByDID(r.Context(), parsed.DID)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "account not found")
		return
	}

	if acct.Status != store.StatusActive || parsed.AuthVersion != acct.AuthVersion || stored.AuthVersion != parsed.AuthVersion || stored.CredentialKind != parsed.CredentialKind || stored.AppPasswordName != parsed.AppPasswordName {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "refresh token has been revoked")
		return
	}
	if err := s.store.ConsumeRefreshToken(r.Context(), tokenHash, parsed.DID, parsed.AuthVersion); err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "refresh token has been revoked")
		return
	}
	s.issueSession(w, acct, auth.Credential{Kind: parsed.CredentialKind, AppPasswordName: parsed.AppPasswordName})
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
	if err := s.store.DeleteRefreshToken(r.Context(), auth.HashToken(parsed.JTI)); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to delete session")
		return
	}
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
	parsed, ok := s.requirePrincipal(w, r, false, false)
	if !ok {
		return "", false
	}
	return parsed.DID, true
}

func (s *Server) requirePrivilegedAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	parsed, ok := s.requirePrincipal(w, r, true, false)
	if !ok {
		return "", false
	}
	return parsed.DID, true
}

func (s *Server) requireMigrationAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	parsed, ok := s.requirePrincipal(w, r, true, true)
	if !ok {
		return "", false
	}
	return parsed.DID, true
}

// requireMigratableAccessToken permits ordinary (unprivileged) access, and
// additionally accepts a deactivated account. Uploading blobs and copying
// preferences are steps of the migration-in flow, which runs entirely
// before server.activateAccount — but they are also everyday operations an
// app-password client performs, so unlike requireMigrationAccessToken this
// does not demand a privileged credential.
func (s *Server) requireMigratableAccessToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	parsed, ok := s.requirePrincipal(w, r, false, true)
	if !ok {
		return "", false
	}
	return parsed.DID, true
}

// statusPermitted reports whether an account in this status may act. Only
// the deactivated state is ever excepted, and only for endpoints in the
// migration-in flow: a taken-down account is never permitted, no matter
// what the caller asks for.
func statusPermitted(status string, allowDeactivated bool) bool {
	if status == store.StatusActive {
		return true
	}
	return allowDeactivated && status == store.StatusDeactivated
}

func (s *Server) requirePrincipal(w http.ResponseWriter, r *http.Request, privileged, allowDeactivated bool) (*auth.ParsedToken, bool) {
	tokenString, ok := bearerToken(r)
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "missing bearer token")
		return nil, false
	}
	parsed, err := auth.ParseAccessToken(s.cfg.JWTSecret, tokenString)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "invalid or expired access token")
		return nil, false
	}
	acct, err := s.store.GetAccountByDID(r.Context(), parsed.DID)
	if err != nil || !statusPermitted(acct.Status, allowDeactivated) || acct.AuthVersion != parsed.AuthVersion {
		writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "session has been revoked")
		return nil, false
	}
	if parsed.AppPasswordName != "" {
		aps, err := s.store.ListAppPasswords(r.Context(), parsed.DID)
		if err != nil || !matchingAppCredential(aps, parsed) {
			writeXRPCError(w, http.StatusUnauthorized, "ExpiredToken", "app password has been revoked")
			return nil, false
		}
	}
	if privileged && parsed.CredentialKind != auth.CredentialPrimary && parsed.CredentialKind != auth.CredentialPrivilegedAppPassword {
		writeXRPCError(w, http.StatusForbidden, "AuthRequired", "privileged credentials required")
		return nil, false
	}
	return parsed, true
}

func matchingAppCredential(aps []store.AppPassword, parsed *auth.ParsedToken) bool {
	for _, ap := range aps {
		if ap.Name != parsed.AppPasswordName {
			continue
		}
		return (ap.Privileged && parsed.CredentialKind == auth.CredentialPrivilegedAppPassword) || (!ap.Privileged && parsed.CredentialKind == auth.CredentialAppPassword)
	}
	return false
}
