package xrpc

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/pds-light/internal/auth"
	"github.com/vrypan/pds-light/internal/plc"
	"github.com/vrypan/pds-light/internal/store"
)

// requireAdmin wraps a handler with HTTP Basic auth against the
// configured admin password. Username is ignored.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.AdminPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="pdslight-admin"`)
			writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid admin credentials")
			return
		}
		next(w, r)
	}
}

type adminCreateAccountInput struct {
	Handle   string `json:"handle"`
	Password string `json:"password"`
}

type adminAccountOutput struct {
	DID    string `json:"did"`
	Handle string `json:"handle"`
	Status string `json:"status"`
}

func (s *Server) handleAdminCreateAccount(w http.ResponseWriter, r *http.Request) {
	var in adminCreateAccountInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	handle, err := syntax.ParseHandle(in.Handle)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid handle: "+err.Error())
		return
	}
	if in.Password == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "password is required")
		return
	}
	if _, err := s.store.GetAccountByHandle(r.Context(), handle.String()); err == nil {
		writeXRPCError(w, http.StatusBadRequest, "HandleNotAvailable", "handle already in use")
		return
	}

	signingPriv, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate signing key")
		return
	}
	signingPub, err := signingPriv.PublicKey()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to derive signing key")
		return
	}
	rotationPriv, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate rotation key")
		return
	}

	did, signedOp, err := plc.Genesis(rotationPriv, signingPub, handle.String(), "https://"+s.cfg.Hostname)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to build PLC genesis operation: "+err.Error())
		return
	}

	plcClient := plc.NewClient(s.cfg.PLCURL)
	if err := plcClient.Submit(r.Context(), did, signedOp); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to submit PLC operation: "+err.Error())
		return
	}

	passwordHash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to hash password")
		return
	}

	acct := store.Account{
		DID:          did,
		Handle:       handle.String(),
		PasswordHash: passwordHash,
		SigningKey:   signingPriv.Multibase(),
		RotationKey:  rotationPriv.Multibase(),
		Status:       store.StatusActive,
		CreatedAt:    time.Now(),
	}
	if err := s.store.CreateAccount(r.Context(), acct); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store account: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, adminAccountOutput{DID: acct.DID, Handle: acct.Handle, Status: acct.Status})
}

func (s *Server) handleAdminListAccounts(w http.ResponseWriter, r *http.Request) {
	accts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list accounts")
		return
	}
	out := make([]adminAccountOutput, 0, len(accts))
	for _, a := range accts {
		out = append(out, adminAccountOutput{DID: a.DID, Handle: a.Handle, Status: a.Status})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

type adminSetPasswordInput struct {
	DID      string `json:"did"`
	Password string `json:"password"`
}

func (s *Server) handleAdminSetPassword(w http.ResponseWriter, r *http.Request) {
	var in adminSetPasswordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" || in.Password == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did and password are required")
		return
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to hash password")
		return
	}
	if err := s.store.SetPasswordHash(r.Context(), in.DID, hash); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	// Revoking outstanding refresh tokens forces re-auth with the new password.
	_ = s.store.DeleteRefreshTokensForDID(r.Context(), in.DID)
	writeJSON(w, http.StatusOK, map[string]any{})
}

type adminDeactivateAccountInput struct {
	DID string `json:"did"`
}

func (s *Server) handleAdminDeactivateAccount(w http.ResponseWriter, r *http.Request) {
	var in adminDeactivateAccountInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	if err := s.store.SetStatus(r.Context(), in.DID, store.StatusDeactivated); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	_ = s.store.DeleteRefreshTokensForDID(r.Context(), in.DID)
	writeJSON(w, http.StatusOK, map[string]any{})
}
