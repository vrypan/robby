package xrpc

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/http"
	"strings"
	"time"

	"github.com/vrypan/pds-light/internal/auth"
	"github.com/vrypan/pds-light/internal/store"
)

// verifyAppPassword checks password against any of did's app passwords.
// Used by createSession as a fallback when the main account password
// doesn't match.
func (s *Server) verifyAppPassword(ctx context.Context, did, password string) bool {
	aps, err := s.store.ListAppPasswords(ctx, did)
	if err != nil {
		return false
	}
	for _, ap := range aps {
		if ok, err := auth.VerifyPassword(password, ap.PasswordHash); err == nil && ok {
			return true
		}
	}
	return false
}

type createAppPasswordInput struct {
	Name       string `json:"name"`
	Privileged bool   `json:"privileged"`
}

type appPasswordOutput struct {
	Name       string `json:"name"`
	Password   string `json:"password,omitempty"`
	CreatedAt  string `json:"createdAt"`
	Privileged bool   `json:"privileged,omitempty"`
}

func (s *Server) handleCreateAppPassword(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in createAppPasswordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.Name == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "name is required")
		return
	}

	password, err := generateAppPassword()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate password")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to hash password")
		return
	}

	now := time.Now()
	if err := s.store.CreateAppPassword(r.Context(), store.AppPassword{
		DID:          did,
		Name:         in.Name,
		PasswordHash: hash,
		Privileged:   in.Privileged,
		CreatedAt:    now,
	}); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "an app password with this name already exists")
		return
	}

	writeJSON(w, http.StatusOK, appPasswordOutput{
		Name:       in.Name,
		Password:   password,
		CreatedAt:  now.UTC().Format(time.RFC3339),
		Privileged: in.Privileged,
	})
}

func (s *Server) handleListAppPasswords(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	aps, err := s.store.ListAppPasswords(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list app passwords")
		return
	}
	out := make([]appPasswordOutput, 0, len(aps))
	for _, ap := range aps {
		out = append(out, appPasswordOutput{
			Name:       ap.Name,
			CreatedAt:  ap.CreatedAt.UTC().Format(time.RFC3339),
			Privileged: ap.Privileged,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"passwords": out})
}

type revokeAppPasswordInput struct {
	Name string `json:"name"`
}

func (s *Server) handleRevokeAppPassword(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in revokeAppPasswordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if err := s.store.DeleteAppPassword(r.Context(), did, in.Name); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "app password not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// generateAppPassword produces a random password in the familiar
// "xxxx-xxxx-xxxx-xxxx" grouping (lowercase base32, no padding).
func generateAppPassword() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	var groups []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return strings.Join(groups, "-"), nil
}
