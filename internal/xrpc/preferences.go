package xrpc

import (
	"encoding/json"
	"net/http"

	"github.com/vrypan/pds-light/internal/actorstore"
)

// handleGetPreferences implements app.bsky.actor.getPreferences. Despite
// the app.bsky.* namespace, this is private per-account data meant to be
// served directly by the PDS (see the lexicon: "Requires auth" /
// account-sync semantics) — not proxied to the AppView, unlike public
// reads under app.bsky.*.
func (s *Server) handleGetPreferences(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	raw, err := st.GetPreferences(r.Context())
	if err == actorstore.ErrNotFound {
		writeJSON(w, http.StatusOK, map[string]any{"preferences": []any{}})
		return
	}
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load preferences")
		return
	}
	var prefs json.RawMessage = []byte(raw)
	writeJSON(w, http.StatusOK, map[string]any{"preferences": prefs})
}

type putPreferencesInput struct {
	Preferences json.RawMessage `json:"preferences"`
}

func (s *Server) handlePutPreferences(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in putPreferencesInput
	if err := decodeJSON(r, &in); err != nil || in.Preferences == nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "preferences is required")
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	if err := st.SetPreferences(r.Context(), string(in.Preferences)); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store preferences")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}
