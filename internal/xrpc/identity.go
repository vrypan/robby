package xrpc

import (
	"context"
	"net/http"
	"strings"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/pds-light/internal/firehose"
	"github.com/vrypan/pds-light/internal/plc"
	"github.com/vrypan/pds-light/internal/store"
)

// --- identity.updateHandle -------------------------------------------------

type updateHandleInput struct {
	Handle string `json:"handle"`
}

// handleUpdateHandle changes the account's handle: it's a normal
// PDS-initiated action (unlike signPlcOperation's arbitrary client-
// supplied op), so it signs and submits the PLC update directly, no
// admin token needed.
func (s *Server) handleUpdateHandle(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in updateHandleInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	newHandle, err := syntax.ParseHandle(in.Handle)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid handle")
		return
	}
	if _, err := s.store.GetAccountByHandle(r.Context(), newHandle.String()); err == nil {
		writeXRPCError(w, http.StatusBadRequest, "HandleNotAvailable", "handle already in use")
		return
	}

	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	rotationPriv, err := atcrypto.ParsePrivateMultibase(acct.RotationKey)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load rotation key")
		return
	}

	plcClient := plc.NewClient(s.cfg.PLCURL)
	prevCID, lastOp, err := plcClient.GetLastOp(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to fetch current PLC state: "+err.Error())
		return
	}

	signedOp, err := plc.SignOp(rotationPriv, &prevCID, plc.OpFields{
		RotationKeys:        toStringSlice(lastOp["rotationKeys"]),
		VerificationMethods: toMap(lastOp["verificationMethods"]),
		AlsoKnownAs:         []string{"at://" + newHandle.String()},
		Services:            toMap(lastOp["services"]),
	})
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sign PLC operation")
		return
	}
	if err := plcClient.Submit(r.Context(), did, signedOp); err != nil {
		writeXRPCError(w, http.StatusBadGateway, "UpstreamFailure", "failed to submit PLC operation: "+err.Error())
		return
	}

	if err := s.store.SetHandle(r.Context(), did, newHandle.String()); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to update local handle record")
		return
	}
	if err := s.emitIdentityEvent(r.Context(), did, newHandle.String()); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence identity event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// --- identity.getRecommendedDidCredentials --------------------------------

// handleGetRecommendedDidCredentials describes what this server would
// like the caller's DID doc to contain — used by a migrating-in client
// to build the PLC update op that finalizes the move.
func (s *Server) handleGetRecommendedDidCredentials(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	signingPub, err := publicKeyOf(acct.SigningKey)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load signing key")
		return
	}
	rotationPub, err := publicKeyOf(acct.RotationKey)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load rotation key")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rotationKeys": []string{rotationPub.DIDKey()},
		"alsoKnownAs":  []string{"at://" + acct.Handle},
		"verificationMethods": map[string]any{
			"atproto": signingPub.DIDKey(),
		},
		"services": map[string]any{
			"atproto_pds": map[string]any{
				"type":     "AtprotoPersonalDataServer",
				"endpoint": "https://" + s.cfg.Hostname,
			},
		},
	})
}

func publicKeyOf(multibasePriv string) (atcrypto.PublicKey, error) {
	priv, err := atcrypto.ParsePrivateMultibase(multibasePriv)
	if err != nil {
		return nil, err
	}
	return priv.PublicKey()
}

// --- identity.signPlcOperation / submitPlcOperation -----------------------

// handleSignPlcOperation signs a PLC update operation on the caller's
// behalf, merging any fields they supplied over the account's current
// published PLC state. Requires a one-time admin-issued token — PLAN.md's
// admin-CLI-confirmation stand-in for the email-gated
// requestPlcOperationSignature flow (see admin.go's approvePlcOp).
func (s *Server) handleSignPlcOperation(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in map[string]any
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	token, _ := in["token"].(string)
	if token == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "token is required")
		return
	}
	if err := s.store.ConsumeAdminToken(r.Context(), token, did, store.TokenPurposePLCSign); err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "InvalidToken", "invalid or expired token")
		return
	}

	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	rotationPriv, err := atcrypto.ParsePrivateMultibase(acct.RotationKey)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load rotation key")
		return
	}

	plcClient := plc.NewClient(s.cfg.PLCURL)
	prevCID, lastOp, err := plcClient.GetLastOp(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to fetch current PLC state: "+err.Error())
		return
	}

	signedOp, err := plc.SignOp(rotationPriv, &prevCID, plc.OpFields{
		RotationKeys:        pickStringSlice(in, "rotationKeys", lastOp["rotationKeys"]),
		VerificationMethods: pickMap(in, "verificationMethods", lastOp["verificationMethods"]),
		AlsoKnownAs:         pickStringSlice(in, "alsoKnownAs", lastOp["alsoKnownAs"]),
		Services:            pickMap(in, "services", lastOp["services"]),
	})
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sign PLC operation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"operation": signedOp})
}

type submitPlcOperationInput struct {
	Operation map[string]any `json:"operation"`
}

// handleSubmitPlcOperation validates nothing beyond what plc.directory
// itself enforces, and submits the (already-signed) operation on the
// caller's behalf.
func (s *Server) handleSubmitPlcOperation(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	var in submitPlcOperationInput
	if err := decodeJSON(r, &in); err != nil || in.Operation == nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "operation is required")
		return
	}

	plcClient := plc.NewClient(s.cfg.PLCURL)
	if err := plcClient.Submit(r.Context(), did, in.Operation); err != nil {
		writeXRPCError(w, http.StatusBadGateway, "UpstreamFailure", "failed to submit PLC operation: "+err.Error())
		return
	}

	newHandle := ""
	if aka, ok := in.Operation["alsoKnownAs"].([]any); ok && len(aka) > 0 {
		if h, ok := aka[0].(string); ok {
			newHandle = strings.TrimPrefix(h, "at://")
		}
	}
	if newHandle != "" {
		// Best-effort: keep our local record in sync if this op is what
		// finalized a migration or handle change. If the handle is taken
		// locally by a different account this silently no-ops.
		_ = s.store.SetHandle(r.Context(), did, newHandle)
	}
	if err := s.emitIdentityEvent(r.Context(), did, newHandle); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence identity event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) emitIdentityEvent(ctx context.Context, did, handle string) error {
	evt := &comatproto.SyncSubscribeRepos_Identity{
		Did:  did,
		Time: time.Now().UTC().Format(time.RFC3339),
	}
	if handle != "" {
		evt.Handle = &handle
	}
	_, err := s.seq.Append(ctx, did, &firehose.Event{RepoIdentity: evt})
	return err
}

// --- generic PLC op field helpers ------------------------------------------

func toStringSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if str, ok := x.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func toMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func pickStringSlice(in map[string]any, key string, fallback any) []string {
	if v, ok := in[key]; ok {
		return toStringSlice(v)
	}
	return toStringSlice(fallback)
}

func pickMap(in map[string]any, key string, fallback any) map[string]any {
	if v, ok := in[key]; ok {
		return toMap(v)
	}
	return toMap(fallback)
}
