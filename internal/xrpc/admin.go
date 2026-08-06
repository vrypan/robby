package xrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"

	"github.com/vrypan/robby/internal/auth"
	"github.com/vrypan/robby/internal/carutil"
	"github.com/vrypan/robby/internal/firehose"
	"github.com/vrypan/robby/internal/plc"
	"github.com/vrypan/robby/internal/repoops"
	"github.com/vrypan/robby/internal/store"
)

// defaultSeedRecords are the app-level records robby writes into a brand-new
// account's initial commit. Bluesky creates these during signup and its
// client expects them to exist — e.g. the "activity subscriptions" settings
// screen fails to load without app.bsky.notification.declaration — so seeding
// sensible defaults keeps a robby-hosted account working out of the box. The
// declaration default ("followers") matches the lexicon's stated default for
// an absent record. Migration-in accounts are not seeded: they import their
// own repo, which already carries the user's real records.
func defaultSeedRecords() []repoops.WriteOp {
	return []repoops.WriteOp{{
		Action:     repoops.ActionCreate,
		Collection: "app.bsky.notification.declaration",
		RKey:       "self",
		Record: map[string]any{
			"$type":              "app.bsky.notification.declaration",
			"allowSubscriptions": "followers",
		},
	}}
}

// requireAdmin wraps a handler with HTTP Basic auth against the
// configured admin password. Username is ignored.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr, ok := clientAddr(r)
		if !ok || !addrInPrefixes(addr, s.adminNets) {
			s.log.Warn("admin request from disallowed address", "addr", r.RemoteAddr, "client", addr, "path", r.URL.Path)
			writeXRPCError(w, http.StatusForbidden, "Forbidden", "admin API is not reachable from this network")
			return
		}
		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(s.cfg.AdminPassword)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="robby-admin"`)
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

	// Give the account a real initial repo/commit seeded with the default
	// app-level records (see defaultSeedRecords), so sync endpoints and the
	// firehose have something to describe from the start and clients find the
	// records they expect. ApplyWrites (via writer.Seq) also emits #commit.
	commit, commitCID, _, err := s.writer.ApplyWrites(r.Context(), did, signingPriv, defaultSeedRecords())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to initialize repo: "+err.Error())
		return
	}
	if err := s.emitSyncEvent(r.Context(), did, commitCID, commit.Rev); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence sync event: "+err.Error())
		return
	}
	if err := s.emitAccountEvent(r.Context(), did, true, nil); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence account event: "+err.Error())
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
	status := store.StatusDeactivated
	if err := s.emitAccountEvent(r.Context(), in.DID, false, &status); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence account event: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// emitSyncEvent appends a #sync firehose event declaring did's current
// repo state (just the commit block — enough to recover cursor position
// and confirm the repo exists).
func (s *Server) emitSyncEvent(ctx context.Context, did string, commitCID cid.Cid, rev string) error {
	st, err := s.actors.Get(did)
	if err != nil {
		return err
	}
	blk, err := st.Blockstore(st.DB()).Get(ctx, commitCID)
	if err != nil {
		return err
	}
	var carBuf bytes.Buffer
	if err := carutil.WriteCAR(&carBuf, []cid.Cid{commitCID}, []blocks.Block{blk}); err != nil {
		return err
	}
	_, err = s.seq.Append(ctx, did, &firehose.Event{
		RepoSync: &comatproto.SyncSubscribeRepos_Sync{
			Did:    did,
			Rev:    rev,
			Blocks: lexutil.LexBytes(carBuf.Bytes()),
			Time:   time.Now().UTC().Format(time.RFC3339),
		},
	})
	return err
}

// emitAccountEvent appends an #account firehose event.
func (s *Server) emitAccountEvent(ctx context.Context, did string, active bool, status *string) error {
	_, err := s.seq.Append(ctx, did, &firehose.Event{
		RepoAccount: &comatproto.SyncSubscribeRepos_Account{
			Did:    did,
			Active: active,
			Status: status,
			Time:   time.Now().UTC().Format(time.RFC3339),
		},
	})
	return err
}

// --- admin token issuance (admin-CLI-confirmation replacement for the ---
// --- email-gated requestPlcOperationSignature / delete-account flows) ---

type adminApproveTokenInput struct {
	DID     string `json:"did"`
	Purpose string `json:"purpose"` // "plc_sign" (default) or "delete_account"
}

const adminTokenTTL = 15 * time.Minute

func (s *Server) handleAdminApproveToken(w http.ResponseWriter, r *http.Request) {
	var in adminApproveTokenInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	purpose := in.Purpose
	if purpose == "" {
		purpose = store.TokenPurposePLCSign
	}
	if purpose != store.TokenPurposePLCSign && purpose != store.TokenPurposeDeleteAccount {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "unknown purpose")
		return
	}
	if _, err := s.store.GetAccountByDID(r.Context(), in.DID); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}

	token, err := randomToken()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate token")
		return
	}
	expiresAt := time.Now().Add(adminTokenTTL)
	if err := s.store.CreateAdminToken(r.Context(), token, in.DID, purpose, expiresAt); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"purpose":   purpose,
		"expiresAt": expiresAt.UTC().Format(time.RFC3339),
	})
}

type adminTakedownAccountInput struct {
	DID string `json:"did"`
}

func (s *Server) handleAdminTakedownAccount(w http.ResponseWriter, r *http.Request) {
	var in adminTakedownAccountInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	if err := s.store.SetStatus(r.Context(), in.DID, store.StatusTakenDown); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	_ = s.store.DeleteRefreshTokensForDID(r.Context(), in.DID)
	status := store.StatusTakenDown
	if err := s.emitAccountEvent(r.Context(), in.DID, false, &status); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence account event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

type adminRefreshIdentityInput struct {
	DID string `json:"did"`
}

// handleAdminRefreshIdentity re-emits an #identity firehose event for an
// account without changing anything. It exists to nudge relays and AppViews
// to re-resolve a handle that has gone stale (e.g. shown as "Invalid Handle"
// / handle.invalid) after a handle change, once DNS and the DID document are
// already correct. It submits no PLC operation.
func (s *Server) handleAdminRefreshIdentity(w http.ResponseWriter, r *http.Request) {
	var in adminRefreshIdentityInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	acct, err := s.store.GetAccountByDID(r.Context(), in.DID)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	if err := s.emitIdentityEvent(r.Context(), acct.DID, acct.Handle); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence identity event: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"did": acct.DID, "handle": acct.Handle})
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
