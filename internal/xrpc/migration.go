package xrpc

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	indigoauth "github.com/bluesky-social/indigo/atproto/auth"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	car "github.com/ipld/go-car"

	"github.com/vrypan/pds-light/internal/actorstore"
	"github.com/vrypan/pds-light/internal/auth"
	"github.com/vrypan/pds-light/internal/store"
)

// --- server.reserveSigningKey --------------------------------------------

type reserveSigningKeyInput struct {
	DID string `json:"did"`
}

// handleReserveSigningKey generates a signing key ahead of account
// creation, so a client migrating a DID in can build a PLC update op
// naming this key before the account (and thus a stable did:key) exists.
// Public; no auth required, per spec.
func (s *Server) handleReserveSigningKey(w http.ResponseWriter, r *http.Request) {
	var in reserveSigningKeyInput
	_ = decodeJSON(r, &in) // body is optional

	if in.DID != "" {
		if _, err := syntax.ParseDID(in.DID); err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid did")
			return
		}
		if existing, err := s.store.GetReservedSigningKey(r.Context(), in.DID); err == nil {
			priv, err := atcrypto.ParsePrivateMultibase(existing)
			if err != nil {
				writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "invalid reserved signing key")
				return
			}
			pub, err := priv.PublicKey()
			if err != nil {
				writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to derive signing key")
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"signingKey": pub.DIDKey()})
			return
		}
	}

	priv, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate signing key")
		return
	}
	pub, err := priv.PublicKey()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to derive signing key")
		return
	}

	if in.DID != "" {
		if err := s.store.ReserveSigningKey(r.Context(), in.DID, priv.Multibase()); err != nil {
			writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to reserve signing key")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"signingKey": pub.DIDKey()})
}

// --- server.createAccount (migration-in only) ----------------------------

type createAccountInput struct {
	DID        string `json:"did"`
	Handle     string `json:"handle"`
	Password   string `json:"password"`
	Email      string `json:"email"`
	InviteCode string `json:"inviteCode"`
}

// handleServerCreateAccount implements the public com.atproto.server.
// createAccount, but — per PLAN.md's "admin-created accounts, no
// self-serve signup" decision — only for the migration-in case: it
// requires an existing "did" plus a service-auth bearer token proving
// the caller currently controls that DID. Brand-new accounts are still
// only created via the admin CLI/API.
func (s *Server) handleServerCreateAccount(w http.ResponseWriter, r *http.Request) {
	var in createAccountInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest",
			"this server only creates accounts via migration (did is required); new accounts are created by the admin")
		return
	}
	did, err := syntax.ParseDID(in.DID)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid did")
		return
	}
	handle, err := syntax.ParseHandle(in.Handle)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidHandle", "invalid handle")
		return
	}
	if in.Password == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidPassword", "password is required")
		return
	}

	tokenString, ok := bearerToken(r)
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "missing service-auth bearer token")
		return
	}
	validator := &indigoauth.ServiceAuthValidator{Audience: ServiceDID(s.cfg), Dir: s.dir}
	lxm := syntax.NSID("com.atproto.server.createAccount")
	callerDID, err := validator.Validate(r.Context(), tokenString, &lxm)
	if err != nil || callerDID != did {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid or non-matching service-auth token")
		return
	}

	if _, err := s.store.GetAccountByDID(r.Context(), did.String()); err == nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "this DID is already registered on this server")
		return
	}
	if _, err := s.store.GetAccountByHandle(r.Context(), handle.String()); err == nil {
		writeXRPCError(w, http.StatusBadRequest, "HandleNotAvailable", "handle already in use")
		return
	}

	var signingPriv atcrypto.PrivateKeyExportable
	if reserved, rErr := s.store.GetReservedSigningKey(r.Context(), did.String()); rErr == nil {
		signingPriv, err = atcrypto.ParsePrivateMultibase(reserved)
	} else {
		signingPriv, err = atcrypto.GeneratePrivateKeyK256()
	}
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to establish signing key")
		return
	}
	rotationPriv, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to generate rotation key")
		return
	}
	passwordHash, err := auth.HashPassword(in.Password)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to hash password")
		return
	}

	acct := store.Account{
		DID:          did.String(),
		Handle:       handle.String(),
		PasswordHash: passwordHash,
		SigningKey:   signingPriv.Multibase(),
		RotationKey:  rotationPriv.Multibase(),
		// Deactivated until repo + identity migration finish and the
		// client calls server.activateAccount.
		Status:      store.StatusDeactivated,
		AuthVersion: 1,
		CreatedAt:   time.Now(),
	}
	if err := s.store.CreateAccount(r.Context(), acct); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store account: "+err.Error())
		return
	}

	s.issueSession(w, &acct, auth.Credential{Kind: auth.CredentialPrimary})
}

// --- repo.importRepo -------------------------------------------------------

const maxImportSize = 500 << 20 // 500 MiB

// handleImportRepo implements com.atproto.repo.importRepo: replaces the
// authenticated account's (empty, freshly-created) repo with one
// uploaded as a CAR file. The commit signature is checked against the
// account's *currently published* identity, since at this point in a
// migration the DID doc still names the old PDS's signing key.
func (s *Server) handleImportRepo(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireMigrationAccessToken(w, r)
	if !ok {
		return
	}
	defer r.Body.Close()

	carBytes, err := io.ReadAll(io.LimitReader(r.Body, maxImportSize+1))
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to read CAR body")
		return
	}
	if len(carBytes) > maxImportSize {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "CAR exceeds max import size")
		return
	}

	cr, err := car.NewCarReader(bytes.NewReader(carBytes))
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to parse CAR: "+err.Error())
		return
	}
	if len(cr.Header.Roots) < 1 {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "CAR file missing root CID")
		return
	}
	commitCID := cr.Header.Roots[0]

	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}

	tx, err := st.BeginTx(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to begin import")
		return
	}
	defer tx.Rollback()

	if err := st.ClearRepo(r.Context(), tx); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to clear existing repo")
		return
	}

	bs := st.Blockstore(tx)
	var commitBytes []byte
	for {
		blk, err := cr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed CAR block stream")
			return
		}
		if err := bs.Put(r.Context(), blk); err != nil {
			writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store block")
			return
		}
		if blk.Cid() == commitCID {
			commitBytes = blk.RawData()
		}
	}
	if commitBytes == nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "CAR file did not include the commit block")
		return
	}

	var commit repo.Commit
	if err := commit.UnmarshalCBOR(bytes.NewReader(commitBytes)); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to parse commit: "+err.Error())
		return
	}
	if err := commit.VerifyStructure(); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid commit: "+err.Error())
		return
	}
	if commit.DID != did {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "commit DID does not match authenticated account")
		return
	}

	parsedDID, err := syntax.ParseDID(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "invalid account DID")
		return
	}
	ident, err := s.dir.LookupDID(r.Context(), parsedDID)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to resolve current identity: "+err.Error())
		return
	}
	pubKey, err := ident.PublicKey()
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to resolve current signing key: "+err.Error())
		return
	}
	if err := commit.VerifySignature(pubKey); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "commit signature verification failed: "+err.Error())
		return
	}

	tree, err := mst.LoadTreeFromStore(r.Context(), bs, commit.Data)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to load MST: "+err.Error())
		return
	}

	if err := importWalk(r.Context(), st, tx, bs, tree); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to index imported records: "+err.Error())
		return
	}

	if err := st.SetRepoRoot(r.Context(), tx, commitCID, commit.Rev); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to set repo root")
		return
	}
	if err := tx.Commit(); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to commit import")
		return
	}

	if err := s.emitSyncEvent(r.Context(), did, commitCID, commit.Rev); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence sync event")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{})
}

// --- repo.listMissingBlobs -------------------------------------------------

func (s *Server) handleListMissingBlobs(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireMigrationAccessToken(w, r)
	if !ok {
		return
	}
	limit := 500
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	cursor := r.URL.Query().Get("cursor")

	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	refs, err := st.MissingBlobRefs(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list missing blobs")
		return
	}

	blobs := make([]map[string]string, 0, len(refs))
	for _, ref := range refs {
		cidStr := ref.CID.String()
		if cursor != "" && cidStr <= cursor {
			continue
		}
		blobs = append(blobs, map[string]string{
			"cid":       cidStr,
			"recordUri": recordURI{DID: did, Collection: ref.Collection, RKey: ref.RKey}.String(),
		})
		if len(blobs) == limit {
			break
		}
	}

	out := map[string]any{"blobs": blobs}
	if len(blobs) == limit {
		out["cursor"] = blobs[len(blobs)-1]["cid"]
	}
	writeJSON(w, http.StatusOK, out)
}

// --- server.activateAccount / deactivateAccount / deleteAccount ----------

func (s *Server) handleActivateAccount(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireMigrationAccessToken(w, r)
	if !ok {
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	if _, err := st.GetRepoRoot(r.Context()); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "account has no repo yet; import one before activating")
		return
	}
	if err := s.store.ActivateAccount(r.Context(), did); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	if err := s.emitAccountEvent(r.Context(), did, true, nil); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence account event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

type deactivateAccountInput struct {
	DeleteAfter string `json:"deleteAfter"`
}

func (s *Server) handleDeactivateAccountSelf(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requirePrivilegedAccessToken(w, r)
	if !ok {
		return
	}
	var in deactivateAccountInput
	_ = decodeJSON(r, &in) // body is optional; deleteAfter isn't enforced

	if err := s.store.SetStatus(r.Context(), did, store.StatusDeactivated); err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	_ = s.store.DeleteRefreshTokensForDID(r.Context(), did)
	status := store.StatusDeactivated
	if err := s.emitAccountEvent(r.Context(), did, false, &status); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to sequence account event")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

type deleteAccountInput struct {
	DID      string `json:"did"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

// handleDeleteAccount requires session auth plus the account password
// and an admin-issued one-time token (see admin.go's approvePlcOp-style
// flow) — the admin-CLI-confirmation replacement for the email-gated
// requestAccountDelete flow.
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	callerDID, ok := s.requirePrivilegedAccessToken(w, r)
	if !ok {
		return
	}
	var in deleteAccountInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if in.DID != callerDID {
		writeXRPCError(w, http.StatusForbidden, "AuthRequired", "can only delete your own account")
		return
	}

	acct, err := s.store.GetAccountByDID(r.Context(), callerDID)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	if ok, err := auth.VerifyPassword(in.Password, acct.PasswordHash); err != nil || !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthenticationRequired", "invalid password")
		return
	}
	if err := s.store.ConsumeAdminToken(r.Context(), in.Token, callerDID, store.TokenPurposeDeleteAccount); err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "InvalidToken", "invalid or expired deletion token")
		return
	}

	if err := s.store.DeleteRefreshTokensForDID(r.Context(), callerDID); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to revoke sessions")
		return
	}
	if err := s.store.DeleteAccount(r.Context(), callerDID); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to delete account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// --- server.checkAccountStatus --------------------------------------------

func (s *Server) handleCheckAccountStatus(w http.ResponseWriter, r *http.Request) {
	did, ok := s.requireAccessToken(w, r)
	if !ok {
		return
	}
	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "account not found")
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}

	out := map[string]any{
		"activated":          acct.Status == store.StatusActive,
		"validDid":           true,
		"repoCommit":         "",
		"repoRev":            "",
		"repoBlocks":         0,
		"indexedRecords":     0,
		"privateStateValues": 0,
		"expectedBlobs":      0,
		"importedBlobs":      0,
	}

	if root, err := st.GetRepoRoot(r.Context()); err == nil {
		out["repoCommit"] = root.CommitCID.String()
		out["repoRev"] = root.Rev
	}
	if n, err := st.CountBlocks(r.Context()); err == nil {
		out["repoBlocks"] = n
	}
	if n, err := st.CountRecords(r.Context()); err == nil {
		out["indexedRecords"] = n
	}
	if n, err := st.CountBlobs(r.Context()); err == nil {
		out["expectedBlobs"] = n
	}
	if n, err := st.CountImportedBlobs(r.Context()); err == nil {
		out["importedBlobs"] = n
	}

	if parsedDID, err := syntax.ParseDID(did); err == nil {
		if doc, err := s.dir.ResolveDID(r.Context(), parsedDID); err == nil {
			valid := false
			ourHost := "https://" + s.cfg.Hostname
			for _, svc := range doc.Service {
				if strings.HasSuffix(svc.ID, "#atproto_pds") && strings.TrimRight(svc.ServiceEndpoint, "/") == ourHost {
					valid = true
					break
				}
			}
			out["validDid"] = valid
		}
	}

	writeJSON(w, http.StatusOK, out)
}

// importWalk rebuilds the record index (and blob metadata/refs) for an
// imported repo by walking its MST and reading each record block back
// out of the block store that was just populated from the CAR.
func importWalk(ctx context.Context, st *actorstore.Store, tx *sql.Tx, bs blockstore.Blockstore, tree *mst.Tree) error {
	return tree.Walk(func(key []byte, val cid.Cid) error {
		collection, rkey, ok := strings.Cut(string(key), "/")
		if !ok {
			return fmt.Errorf("malformed record path in MST: %q", key)
		}
		if err := st.PutRecordIndex(ctx, tx, collection, rkey, val); err != nil {
			return err
		}

		blk, err := bs.Get(ctx, val)
		if err != nil {
			return fmt.Errorf("reading record block %s: %w", val, err)
		}
		record, err := atdata.UnmarshalCBOR(blk.RawData())
		if err != nil {
			return fmt.Errorf("decoding record %s: %w", val, err)
		}
		for _, b := range atdata.ExtractBlobs(record) {
			blobCID := b.Ref.CID()
			if err := st.PutBlobMeta(ctx, tx, blobCID, b.MimeType, b.Size); err != nil {
				return err
			}
			if err := st.AddBlobRef(ctx, tx, blobCID, collection, rkey); err != nil {
				return err
			}
		}
		return nil
	})
}
