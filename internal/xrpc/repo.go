package xrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/vrypan/robby/internal/actorstore"
	"github.com/vrypan/robby/internal/repoops"
)

// resolveRepoDID resolves the "repo" XRPC param (handle or DID) to a DID
// by looking up the account locally; robby only hosts its own users.
func (s *Server) resolveRepoDID(ctx context.Context, repoParam string) (string, error) {
	acct, err := s.store.GetAccountByIdentifier(ctx, strings.TrimPrefix(repoParam, "at://"))
	if err != nil {
		return "", err
	}
	return acct.DID, nil
}

// requireOwnRepo validates the bearer access token and checks that its DID
// matches repoParam (handle or DID). robby doesn't yet support
// acting-on-behalf-of, so writes must be made by the record owner.
func (s *Server) requireOwnRepo(w http.ResponseWriter, r *http.Request, repoParam string) (did string, ok bool) {
	authDID, ok := s.requireAccessToken(w, r)
	if !ok {
		return "", false
	}
	targetDID, err := s.resolveRepoDID(r.Context(), repoParam)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return "", false
	}
	if targetDID != authDID {
		writeXRPCError(w, http.StatusForbidden, "AuthRequired", "not authorized to write to this repo")
		return "", false
	}
	return authDID, true
}

func (s *Server) signingKeyFor(ctx context.Context, did string) (atcrypto.PrivateKey, error) {
	acct, err := s.store.GetAccountByDID(ctx, did)
	if err != nil {
		return nil, err
	}
	return atcrypto.ParsePrivateMultibase(acct.SigningKey)
}

type recordURI struct {
	DID        string
	Collection string
	RKey       string
}

func (u recordURI) String() string {
	return fmt.Sprintf("at://%s/%s/%s", u.DID, u.Collection, u.RKey)
}

// --- createRecord / putRecord / deleteRecord -------------------------------

// parseRecord converts an incoming record's JSON into the atproto data
// model. It must be atdata.UnmarshalJSON rather than a plain encoding/json
// decode: only the former turns JSON blob refs ({"$type":"blob",...}) and
// links ({"$link":...}) into the typed values the Lexicon validator and CBOR
// encoder expect. Decoding straight into map[string]any leaves a blob as an
// untyped map, which fails validation with "expected a blob".
func parseRecord(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("record is required")
	}
	return atdata.UnmarshalJSON(raw)
}

type createRecordInput struct {
	Repo       string          `json:"repo"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Record     json.RawMessage `json:"record"`
}

type recordWriteOutput struct {
	URI    string        `json:"uri"`
	CID    string        `json:"cid"`
	Commit commitSummary `json:"commit"`
}

type commitSummary struct {
	CID string `json:"cid"`
	Rev string `json:"rev"`
}

func (s *Server) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	var in createRecordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if _, err := syntax.ParseNSID(in.Collection); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid collection NSID")
		return
	}
	if in.RKey != "" {
		if _, err := syntax.ParseRecordKey(in.RKey); err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid rkey")
			return
		}
	}
	did, ok := s.requireOwnRepo(w, r, in.Repo)
	if !ok {
		return
	}
	record, err := parseRecord(in.Record)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid record data: "+err.Error())
		return
	}
	s.doWrite(w, r, did, []repoops.WriteOp{{
		Action:     repoops.ActionCreate,
		Collection: in.Collection,
		RKey:       in.RKey,
		Record:     record,
	}})
}

type putRecordInput struct {
	Repo       string          `json:"repo"`
	Collection string          `json:"collection"`
	RKey       string          `json:"rkey"`
	Record     json.RawMessage `json:"record"`
}

func (s *Server) handlePutRecord(w http.ResponseWriter, r *http.Request) {
	var in putRecordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	if _, err := syntax.ParseNSID(in.Collection); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid collection NSID")
		return
	}
	if _, err := syntax.ParseRecordKey(in.RKey); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid rkey")
		return
	}
	did, ok := s.requireOwnRepo(w, r, in.Repo)
	if !ok {
		return
	}
	record, err := parseRecord(in.Record)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid record data: "+err.Error())
		return
	}

	action := repoops.ActionCreate
	if st, gerr := s.actors.Get(did); gerr == nil {
		if _, cerr := st.GetRecordCID(r.Context(), in.Collection, in.RKey); cerr == nil {
			action = repoops.ActionUpdate
		}
	}

	s.doWrite(w, r, did, []repoops.WriteOp{{
		Action:     action,
		Collection: in.Collection,
		RKey:       in.RKey,
		Record:     record,
	}})
}

type deleteRecordInput struct {
	Repo       string `json:"repo"`
	Collection string `json:"collection"`
	RKey       string `json:"rkey"`
}

func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	var in deleteRecordInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	did, ok := s.requireOwnRepo(w, r, in.Repo)
	if !ok {
		return
	}
	s.doWrite(w, r, did, []repoops.WriteOp{{
		Action:     repoops.ActionDelete,
		Collection: in.Collection,
		RKey:       in.RKey,
	}})
}

// doWrite runs a single-op write batch and writes the standard
// create/put/delete XRPC response.
func (s *Server) doWrite(w http.ResponseWriter, r *http.Request, did string, ops []repoops.WriteOp) {
	signingKey, err := s.signingKeyFor(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load signing key")
		return
	}
	commit, commitCID, results, err := s.writer.ApplyWrites(r.Context(), did, signingKey, ops)
	if err != nil {
		writeWriteError(w, err)
		return
	}
	res := results[0]
	if res.Action == repoops.ActionDelete {
		writeJSON(w, http.StatusOK, map[string]any{
			"commit": commitSummary{CID: commitCID.String(), Rev: commit.Rev},
		})
		return
	}
	writeJSON(w, http.StatusOK, recordWriteOutput{
		URI:    recordURI{DID: did, Collection: res.Collection, RKey: res.RKey}.String(),
		CID:    res.CID.String(),
		Commit: commitSummary{CID: commitCID.String(), Rev: commit.Rev},
	})
}

func writeWriteError(w http.ResponseWriter, err error) {
	if err == actorstore.ErrNotFound {
		writeXRPCError(w, http.StatusBadRequest, "RecordNotFound", "record not found")
		return
	}
	writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", err.Error())
}

// --- applyWrites -------------------------------------------------------

type applyWritesInput struct {
	Repo   string            `json:"repo"`
	Writes []json.RawMessage `json:"writes"`
}

func (s *Server) handleApplyWrites(w http.ResponseWriter, r *http.Request) {
	var in applyWritesInput
	if err := decodeJSON(r, &in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed request body")
		return
	}
	did, ok := s.requireOwnRepo(w, r, in.Repo)
	if !ok {
		return
	}

	ops := make([]repoops.WriteOp, 0, len(in.Writes))
	for _, raw := range in.Writes {
		var head struct {
			Type       string          `json:"$type"`
			Collection string          `json:"collection"`
			RKey       string          `json:"rkey"`
			Value      json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "malformed write entry")
			return
		}
		var action repoops.Action
		switch head.Type {
		case "com.atproto.repo.applyWrites#create":
			action = repoops.ActionCreate
		case "com.atproto.repo.applyWrites#update":
			action = repoops.ActionUpdate
		case "com.atproto.repo.applyWrites#delete":
			action = repoops.ActionDelete
		default:
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "unknown write $type: "+head.Type)
			return
		}
		var record map[string]any
		if action != repoops.ActionDelete {
			parsed, perr := parseRecord(head.Value)
			if perr != nil {
				writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid record data: "+perr.Error())
				return
			}
			record = parsed
		}
		ops = append(ops, repoops.WriteOp{
			Action:     action,
			Collection: head.Collection,
			RKey:       head.RKey,
			Record:     record,
		})
	}

	signingKey, err := s.signingKeyFor(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to load signing key")
		return
	}
	commit, commitCID, results, err := s.writer.ApplyWrites(r.Context(), did, signingKey, ops)
	if err != nil {
		writeWriteError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		if res.Action == repoops.ActionDelete {
			out = append(out, map[string]any{
				"$type": "com.atproto.repo.applyWrites#deleteResult",
			})
			continue
		}
		out = append(out, map[string]any{
			"$type": "com.atproto.repo.applyWrites#" + string(res.Action) + "Result",
			"uri":   recordURI{DID: did, Collection: res.Collection, RKey: res.RKey}.String(),
			"cid":   res.CID.String(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"commit":  commitSummary{CID: commitCID.String(), Rev: commit.Rev},
		"results": out,
	})
}

// --- getRecord / listRecords / describeRepo -----------------------------

func (s *Server) handleGetRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	repoParam, collection, rkey := q.Get("repo"), q.Get("collection"), q.Get("rkey")
	if repoParam == "" || collection == "" || rkey == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo, collection, and rkey are required")
		return
	}
	did, err := s.resolveRepoDID(r.Context(), repoParam)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	c, err := st.GetRecordCID(r.Context(), collection, rkey)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RecordNotFound", "record not found")
		return
	}
	bs := st.Blockstore(st.DB())
	blk, err := bs.Get(r.Context(), *c)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to read record block")
		return
	}
	record, err := atdata.UnmarshalCBOR(blk.RawData())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to decode record")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"uri":   recordURI{DID: did, Collection: collection, RKey: rkey}.String(),
		"cid":   c.String(),
		"value": record,
	})
}

func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	repoParam, collection := q.Get("repo"), q.Get("collection")
	if repoParam == "" || collection == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo and collection are required")
		return
	}
	limit := 50
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	reverse := q.Get("reverse") == "true"
	cursor := q.Get("cursor")

	did, err := s.resolveRepoDID(r.Context(), repoParam)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	entries, err := st.ListRecords(r.Context(), collection, cursor, limit, reverse)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list records")
		return
	}

	bs := st.Blockstore(st.DB())
	records := make([]map[string]any, 0, len(entries))
	var nextCursor string
	for _, e := range entries {
		blk, err := bs.Get(r.Context(), e.CID)
		if err != nil {
			writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to read record block")
			return
		}
		value, err := atdata.UnmarshalCBOR(blk.RawData())
		if err != nil {
			writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to decode record")
			return
		}
		records = append(records, map[string]any{
			"uri":   recordURI{DID: did, Collection: e.Collection, RKey: e.RKey}.String(),
			"cid":   e.CID.String(),
			"value": value,
		})
		nextCursor = e.RKey
	}
	out := map[string]any{"records": records}
	if len(entries) == limit {
		out["cursor"] = nextCursor
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDescribeRepo(w http.ResponseWriter, r *http.Request) {
	repoParam := r.URL.Query().Get("repo")
	if repoParam == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo is required")
		return
	}
	acct, err := s.store.GetAccountByIdentifier(r.Context(), strings.TrimPrefix(repoParam, "at://"))
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"handle":          acct.Handle,
		"did":             acct.DID,
		"didDoc":          map[string]any{},
		"collections":     []string{},
		"handleIsCorrect": true,
	})
}

// --- uploadBlob ----------------------------------------------------------

const maxBlobSize = 100 << 20 // 100 MiB, matching the Cloudflare body limit from PLAN.md Ops.

func (s *Server) handleUploadBlob(w http.ResponseWriter, r *http.Request) {
	// Migratable: a migrating account is deactivated until the final
	// activateAccount step, and transferring blobs happens before that.
	did, ok := s.requireMigratableAccessToken(w, r)
	if !ok {
		return
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBlobSize+1))
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "failed to read blob body")
		return
	}
	if len(data) > maxBlobSize {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "blob exceeds max size")
		return
	}
	mime := r.Header.Get("Content-Type")
	if mime == "" {
		mime = "application/octet-stream"
	}

	c, err := repoops.BlobCID(data)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to hash blob")
		return
	}

	st, err := s.actors.Get(did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	if err := st.WriteBlobFile(c, data); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store blob")
		return
	}
	tx, err := st.BeginTx(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store blob metadata")
		return
	}
	if err := st.PutBlobMeta(r.Context(), tx, c, mime, int64(len(data))); err != nil {
		tx.Rollback()
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store blob metadata")
		return
	}
	if err := tx.Commit(); err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to store blob metadata")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"blob": map[string]any{
			"$type":    "blob",
			"ref":      map[string]any{"$link": c.String()},
			"mimeType": mime,
			"size":     len(data),
		},
	})
}
