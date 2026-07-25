package xrpc

import (
	"net/http"
	"strconv"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"

	"github.com/vrypan/pds-light/internal/actorstore"
	"github.com/vrypan/pds-light/internal/carutil"
	"github.com/vrypan/pds-light/internal/store"
)

func writeCARResponse(w http.ResponseWriter, roots []cid.Cid, blks []blocks.Block) {
	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	w.WriteHeader(http.StatusOK)
	_ = carutil.WriteCAR(w, roots, blks)
}

func (s *Server) hostedActorStore(r *http.Request, did string) (*actorstore.Store, error) {
	if _, err := s.store.GetAccountByDID(r.Context(), did); err != nil {
		return nil, err
	}
	return s.actors.GetExisting(did)
}

func (s *Server) handleSyncGetRepo(w http.ResponseWriter, r *http.Request) {
	did := r.URL.Query().Get("did")
	if did == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	root, err := st.GetRepoRoot(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	blks, err := st.AllBlocks(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to read repo blocks")
		return
	}
	writeCARResponse(w, []cid.Cid{root.CommitCID}, blks)
}

func (s *Server) handleSyncGetRepoStatus(w http.ResponseWriter, r *http.Request) {
	did := r.URL.Query().Get("did")
	if did == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	acct, err := s.store.GetAccountByDID(r.Context(), did)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	out := map[string]any{
		"did":    acct.DID,
		"active": acct.Status == store.StatusActive,
	}
	if acct.Status != store.StatusActive {
		out["status"] = acct.Status
	}
	if st, err := s.hostedActorStore(r, did); err == nil {
		if root, err := st.GetRepoRoot(r.Context()); err == nil {
			out["rev"] = root.Rev
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSyncGetLatestCommit(w http.ResponseWriter, r *http.Request) {
	did := r.URL.Query().Get("did")
	if did == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	root, err := st.GetRepoRoot(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": root.CommitCID.String(), "rev": root.Rev})
}

// handleSyncGetRecord returns data blocks proving a record's (non-)
// existence. pds-light doesn't compute a minimal MST inclusion proof, so
// this returns the full block set — a valid but non-minimal proof.
func (s *Server) handleSyncGetRecord(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	did, collection, rkey := q.Get("did"), q.Get("collection"), q.Get("rkey")
	if did == "" || collection == "" || rkey == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did, collection, and rkey are required")
		return
	}
	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	root, err := st.GetRepoRoot(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
	if _, err := st.GetRecordCID(r.Context(), collection, rkey); err != nil {
		writeXRPCError(w, http.StatusNotFound, "RecordNotFound", "record not found")
		return
	}
	blks, err := st.AllBlocks(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to read repo blocks")
		return
	}
	writeCARResponse(w, []cid.Cid{root.CommitCID}, blks)
}

func (s *Server) handleSyncGetBlocks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	did := q.Get("did")
	cidStrs := q["cids"]
	if did == "" || len(cidStrs) == 0 {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did and cids are required")
		return
	}
	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	bs := st.Blockstore(st.DB())

	var blks []blocks.Block
	for _, cs := range cidStrs {
		c, err := cid.Decode(cs)
		if err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid cid: "+cs)
			return
		}
		blk, err := bs.Get(r.Context(), c)
		if err != nil {
			writeXRPCError(w, http.StatusNotFound, "BlockNotFound", "block not found: "+cs)
			return
		}
		blks = append(blks, blk)
	}
	writeCARResponse(w, nil, blks)
}

func (s *Server) handleSyncListBlobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	did := q.Get("did")
	if did == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	limit := 500
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	cursor := q.Get("cursor")

	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	cids, err := st.ListBlobCIDs(r.Context(), cursor, limit)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list blobs")
		return
	}
	out := map[string]any{"cids": cidStrings(cids)}
	if len(cids) == limit {
		out["cursor"] = cids[len(cids)-1].String()
	}
	writeJSON(w, http.StatusOK, out)
}

func cidStrings(cids []cid.Cid) []string {
	out := make([]string, len(cids))
	for i, c := range cids {
		out[i] = c.String()
	}
	return out
}

func (s *Server) handleSyncGetBlob(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	did, cidStr := q.Get("did"), q.Get("cid")
	if did == "" || cidStr == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did and cid are required")
		return
	}
	c, err := cid.Decode(cidStr)
	if err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid cid")
		return
	}
	st, err := s.hostedActorStore(r, did)
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to open repo")
		return
	}
	meta, err := st.GetBlobMeta(r.Context(), c)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "BlobNotFound", "blob not found")
		return
	}
	data, err := st.ReadBlobFile(c)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "BlobNotFound", "blob not found")
		return
	}
	w.Header().Set("Content-Type", meta.Mime)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleSyncListRepos(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 500
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	cursor := q.Get("cursor")

	accts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalServerError", "failed to list accounts")
		return
	}

	repos := make([]map[string]any, 0, len(accts))
	for _, a := range accts {
		if cursor != "" && a.DID <= cursor {
			continue
		}
		st, err := s.actors.GetExisting(a.DID)
		if err != nil {
			continue
		}
		root, err := st.GetRepoRoot(r.Context())
		if err != nil {
			continue
		}
		entry := map[string]any{
			"did":    a.DID,
			"head":   root.CommitCID.String(),
			"rev":    root.Rev,
			"active": a.Status == store.StatusActive,
		}
		if a.Status != store.StatusActive {
			entry["status"] = a.Status
		}
		repos = append(repos, entry)
		if len(repos) == limit {
			break
		}
	}

	out := map[string]any{"repos": repos}
	if len(repos) == limit {
		out["cursor"] = repos[len(repos)-1]["did"]
	}
	writeJSON(w, http.StatusOK, out)
}
