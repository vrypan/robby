package xrpc

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vrypan/robby/internal/actorstore"
	"github.com/vrypan/robby/internal/config"
	"github.com/vrypan/robby/internal/store"
)

// TestSyncUnknownDIDAllocatesNothing is the plan-004 guarantee: an
// unauthenticated public sync request for a syntactically valid but
// not-hosted DID must be read-only — it may not create an actor database,
// WAL/SHM sidecar, blob directory, or cache entry — and must return a clean
// 404 RepoNotFound rather than a misleading 500.
func TestSyncUnknownDIDAllocatesNothing(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(filepath.Join(dataDir, "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s := &Server{cfg: &config.Config{DataDir: dataDir}, store: st, actors: actorstore.NewManager(dataDir)}
	const did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"

	endpoints := []struct {
		name string
		fn   http.HandlerFunc
	}{
		{"getRepo", s.handleSyncGetRepo},
		{"getLatestCommit", s.handleSyncGetLatestCommit},
		{"getRecord", s.handleSyncGetRecord},
		{"getBlocks", s.handleSyncGetBlocks},
		{"listBlobs", s.handleSyncListBlobs},
		{"getBlob", s.handleSyncGetBlob},
	}
	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// Provide every query param any endpoint might require so the
			// request reaches the actor-store lookup rather than short-circuiting.
			req := httptest.NewRequest(http.MethodGet,
				"/xrpc/x?did="+did+"&collection=app.bsky.feed.post&rkey=abc"+
					"&cids=bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"+
					"&cid=bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq", nil)
			rec := httptest.NewRecorder()
			ep.fn(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s: status = %d, want 404; body=%s", ep.name, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "RepoNotFound") {
				t.Fatalf("%s: body = %s, want RepoNotFound", ep.name, rec.Body.String())
			}
		})
	}

	// Nothing on disk, and nothing cached in the manager.
	for _, p := range []string{
		filepath.Join(dataDir, "actors", did+".db"),
		filepath.Join(dataDir, "actors", did+".db-wal"),
		filepath.Join(dataDir, "actors", did+".db-shm"),
		filepath.Join(dataDir, "blobs", did),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("unexpected on-disk allocation %s (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "actors")); !os.IsNotExist(err) {
		t.Fatalf("actors directory should not have been created")
	}
	if _, err := s.actors.GetExisting(did); !os.IsNotExist(err) {
		t.Fatalf("manager cached or created a store for an unknown DID: err=%v", err)
	}
}

// TestSyncGetRepoStatusUnknownDID confirms getRepoStatus (which does its own
// account lookup before touching the actor store) also refuses to allocate.
func TestSyncGetRepoStatusUnknownDID(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(filepath.Join(dataDir, "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	s := &Server{cfg: &config.Config{DataDir: dataDir}, store: st, actors: actorstore.NewManager(dataDir)}
	req := httptest.NewRequest(http.MethodGet, "/xrpc/x?did=did:plc:ewvi7nxzyoun6zhxrhs64oiz", nil)
	rec := httptest.NewRecorder()
	s.handleSyncGetRepoStatus(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "actors")); !os.IsNotExist(err) {
		t.Fatal("getRepoStatus allocated actor storage for an unknown DID")
	}
}
