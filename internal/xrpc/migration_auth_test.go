package xrpc

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vrypan/robby/internal/actorstore"
	"github.com/vrypan/robby/internal/auth"
	"github.com/vrypan/robby/internal/config"
	"github.com/vrypan/robby/internal/store"
)

// migrationServer builds a server with real actor storage, so handlers can
// run past the auth check and actually write.
func migrationServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := &Server{
		cfg:    &config.Config{JWTSecret: principalSecret, DataDir: dir},
		store:  st,
		actors: actorstore.NewManager(dir),
	}
	return s, st
}

func primaryReq(t *testing.T, did, method, target string, body []byte) *http.Request {
	t.Helper()
	tok, _, err := auth.IssueAccessToken(principalSecret, did, "did:web:svc", 1,
		auth.Credential{Kind: auth.CredentialPrimary})
	if err != nil {
		t.Fatal(err)
	}
	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// TestUploadBlobAcceptsMigrationSession is the regression guard for the
// migration defect: a migrating account is deactivated from creation until
// server.activateAccount, and blob transfer happens in between. Before the
// fix this returned 401 and migrations silently arrived with missing blobs.
func TestUploadBlobAcceptsMigrationSession(t *testing.T) {
	s, st := migrationServer(t)
	mkAccount(t, st, "did:plc:m", "m.test", store.StatusDeactivated)

	req := primaryReq(t, "did:plc:m", http.MethodPost, "/xrpc/uploadBlob", []byte("image-bytes"))
	req.Header.Set("Content-Type", "image/jpeg")
	rec := httptest.NewRecorder()
	s.handleUploadBlob(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"$type":"blob"`) {
		t.Fatalf("expected a blob ref, got %s", rec.Body.String())
	}
}

func TestPutPreferencesAcceptsMigrationSession(t *testing.T) {
	s, st := migrationServer(t)
	mkAccount(t, st, "did:plc:m", "m.test", store.StatusDeactivated)

	body := []byte(`{"preferences":[{"$type":"app.bsky.actor.defs#adultContentPref"}]}`)
	req := primaryReq(t, "did:plc:m", http.MethodPost, "/xrpc/putPreferences", body)
	rec := httptest.NewRecorder()
	s.handlePutPreferences(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestDeactivatedStillCannotWriteRecords proves the exception stayed narrow:
// widening blob upload must not let a deactivated account post.
func TestDeactivatedStillCannotWriteRecords(t *testing.T) {
	s, st := migrationServer(t)
	mkAccount(t, st, "did:plc:m", "m.test", store.StatusDeactivated)

	body := []byte(`{"repo":"did:plc:m","collection":"app.bsky.feed.post",` +
		`"record":{"$type":"app.bsky.feed.post","text":"hi","createdAt":"2026-01-01T00:00:00Z"}}`)
	rec := httptest.NewRecorder()
	s.handleCreateRecord(rec, primaryReq(t, "did:plc:m", http.MethodPost, "/xrpc/createRecord", body))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("deactivated account created a record: status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

// TestTakenDownNeverPermitted covers the tightening that came with the fix:
// the status exception is for "deactivated" specifically, so a taken-down
// account is refused even on migration-flow endpoints. Previously any
// non-active status satisfied the migration check.
func TestTakenDownNeverPermitted(t *testing.T) {
	s, st := migrationServer(t)
	mkAccount(t, st, "did:plc:t", "t.test", store.StatusTakenDown)

	req := primaryReq(t, "did:plc:t", http.MethodPost, "/xrpc/uploadBlob", []byte("x"))
	rec := httptest.NewRecorder()
	s.handleUploadBlob(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("taken-down account uploaded a blob: status = %d", rec.Code)
	}

	if _, ok := s.requireMigrationAccessToken(httptest.NewRecorder(),
		primaryReq(t, "did:plc:t", http.MethodPost, "/xrpc/importRepo", nil)); ok {
		t.Fatal("taken-down account passed the migration access check")
	}
}

func TestStatusPermitted(t *testing.T) {
	cases := []struct {
		status           string
		allowDeactivated bool
		want             bool
	}{
		{store.StatusActive, false, true},
		{store.StatusActive, true, true},
		{store.StatusDeactivated, false, false},
		{store.StatusDeactivated, true, true},
		{store.StatusTakenDown, false, false},
		{store.StatusTakenDown, true, false},
	}
	for _, c := range cases {
		if got := statusPermitted(c.status, c.allowDeactivated); got != c.want {
			t.Errorf("statusPermitted(%q, %v) = %v, want %v",
				c.status, c.allowDeactivated, got, c.want)
		}
	}
}
