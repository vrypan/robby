package xrpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vrypan/robby/internal/auth"
	"github.com/vrypan/robby/internal/config"
	"github.com/vrypan/robby/internal/store"
)

const principalSecret = "principal-test-secret"

func principalServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{cfg: &config.Config{JWTSecret: principalSecret}, store: st}, st
}

func bearerReq(t *testing.T, did string, av int64, cred auth.Credential) *http.Request {
	t.Helper()
	tok, _, err := auth.IssueAccessToken(principalSecret, did, "did:web:svc", av, cred)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/xrpc/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	return req
}

func mkAccount(t *testing.T, st *store.Store, did, handle, status string) {
	t.Helper()
	err := st.CreateAccount(context.Background(), store.Account{
		DID: did, Handle: handle, PasswordHash: "h", SigningKey: "s", RotationKey: "r",
		Status: status, CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPrimarySessionIsPrivileged(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	req := bearerReq(t, "did:plc:a", 1, auth.Credential{Kind: auth.CredentialPrimary})

	if _, ok := s.requirePrivilegedAccessToken(httptest.NewRecorder(), req); !ok {
		t.Fatal("primary session was denied privileged access")
	}
}

// TestUnprivilegedAppPasswordCannotEscalate is the core plan-003 guarantee:
// an unprivileged app-password session performs ordinary operations but is
// refused at every sensitive (privileged) endpoint.
func TestUnprivilegedAppPasswordCannotEscalate(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	if err := st.CreateAppPassword(context.Background(), store.AppPassword{
		DID: "did:plc:a", Name: "phone", PasswordHash: "h", Privileged: false, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential{Kind: auth.CredentialAppPassword, AppPasswordName: "phone"}

	// Ordinary access is allowed.
	if _, ok := s.requireAccessToken(httptest.NewRecorder(), bearerReq(t, "did:plc:a", 1, cred)); !ok {
		t.Fatal("unprivileged app password was denied ordinary access")
	}
	// Privileged access is refused with 403.
	rec := httptest.NewRecorder()
	if _, ok := s.requirePrivilegedAccessToken(rec, bearerReq(t, "did:plc:a", 1, cred)); ok {
		t.Fatal("unprivileged app password was granted privileged access")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("privileged denial status = %d, want 403", rec.Code)
	}
}

func TestPrivilegedAppPasswordIsPrivileged(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	if err := st.CreateAppPassword(context.Background(), store.AppPassword{
		DID: "did:plc:a", Name: "laptop", PasswordHash: "h", Privileged: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential{Kind: auth.CredentialPrivilegedAppPassword, AppPasswordName: "laptop"}
	if _, ok := s.requirePrivilegedAccessToken(httptest.NewRecorder(), bearerReq(t, "did:plc:a", 1, cred)); !ok {
		t.Fatal("privileged app password was denied privileged access")
	}
}

// TestStaleAuthVersionRejected proves password reset / takedown (which bump
// the account auth version) immediately invalidate an existing access token.
func TestStaleAuthVersionRejected(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	// Token minted at version 1; account then moves to version 2.
	req := bearerReq(t, "did:plc:a", 1, auth.Credential{Kind: auth.CredentialPrimary})
	if err := st.SetPasswordHash(context.Background(), "did:plc:a", "new"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, ok := s.requireAccessToken(rec, req); ok {
		t.Fatal("token from a superseded auth version was accepted")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale-version status = %d, want 401", rec.Code)
	}
}

func TestTakenDownAccountCannotAuthenticate(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	req := bearerReq(t, "did:plc:a", 1, auth.Credential{Kind: auth.CredentialPrimary})
	// Takedown bumps auth_version and flips status; both should block access.
	if err := st.SetStatus(context.Background(), "did:plc:a", store.StatusTakenDown); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.requireAccessToken(httptest.NewRecorder(), req); ok {
		t.Fatal("taken-down account authenticated")
	}
}

// TestRevokedAppPasswordRejected proves a session whose app password was
// deleted can no longer authenticate, even though its JWT is still unexpired.
func TestRevokedAppPasswordRejected(t *testing.T) {
	s, st := principalServer(t)
	mkAccount(t, st, "did:plc:a", "a.test", store.StatusActive)
	if err := st.CreateAppPassword(context.Background(), store.AppPassword{
		DID: "did:plc:a", Name: "phone", PasswordHash: "h", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential{Kind: auth.CredentialAppPassword, AppPasswordName: "phone"}
	req := bearerReq(t, "did:plc:a", 1, cred)
	if err := st.RevokeAppPassword(context.Background(), "did:plc:a", "phone"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.requireAccessToken(httptest.NewRecorder(), req); ok {
		t.Fatal("revoked app-password session still authenticated")
	}
}
