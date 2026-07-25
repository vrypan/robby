package store

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func makeAccount(t *testing.T, st *Store, did, handle, status string) *Account {
	t.Helper()
	a := Account{
		DID:          did,
		Handle:       handle,
		PasswordHash: "hash",
		SigningKey:   "sk",
		RotationKey:  "rk",
		Status:       status,
		CreatedAt:    time.Now(),
	}
	if err := st.CreateAccount(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAccountByDID(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestNewAccountStartsAtAuthVersionOne(t *testing.T) {
	st := testStore(t)
	acct := makeAccount(t, st, "did:plc:a", "a.test", StatusActive)
	if acct.AuthVersion != 1 {
		t.Fatalf("new account auth_version = %d, want 1", acct.AuthVersion)
	}
}

func TestPasswordAndStatusChangesBumpAuthVersion(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusActive)

	if err := st.SetPasswordHash(ctx, "did:plc:a", "newhash"); err != nil {
		t.Fatal(err)
	}
	acct, _ := st.GetAccountByDID(ctx, "did:plc:a")
	if acct.AuthVersion != 2 {
		t.Fatalf("after password change auth_version = %d, want 2", acct.AuthVersion)
	}

	if err := st.SetStatus(ctx, "did:plc:a", StatusTakenDown); err != nil {
		t.Fatal(err)
	}
	acct, _ = st.GetAccountByDID(ctx, "did:plc:a")
	if acct.AuthVersion != 3 {
		t.Fatalf("after takedown auth_version = %d, want 3", acct.AuthVersion)
	}
}

// TestActivateAccountDoesNotBumpAuthVersion guards the migration flow: the
// session that imports a repo and then activates the account must survive
// activation, so activation is deliberately non-revoking.
func TestActivateAccountDoesNotBumpAuthVersion(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusDeactivated)

	if err := st.ActivateAccount(ctx, "did:plc:a"); err != nil {
		t.Fatal(err)
	}
	acct, _ := st.GetAccountByDID(ctx, "did:plc:a")
	if acct.Status != StatusActive {
		t.Fatalf("status = %q, want active", acct.Status)
	}
	if acct.AuthVersion != 1 {
		t.Fatalf("activation changed auth_version to %d, want 1", acct.AuthVersion)
	}
}

func addRefresh(t *testing.T, st *Store, hash, did string, authVersion int64, exp time.Time) {
	t.Helper()
	err := st.CreateRefreshToken(context.Background(), RefreshToken{
		TokenHash:      hash,
		DID:            did,
		ExpiresAt:      exp,
		CreatedAt:      time.Now(),
		AuthVersion:    authVersion,
		CredentialKind: "primary",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestConsumeRefreshTokenHasOneWinner(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusActive)
	addRefresh(t, st, "hash1", "did:plc:a", 1, time.Now().Add(time.Hour))

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			if err := st.ConsumeRefreshToken(ctx, "hash1", "did:plc:a", 1); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("concurrent consume winners = %d, want exactly 1", wins)
	}
}

func TestConsumeRefreshTokenRejectsExpiredAndStaleVersion(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusActive)

	addRefresh(t, st, "expired", "did:plc:a", 1, time.Now().Add(-time.Minute))
	if err := st.ConsumeRefreshToken(ctx, "expired", "did:plc:a", 1); err == nil {
		t.Fatal("expired refresh token was consumed")
	}

	addRefresh(t, st, "stale", "did:plc:a", 1, time.Now().Add(time.Hour))
	if err := st.ConsumeRefreshToken(ctx, "stale", "did:plc:a", 2); err == nil {
		t.Fatal("refresh token consumed under a mismatched auth version")
	}
}

// TestCreateRefreshTokenPrunesExpired proves the opportunistic cleanup keeps
// expired rows from accumulating (they are otherwise never deleted).
func TestCreateRefreshTokenPrunesExpired(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusActive)

	addRefresh(t, st, "old", "did:plc:a", 1, time.Now().Add(-time.Hour))
	addRefresh(t, st, "new", "did:plc:a", 1, time.Now().Add(time.Hour))

	if _, err := st.GetRefreshToken(ctx, "old"); err != ErrNotFound {
		t.Fatalf("expired token lookup err = %v, want ErrNotFound (should have been pruned)", err)
	}
	if _, err := st.GetRefreshToken(ctx, "new"); err != nil {
		t.Fatalf("valid token was pruned: %v", err)
	}
}

func TestRevokeAppPasswordDeletesSessions(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	makeAccount(t, st, "did:plc:a", "a.test", StatusActive)
	if err := st.CreateAppPassword(ctx, AppPassword{DID: "did:plc:a", Name: "phone", PasswordHash: "h", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// A session issued from that app password, plus one from the primary login.
	if err := st.CreateRefreshToken(ctx, RefreshToken{TokenHash: "ap", DID: "did:plc:a", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), AuthVersion: 1, CredentialKind: "app_password", AppPasswordName: "phone"}); err != nil {
		t.Fatal(err)
	}
	addRefresh(t, st, "primary", "did:plc:a", 1, time.Now().Add(time.Hour))

	if err := st.RevokeAppPassword(ctx, "did:plc:a", "phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetRefreshToken(ctx, "ap"); err != ErrNotFound {
		t.Fatalf("app-password session survived revocation: %v", err)
	}
	if _, err := st.GetRefreshToken(ctx, "primary"); err != nil {
		t.Fatalf("unrelated primary session was revoked: %v", err)
	}
	// Revoking a name that does not exist is a not-found error, not a silent no-op.
	if err := st.RevokeAppPassword(ctx, "did:plc:a", "phone"); err != ErrNotFound {
		t.Fatalf("second revoke err = %v, want ErrNotFound", err)
	}
}

func TestReserveSigningKeyIsFiniteAndNonOverwriting(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	if err := st.ReserveSigningKey(ctx, "did:plc:a", "key-one"); err != nil {
		t.Fatal(err)
	}
	// A second reservation for the same DID must not overwrite the first.
	if err := st.ReserveSigningKey(ctx, "did:plc:a", "key-two"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetReservedSigningKey(ctx, "did:plc:a")
	if err != nil {
		t.Fatal(err)
	}
	if got != "key-one" {
		t.Fatalf("reservation was overwritten: got %q, want key-one", got)
	}
}

func TestExpiredReservationIsNotReturnedAndGetsCleaned(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	// Insert an already-expired reservation directly.
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := st.db.ExecContext(ctx, `INSERT INTO reserved_signing_keys (did, signing_key, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		"did:plc:a", "stale", past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetReservedSigningKey(ctx, "did:plc:a"); err != ErrNotFound {
		t.Fatalf("expired reservation was returned: %v", err)
	}
	// A fresh reservation for another DID triggers cleanup of the expired row,
	// so the DID can be reserved again with a new key.
	if err := st.ReserveSigningKey(ctx, "did:plc:b", "kb"); err != nil {
		t.Fatal(err)
	}
	if err := st.ReserveSigningKey(ctx, "did:plc:a", "fresh"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetReservedSigningKey(ctx, "did:plc:a")
	if err != nil || got != "fresh" {
		t.Fatalf("re-reservation after expiry: got %q err %v, want fresh", got, err)
	}
}

func TestConsumeAdminTokenSingleUseAndScoped(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.CreateAdminToken(ctx, "tok", "did:plc:a", "delete", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Wrong purpose is rejected without consuming the token.
	if err := st.ConsumeAdminToken(ctx, "tok", "did:plc:a", "plc"); err == nil {
		t.Fatal("admin token accepted for the wrong purpose")
	}
	// Correct purpose consumes it exactly once.
	if err := st.ConsumeAdminToken(ctx, "tok", "did:plc:a", "delete"); err != nil {
		t.Fatalf("valid admin token rejected: %v", err)
	}
	if err := st.ConsumeAdminToken(ctx, "tok", "did:plc:a", "delete"); err == nil {
		t.Fatal("admin token was consumable twice")
	}
}
