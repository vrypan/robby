// Package store provides access to accounts.db, the global SQLite database
// holding accounts, auth state, and (in later phases) the event sequencer.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	StatusActive      = "active"
	StatusDeactivated = "deactivated"
	StatusTakenDown   = "taken-down"
)

var ErrNotFound = errors.New("not found")

type Account struct {
	DID          string
	Handle       string
	PasswordHash string
	SigningKey   string // multibase-encoded private key
	RotationKey  string // multibase-encoded private key
	Status       string
	CreatedAt    time.Time
}

type RefreshToken struct {
	TokenHash string // sha256 hex of the token value
	DID       string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type AppPassword struct {
	DID          string
	Name         string
	PasswordHash string
	Privileged   bool
	CreatedAt    time.Time
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("opening accounts db: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// DB returns the underlying connection, for packages (like sequencer)
// that share accounts.db for their own tables.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS accounts (
	did           TEXT PRIMARY KEY,
	handle        TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	signing_key   TEXT NOT NULL,
	rotation_key  TEXT NOT NULL,
	status        TEXT NOT NULL,
	created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash TEXT PRIMARY KEY,
	did        TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_did ON refresh_tokens(did);

CREATE TABLE IF NOT EXISTS app_passwords (
	did           TEXT NOT NULL,
	name          TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	privileged    INTEGER NOT NULL,
	created_at    TEXT NOT NULL,
	PRIMARY KEY (did, name)
);

CREATE TABLE IF NOT EXISTS reserved_signing_keys (
	did        TEXT PRIMARY KEY,
	signing_key TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_tokens (
	token      TEXT PRIMARY KEY,
	did        TEXT NOT NULL,
	purpose    TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`)
	if err != nil {
		return fmt.Errorf("migrating accounts db: %w", err)
	}
	return nil
}

func (s *Store) CreateAccount(ctx context.Context, a Account) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO accounts (did, handle, password_hash, signing_key, rotation_key, status, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.DID, a.Handle, a.PasswordHash, a.SigningKey, a.RotationKey, a.Status, a.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("creating account: %w", err)
	}
	return nil
}

func (s *Store) GetAccountByDID(ctx context.Context, did string) (*Account, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT did, handle, password_hash, signing_key, rotation_key, status, created_at
FROM accounts WHERE did = ?`, did)
	return scanAccount(row)
}

func (s *Store) GetAccountByHandle(ctx context.Context, handle string) (*Account, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT did, handle, password_hash, signing_key, rotation_key, status, created_at
FROM accounts WHERE handle = ?`, handle)
	return scanAccount(row)
}

// GetAccountByIdentifier looks up an account by handle or DID, whichever
// identifier looks like a DID (has a "did:" prefix).
func (s *Store) GetAccountByIdentifier(ctx context.Context, identifier string) (*Account, error) {
	if len(identifier) > 4 && identifier[:4] == "did:" {
		return s.GetAccountByDID(ctx, identifier)
	}
	return s.GetAccountByHandle(ctx, identifier)
}

func (s *Store) ListAccounts(ctx context.Context) ([]Account, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT did, handle, password_hash, signing_key, rotation_key, status, created_at
FROM accounts ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing accounts: %w", err)
	}
	defer rows.Close()

	var out []Account
	for rows.Next() {
		a, err := scanAccountRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *Store) SetPasswordHash(ctx context.Context, did, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET password_hash = ? WHERE did = ?`, hash, did)
	if err != nil {
		return fmt.Errorf("setting password: %w", err)
	}
	return checkRowsAffected(res)
}

func (s *Store) SetHandle(ctx context.Context, did, handle string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET handle = ? WHERE did = ?`, handle, did)
	if err != nil {
		return fmt.Errorf("setting handle: %w", err)
	}
	return checkRowsAffected(res)
}

func (s *Store) SetStatus(ctx context.Context, did, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET status = ? WHERE did = ?`, status, did)
	if err != nil {
		return fmt.Errorf("setting status: %w", err)
	}
	return checkRowsAffected(res)
}

// DeleteAccount removes the accounts.db row and any associated
// refresh-token/app-password/reserved-key/admin-token rows for did. It
// does not touch the actor's repo DB or blob files on disk — pds-light
// takes a soft-delete approach at the storage layer; those can be
// garbage-collected separately if desired.
func (s *Store) DeleteAccount(ctx context.Context, did string) error {
	for _, table := range []string{"refresh_tokens", "app_passwords", "reserved_signing_keys", "admin_tokens"} {
		if _, err := s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE did = ?", did); err != nil {
			return fmt.Errorf("deleting %s for account: %w", table, err)
		}
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE did = ?`, did)
	if err != nil {
		return fmt.Errorf("deleting account: %w", err)
	}
	return checkRowsAffected(res)
}

func (s *Store) CreateRefreshToken(ctx context.Context, t RefreshToken) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO refresh_tokens (token_hash, did, expires_at, created_at)
VALUES (?, ?, ?, ?)`,
		t.TokenHash, t.DID, t.ExpiresAt.UTC().Format(time.RFC3339), t.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("creating refresh token: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT token_hash, did, expires_at, created_at FROM refresh_tokens WHERE token_hash = ?`, tokenHash)

	var t RefreshToken
	var expiresAt, createdAt string
	if err := row.Scan(&t.TokenHash, &t.DID, &expiresAt, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting refresh token: %w", err)
	}
	var err error
	if t.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt); err != nil {
		return nil, err
	}
	if t.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash = ?`, tokenHash)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

func (s *Store) DeleteRefreshTokensForDID(ctx context.Context, did string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE did = ?`, did)
	if err != nil {
		return fmt.Errorf("deleting refresh tokens for did: %w", err)
	}
	return nil
}

func (s *Store) CreateAppPassword(ctx context.Context, ap AppPassword) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO app_passwords (did, name, password_hash, privileged, created_at)
VALUES (?, ?, ?, ?, ?)`,
		ap.DID, ap.Name, ap.PasswordHash, ap.Privileged, ap.CreatedAt.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("creating app password: %w", err)
	}
	return nil
}

func (s *Store) ListAppPasswords(ctx context.Context, did string) ([]AppPassword, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT did, name, password_hash, privileged, created_at FROM app_passwords
WHERE did = ? ORDER BY created_at ASC`, did)
	if err != nil {
		return nil, fmt.Errorf("listing app passwords: %w", err)
	}
	defer rows.Close()

	var out []AppPassword
	for rows.Next() {
		ap, err := scanAppPassword(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ap)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAppPassword(ctx context.Context, did, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_passwords WHERE did = ? AND name = ?`, did, name)
	if err != nil {
		return fmt.Errorf("deleting app password: %w", err)
	}
	return checkRowsAffected(res)
}

func scanAppPassword(row rowScanner) (*AppPassword, error) {
	var ap AppPassword
	var privileged int
	var createdAt string
	if err := row.Scan(&ap.DID, &ap.Name, &ap.PasswordHash, &privileged, &createdAt); err != nil {
		return nil, err
	}
	ap.Privileged = privileged != 0
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	ap.CreatedAt = t
	return &ap, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAccount(row *sql.Row) (*Account, error) {
	a, err := scanAccountRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

func scanAccountRow(row rowScanner) (*Account, error) {
	var a Account
	var createdAt string
	if err := row.Scan(&a.DID, &a.Handle, &a.PasswordHash, &a.SigningKey, &a.RotationKey, &a.Status, &createdAt); err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	a.CreatedAt = t
	return &a, nil
}

func checkRowsAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReserveSigningKey records a signing key generated for did before the
// account exists (com.atproto.server.reserveSigningKey), so a later
// createAccount call for the same did can reuse it — keeping the
// did:key stable across both calls, which migration flows depend on.
func (s *Store) ReserveSigningKey(ctx context.Context, did, signingKey string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO reserved_signing_keys (did, signing_key, created_at) VALUES (?, ?, ?)
ON CONFLICT (did) DO UPDATE SET signing_key = excluded.signing_key`,
		did, signingKey, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("reserving signing key: %w", err)
	}
	return nil
}

// GetReservedSigningKey returns the previously-reserved key for did, if
// any.
func (s *Store) GetReservedSigningKey(ctx context.Context, did string) (string, error) {
	row := s.db.QueryRowContext(ctx, `SELECT signing_key FROM reserved_signing_keys WHERE did = ?`, did)
	var key string
	if err := row.Scan(&key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("getting reserved signing key: %w", err)
	}
	return key, nil
}

const (
	TokenPurposePLCSign       = "plc_sign"
	TokenPurposeDeleteAccount = "delete_account"
)

// CreateAdminToken stores an admin-issued, one-time token authorizing a
// sensitive self-service action (signing a PLC operation, deleting the
// account) for did — the admin-CLI-confirmation replacement for
// email-gated confirmation flows (see PLAN.md).
func (s *Store) CreateAdminToken(ctx context.Context, token, did, purpose string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO admin_tokens (token, did, purpose, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		token, did, purpose, expiresAt.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("creating admin token: %w", err)
	}
	return nil
}

// ConsumeAdminToken validates and deletes a token in one step (so it
// can't be reused). Returns an error if the token doesn't exist, was
// issued for a different did/purpose, or has expired.
func (s *Store) ConsumeAdminToken(ctx context.Context, token, did, purpose string) error {
	row := s.db.QueryRowContext(ctx, `SELECT did, purpose, expires_at FROM admin_tokens WHERE token = ?`, token)
	var tokDID, tokPurpose, expiresAt string
	if err := row.Scan(&tokDID, &tokPurpose, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("looking up admin token: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM admin_tokens WHERE token = ?`, token); err != nil {
		return fmt.Errorf("consuming admin token: %w", err)
	}
	if tokDID != did || tokPurpose != purpose {
		return fmt.Errorf("token is not valid for this account/purpose")
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return err
	}
	if time.Now().After(exp) {
		return fmt.Errorf("token has expired")
	}
	return nil
}
