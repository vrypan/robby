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

func (s *Store) SetStatus(ctx context.Context, did, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET status = ? WHERE did = ?`, status, did)
	if err != nil {
		return fmt.Errorf("setting status: %w", err)
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
