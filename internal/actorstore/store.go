// Package actorstore provides per-actor storage: the IPLD block store
// backing each user's repo MST, a record-path index, blob metadata, and
// blob bytes on disk.
package actorstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	DID     string
	db      *sql.DB
	blobDir string
}

// Open opens (creating if necessary) the per-actor SQLite DB at dbPath and
// ensures blobDir exists for raw blob storage.
func Open(dbPath, blobDir, did string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("creating actor db dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("opening actor db %s: %w", dbPath, err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{DID: did, db: db, blobDir: blobDir}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.MkdirAll(blobDir, 0700); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating blob dir %s: %w", blobDir, err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS blocks (
	cid   TEXT PRIMARY KEY,
	bytes BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS repo_root (
	id        INTEGER PRIMARY KEY CHECK (id = 1),
	commit_cid TEXT NOT NULL,
	rev        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
	collection TEXT NOT NULL,
	rkey       TEXT NOT NULL,
	cid        TEXT NOT NULL,
	PRIMARY KEY (collection, rkey)
);

CREATE TABLE IF NOT EXISTS blobs (
	cid        TEXT PRIMARY KEY,
	mime       TEXT NOT NULL,
	size       INTEGER NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blob_refs (
	blob_cid   TEXT NOT NULL,
	collection TEXT NOT NULL,
	rkey       TEXT NOT NULL,
	PRIMARY KEY (blob_cid, collection, rkey)
);
`)
	if err != nil {
		return fmt.Errorf("migrating actor db: %w", err)
	}
	return nil
}

// BeginTx starts a write transaction covering block writes, the repo root
// pointer, the record index, and blob refs — all committed atomically.
func (s *Store) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return s.db.BeginTx(ctx, nil)
}

// Blockstore returns an IPLD blockstore.Blockstore adapter over q, which
// may be either the Store's underlying *sql.DB (read-only use) or a
// *sql.Tx from BeginTx (for writes that must commit atomically with other
// actor-db changes).
func (s *Store) Blockstore(q querier) *sqlBlockstore {
	return &sqlBlockstore{q: q}
}

// DB returns the underlying connection for use as a read-only querier
// (e.g. Store.Blockstore(store.DB())).
func (s *Store) DB() querier { return s.db }

type RepoRoot struct {
	CommitCID cid.Cid
	Rev       string
}

// GetRepoRoot returns the current commit CID + rev, or ErrNotFound if the
// repo has no commits yet.
func (s *Store) GetRepoRoot(ctx context.Context) (*RepoRoot, error) {
	return getRepoRoot(ctx, s.db)
}

func getRepoRoot(ctx context.Context, q rowQuerier) (*RepoRoot, error) {
	row := q.QueryRowContext(ctx, `SELECT commit_cid, rev FROM repo_root WHERE id = 1`)
	var commitCIDStr, rev string
	if err := row.Scan(&commitCIDStr, &rev); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting repo root: %w", err)
	}
	c, err := cid.Decode(commitCIDStr)
	if err != nil {
		return nil, fmt.Errorf("parsing stored commit cid: %w", err)
	}
	return &RepoRoot{CommitCID: c, Rev: rev}, nil
}

// SetRepoRoot upserts the repo's current commit pointer within tx.
func (s *Store) SetRepoRoot(ctx context.Context, tx *sql.Tx, commitCID cid.Cid, rev string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO repo_root (id, commit_cid, rev) VALUES (1, ?, ?)
ON CONFLICT (id) DO UPDATE SET commit_cid = excluded.commit_cid, rev = excluded.rev`,
		commitCID.String(), rev)
	if err != nil {
		return fmt.Errorf("setting repo root: %w", err)
	}
	return nil
}

// PutRecordIndex upserts the collection/rkey -> cid index entry within tx.
func (s *Store) PutRecordIndex(ctx context.Context, tx *sql.Tx, collection, rkey string, c cid.Cid) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO records (collection, rkey, cid) VALUES (?, ?, ?)
ON CONFLICT (collection, rkey) DO UPDATE SET cid = excluded.cid`,
		collection, rkey, c.String())
	if err != nil {
		return fmt.Errorf("indexing record: %w", err)
	}
	return nil
}

// DeleteRecordIndex removes a collection/rkey index entry within tx.
func (s *Store) DeleteRecordIndex(ctx context.Context, tx *sql.Tx, collection, rkey string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM records WHERE collection = ? AND rkey = ?`, collection, rkey)
	if err != nil {
		return fmt.Errorf("deleting record index: %w", err)
	}
	return nil
}

// GetRecordCID looks up the current block CID for a record path.
func (s *Store) GetRecordCID(ctx context.Context, collection, rkey string) (*cid.Cid, error) {
	row := s.db.QueryRowContext(ctx, `SELECT cid FROM records WHERE collection = ? AND rkey = ?`, collection, rkey)
	var cidStr string
	if err := row.Scan(&cidStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting record: %w", err)
	}
	c, err := cid.Decode(cidStr)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type RecordEntry struct {
	Collection string
	RKey       string
	CID        cid.Cid
}

// ListRecords returns records in a collection, ordered by rkey, starting
// strictly after the given cursor rkey (empty cursor = start from the
// beginning), up to limit entries.
func (s *Store) ListRecords(ctx context.Context, collection, cursor string, limit int, reverse bool) ([]RecordEntry, error) {
	order := "ASC"
	cmp := ">"
	if reverse {
		order = "DESC"
		cmp = "<"
	}
	var rows *sql.Rows
	var err error
	if cursor == "" {
		rows, err = s.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT collection, rkey, cid FROM records WHERE collection = ? ORDER BY rkey %s LIMIT ?`, order),
			collection, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			fmt.Sprintf(`SELECT collection, rkey, cid FROM records WHERE collection = ? AND rkey %s ? ORDER BY rkey %s LIMIT ?`, cmp, order),
			collection, cursor, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("listing records: %w", err)
	}
	defer rows.Close()

	var out []RecordEntry
	for rows.Next() {
		var e RecordEntry
		var cidStr string
		if err := rows.Scan(&e.Collection, &e.RKey, &cidStr); err != nil {
			return nil, err
		}
		if e.CID, err = cid.Decode(cidStr); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PutBlobMeta records metadata for an uploaded blob within tx.
func (s *Store) PutBlobMeta(ctx context.Context, tx *sql.Tx, c cid.Cid, mime string, size int64) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO blobs (cid, mime, size, created_at) VALUES (?, ?, ?, ?)
ON CONFLICT (cid) DO NOTHING`,
		c.String(), mime, size, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("storing blob metadata: %w", err)
	}
	return nil
}

type BlobMeta struct {
	CID  cid.Cid
	Mime string
	Size int64
}

func (s *Store) GetBlobMeta(ctx context.Context, c cid.Cid) (*BlobMeta, error) {
	row := s.db.QueryRowContext(ctx, `SELECT cid, mime, size FROM blobs WHERE cid = ?`, c.String())
	var m BlobMeta
	var cidStr string
	if err := row.Scan(&cidStr, &m.Mime, &m.Size); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting blob metadata: %w", err)
	}
	var err error
	if m.CID, err = cid.Decode(cidStr); err != nil {
		return nil, err
	}
	return &m, nil
}

// AddBlobRef records that a blob is referenced by a given record path,
// within tx. Used for refcounting so deleteRecord can GC unreferenced
// blobs.
func (s *Store) AddBlobRef(ctx context.Context, tx *sql.Tx, blobCID cid.Cid, collection, rkey string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO blob_refs (blob_cid, collection, rkey) VALUES (?, ?, ?)
ON CONFLICT (blob_cid, collection, rkey) DO NOTHING`,
		blobCID.String(), collection, rkey)
	if err != nil {
		return fmt.Errorf("adding blob ref: %w", err)
	}
	return nil
}

// ClearBlobRefsForRecord removes all blob refs for a record path within
// tx (called before re-adding refs on update, or on delete).
func (s *Store) ClearBlobRefsForRecord(ctx context.Context, tx *sql.Tx, collection, rkey string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM blob_refs WHERE collection = ? AND rkey = ?`, collection, rkey)
	if err != nil {
		return fmt.Errorf("clearing blob refs: %w", err)
	}
	return nil
}

// BlobRefCount returns how many record paths currently reference a blob.
func (s *Store) BlobRefCount(ctx context.Context, blobCID cid.Cid) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blob_refs WHERE blob_cid = ?`, blobCID.String())
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// BlobPath returns the on-disk path for a blob's raw bytes.
func (s *Store) BlobPath(c cid.Cid) string {
	return filepath.Join(s.blobDir, c.String())
}

func (s *Store) WriteBlobFile(c cid.Cid, data []byte) error {
	tmp := s.BlobPath(c) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing blob: %w", err)
	}
	if err := os.Rename(tmp, s.BlobPath(c)); err != nil {
		return fmt.Errorf("finalizing blob: %w", err)
	}
	return nil
}

func (s *Store) ReadBlobFile(c cid.Cid) ([]byte, error) {
	b, err := os.ReadFile(s.BlobPath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return b, nil
}

// AllBlocks returns every block in the repo's block store. Used for full
// repo export (sync.getRepo) and record proof responses (sync.getRecord)
// — pds-light doesn't compute minimal MST inclusion proofs, so it returns
// the full block set, which is a valid (non-minimal) proof.
func (s *Store) AllBlocks(ctx context.Context) ([]blocks.Block, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cid, bytes FROM blocks`)
	if err != nil {
		return nil, fmt.Errorf("listing blocks: %w", err)
	}
	defer rows.Close()

	var out []blocks.Block
	for rows.Next() {
		var cidStr string
		var data []byte
		if err := rows.Scan(&cidStr, &data); err != nil {
			return nil, err
		}
		c, err := cid.Decode(cidStr)
		if err != nil {
			return nil, err
		}
		blk, err := blocks.NewBlockWithCid(data, c)
		if err != nil {
			return nil, err
		}
		out = append(out, blk)
	}
	return out, rows.Err()
}

// ListBlobCIDs returns blob CIDs in insertion order, for cursor-paginated
// listBlobs.
func (s *Store) ListBlobCIDs(ctx context.Context, cursor string, limit int) ([]cid.Cid, error) {
	var rows *sql.Rows
	var err error
	if cursor == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT cid FROM blobs ORDER BY cid ASC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT cid FROM blobs WHERE cid > ? ORDER BY cid ASC LIMIT ?`, cursor, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("listing blobs: %w", err)
	}
	defer rows.Close()

	var out []cid.Cid
	for rows.Next() {
		var cidStr string
		if err := rows.Scan(&cidStr); err != nil {
			return nil, err
		}
		c, err := cid.Decode(cidStr)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
