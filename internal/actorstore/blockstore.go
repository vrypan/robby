package actorstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
)

// querier is satisfied by both *sql.DB and *sql.Tx, letting sqlBlockstore
// work either as a read-only view or as part of an atomic write.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

var _ querier = (*sql.DB)(nil)
var _ querier = (*sql.Tx)(nil)

// sqlBlockstore implements the subset of blockstore.Blockstore that
// indigo's atproto/repo and atproto/repo/mst packages need, backed by the
// actor DB's `blocks` table.
type sqlBlockstore struct {
	q querier
}

func (b *sqlBlockstore) Get(ctx context.Context, c cid.Cid) (blocks.Block, error) {
	row := b.q.QueryRowContext(ctx, `SELECT bytes FROM blocks WHERE cid = ?`, c.String())
	var data []byte
	if err := row.Scan(&data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("reading block %s: %w", c, err)
	}
	return blocks.NewBlockWithCid(data, c)
}

func (b *sqlBlockstore) Has(ctx context.Context, c cid.Cid) (bool, error) {
	row := b.q.QueryRowContext(ctx, `SELECT 1 FROM blocks WHERE cid = ?`, c.String())
	var x int
	if err := row.Scan(&x); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (b *sqlBlockstore) GetSize(ctx context.Context, c cid.Cid) (int, error) {
	blk, err := b.Get(ctx, c)
	if err != nil {
		return 0, err
	}
	return len(blk.RawData()), nil
}

func (b *sqlBlockstore) Put(ctx context.Context, blk blocks.Block) error {
	_, err := b.q.ExecContext(ctx, `
INSERT INTO blocks (cid, bytes) VALUES (?, ?)
ON CONFLICT (cid) DO NOTHING`,
		blk.Cid().String(), blk.RawData())
	if err != nil {
		return fmt.Errorf("writing block %s: %w", blk.Cid(), err)
	}
	return nil
}

func (b *sqlBlockstore) PutMany(ctx context.Context, blks []blocks.Block) error {
	for _, blk := range blks {
		if err := b.Put(ctx, blk); err != nil {
			return err
		}
	}
	return nil
}

func (b *sqlBlockstore) DeleteBlock(ctx context.Context, c cid.Cid) error {
	_, err := b.q.ExecContext(ctx, `DELETE FROM blocks WHERE cid = ?`, c.String())
	return err
}

func (b *sqlBlockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	rows, err := b.q.QueryContext(ctx, `SELECT cid FROM blocks`)
	if err != nil {
		return nil, err
	}
	ch := make(chan cid.Cid)
	go func() {
		defer close(ch)
		defer rows.Close()
		for rows.Next() {
			var cidStr string
			if rows.Scan(&cidStr) != nil {
				return
			}
			c, err := cid.Decode(cidStr)
			if err != nil {
				continue
			}
			select {
			case ch <- c:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

// HashOnRead is a no-op: sqlBlockstore always trusts the stored bytes for
// the CID they're keyed under.
func (b *sqlBlockstore) HashOnRead(enabled bool) {}
