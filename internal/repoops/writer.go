// Package repoops implements the repo write path: MST mutation, record
// validation and encoding, and commit signing. All writes for a given DID
// go through Writer.ApplyWrites, which the actorstore.Manager serializes
// behind a per-DID mutex and commits atomically to the actor DB.
package repoops

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/repo"
	"github.com/bluesky-social/indigo/atproto/repo/mst"
	"github.com/bluesky-social/indigo/atproto/syntax"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/multiformats/go-multihash"

	"github.com/vrypan/pds-light/internal/actorstore"
	"github.com/vrypan/pds-light/internal/lexicon"
)

type Action string

const (
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// WriteOp describes one record mutation within a batch. For ActionCreate
// with an empty RKey, a TID rkey is generated. Record is required for
// Create/Update and ignored for Delete.
type WriteOp struct {
	Action     Action
	Collection string
	RKey       string
	Record     map[string]any
}

type WriteResult struct {
	Action     Action
	Collection string
	RKey       string
	CID        *cid.Cid // nil for deletes
}

var recordPrefix = cid.NewPrefixV1(cid.DagCBOR, multihash.SHA2_256)
var rawPrefix = cid.NewPrefixV1(cid.Raw, multihash.SHA2_256)

// BlobCID computes the content-addressed CID pds-light uses for blob
// bytes (raw codec, sha2-256), matching how record `blob` refs resolve.
func BlobCID(data []byte) (cid.Cid, error) {
	return rawPrefix.Sum(data)
}

type Writer struct {
	Manager *actorstore.Manager
}

func NewWriter(mgr *actorstore.Manager) *Writer {
	return &Writer{Manager: mgr}
}

// ApplyWrites mutates did's repo by applying ops in order, signs a new
// commit with signingKey, and commits everything (blocks, repo root,
// record index, blob refs) atomically. It is the only path that mutates
// a repo, and always runs under the actor's per-DID lock.
func (w *Writer) ApplyWrites(ctx context.Context, did string, signingKey atcrypto.PrivateKey, ops []WriteOp) (commit *repo.Commit, commitCID cid.Cid, results []WriteResult, err error) {
	err = w.Manager.WithLock(did, func(st *actorstore.Store) error {
		root, rootErr := st.GetRepoRoot(ctx)

		var tree mst.Tree
		var clk syntax.TIDClock
		switch {
		case rootErr == nil:
			t, prevCommit, lErr := loadTree(ctx, st, root.CommitCID)
			if lErr != nil {
				return lErr
			}
			tree = *t
			clk = syntax.ClockFromTID(syntax.TID(prevCommit.Rev))
		case rootErr == actorstore.ErrNotFound:
			tree = mst.NewEmptyTree()
			clk = *syntax.NewTIDClock(0)
		default:
			return rootErr
		}

		tx, txErr := st.BeginTx(ctx)
		if txErr != nil {
			return txErr
		}
		defer tx.Rollback()

		var bs blockstore.Blockstore = st.Blockstore(tx)
		results = nil

		for _, op := range ops {
			res, opErr := applyOne(ctx, st, tx, bs, &tree, &clk, op)
			if opErr != nil {
				return fmt.Errorf("applying write to %s/%s: %w", op.Collection, op.RKey, opErr)
			}
			results = append(results, *res)
		}

		rootCID, wErr := tree.WriteDiffBlocks(ctx, bs)
		if wErr != nil {
			return fmt.Errorf("writing MST blocks: %w", wErr)
		}

		newCommit := &repo.Commit{
			DID:     did,
			Version: repo.ATPROTO_REPO_VERSION,
			Prev:    nil,
			Data:    *rootCID,
			Rev:     clk.Next().String(),
		}
		if sErr := newCommit.Sign(signingKey); sErr != nil {
			return fmt.Errorf("signing commit: %w", sErr)
		}

		buf := new(bytes.Buffer)
		if err := newCommit.MarshalCBOR(buf); err != nil {
			return fmt.Errorf("encoding commit: %w", err)
		}
		newCommitCID, cidErr := recordPrefix.Sum(buf.Bytes())
		if cidErr != nil {
			return cidErr
		}
		commitBlock, blkErr := blocks.NewBlockWithCid(buf.Bytes(), newCommitCID)
		if blkErr != nil {
			return blkErr
		}
		if err := bs.Put(ctx, commitBlock); err != nil {
			return fmt.Errorf("writing commit block: %w", err)
		}

		if err := st.SetRepoRoot(ctx, tx, newCommitCID, newCommit.Rev); err != nil {
			return err
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing repo write: %w", err)
		}

		commit = newCommit
		commitCID = newCommitCID
		return nil
	})
	return commit, commitCID, results, err
}

func loadTree(ctx context.Context, st *actorstore.Store, commitCID cid.Cid) (*mst.Tree, *repo.Commit, error) {
	bs := st.Blockstore(st.DB())
	blk, err := bs.Get(ctx, commitCID)
	if err != nil {
		return nil, nil, fmt.Errorf("reading commit block: %w", err)
	}
	var c repo.Commit
	if err := c.UnmarshalCBOR(bytes.NewReader(blk.RawData())); err != nil {
		return nil, nil, fmt.Errorf("parsing commit block: %w", err)
	}
	tree, err := mst.LoadTreeFromStore(ctx, bs, c.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("loading MST: %w", err)
	}
	return tree, &c, nil
}

func applyOne(ctx context.Context, st *actorstore.Store, tx *sql.Tx, bs blockstore.Blockstore, tree *mst.Tree, clk *syntax.TIDClock, op WriteOp) (*WriteResult, error) {
	switch op.Action {
	case ActionDelete:
		path := op.Collection + "/" + op.RKey
		prev, err := tree.Remove([]byte(path))
		if err != nil {
			return nil, err
		}
		if prev == nil {
			return nil, actorstore.ErrNotFound
		}
		if err := st.DeleteRecordIndex(ctx, tx, op.Collection, op.RKey); err != nil {
			return nil, err
		}
		if err := st.ClearBlobRefsForRecord(ctx, tx, op.Collection, op.RKey); err != nil {
			return nil, err
		}
		return &WriteResult{Action: op.Action, Collection: op.Collection, RKey: op.RKey, CID: nil}, nil

	case ActionCreate, ActionUpdate:
		record := op.Record
		if record == nil {
			return nil, fmt.Errorf("record is required for %s", op.Action)
		}
		if _, ok := record["$type"]; !ok {
			record["$type"] = op.Collection
		}
		if err := lexicon.ValidateRecord(record); err != nil {
			return nil, fmt.Errorf("record failed lexicon validation: %w", err)
		}

		rkey := op.RKey
		if rkey == "" {
			rkey = clk.Next().String()
		}
		recPath := op.Collection + "/" + rkey

		recordBytes, err := atdata.MarshalCBOR(record)
		if err != nil {
			return nil, fmt.Errorf("encoding record: %w", err)
		}
		recordCID, err := recordPrefix.Sum(recordBytes)
		if err != nil {
			return nil, err
		}
		blk, err := blocks.NewBlockWithCid(recordBytes, recordCID)
		if err != nil {
			return nil, err
		}
		if err := bs.Put(ctx, blk); err != nil {
			return nil, err
		}

		if _, err := tree.Insert([]byte(recPath), recordCID); err != nil {
			return nil, err
		}
		if err := st.PutRecordIndex(ctx, tx, op.Collection, rkey, recordCID); err != nil {
			return nil, err
		}

		if err := st.ClearBlobRefsForRecord(ctx, tx, op.Collection, rkey); err != nil {
			return nil, err
		}
		for _, b := range atdata.ExtractBlobs(record) {
			blobCID := b.Ref.CID()
			if err := st.PutBlobMeta(ctx, tx, blobCID, b.MimeType, b.Size); err != nil {
				return nil, err
			}
			if err := st.AddBlobRef(ctx, tx, blobCID, op.Collection, rkey); err != nil {
				return nil, err
			}
		}

		return &WriteResult{Action: op.Action, Collection: op.Collection, RKey: rkey, CID: &recordCID}, nil

	default:
		return nil, fmt.Errorf("unknown write action: %q", op.Action)
	}
}
