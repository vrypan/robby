// Package carutil writes minimal CAR (Content Addressable aRchive) v1
// files: a dag-cbor header naming the roots, followed by length-prefixed
// (cid, bytes) block frames. This is all sync.getRepo/getRecord/getBlocks
// and firehose #commit/#sync events need.
package carutil

import (
	"fmt"
	"io"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	car "github.com/ipld/go-car"
	carutil "github.com/ipld/go-car/util"
)

// WriteCAR writes a CAR v1 file with the given roots, containing exactly
// the given blocks (in the given order) — no traversal, since callers
// already know the exact block set to include.
func WriteCAR(w io.Writer, roots []cid.Cid, blks []blocks.Block) error {
	if err := car.WriteHeader(&car.CarHeader{Roots: roots, Version: 1}, w); err != nil {
		return fmt.Errorf("writing CAR header: %w", err)
	}
	for _, blk := range blks {
		if err := carutil.LdWrite(w, blk.Cid().Bytes(), blk.RawData()); err != nil {
			return fmt.Errorf("writing CAR block %s: %w", blk.Cid(), err)
		}
	}
	return nil
}
