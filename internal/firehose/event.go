// Package firehose defines the subscribeRepos wire format: each frame is
// a dag-cbor header ({"op":1,"t":"#commit"}, or {"op":-1} for errors)
// immediately followed by a dag-cbor body. This intentionally avoids
// indigo's events package (which pulls in gorm/otel/websocket relay
// machinery pds-light doesn't need) and instead encodes directly against
// the generated comatproto message structs.
package firehose

import (
	"fmt"
	"io"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	cbornode "github.com/ipfs/go-ipld-cbor"
)

type cborMarshaler interface {
	MarshalCBOR(w io.Writer) error
}

// ErrorFrame is sent (as an op:-1 frame) when a subscribeRepos session
// must be terminated, e.g. FutureCursor.
type ErrorFrame struct {
	Error   string
	Message string
}

// Event is a tagged union of the message kinds pds-light emits on the
// firehose. Exactly one field should be set.
type Event struct {
	RepoCommit   *comatproto.SyncSubscribeRepos_Commit
	RepoSync     *comatproto.SyncSubscribeRepos_Sync
	RepoIdentity *comatproto.SyncSubscribeRepos_Identity
	RepoAccount  *comatproto.SyncSubscribeRepos_Account
	Info         *comatproto.SyncSubscribeRepos_Info
	Error        *ErrorFrame
}

// Serialize writes the header+body frame to w.
func (e *Event) Serialize(w io.Writer) error {
	var header map[string]any
	var body cborMarshaler

	switch {
	case e.Error != nil:
		header = map[string]any{"op": int64(-1)}
		errBody := map[string]any{"error": e.Error.Error}
		if e.Error.Message != "" {
			errBody["message"] = e.Error.Message
		}
		if err := writeCBOR(w, header); err != nil {
			return err
		}
		return writeCBOR(w, errBody)
	case e.RepoCommit != nil:
		header = map[string]any{"op": int64(1), "t": "#commit"}
		body = e.RepoCommit
	case e.RepoSync != nil:
		header = map[string]any{"op": int64(1), "t": "#sync"}
		body = e.RepoSync
	case e.RepoIdentity != nil:
		header = map[string]any{"op": int64(1), "t": "#identity"}
		body = e.RepoIdentity
	case e.RepoAccount != nil:
		header = map[string]any{"op": int64(1), "t": "#account"}
		body = e.RepoAccount
	case e.Info != nil:
		header = map[string]any{"op": int64(1), "t": "#info"}
		body = e.Info
	default:
		return fmt.Errorf("firehose: empty event")
	}

	if err := writeCBOR(w, header); err != nil {
		return err
	}
	return body.MarshalCBOR(w)
}

func writeCBOR(w io.Writer, v map[string]any) error {
	b, err := cbornode.DumpObject(v)
	if err != nil {
		return fmt.Errorf("firehose: encoding frame: %w", err)
	}
	_, err = w.Write(b)
	return err
}

// SeqOf stamps seq into whichever sequenceable variant is set (all but
// Info and Error carry a seq field) and returns a short type tag.
func (e *Event) SeqOf(seq int64) (string, error) {
	switch {
	case e.RepoCommit != nil:
		e.RepoCommit.Seq = seq
		return "#commit", nil
	case e.RepoSync != nil:
		e.RepoSync.Seq = seq
		return "#sync", nil
	case e.RepoIdentity != nil:
		e.RepoIdentity.Seq = seq
		return "#identity", nil
	case e.RepoAccount != nil:
		e.RepoAccount.Seq = seq
		return "#account", nil
	default:
		return "", fmt.Errorf("firehose: event has no sequenceable body")
	}
}
