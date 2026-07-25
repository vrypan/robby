package xrpc

import (
	"bytes"
	"net/http"
	"strconv"

	comatproto "github.com/bluesky-social/indigo/api/atproto"
	"github.com/gorilla/websocket"

	"github.com/vrypan/robby/internal/firehose"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// handleSubscribeRepos implements com.atproto.sync.subscribeRepos: a
// websocket firehose of #commit/#sync/#identity/#account events. On
// connect, a subscriber first gets backfill (if it sent a cursor, and
// that cursor is still within the retained window), then a live tail.
//
// Subscribe() is called before the backfill query runs so no events are
// missed in between; Msg.Seq lets the live-tail loop skip anything the
// backfill already delivered.
func (s *Server) handleSubscribeRepos(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var cursor int64
	hasCursor := false
	if cs := r.URL.Query().Get("cursor"); cs != "" {
		n, err := strconv.ParseInt(cs, 10, 64)
		if err != nil {
			writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "invalid cursor")
			return
		}
		cursor = n
		hasCursor = true
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("subscribeRepos: upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	// Log firehose consumers at connect and disconnect: a long-lived
	// websocket otherwise wouldn't appear in the request log until it
	// closes, hiding (e.g.) a relay that's actively subscribed.
	s.log.Info("subscribeRepos: consumer connected", "remote", r.RemoteAddr, "cursor", r.URL.Query().Get("cursor"), "user_agent", r.UserAgent())
	defer s.log.Info("subscribeRepos: consumer disconnected", "remote", r.RemoteAddr)

	liveCh, cancel := s.seq.Subscribe()
	defer cancel()

	// Detect client disconnect without blocking the write loop on reads.
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	send := func(payload []byte) bool {
		return conn.WriteMessage(websocket.BinaryMessage, payload) == nil
	}

	lastSent := int64(0)
	if hasCursor {
		latest, err := s.seq.LatestSeq(ctx)
		if err != nil {
			return
		}
		if cursor > latest {
			sendFrame(conn, &firehose.Event{Error: &firehose.ErrorFrame{
				Error:   "FutureCursor",
				Message: "requested cursor is ahead of the latest known sequence",
			}})
			closeClean(conn)
			return
		}

		earliest, err := s.seq.EarliestSeq(ctx)
		if err != nil {
			return
		}
		if earliest > 0 && cursor < earliest-1 {
			sendFrame(conn, &firehose.Event{Info: &comatproto.SyncSubscribeRepos_Info{
				Name:    "OutdatedCursor",
				Message: strPtr("requested cursor is before the earliest available event; resuming from latest"),
			}})
			lastSent = latest
		} else {
			ok := true
			if err := s.seq.Backfill(ctx, cursor, func(seq int64, payload []byte) error {
				if !send(payload) {
					ok = false
					return errStop
				}
				lastSent = seq
				return nil
			}); err != nil && ok {
				return
			}
			if !ok {
				return
			}
		}
	} else {
		latest, err := s.seq.LatestSeq(ctx)
		if err != nil {
			return
		}
		lastSent = latest
	}

	for {
		select {
		case <-closed:
			return
		case <-ctx.Done():
			return
		case msg, ok := <-liveCh:
			if !ok {
				return
			}
			if msg.Seq <= lastSent {
				continue
			}
			if !send(msg.Payload) {
				return
			}
			lastSent = msg.Seq
		}
	}
}

var errStop = &stopError{}

type stopError struct{}

func (*stopError) Error() string { return "subscribeRepos: client write failed" }

func sendFrame(conn *websocket.Conn, evt *firehose.Event) {
	var buf bytes.Buffer
	if err := evt.Serialize(&buf); err != nil {
		return
	}
	_ = conn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
}

// closeClean sends a proper close handshake, so clients see a clean
// disconnect (code 1000) instead of an abnormal closure after an error
// frame that terminates the session (e.g. FutureCursor).
func closeClean(conn *websocket.Conn) {
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

func strPtr(s string) *string { return &s }
