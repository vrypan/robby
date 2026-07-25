// Package sequencer implements the firehose event log: an ordered,
// durable, trimmed record of #commit/#sync/#identity/#account events
// (accounts.db `events` table) plus an in-process broadcaster for live
// subscribeRepos tails. Backfill reads from the table; new subscribers
// get both backfill (if requested) and the live tail, spliced together
// without gaps.
package sequencer

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/vrypan/pds-light/internal/firehose"
)

// BackfillWindow is how long events are retained for backfill, per
// PLAN.md ("Trimmed to 72 h backfill window").
const BackfillWindow = 72 * time.Hour

// Msg is a live event delivered to a Subscribe()'d channel. Seq lets
// subscribers that also did a Backfill dedupe events they may have
// already seen (Subscribe is called before the backfill query runs, to
// avoid missing events written in between).
type Msg struct {
	Seq     int64
	Payload []byte
}

type Sequencer struct {
	db *sql.DB

	mu   sync.Mutex
	subs map[chan Msg]struct{}
}

func New(db *sql.DB) (*Sequencer, error) {
	s := &Sequencer{db: db, subs: make(map[chan Msg]struct{})}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sequencer) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	did        TEXT NOT NULL,
	evt_type   TEXT NOT NULL,
	payload    BLOB NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
`)
	if err != nil {
		return fmt.Errorf("migrating events table: %w", err)
	}
	return nil
}

// Append allocates the next sequence number, stamps it into evt, encodes
// the wire frame, stores it, and broadcasts it to live subscribers.
func (s *Sequencer) Append(ctx context.Context, did string, evt *firehose.Event) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `INSERT INTO events (did, evt_type, payload, created_at) VALUES (?, '', X'', ?)`,
		did, now.Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("allocating seq: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	evtType, err := evt.SeqOf(seq)
	if err != nil {
		return 0, err
	}

	var buf bytes.Buffer
	if err := evt.Serialize(&buf); err != nil {
		return 0, fmt.Errorf("serializing event: %w", err)
	}
	payload := buf.Bytes()

	if _, err := tx.ExecContext(ctx, `UPDATE events SET evt_type = ?, payload = ? WHERE seq = ?`, evtType, payload, seq); err != nil {
		return 0, fmt.Errorf("storing event: %w", err)
	}

	if err := s.trimLocked(ctx, tx, now); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing event: %w", err)
	}

	s.broadcast(seq, payload)
	return seq, nil
}

func (s *Sequencer) trimLocked(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-BackfillWindow).Format(time.RFC3339Nano)
	_, err := tx.ExecContext(ctx, `DELETE FROM events WHERE created_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("trimming events: %w", err)
	}
	return nil
}

// LatestSeq returns the highest stored sequence number, or 0 if the log
// is empty.
func (s *Sequencer) LatestSeq(ctx context.Context) (int64, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM events`)
	var seq int64
	if err := row.Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// EarliestSeq returns the lowest stored sequence number, or 0 if the log
// is empty (used to detect an out-of-window cursor).
func (s *Sequencer) EarliestSeq(ctx context.Context) (int64, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(MIN(seq), 0) FROM events`)
	var seq int64
	if err := row.Scan(&seq); err != nil {
		return 0, err
	}
	return seq, nil
}

// Backfill calls emit for every stored event with seq > since, in order.
func (s *Sequencer) Backfill(ctx context.Context, since int64, emit func(seq int64, payload []byte) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, payload FROM events WHERE seq > ? ORDER BY seq ASC`, since)
	if err != nil {
		return fmt.Errorf("querying backfill: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var seq int64
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return err
		}
		if err := emit(seq, payload); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Subscribe registers a new live-event channel. Callers must call the
// returned cancel func when done to avoid leaking the channel.
func (s *Sequencer) Subscribe() (ch chan Msg, cancel func()) {
	ch = make(chan Msg, 256)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	return ch, func() {
		s.mu.Lock()
		if _, ok := s.subs[ch]; ok {
			delete(s.subs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
}

func (s *Sequencer) broadcast(seq int64, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- Msg{Seq: seq, Payload: payload}:
		default:
			// Slow consumer: drop rather than block the writer. The
			// consumer's next backfill (by cursor) will catch it up.
		}
	}
}
