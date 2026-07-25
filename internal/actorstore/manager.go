package actorstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// validDID guards against path traversal: did is used to build
// filesystem paths (actors/<did>.db, blobs/<did>/), and these stores are
// reachable via unauthenticated sync endpoints with a client-supplied
// did. Require a syntactically valid atproto DID, and defensively reject
// any path separators or "." components even though ParseDID already
// excludes them.
func validDID(did string) error {
	if _, err := syntax.ParseDID(did); err != nil {
		return fmt.Errorf("invalid did: %w", err)
	}
	if strings.ContainsAny(did, "/\\") || did == "." || did == ".." || strings.Contains(did, "..") {
		return fmt.Errorf("invalid did: contains path separators")
	}
	return nil
}

// Manager opens and caches per-actor Stores, and serializes all writes to
// a given actor's repo behind a per-DID mutex (per PLAN.md: "All writes
// to an actor's repo are serialized behind a per-DID mutex").
type Manager struct {
	dataDir string

	mu     sync.Mutex
	stores map[string]*Store
	locks  map[string]*sync.Mutex
}

func NewManager(dataDir string) *Manager {
	return &Manager{
		dataDir: dataDir,
		stores:  make(map[string]*Store),
		locks:   make(map[string]*sync.Mutex),
	}
}

func (m *Manager) actorDBPath(did string) string {
	return filepath.Join(m.dataDir, "actors", did+".db")
}

func (m *Manager) actorBlobDir(did string) string {
	return filepath.Join(m.dataDir, "blobs", did)
}

// Get returns the (opened, cached) Store for did, opening it on disk if
// this is the first access this process.
func (m *Manager) Get(did string) (*Store, error) {
	if err := validDID(did); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.stores[did]; ok {
		return s, nil
	}
	s, err := Open(m.actorDBPath(did), m.actorBlobDir(did), did)
	if err != nil {
		return nil, fmt.Errorf("opening actor store for %s: %w", did, err)
	}
	m.stores[did] = s
	return s, nil
}

// GetExisting opens an actor store only when both of its on-disk components
// already exist. It is for public read paths: unlike Get, it never allocates
// a database, blob directory, or cache entry for a caller-supplied DID.
func (m *Manager) GetExisting(did string) (*Store, error) {
	if err := validDID(did); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.stores[did]; ok {
		return s, nil
	}
	if _, err := os.Stat(m.actorDBPath(did)); err != nil {
		return nil, err
	}
	if _, err := os.Stat(m.actorBlobDir(did)); err != nil {
		return nil, err
	}
	s, err := Open(m.actorDBPath(did), m.actorBlobDir(did), did)
	if err != nil {
		return nil, fmt.Errorf("opening existing actor store for %s: %w", did, err)
	}
	m.stores[did] = s
	return s, nil
}

func (m *Manager) didLock(did string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[did]
	if !ok {
		l = &sync.Mutex{}
		m.locks[did] = l
	}
	return l
}

// WithLock serializes access to did's repo: it acquires the per-DID
// mutex, opens (or reuses) the actor Store, and calls fn.
func (m *Manager) WithLock(did string, fn func(*Store) error) error {
	l := m.didLock(did)
	l.Lock()
	defer l.Unlock()

	s, err := m.Get(did)
	if err != nil {
		return err
	}
	return fn(s)
}
