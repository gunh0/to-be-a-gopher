package races

import (
	"sync"
	"sync/atomic"
)

// Config is an immutable snapshot of security settings. It is never modified
// after publication; a reload builds a new one.
type Config struct {
	Version   int
	AllowedIP []string
	AdminOnly bool
}

// ConfigStore publishes Config snapshots to concurrent readers.
//
// The unsafe version of this type is a plain *Config field assigned by the
// reload goroutine and read by handlers. That is a data race on a pointer;
// the equivalent race on an interface or slice field is worse, because those
// are two- and three-word values and a reader can observe a torn mix of old
// and new words (Go memory model: such races "can in turn lead to arbitrary
// memory corruption"). It cannot be shown in a test that runs under -race
// without being reported, which is the point.
type ConfigStore struct {
	p atomic.Pointer[Config]
}

// NewConfigStore returns a store holding c.
func NewConfigStore(c *Config) *ConfigStore {
	s := &ConfigStore{}
	s.p.Store(c)
	return s
}

// Load returns the current snapshot. Readers must treat it as read-only.
func (s *ConfigStore) Load() *Config { return s.p.Load() }

// Store publishes a new snapshot. Everything written to *c before Store
// happens-before any Load that observes it.
func (s *ConfigStore) Store(c *Config) { s.p.Store(c) }

// Sessions maps session IDs to user names. Unsynchronised concurrent writes
// to a Go map are detected by the runtime on a best-effort basis and abort
// the whole process with "fatal error: concurrent map writes" — a throw, not
// a panic, so recover cannot catch it.
type Sessions struct {
	mu sync.RWMutex
	m  map[string]string
}

// NewSessions returns an empty session table.
func NewSessions() *Sessions { return &Sessions{m: make(map[string]string)} }

// Put records a session.
func (s *Sessions) Put(id, user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = user
}

// Get looks up a session.
func (s *Sessions) Get(id string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.m[id]
	return u, ok
}

// Len returns the number of sessions.
func (s *Sessions) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}
