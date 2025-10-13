// Package session implements server-side sessions with a hardened cookie:
// a 128-bit random ID from crypto/rand, the __Host- prefix with Secure,
// HttpOnly and SameSite, ID rotation at login against session fixation, idle
// and absolute timeouts enforced on the server, and logout that destroys the
// server-side record.
package session

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// ErrNoSession is returned for unknown, expired or destroyed session IDs.
var ErrNoSession = errors.New("session: no valid session")

// Session is the server-side state. The cookie carries only the ID.
type Session struct {
	ID       string
	UserID   string // empty before login
	Created  time.Time
	LastSeen time.Time
}

// Store keeps sessions in memory. Expiry is decided here, from server time:
// a cookie's Expires/Max-Age is a hint to the browser and an attacker who
// copied the cookie simply ignores it.
type Store struct {
	Idle     time.Duration // maximum time between requests
	Absolute time.Duration // maximum session lifetime, regardless of activity
	Now      func() time.Time

	mu       sync.Mutex
	sessions map[string]*Session
	idFunc   func() string // nil means NewID; the insecure variant swaps it
}

func (s *Store) newID() string {
	if s.idFunc != nil {
		return s.idFunc()
	}
	return NewID()
}

// NewStore returns a store with the given timeouts using the real clock.
func NewStore(idle, absolute time.Duration) *Store {
	return &Store{Idle: idle, Absolute: absolute, Now: time.Now, sessions: map[string]*Session{}}
}

// NewID returns 128 bits from the OS CSPRNG as 26 base32 characters
// (crypto/rand.Text, Go 1.24). OWASP asks for at least 64 bits of entropy;
// 128 makes guessing irrelevant even across billions of live sessions.
func NewID() string { return rand.Text() }

// Create starts an anonymous session (for example to hold a cart or the
// post-login redirect target).
func (s *Store) Create() *Session {
	now := s.Now()
	sess := &Session{ID: s.newID(), Created: now, LastSeen: now}
	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// Get returns a copy of the session if it exists and has not hit either
// timeout, and records the activity. Expired sessions are deleted.
func (s *Store) Get(id string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, ErrNoSession
	}
	now := s.Now()
	if now.Sub(sess.LastSeen) > s.Idle || now.Sub(sess.Created) > s.Absolute {
		delete(s.sessions, id)
		return Session{}, ErrNoSession
	}
	sess.LastSeen = now
	return *sess, nil
}

// Login authenticates the session identified by oldID as userID under a
// NEW identifier and destroys the old one. Whoever knew the pre-login ID (an
// attacker who planted it: session fixation, CWE-384) is left holding a dead
// ID. The absolute timeout restarts, since this is a new authentication.
func (s *Store) Login(oldID, userID string) *Session {
	now := s.Now()
	sess := &Session{ID: s.newID(), UserID: userID, Created: now, LastSeen: now}
	s.mu.Lock()
	delete(s.sessions, oldID)
	s.sessions[sess.ID] = sess
	s.mu.Unlock()
	return sess
}

// authenticateInPlace marks an existing session as logged in without
// changing its ID. Only the insecure App uses it.
func (s *Store) authenticateInPlace(id, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.UserID = userID
	}
}

// Destroy removes the session. Logout must call this; clearing the cookie
// alone leaves a copied or stolen cookie valid until it expires.
func (s *Store) Destroy(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// DestroyUser removes every session of a user, for "log out everywhere" and
// for password changes.
func (s *Store) DestroyUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, id)
		}
	}
}
