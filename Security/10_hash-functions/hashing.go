// Package hashing shows two ways a hash function is chosen wrongly: a
// non-cryptographic hash used where collisions matter, and a cryptographic
// hash used as a MAC by prefixing the key, H(key || msg), which Merkle–Damgård
// hashes such as SHA-256 do not support.
package hashing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"slices"
	"sync"
)

// StoreUnsafe is a content-addressed, de-duplicating blob store keyed by
// FNV-1a. FNV is fast and well distributed for hash tables, but it was never
// meant to resist an adversary: 32-bit collisions take ~2^16 attempts and
// can be found in milliseconds. Whoever uploads first decides what every
// later colliding upload resolves to (CWE-328).
type StoreUnsafe struct {
	mu sync.Mutex
	m  map[uint32][]byte
}

// KeyUnsafe returns the store key for data.
func KeyUnsafe(data []byte) uint32 {
	h := fnv.New32a()
	h.Write(data)
	return h.Sum32()
}

// Put stores data unless a blob with the same key exists, and returns the
// key and whether data was stored.
func (s *StoreUnsafe) Put(data []byte) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[uint32][]byte)
	}
	k := KeyUnsafe(data)
	if _, ok := s.m[k]; ok {
		return k, false
	}
	s.m[k] = slices.Clone(data)
	return k, true
}

// Get returns the blob stored under k.
func (s *StoreUnsafe) Get(k uint32) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}

// ContentID is a SHA-256 digest in hex. Finding two inputs with the same ID
// requires about 2^128 work; no collision is known.
func ContentID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Store is StoreUnsafe keyed by ContentID.
type Store struct {
	mu sync.Mutex
	m  map[string][]byte
}

// Put stores data under its ContentID.
func (s *Store) Put(data []byte) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string][]byte)
	}
	id := ContentID(data)
	if _, ok := s.m[id]; ok {
		return id, false
	}
	s.m[id] = slices.Clone(data)
	return id, true
}

// Get returns the blob stored under id.
func (s *Store) Get(id string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

// SignUnsafe authenticates msg as SHA-256(key || msg). SHA-256 is a
// Merkle–Damgård hash: its output is its complete internal state after
// processing key || msg || padding. Anyone who sees a tag can continue
// hashing from that state and produce a valid tag for
// key || msg || padding || suffix without knowing the key — a length
// extension (CWE-327). The same holds for MD5, SHA-1 and SHA-512, but not
// for SHA-3, SHA-512/256 or HMAC.
func SignUnsafe(key, msg []byte) [32]byte {
	buf := make([]byte, 0, len(key)+len(msg))
	buf = append(buf, key...)
	buf = append(buf, msg...)
	return sha256.Sum256(buf)
}

// Sign authenticates msg with HMAC-SHA-256 (RFC 2104). HMAC hashes the
// message under an inner key and then hashes that result under an outer
// key, so the published tag is not a resumable state.
func Sign(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Verify checks a tag from Sign in constant time (chapter 09).
func Verify(key, msg, tag []byte) bool {
	return hmac.Equal(Sign(key, msg), tag)
}
