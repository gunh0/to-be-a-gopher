package hmactoken

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// b64 is the canonical encoding for every token segment: URL-safe, no
// padding, and Strict, so that the unused low bits of the last character must
// be zero. Without Strict, several strings decode to the same bytes and a
// token has more than one valid spelling (which breaks deny-lists and caches
// keyed by the token string).
var b64 = base64.RawURLEncoding.Strict()

const (
	version   = "v1"
	tagSize   = sha256.Size
	maxSubLen = 256
)

// Key is a master secret with a short public identifier.
type Key struct {
	ID     string // [a-z0-9], carried in the token so verifiers can pick the key
	Secret []byte // at least 32 bytes from crypto/rand
}

// Claims are the verified contents of a token.
type Claims struct {
	Subject string
	Expires time.Time
}

// Signer issues and verifies tokens for exactly one purpose.
//
// Token layout:
//
//	v1.<kid>.<b64(payload)>.<b64(HMAC-SHA-256(k_purpose, "v1.<kid>.<b64(payload)>"))>
//	payload = uvarint(len(sub)) || sub || int64be(exp unix seconds)
//
// The payload is length-prefixed binary, so no two (subject, expiry) pairs
// encode to the same bytes. The MAC covers the version and key ID as well as
// the payload. Each purpose uses its own key derived with HKDF, so a token
// minted for one purpose never verifies for another.
type Signer struct {
	purpose string
	active  string
	keys    map[string][]byte

	// Clock returns the current time; nil means time.Now. Tests inject a
	// fixed clock.
	Clock func() time.Time
}

// NewSigner derives per-purpose keys from active and from any previous keys
// that should still verify during rotation. Only active is used to issue.
func NewSigner(purpose string, active Key, previous ...Key) (*Signer, error) {
	s := &Signer{purpose: purpose, active: active.ID, keys: make(map[string][]byte)}
	for _, k := range append([]Key{active}, previous...) {
		if k.ID == "" || strings.Trim(k.ID, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			return nil, fmt.Errorf("hmactoken: invalid key ID %q", k.ID)
		}
		if len(k.Secret) < 32 {
			return nil, fmt.Errorf("hmactoken: key %q shorter than 32 bytes", k.ID)
		}
		if _, dup := s.keys[k.ID]; dup {
			return nil, fmt.Errorf("hmactoken: duplicate key ID %q", k.ID)
		}
		// crypto/hkdf (Go 1.24). The info string binds the derived key to
		// the token format and purpose: key separation, not just naming.
		dk, err := hkdf.Key(sha256.New, k.Secret, nil, "hmactoken/"+version+"/"+purpose, 32)
		if err != nil {
			return nil, err
		}
		s.keys[k.ID] = dk
	}
	return s, nil
}

func (s *Signer) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

func tag(key []byte, signed string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(signed))
	return m.Sum(nil)
}

// Issue returns a token for subject that expires after ttl.
func (s *Signer) Issue(subject string, ttl time.Duration) (string, error) {
	if len(subject) == 0 || len(subject) > maxSubLen {
		return "", fmt.Errorf("hmactoken: subject length %d out of range", len(subject))
	}
	payload := binary.AppendUvarint(nil, uint64(len(subject)))
	payload = append(payload, subject...)
	payload = binary.BigEndian.AppendUint64(payload, uint64(s.now().Add(ttl).Unix()))

	signed := version + "." + s.active + "." + b64.EncodeToString(payload)
	return signed + "." + b64.EncodeToString(tag(s.keys[s.active], signed)), nil
}

// Verify authenticates tok and only then interprets it. The order matters:
// nothing in the payload — not even the expiry — is parsed or acted on
// until the MAC over the exact received bytes has been checked in constant
// time.
func (s *Signer) Verify(tok string) (Claims, error) {
	dot := strings.LastIndexByte(tok, '.')
	if dot < 0 {
		return Claims{}, ErrInvalid
	}
	signed, tagPart := tok[:dot], tok[dot+1:]
	parts := strings.Split(signed, ".")
	if len(parts) != 3 || parts[0] != version {
		return Claims{}, ErrInvalid
	}
	key, ok := s.keys[parts[1]]
	if !ok {
		return Claims{}, ErrInvalid
	}
	got, err := b64.DecodeString(tagPart)
	if err != nil || len(got) != tagSize {
		return Claims{}, ErrInvalid
	}
	if !hmac.Equal(got, tag(key, signed)) {
		return Claims{}, ErrInvalid
	}

	// Authentic from here on.
	payload, err := b64.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrInvalid
	}
	c, err := decodePayload(payload)
	if err != nil {
		return Claims{}, err
	}
	if !s.now().Before(c.Expires) {
		return Claims{}, ErrExpired
	}
	return c, nil
}

func decodePayload(p []byte) (Claims, error) {
	n, k := binary.Uvarint(p)
	if k <= 0 || n == 0 || n > maxSubLen || uint64(len(p)-k) != n+8 {
		return Claims{}, ErrInvalid
	}
	sub := string(p[k : k+int(n)])
	exp := int64(binary.BigEndian.Uint64(p[k+int(n):]))
	return Claims{Subject: sub, Expires: time.Unix(exp, 0)}, nil
}
