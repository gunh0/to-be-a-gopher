// Package kdf derives many independent keys from one master secret with
// crypto/hkdf, and shows the separation failures that occur when one key
// serves two purposes or when attacker-chosen strings reach the HKDF info.
package kdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// --- Insecure: one key, two algorithms --------------------------------------

// SharedKeyUnsafe uses the same 32 bytes as the AES-GCM key for stored
// records and as the HMAC-SHA256 key for outgoing webhooks. HMAC is
// symmetric: every partner that verifies webhooks must hold the key, and now
// every partner can also decrypt the database (CWE-323, CWE-320). Even when
// no key is shared, using one key in two algorithms voids both algorithms'
// security proofs, which assume an independent key.
type SharedKeyUnsafe struct{ key []byte }

// NewSharedKeyUnsafe wraps a single 32-byte key.
func NewSharedKeyUnsafe(key []byte) *SharedKeyUnsafe { return &SharedKeyUnsafe{key: key} }

// EncryptionKey is the AES-256-GCM key for records.
func (s *SharedKeyUnsafe) EncryptionKey() []byte { return s.key }

// WebhookVerificationKey is what gets sent to partners. It is the same key.
func (s *SharedKeyUnsafe) WebhookVerificationKey() []byte { return s.key }

// --- Insecure: attacker-controlled label --------------------------------------

// SystemKeyUnsafe and TenantKeyUnsafe call HKDF correctly but share one
// label namespace. System keys use fixed labels such as "webhook-mac"; tenant
// keys use the tenant ID as the label. A tenant that registers the ID
// "webhook-mac" receives the system's webhook key.
func SystemKeyUnsafe(master []byte, name string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, nil, name, 32)
}

// TenantKeyUnsafe derives a tenant's key with info = tenantID.
func TenantKeyUnsafe(master []byte, tenantID string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, nil, tenantID, 32)
}

// KeyFromPasswordUnsafe runs HKDF over a password. HKDF is an extractor and
// expander for inputs that already carry enough entropy (a DH output, a random
// master key); it adds no work factor, so an offline guess costs two HMAC
// calls (CWE-916). Use Argon2id or PBKDF2 (chapter 12) for passwords.
func KeyFromPasswordUnsafe(password string) ([]byte, error) {
	return hkdf.Key(sha256.New, []byte(password), nil, "file-encryption", 32)
}

// --- Secure ---------------------------------------------------------------------

// Purpose is a key's intended use. The type has unexported fields, so the
// only Purposes that exist are the ones declared in this package: callers
// cannot invent labels, and user data can only enter as context.
type Purpose struct {
	label string
	size  int
}

// The fixed set of purposes. Each label is used for exactly one algorithm.
var (
	RecordEncryption = Purpose{"record-enc/aes-256-gcm", 32}
	WebhookMAC       = Purpose{"webhook-mac/hmac-sha256", 32}
	TenantEncryption = Purpose{"tenant-enc/aes-256-gcm", 32}
	CookieMAC        = Purpose{"cookie-mac/hmac-sha256", 32}
)

const domain = "github.com/gunh0/to-be-a-gopher/kdf/v1"

// ErrShortSecret is returned for master secrets below 256 bits.
var ErrShortSecret = errors.New("kdf: master secret must be at least 32 bytes")

// Keyring holds the HKDF pseudorandom key (the output of Extract) and expands
// per-purpose keys from it on demand.
type Keyring struct{ prk []byte }

// NewKeyring runs HKDF-Extract once. salt may be nil when master is already
// a uniformly random key (from a KMS or crypto/rand); it should be a fixed,
// public, application-specific value when master is a Diffie-Hellman output.
func NewKeyring(master, salt []byte) (*Keyring, error) {
	if len(master) < 32 {
		return nil, ErrShortSecret
	}
	prk, err := hkdf.Extract(sha256.New, master, salt)
	if err != nil {
		return nil, err
	}
	return &Keyring{prk: prk}, nil
}

// Key runs HKDF-Expand with an info string that encodes, unambiguously, the
// domain, the purpose label, the output length and any context values (tenant
// ID, key version). Every element is length-prefixed, in the spirit of the
// TLS 1.3 HkdfLabel structure (RFC 8446, section 7.1).
func (k *Keyring) Key(p Purpose, context ...string) ([]byte, error) {
	if p.label == "" {
		return nil, errors.New("kdf: zero Purpose")
	}
	return hkdf.Expand(sha256.New, k.prk, Info(p, context...), p.size)
}

// Info returns the encoded HKDF info string used by Key. It is exported so
// tests and other implementations can check interoperability.
func Info(p Purpose, context ...string) string {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(p.size))
	for _, s := range append([]string{domain, p.label}, context...) {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	return string(b)
}

// SealRecord is a small consumer of a derived key, used to show separation
// end to end. It uses random-nonce AES-GCM (chapter 13).
func SealRecord(key, plaintext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nil, plaintext, nil), nil
}

// OpenRecord reverses SealRecord.
func OpenRecord(key, ciphertext []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nil, ciphertext, nil)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// SignWebhook computes HMAC-SHA256 over body.
func SignWebhook(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return m.Sum(nil)
}
