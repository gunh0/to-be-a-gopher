// Package consttime shows why comparing secrets with == or bytes.Equal leaks
// them one byte at a time, and how crypto/subtle and crypto/hmac remove the
// content-dependent early exit. Timing is replaced by an explicit step
// counter so tests can measure the side channel exactly.
package consttime

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

// Probe counts how many byte positions a comparison examined. It is a
// deterministic stand-in for the wall-clock time an attacker measures.
type Probe struct{ Steps int }

func (p *Probe) step() {
	if p != nil {
		p.Steps++
	}
}

// EqualUnsafe has the shape of bytes.Equal, string ==, and most hand-written
// loops: it returns at the first differing byte. Its running time is
// proportional to the length of the matching prefix, so an attacker who can
// time many attempts learns the secret byte by byte: about 256·n guesses
// instead of 256^n (CWE-208).
func EqualUnsafe(secret, guess []byte, p *Probe) bool {
	if len(secret) != len(guess) {
		return false
	}
	for i := range secret {
		p.step()
		if secret[i] != guess[i] {
			return false
		}
	}
	return true
}

// EqualConstant mirrors subtle.ConstantTimeCompare: it accumulates the XOR
// of every byte pair and inspects the result once, so the work done depends
// only on the length. Length itself is compared up front and therefore is
// NOT hidden.
func EqualConstant(secret, guess []byte, p *Probe) bool {
	if len(secret) != len(guess) {
		return false
	}
	var v byte
	for i := range secret {
		p.step()
		v |= secret[i] ^ guess[i]
	}
	return subtle.ConstantTimeByteEq(v, 0) == 1
}

// CheckKeyUnsafe compares a presented API key with ==.
func CheckKeyUnsafe(stored, presented string) bool {
	return presented == stored
}

// CheckKey compares with subtle.ConstantTimeCompare. Use it when both values
// have a fixed, public length (MACs, digests, fixed-format keys).
func CheckKey(stored, presented string) bool {
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// Verifier checks presented secrets of any length without revealing the
// stored secret's content or length. Both sides are reduced to an HMAC under
// a random per-process key before a constant-time comparison of two 32-byte
// values. The random key means an attacker cannot precompute which inputs
// produce which digests.
type Verifier struct {
	key  []byte
	want []byte
}

// NewVerifier prepares a verifier for secret.
func NewVerifier(secret []byte) *Verifier {
	key := make([]byte, 32)
	rand.Read(key)
	return &Verifier{key: key, want: mac(key, secret)}
}

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Verify reports whether presented equals the secret.
func (v *Verifier) Verify(presented []byte) bool {
	return hmac.Equal(mac(v.key, presented), v.want)
}
