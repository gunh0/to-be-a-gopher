// Package secrand contrasts math/rand, whose output is a deterministic
// function of a seed, with crypto/rand, and shows the two ways randomness
// usually goes wrong in security code: a guessable seed and a biased mapping
// from random bytes to symbols.
package secrand

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	mrand "math/rand"
	"time"
)

// Alphabet is the 62-symbol alphabet used for generated passwords.
const Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// TokenUnsafe generates a 16-character reset token with math/rand seeded
// from the wall clock in seconds — the pattern of a thousand tutorials. The
// token is a pure function of now.Unix(): two users who ask in the same
// second get the same token, and anyone who knows roughly when a token was
// issued can enumerate the candidates (CWE-335, CWE-338). Seeding with
// UnixNano only widens the search; it does not change the nature of the bug.
func TokenUnsafe(now time.Time) string {
	r := mrand.New(mrand.NewSource(now.Unix()))
	b := make([]byte, 16)
	for i := range b {
		b[i] = Alphabet[r.Intn(len(Alphabet))]
	}
	return string(b)
}

// Token returns a token from crypto/rand.Text (Go 1.24): base32, at least
// 128 bits from the operating system's CSPRNG, no seed and no state to guess.
func Token() string {
	return rand.Text()
}

// TokenBytes returns n random bytes, base64url-encoded without padding, for
// formats that need a specific length. Since Go 1.24 crypto/rand.Read never
// returns an error: if the OS source fails, the program crashes rather than
// continuing with a partially filled buffer.
func TokenBytes(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// PasswordUnsafe maps each random byte to a symbol with b % 62. 256 is not a
// multiple of 62, so the first 256 % 62 = 8 symbols ("A".."H") are produced
// by 5 byte values each and the other 54 by 4: those 8 are 25 % more likely,
// which reduces the effective entropy and front-loads guessing (CWE-330).
// The randomness source is fine; the mapping is not.
func PasswordUnsafe(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = Alphabet[int(b[i])%len(Alphabet)]
	}
	return string(b), nil
}

// Password uses rejection sampling: bytes at or above the largest multiple of
// 62 (248) are discarded and redrawn, so every accepted byte maps to exactly
// four values per symbol. crypto/rand.Int does the same for arbitrary ranges.
func Password(r io.Reader, n int) (string, error) {
	const limit = 256 - 256%len(Alphabet) // 248
	out := make([]byte, 0, n)
	var buf [64]byte
	for len(out) < n {
		k, err := r.Read(buf[:])
		if k == 0 && err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
		for _, c := range buf[:k] {
			if int(c) < limit && len(out) < n {
				out = append(out, Alphabet[int(c)%len(Alphabet)])
			}
		}
	}
	return string(out), nil
}

// NewPassword draws a 20-symbol password (about 119 bits) from crypto/rand.
func NewPassword() string {
	p, err := Password(rand.Reader, 20)
	if err != nil {
		panic(err) // unreachable: crypto/rand.Reader does not fail (Go 1.24)
	}
	return p
}
