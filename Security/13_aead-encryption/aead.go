// Package aead shows why encryption without authentication is malleable, why
// a repeated AES-GCM nonce is catastrophic, and how to use random-nonce GCM,
// XChaCha20-Poly1305 and associated data to bind ciphertexts to their context.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrOpen is returned for any ciphertext that fails authentication. It does
// not say why, so it cannot be used as an oracle.
var ErrOpen = errors.New("aead: message authentication failed")

// --- Insecure: unauthenticated CTR -----------------------------------------

// EncryptCTRUnsafe encrypts with AES-CTR and a random IV but no MAC. The
// ciphertext is plaintext XOR keystream, so flipping bit i of the ciphertext
// flips bit i of the plaintext, and decryption cannot notice (CWE-353).
// CBC without a MAC has the same problem for the IV and adds padding oracles.
func EncryptCTRUnsafe(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize+len(plaintext))
	iv := out[:aes.BlockSize]
	rand.Read(iv)
	cipher.NewCTR(block, iv).XORKeyStream(out[aes.BlockSize:], plaintext)
	return out, nil
}

// DecryptCTRUnsafe always "succeeds": there is nothing to check.
func DecryptCTRUnsafe(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrOpen
	}
	out := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCTR(block, ciphertext[:aes.BlockSize]).XORKeyStream(out, ciphertext[aes.BlockSize:])
	return out, nil
}

// --- Insecure: counter nonces that restart ----------------------------------

// CounterSealerUnsafe uses AES-GCM correctly except for the nonce: an
// in-memory counter starting at zero. Every process restart, and every second
// replica sharing the key, replays nonces 0, 1, 2... (CWE-323). GCM is CTR
// mode underneath, so two messages under one nonce share a keystream, and
// the GHASH authentication key can be recovered from the two tags, which
// enables forgeries under that key.
type CounterSealerUnsafe struct {
	aead cipher.AEAD
	n    uint64
}

// NewCounterSealerUnsafe returns a sealer whose nonce counter starts at zero.
func NewCounterSealerUnsafe(key []byte) (*CounterSealerUnsafe, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &CounterSealerUnsafe{aead: g}, nil
}

// Seal returns nonce || ciphertext || tag.
func (s *CounterSealerUnsafe) Seal(plaintext []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	return s.aead.Seal(nonce, nonce, plaintext, nil)
}

// --- Secure ------------------------------------------------------------------

// Sealer is an AEAD that manages its own nonces.
type Sealer interface {
	Seal(plaintext, ad []byte) []byte
	Open(ciphertext, ad []byte) ([]byte, error)
}

type gcmRandom struct{ aead cipher.AEAD }

// NewGCM returns AES-256-GCM built with cipher.NewGCMWithRandomNonce (Go
// 1.24): Seal draws a fresh 96-bit nonce from crypto/rand and prepends it,
// Open strips it. Callers cannot pass a nonce, so they cannot reuse one. The
// documented limit is 2^32 messages per key, after which the chance of a
// random nonce collision stops being negligible. It is also the GCM
// constructor that remains usable in GODEBUG=fips140=only mode.
func NewGCM(key []byte) (Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("aead: AES-256 key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return gcmRandom{g}, nil
}

func (g gcmRandom) Seal(plaintext, ad []byte) []byte {
	return g.aead.Seal(nil, nil, plaintext, ad)
}

func (g gcmRandom) Open(ciphertext, ad []byte) ([]byte, error) {
	pt, err := g.aead.Open(nil, nil, ciphertext, ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

type xchacha struct{ aead cipher.AEAD }

// NewXChaCha returns XChaCha20-Poly1305 (golang.org/x/crypto). Its 192-bit
// nonce makes random nonces safe for any realistic message count per key,
// and it is fast without AES hardware. It is not a FIPS 140-3 approved
// algorithm (chapter 17).
func NewXChaCha(key []byte) (Sealer, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return xchacha{a}, nil
}

func (x xchacha) Seal(plaintext, ad []byte) []byte {
	nonce := make([]byte, x.aead.NonceSize(), x.aead.NonceSize()+len(plaintext)+x.aead.Overhead())
	rand.Read(nonce)
	return x.aead.Seal(nonce, nonce, plaintext, ad)
}

func (x xchacha) Open(ciphertext, ad []byte) ([]byte, error) {
	ns := x.aead.NonceSize()
	if len(ciphertext) < ns+x.aead.Overhead() {
		return nil, ErrOpen
	}
	pt, err := x.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], ad)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// FieldAD builds associated data that binds an encrypted column value to
// where it is stored. Each part is length-prefixed so ("ab","c") and
// ("a","bc") cannot collide. A ciphertext copied into another row, column or
// table then fails to open instead of decrypting under the wrong identity.
func FieldAD(table, column, rowID string) []byte {
	var ad []byte
	for _, p := range []string{"v1", table, column, rowID} {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(p)))
		ad = append(ad, p...)
	}
	return ad
}

// CollisionProbability approximates the birthday bound n²/2^(b+1) for n
// random b-bit nonces under one key.
func CollisionProbability(messages float64, nonceBits int) float64 {
	return messages * messages / math.Exp2(float64(nonceBits+1))
}
