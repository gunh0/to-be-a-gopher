// Package pqkem shows post-quantum key establishment in Go: the hybrid
// X25519MLKEM768 group that crypto/tls negotiates by default since Go 1.24,
// the configurations that silently switch it off, and a hybrid KEM built
// from crypto/mlkem and crypto/ecdh for protocols that are not TLS.
package pqkem

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
)

// Sizes of the hybrid encoding: ML-KEM-768 part first, X25519 part second.
const (
	PublicKeySize  = mlkem.EncapsulationKeySize768 + 32
	CiphertextSize = mlkem.CiphertextSize768 + 32
	SharedKeySize  = 32
)

// combinerLabel separates this construction from every other use of SHA3-256.
const combinerLabel = "github.com/gunh0/to-be-a-gopher/pqkem X25519+ML-KEM-768 v1"

// ErrMalformed reports a public key or ciphertext of the wrong size or with
// an invalid X25519 component. It is never returned for a well-formed but
// tampered ML-KEM ciphertext: see Decapsulate.
var ErrMalformed = errors.New("pqkem: malformed input")

// PrivateKey is a hybrid decapsulation key.
type PrivateKey struct {
	m *mlkem.DecapsulationKey768
	x *ecdh.PrivateKey
}

// GenerateKey creates fresh ML-KEM-768 and X25519 key pairs.
func GenerateKey() (*PrivateKey, error) {
	m, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{m: m, x: x}, nil
}

// PublicKey returns ek_ML-KEM || pk_X25519.
func (k *PrivateKey) PublicKey() []byte {
	return append(k.m.EncapsulationKey().Bytes(), k.x.PublicKey().Bytes()...)
}

// Encapsulate runs both KEMs against pub and combines the two shared secrets
// with the transcript. The sender learns the key; ciphertext goes to the
// holder of the private key.
func Encapsulate(pub []byte) (key, ciphertext []byte, err error) {
	if len(pub) != PublicKeySize {
		return nil, nil, ErrMalformed
	}
	ekM, err := mlkem.NewEncapsulationKey768(pub[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	pkX, err := ecdh.X25519().NewPublicKey(pub[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return nil, nil, ErrMalformed
	}
	ssM, ctM := ekM.Encapsulate()

	// X25519 as a KEM: a fresh ephemeral key pair; its public half is the
	// "ciphertext".
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ssX, err := eph.ECDH(pkX) // errors on low-order points (all-zero output)
	if err != nil {
		return nil, nil, ErrMalformed
	}
	ctX := eph.PublicKey().Bytes()

	ciphertext = append(ctM, ctX...)
	return combine(ssM, ssX, ciphertext, pub), ciphertext, nil
}

// Decapsulate recovers the shared key. ML-KEM uses implicit rejection: a
// modified ML-KEM ciphertext does not produce an error, it produces an
// unrelated pseudorandom key. The protocol must therefore confirm the key
// (use it in an AEAD, or exchange a MAC over the transcript) before trusting
// that both sides agree.
func (k *PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != CiphertextSize {
		return nil, ErrMalformed
	}
	ssM, err := k.m.Decapsulate(ciphertext[:mlkem.CiphertextSize768])
	if err != nil {
		return nil, ErrMalformed
	}
	ctX, err := ecdh.X25519().NewPublicKey(ciphertext[mlkem.CiphertextSize768:])
	if err != nil {
		return nil, ErrMalformed
	}
	ssX, err := k.x.ECDH(ctX)
	if err != nil {
		return nil, ErrMalformed
	}
	return combine(ssM, ssX, ciphertext, k.PublicKey()), nil
}

// combine hashes both shared secrets together with both ciphertexts and the
// recipient's full public key. Every field has a fixed size, so plain
// concatenation is unambiguous.
//
// Both secrets: the result stays secret as long as either KEM holds (ML-KEM
// against a future quantum attacker, X25519 against a flaw in the young
// ML-KEM implementations).
// Transcript: X25519 is not an IND-CCA KEM on its own; hashing ct_X and pk_X
// binds the key to this exact exchange so a ciphertext cannot be re-used or
// re-combined across sessions or recipients. X-Wing (draft-connolly-cfrg-
// xwing-kem) omits ct_ML-KEM and ek_ML-KEM, relying on ML-KEM's own binding;
// including them costs microseconds and removes that dependency.
func combine(ssM, ssX, ciphertext, pub []byte) []byte {
	h := sha3.New256()
	h.Write([]byte(combinerLabel))
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ciphertext)
	h.Write(pub)
	return h.Sum(nil)
}
