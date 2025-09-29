// Package sigs covers the signature failures that survive good primitives:
// ECDSA nonce reuse, malleable signatures used as identifiers, and verifiers
// that let the token pick its own algorithm or parse before they verify.
package sigs

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"math/big"
)

// p256N is the order of the P-256 base point.
var p256N = elliptic.P256().Params().N

type ecdsaSig struct{ R, S *big.Int }

// SignWithNonceUnsafe produces a textbook ECDSA P-256 signature over a
// SHA-256 digest with a caller-chosen nonce k: r = x(kG) mod n,
// s = k⁻¹(z + r·d) mod n. The output verifies with ecdsa.VerifyASN1. It exists
// to model an implementation with a constant or repeated k, the bug that
// exposed the PlayStation 3 signing key (fail0verflow, 2010). Never sign this
// way: the standard library does not let callers choose k.
func SignWithNonceUnsafe(priv *ecdsa.PrivateKey, digest []byte, k *big.Int) ([]byte, error) {
	if priv.Curve != elliptic.P256() || len(digest) != 32 {
		return nil, errors.New("sigs: P-256 with a SHA-256 digest only")
	}
	// kG via crypto/ecdh: a P-256 "private key" k has public key kG, encoded
	// uncompressed as 0x04 || X || Y.
	ek, err := ecdh.P256().NewPrivateKey(k.FillBytes(make([]byte, 32)))
	if err != nil {
		return nil, err
	}
	point := ek.PublicKey().Bytes()
	r := new(big.Int).Mod(new(big.Int).SetBytes(point[1:33]), p256N)

	dBytes, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(dBytes)
	z := new(big.Int).SetBytes(digest) // 256-bit digest, 256-bit order: no truncation

	s := new(big.Int).Mul(r, d)
	s.Add(s, z)
	s.Mul(s, new(big.Int).ModInverse(k, p256N))
	s.Mod(s, p256N)
	return asn1.Marshal(ecdsaSig{r, s})
}

// RecoverKeyFromNonceReuse returns the private scalar d given two signatures
// over different digests that share r (and therefore k):
//
//	k = (z1 − z2) / (s1 − s2)    d = (s1·k − z1) / r     (mod n)
//
// Two signatures are enough. Partial nonce bias across many signatures
// is enough too, via lattice attacks; this is the simplest case.
func RecoverKeyFromNonceReuse(z1, sig1, z2, sig2 []byte) ([]byte, error) {
	var a, b ecdsaSig
	if _, err := asn1.Unmarshal(sig1, &a); err != nil {
		return nil, err
	}
	if _, err := asn1.Unmarshal(sig2, &b); err != nil {
		return nil, err
	}
	if a.R.Cmp(b.R) != 0 {
		return nil, errors.New("sigs: nonces differ")
	}
	n := p256N
	zA, zB := new(big.Int).SetBytes(z1), new(big.Int).SetBytes(z2)

	dz := new(big.Int).Sub(zA, zB)
	ds := new(big.Int).Sub(a.S, b.S)
	ds.Mod(ds, n)
	if ds.Sign() == 0 {
		return nil, errors.New("sigs: identical signatures")
	}
	k := dz.Mul(dz, new(big.Int).ModInverse(ds, n))
	k.Mod(k, n)

	d := new(big.Int).Mul(a.S, k)
	d.Sub(d, zA)
	d.Mul(d, new(big.Int).ModInverse(a.R, n))
	d.Mod(d, n)
	return d.FillBytes(make([]byte, 32)), nil
}

// MalleateECDSA returns (r, n−s), a second valid signature for the same
// message and key. Anything that uses signature bytes as an identifier
// (transaction IDs, replay caches keyed on the signature) is fooled by it.
func MalleateECDSA(sig []byte) ([]byte, error) {
	var v ecdsaSig
	rest, err := asn1.Unmarshal(sig, &v)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("sigs: malformed signature")
	}
	return asn1.Marshal(ecdsaSig{v.R, new(big.Int).Sub(p256N, v.S)})
}
