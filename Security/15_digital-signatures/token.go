package sigs

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Tokens here use the JWS compact shape: b64(header).b64(payload).b64(sig),
// with the signature computed over the first two segments as transmitted.

var b64 = base64.RawURLEncoding

// ErrInvalidToken is the only error a verifier returns for a bad token.
var ErrInvalidToken = errors.New("sigs: invalid token")

// Claims is the token payload.
type Claims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp int64  `json:"exp"`
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// VerifyTokenUnsafe parses the header first and lets it choose the algorithm,
// then looks up raw key bytes by kid and uses them with whatever algorithm the
// header named (CWE-347):
//
//   - alg "none" skips verification entirely;
//   - alg "HS256" turns the issuer's *public* Ed25519 key, which anyone may
//     know, into an HMAC secret (the 2015 JWT "algorithm confusion" class,
//     e.g. CVE-2015-9235).
func VerifyTokenUnsafe(token string, keys map[string][]byte) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	hb, _ := b64.DecodeString(parts[0])
	var h header
	if json.Unmarshal(hb, &h) != nil {
		return nil, ErrInvalidToken
	}
	sig, _ := b64.DecodeString(parts[2])
	signed := []byte(parts[0] + "." + parts[1])
	key := keys[h.Kid]

	switch strings.ToLower(h.Alg) {
	case "none":
		// "unsecured JWS", RFC 7515 appendix A.5
	case "hs256":
		m := hmac.New(sha256.New, key)
		m.Write(signed)
		if !hmac.Equal(m.Sum(nil), sig) {
			return nil, ErrInvalidToken
		}
	case "eddsa":
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signed, sig) {
			return nil, ErrInvalidToken
		}
	default:
		return nil, ErrInvalidToken
	}
	pb, _ := b64.DecodeString(parts[1])
	var c Claims
	if json.Unmarshal(pb, &c) != nil {
		return nil, ErrInvalidToken
	}
	return &c, nil
}

// fixedHeader is the only header the secure issuer emits and the only one
// the secure verifier accepts, byte for byte. The algorithm is pinned by the
// verifier's configuration, not read from the token.
var fixedHeader = b64.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))

// Issue signs claims with an Ed25519 crypto.Signer. crypto.SignMessage (Go
// 1.25) calls SignMessage directly when the signer implements
// crypto.MessageSigner (a KMS or HSM that hashes on its side), and otherwise
// falls back to Signer.Sign; with crypto.Hash(0) an ed25519.PrivateKey signs
// the message itself, as Ed25519 requires.
func Issue(signer crypto.Signer, c Claims) (string, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		return "", errors.New("sigs: issuer key must be Ed25519")
	}
	pb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signed := fixedHeader + "." + b64.EncodeToString(pb)
	sig, err := crypto.SignMessage(signer, rand.Reader, []byte(signed), crypto.Hash(0))
	if err != nil {
		return "", err
	}
	return signed + "." + b64.EncodeToString(sig), nil
}

// Verifier accepts tokens from exactly one Ed25519 key for one audience.
type Verifier struct {
	Key      ed25519.PublicKey
	Audience string
	Now      func() time.Time
}

// Verify checks, in this order: shape, the pinned header, the signature over
// the raw transmitted bytes, and only then decodes the payload, strictly. No
// attacker-controlled byte influences which key or algorithm is used, and no
// JSON parser sees unauthenticated input.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != fixedHeader {
		return nil, ErrInvalidToken
	}
	sig, err := b64.Strict().DecodeString(parts[2])
	if err != nil || len(v.Key) != ed25519.PublicKeySize ||
		!ed25519.Verify(v.Key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, ErrInvalidToken
	}
	pb, err := b64.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.DisallowUnknownFields()
	var c Claims
	if dec.Decode(&c) != nil || dec.More() {
		return nil, ErrInvalidToken
	}
	if c.Aud != v.Audience || v.Now().Unix() >= c.Exp {
		return nil, ErrInvalidToken
	}
	return &c, nil
}
