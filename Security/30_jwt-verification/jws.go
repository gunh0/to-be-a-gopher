// Package jwtverify is a deliberately minimal JWS/JWT verifier (HS256 and
// EdDSA/Ed25519, compact serialisation) written to show where JWT
// verification goes wrong: trusting the token's own "alg" header ("none",
// algorithm confusion), lax base64url and JSON parsing, and skipped claim
// checks. Production code should use a maintained library and configure it
// the way Verifier is configured here: one pinned algorithm per key.
package jwtverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by the verifiers.
var (
	ErrMalformed = errors.New("jwt: malformed token")
	ErrSignature = errors.New("jwt: invalid signature")
	ErrAlgorithm = errors.New("jwt: algorithm not allowed for this key")
	ErrKey       = errors.New("jwt: unknown key")
	ErrClaims    = errors.New("jwt: claims rejected")
)

// Header is the JOSE header subset this package reads.
type Header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid,omitempty"`
	Typ  string   `json:"typ,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Claims holds the registered claims used for validation (RFC 7519 §4.1).
// Aud may be a string or an array in the JSON; Audience handles both.
type Claims struct {
	Iss string   `json:"iss,omitempty"`
	Sub string   `json:"sub,omitempty"`
	Aud Audience `json:"aud,omitempty"`
	Exp *float64 `json:"exp,omitempty"`
	Nbf *float64 `json:"nbf,omitempty"`
	Iat *float64 `json:"iat,omitempty"`
}

// Audience is the "aud" claim: a single string or an array of strings.
type Audience []string

// UnmarshalJSON accepts both forms allowed by RFC 7519 §4.1.3.
func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

var b64 = base64.RawURLEncoding.Strict()

// decodeSegment is strict base64url: no padding (RawURLEncoding), no
// non-zero trailing bits (Strict), and no characters outside the alphabet.
// The last check is needed because Go's base64 decoders silently skip '\r'
// and '\n', which would let two different strings verify as the same token.
func decodeSegment(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return nil, ErrMalformed
		}
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

// split returns the three segments of a compact JWS and the signing input.
func split(token string) (h, p, sig string, signingInput []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", nil, ErrMalformed
	}
	return parts[0], parts[1], parts[2], []byte(parts[0] + "." + parts[1]), nil
}

// Sign produces a compact JWS. key is []byte for HS256 and
// ed25519.PrivateKey for EdDSA.
func Sign(alg, kid string, claims any, key any) (string, error) {
	hb, err := json.Marshal(Header{Alg: alg, Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(hb) + "." + b64.EncodeToString(pb)
	var sig []byte
	switch k := key.(type) {
	case []byte:
		if alg != "HS256" {
			return "", ErrAlgorithm
		}
		m := hmac.New(sha256.New, k)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case ed25519.PrivateKey:
		if alg != "EdDSA" {
			return "", ErrAlgorithm
		}
		sig = ed25519.Sign(k, []byte(input))
	default:
		return "", fmt.Errorf("jwt: unsupported key type %T", key)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// VerifyNaive is the verifier that RFC 8725 was written about. It lets the
// token choose the algorithm and uses one blob of key material for all of
// them:
//
//   - "alg":"none" skips the signature entirely (CWE-347);
//   - "alg":"HS256" with an asymmetric deployment turns the PUBLIC key into
//     an HMAC secret, so anyone can mint tokens (algorithm confusion);
//   - claims are decoded with encoding/json defaults and exp/aud/iss are not
//     checked (CWE-613).
func VerifyNaive(token string, keyMaterial []byte) (Claims, error) {
	hs, ps, ss, input, err := split(token)
	if err != nil {
		return Claims{}, err
	}
	hb, _ := base64.RawURLEncoding.DecodeString(hs)
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, ErrMalformed
	}
	sig, _ := base64.RawURLEncoding.DecodeString(ss)
	switch h.Alg {
	case "none":
	case "HS256":
		m := hmac.New(sha256.New, keyMaterial)
		m.Write(input)
		if !hmac.Equal(m.Sum(nil), sig) {
			return Claims{}, ErrSignature
		}
	case "EdDSA":
		if len(keyMaterial) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(keyMaterial), input, sig) {
			return Claims{}, ErrSignature
		}
	default:
		return Claims{}, ErrAlgorithm
	}
	pb, _ := base64.RawURLEncoding.DecodeString(ps)
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	return c, nil
}

// noDuplicateKeys walks a JSON value and rejects objects that contain the
// same member name twice, comparing names the way encoding/json (v1) matches
// struct fields: case-insensitively, with Unicode simple folding (so "sub",
// "SUB" and "ſub" collide). encoding/json keeps the last duplicate, while
// another parser may keep the first: a parser differential an attacker can
// use to show one service "alice" and another "admin".
func noDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walk(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return nil
}

func walk(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	switch tok {
	case json.Delim('{'):
		var seen []string
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			k := kt.(string)
			for _, s := range seen {
				if strings.EqualFold(s, k) {
					return fmt.Errorf("%w: duplicate member %q", ErrMalformed, k)
				}
			}
			seen = append(seen, k)
			if err := walk(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walk(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}
