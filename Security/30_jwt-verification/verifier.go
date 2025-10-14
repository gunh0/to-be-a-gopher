package jwtverify

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"time"
)

// Key binds key material to exactly one algorithm (RFC 8725 §3.1). The
// algorithm comes from server configuration, never from the token.
type Key struct {
	Alg     string            // "HS256" or "EdDSA"
	Secret  []byte            // HS256: at least 32 random bytes
	Public  ed25519.PublicKey // EdDSA
	Comment string
}

// Verifier validates tokens issued by one issuer for one audience.
type Verifier struct {
	Keys     map[string]Key // by "kid"
	Issuer   string
	Audience string
	Leeway   time.Duration // clock skew allowance; keep it small (≤ 1 min)
	Now      func() time.Time
}

// Verify checks, in order: structure and strict encoding, the header, the
// key selected by kid, that the header's alg equals the key's pinned alg,
// the signature, and only then the claims. Nothing from the payload is
// trusted before the signature has been verified.
func (v *Verifier) Verify(token string) (Claims, error) {
	hs, ps, ss, input, err := split(token)
	if err != nil {
		return Claims{}, err
	}
	hb, err := decodeSegment(hs)
	if err != nil {
		return Claims{}, err
	}
	if err := noDuplicateKeys(hb); err != nil {
		return Claims{}, err
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, ErrMalformed
	}
	if len(h.Crit) > 0 {
		// RFC 7515 §4.1.11: unknown critical extensions must be rejected.
		return Claims{}, fmt.Errorf("%w: unsupported crit %v", ErrMalformed, h.Crit)
	}

	// kid is attacker-controlled: it is only ever a map key here, never a
	// file path, URL (jku/x5u are ignored) or database query.
	key, ok := v.Keys[h.Kid]
	if !ok {
		return Claims{}, fmt.Errorf("%w: kid %q", ErrKey, h.Kid)
	}
	if h.Alg != key.Alg {
		return Claims{}, fmt.Errorf("%w: token says %q, key %q is pinned to %q", ErrAlgorithm, h.Alg, h.Kid, key.Alg)
	}

	sig, err := decodeSegment(ss)
	if err != nil {
		return Claims{}, err
	}
	switch key.Alg {
	case "HS256":
		if len(key.Secret) < sha256.Size { // RFC 7518 §3.2
			return Claims{}, fmt.Errorf("%w: HS256 secret shorter than 256 bits", ErrKey)
		}
		m := hmac.New(sha256.New, key.Secret)
		m.Write(input)
		if !hmac.Equal(m.Sum(nil), sig) { // constant time
			return Claims{}, ErrSignature
		}
	case "EdDSA":
		if len(key.Public) != ed25519.PublicKeySize || !ed25519.Verify(key.Public, input, sig) {
			return Claims{}, ErrSignature
		}
	default:
		return Claims{}, ErrAlgorithm
	}

	pb, err := decodeSegment(ps)
	if err != nil {
		return Claims{}, err
	}
	if err := noDuplicateKeys(pb); err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Claims{}, ErrMalformed
	}
	if err := v.validate(c); err != nil {
		return Claims{}, err
	}
	return c, nil
}

func (v *Verifier) validate(c Claims) error {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.Exp == nil {
		return fmt.Errorf("%w: exp is required", ErrClaims)
	}
	for _, d := range []*float64{c.Exp, c.Nbf, c.Iat} {
		if d != nil && (*d < 0 || *d > maxNumericDate) {
			return fmt.Errorf("%w: date out of range", ErrClaims)
		}
	}
	if !now.Before(numericDate(*c.Exp).Add(v.Leeway)) {
		return fmt.Errorf("%w: expired", ErrClaims)
	}
	if c.Nbf != nil && now.Add(v.Leeway).Before(numericDate(*c.Nbf)) {
		return fmt.Errorf("%w: not valid yet", ErrClaims)
	}
	if c.Iss != v.Issuer {
		return fmt.Errorf("%w: issuer %q", ErrClaims, c.Iss)
	}
	if !slices.Contains(c.Aud, v.Audience) {
		return fmt.Errorf("%w: audience %q", ErrClaims, c.Aud)
	}
	return nil
}

// maxNumericDate (9999-12-31T23:59:59Z) bounds dates before conversion, so
// a value like 1e300 cannot overflow int64 into the distant past.
const maxNumericDate = 253402300799

// numericDate converts seconds since the epoch, possibly fractional
// (RFC 7519 §2), to a time.Time. Callers range-check f first.
func numericDate(f float64) time.Time {
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9))
}
