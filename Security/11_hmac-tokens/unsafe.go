// Package hmactoken designs a stateless signed token — for password-reset
// links, e-mail verification or signed cookie values — and shows the three
// mistakes that make such tokens forgeable: no MAC at all, a MAC over an
// ambiguous concatenation, and one key shared by every purpose.
package hmactoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is returned for any token that fails verification. Callers get
// one error for every failure mode so responses do not become an oracle.
var ErrInvalid = errors.New("hmactoken: invalid token")

// ErrExpired is returned for an authentic token past its expiry.
var ErrExpired = errors.New("hmactoken: token expired")

// UnsignedClaims is what the insecure designs carry.
type UnsignedClaims struct {
	Subject string `json:"sub"`
	Admin   bool   `json:"admin"`
	Expires int64  `json:"exp"`
}

// EncodeUnsigned base64-encodes the claims as JSON. Base64 is an encoding,
// not a protection: the client can decode, edit and re-encode it (CWE-345).
func EncodeUnsigned(c UnsignedClaims) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeUnsigned trusts whatever the client sent.
func DecodeUnsigned(tok string) (UnsignedClaims, error) {
	var c UnsignedClaims
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return c, ErrInvalid
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, ErrInvalid
	}
	return c, nil
}

// SignAmbiguous issues "user|exp|mac" where mac = HMAC(key, user + exp). The
// token separates the fields with "|", but the MAC input does not: the
// strings ("bob1", "1760000000") and ("bob", "11760000000") produce the same
// MAC input "bob11760000000". A user who registers as "bob1" receives a tag
// that is also valid for "bob", with an expiry three centuries away (CWE-347).
func SignAmbiguous(key []byte, user string, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(user + e))
	return user + "|" + e + "|" + hex.EncodeToString(m.Sum(nil))
}

// VerifyAmbiguous checks the MAC (correctly, in constant time) and then the
// expiry. Its only flaw is the encoding of what was signed.
func VerifyAmbiguous(key []byte, tok string, now time.Time) (string, error) {
	parts := strings.Split(tok, "|")
	if len(parts) != 3 {
		return "", ErrInvalid
	}
	user, e, tagHex := parts[0], parts[1], parts[2]
	tag, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", ErrInvalid
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(user + e))
	if !hmac.Equal(m.Sum(nil), tag) {
		return "", ErrInvalid
	}
	exp, err := strconv.ParseInt(e, 10, 64)
	if err != nil {
		return "", ErrInvalid
	}
	if !now.Before(time.Unix(exp, 0)) {
		return "", ErrExpired
	}
	return user, nil
}
