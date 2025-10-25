package token

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Sign authenticates a token.
func Sign(key []byte, tok string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(tok))
	return m.Sum(nil)
}
