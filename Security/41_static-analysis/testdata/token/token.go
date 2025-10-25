// Package token is a fixture for seclint: a session token from math/rand.
package token

import (
	"encoding/hex"
	"math/rand"
)

// New returns a "random" 128-bit token.
func New() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return hex.EncodeToString(b)
}
