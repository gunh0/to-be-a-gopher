// Package clean is a fixture for seclint that must produce no findings.
package clean

import (
	"crypto/tls"
	"math/rand/v2"
	"time"
)

// Jitter uses math/rand for retry back-off, which is fine.
func Jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d/10)+1))
}

// Config verifies certificates (the zero value of InsecureSkipVerify).
func Config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}
