package pqkem

import "crypto/tls"

// ClassicalCurvesUnsafe is the configuration found in many pre-2024
// hardening guides: an explicit CurvePreferences list "to disable weak
// curves". Since Go 1.24 any explicit list replaces the default, so this one
// also removes X25519MLKEM768 and every handshake falls back to classical
// X25519. Traffic recorded today can then be decrypted once a
// cryptographically relevant quantum computer exists (harvest now, decrypt
// later). Nothing fails and nothing is logged (CWE-327).
func ClassicalCurvesUnsafe() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// DefaultConfig leaves CurvePreferences nil, so the standard library's
// default applies: X25519MLKEM768 first, then X25519, P-256, P-384, P-521.
// Post-quantum protection then improves with each Go release without a
// config change. Hybrid key exchange exists only in TLS 1.3; TLS 1.2 peers
// get classical ECDHE.
func DefaultConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// PQOnlyConfig is for links where both ends are known to be Go 1.24+ (or
// another hybrid-capable stack), such as internal service-to-service traffic:
// TLS 1.3 only and the hybrid group only, so a downgrade to classical key
// exchange is a handshake failure rather than a silent fallback.
func PQOnlyConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
}

// IsPostQuantum reports whether a completed handshake used a hybrid
// post-quantum key exchange. ConnectionState.CurveID was added in Go 1.25;
// export it as a metric to see how much traffic is actually protected.
func IsPostQuantum(cs tls.ConnectionState) bool {
	return cs.CurveID == tls.X25519MLKEM768
}
