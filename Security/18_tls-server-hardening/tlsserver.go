// Package tlsserver builds a hardened crypto/tls server configuration and
// contrasts it with the "compatibility" settings that undo Go's defaults.
package tlsserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// LegacyConfigUnsafe is what "make old clients work" tickets produce. Every
// line overrides a safe default (CWE-757, CWE-327):
//
//   - MinVersion TLS 1.0: TLS 1.0/1.1 use MD5/SHA-1 in the handshake and
//     CBC suites with known weaknesses (BEAST, Lucky13); RFC 8996 deprecates
//     both versions. Go servers default to TLS 1.2 since Go 1.22.
//   - An explicit CipherSuites list with CBC-SHA1 suites: an explicit list
//     replaces Go's default, so future default improvements no longer apply.
//   - PreferServerCipherSuites: ignored since Go 1.17 and deprecated. Its
//     presence is a sign the config was copied from an older guide.
func LegacyConfigUnsafe(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true, // deprecated no-op, shown on purpose
	}
}

// HardenedConfig returns a server configuration that keeps Go's defaults
// where they are already right and tightens the rest:
//
//   - TLS 1.2 minimum (TLS 1.3 negotiated whenever the client supports it);
//   - TLS 1.2 restricted to ECDHE with AEAD ciphers: forward secrecy and no
//     CBC (Go's default list still includes ECDHE CBC-SHA1 suites);
//   - CurvePreferences left nil so X25519MLKEM768 stays enabled (chapter 16);
//   - certificates from GetCertificate, so they can rotate without restart.
//
// TLS 1.3 cipher suites are not configurable in Go and are all AEADs.
func HardenedConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: getCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// CertReloader serves the current certificate and swaps it atomically. A
// failed reload (unreadable file, key that does not match the certificate,
// expired certificate) keeps the previous certificate: rotation must never
// turn into an outage or into serving nothing.
type CertReloader struct {
	cur atomic.Pointer[tls.Certificate]
	now func() time.Time
}

// NewCertReloader loads the initial certificate; now may be nil.
func NewCertReloader(certPEM, keyPEM []byte, now func() time.Time) (*CertReloader, error) {
	if now == nil {
		now = time.Now
	}
	r := &CertReloader{now: now}
	return r, r.Load(certPEM, keyPEM)
}

// Load parses and validates a new key pair and, only if it is usable,
// publishes it for subsequent handshakes. In-flight connections are not
// affected.
func (r *CertReloader) Load(certPEM, keyPEM []byte) error {
	c, err := tls.X509KeyPair(certPEM, keyPEM) // checks the key matches; sets Leaf (Go 1.23+)
	if err != nil {
		return err
	}
	leaf := c.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return err
		}
	}
	if now := r.now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return errors.New("tlsserver: certificate not valid at current time")
	}
	r.cur.Store(&c)
	return nil
}

// LoadFiles is Load from disk, for a SIGHUP handler or a file watcher.
func (r *CertReloader) LoadFiles(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	return r.Load(certPEM, keyPEM)
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cur.Load(), nil
}

// HSTS adds Strict-Transport-Security to responses served over TLS, telling
// browsers to refuse plain HTTP for this host for two years. TLS
// configuration cannot protect a user whose first request is http:// and
// gets redirected by an attacker instead of by you.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// NewServer assembles the pieces: hardened TLS, HSTS, and the timeouts from
// chapter 21 (a TLS handshake is also a slow-client target).
func NewServer(addr string, h http.Handler, certs *CertReloader) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           HSTS(h),
		TLSConfig:         HardenedConfig(certs.GetCertificate),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// RotateTicketKeys installs current as the key for new session tickets and
// keeps previous for decrypting tickets issued before the rotation. Go rotates
// ticket keys automatically (daily, seven-day lifetime) as long as no keys
// are set; once a fleet shares keys through SetSessionTicketKeys so that any
// replica can resume any session, rotation becomes the operator's job. A
// ticket key that never changes is a long-term secret protecting every
// resumable session: in TLS 1.2 the ticket carries the session's master
// secret.
func RotateTicketKeys(cfg *tls.Config, current [32]byte, previous ...[32]byte) {
	cfg.SetSessionTicketKeys(append([][32]byte{current}, previous...))
}
