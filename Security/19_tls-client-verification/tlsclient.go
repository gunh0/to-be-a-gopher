// Package tlsclient shows how Go TLS clients lose server authentication
// (InsecureSkipVerify, custom verification that forgets the hostname) and
// how to keep it while trusting a private CA and pinning server keys.
package tlsclient

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewClientUnsafe is the most common Go TLS vulnerability: verification
// switched off, usually "temporarily" for a self-signed test server or an
// internal CA (CWE-295). The connection is still encrypted, to whoever
// answers. gosec reports it as G402.
func NewClientUnsafe() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// NewClientNoHostnameUnsafe is the subtler variant: verification is turned
// off and re-implemented in VerifyPeerCertificate, checking the chain against
// the right roots but not the hostname (no DNSName in VerifyOptions). Any
// certificate the internal CA ever issued, for any service, now authenticates
// as any other service (CWE-297).
func NewClientNoHostnameUnsafe(roots *x509.CertPool) *http.Client {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, r := range raw[1:] {
				if c, err := x509.ParseCertificate(r); err == nil {
					inter.AddCert(c)
				}
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
			return err
		},
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// Config is the input to NewClient.
type Config struct {
	// Roots are the CAs trusted for this client. nil means the system pool;
	// for internal services use only the internal CA, not system + internal.
	Roots *x509.CertPool
	// ServerName overrides the name verified (and sent as SNI). Leave empty
	// to use the host from the request URL, which is almost always right.
	ServerName string
	// Pins, if set, are SPKIPin values; the verified chain must contain at
	// least one matching key. At least two are required: a primary and a
	// backup key that is not yet deployed.
	Pins []string
}

// NewClient keeps standard verification (chain to Roots, validity, key
// usage, hostname against SANs) and adds optional key pinning on top of it
// in VerifyConnection, which, unlike VerifyPeerCertificate, also runs on
// resumed sessions.
func NewClient(c Config) (*http.Client, error) {
	cfg := &tls.Config{
		RootCAs:    c.Roots,
		ServerName: c.ServerName,
		MinVersion: tls.VersionTLS12,
	}
	if len(c.Pins) > 0 {
		v, err := PinVerifier(c.Pins)
		if err != nil {
			return nil, err
		}
		cfg.VerifyConnection = v
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     cfg,
			TLSHandshakeTimeout: 5 * time.Second,
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}, nil
}

// SPKIPin returns base64(SHA-256(SubjectPublicKeyInfo)), the format used by
// HPKP and most pinning tools. Pinning the key rather than the certificate
// survives renewals that keep the key.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ErrPinMismatch is returned when no certificate in the verified chain
// matches a pin.
var ErrPinMismatch = errors.New("tlsclient: no certificate in the verified chain matches a pinned key")

// PinVerifier returns a VerifyConnection callback. It runs after Go's normal
// verification, so it only ever sees chains that already validated; it
// accepts the connection if any certificate in any verified chain (leaf,
// intermediate or root) has a pinned key, which allows pinning an issuing
// CA as the backup.
func PinVerifier(pins []string) (func(tls.ConnectionState) error, error) {
	if len(pins) < 2 {
		return nil, errors.New("tlsclient: pinning needs a primary and at least one backup pin")
	}
	set := make(map[string]bool, len(pins))
	for _, p := range pins {
		set[p] = true
	}
	return func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 {
			return fmt.Errorf("%w: no verified chain (InsecureSkipVerify?)", ErrPinMismatch)
		}
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {
				if set[SPKIPin(cert)] {
					return nil
				}
			}
		}
		return ErrPinMismatch
	}, nil
}
