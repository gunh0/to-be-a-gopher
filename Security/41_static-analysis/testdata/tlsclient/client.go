// Package tlsclient is a fixture for seclint. Do not copy.
package tlsclient

import (
	cryptotls "crypto/tls"
	"net/http"
	"os"
)

// A comment that mentions InsecureSkipVerify: true is not code.
const help = "never set InsecureSkipVerify: true in production"

// Insecure disables verification under an import alias.
func Insecure() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &cryptotls.Config{InsecureSkipVerify: true},
	}}
}

// FromEnv lets configuration decide.
func FromEnv() *cryptotls.Config {
	skip := os.Getenv("SKIP_VERIFY") == "1"
	return &cryptotls.Config{
		MinVersion:         cryptotls.VersionTLS12,
		InsecureSkipVerify: skip,
	}
}

// Later mutates an existing configuration.
func Later(cfg *cryptotls.Config) {
	cfg.InsecureSkipVerify = true
}

// Explicit spells out the default and is fine.
func Explicit() *cryptotls.Config {
	return &cryptotls.Config{InsecureSkipVerify: false}
}
