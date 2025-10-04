// Package mtls authenticates services with client certificates and
// authorizes them by a verified URI SAN (a SPIFFE ID), contrasting that with
// servers that request but do not verify certificates and trust the CN.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"slices"
)

// ServerConfigUnsafe asks clients for a certificate but does not verify it
// (tls.RequestClientCert). r.TLS.PeerCertificates is then whatever the
// client sent, including a self-signed certificate with any subject
// (CWE-295).
func ServerConfigUnsafe(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
}

// AuthorizeByCNUnsafe authorizes on the Subject Common Name of the first
// presented certificate. It reads PeerCertificates (presented) rather than
// VerifiedChains (verified), and CN is a free-text field with no defined
// relation to a service identity (CWE-287, CWE-863).
func AuthorizeByCNUnsafe(allowedCN string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if r.TLS.PeerCertificates[0].Subject.CommonName != allowedCN {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServerConfig requires a client certificate that chains to clientCAs and
// carries the clientAuth extended key usage. clientCAs should be a dedicated
// client-issuing CA, not the system pool and not the CA that issues server
// certificates: whoever can obtain a certificate from it can authenticate.
func ServerConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13, // service-to-service: both ends are under our control
	}
}

// ErrNoIdentity means the request carries no verified client identity.
var ErrNoIdentity = errors.New("mtls: no verified client identity")

// SPIFFEID returns the single spiffe:// URI SAN of the verified client
// certificate, checked against trustDomain. It reads VerifiedChains, which is
// empty unless crypto/tls verified the chain, so it fails closed under
// RequestClientCert, RequireAnyClientCert, or VerifyClientCertIfGiven
// without a certificate.
func SPIFFEID(cs *tls.ConnectionState, trustDomain string) (*url.URL, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return nil, ErrNoIdentity
	}
	leaf := cs.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 { // SPIFFE X.509-SVID: exactly one URI SAN
		return nil, ErrNoIdentity
	}
	id := leaf.URIs[0]
	if id.Scheme != "spiffe" || id.Host != trustDomain || id.User != nil ||
		id.RawQuery != "" || id.Fragment != "" || id.Path == "" {
		return nil, ErrNoIdentity
	}
	return id, nil
}

// Require authorizes requests whose verified SPIFFE ID is in allowed. No
// verified identity is 401; a verified identity that is not allowed is 403.
// Authentication (who) and authorization (may they) stay separate decisions.
func Require(trustDomain string, allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := SPIFFEID(r.TLS, trustDomain)
		if err != nil {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		if !slices.Contains(allowed, id.String()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
