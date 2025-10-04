package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const (
	trustDomain = "example.test"
	billingID   = "spiffe://example.test/ns/prod/sa/billing"
	reportingID = "spiffe://example.test/ns/prod/sa/reporting"
)

type pki struct {
	serverCA, clientCA *testCA
	serverCert         tls.Certificate
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{serverCA: newCA(t, "server CA"), clientCA: newCA(t, "client CA")}
	p.serverCert = issue(t, leafOpts{cn: "invoices", ips: []net.IP{net.IPv4(127, 0, 0, 1)},
		eku: x509.ExtKeyUsageServerAuth, issuer: p.serverCA})
	return p
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "invoice data") })

func serve(t *testing.T, cfg *tls.Config, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// call connects with the given client certificate (nil for none) and
// returns the HTTP status, or an error if the handshake failed.
func call(p *pki, srv *httptest.Server, cert *tls.Certificate) (int, error) {
	cfg := &tls.Config{RootCAs: p.serverCA.pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	resp, err := c.Get(srv.URL)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func TestUnverifiedCNIsSpoofable(t *testing.T) {
	p := newPKI(t)
	srv := serve(t, ServerConfigUnsafe(p.serverCert), AuthorizeByCNUnsafe("billing", ok))

	// Self-signed, minted by the attacker in a millisecond.
	forged := issue(t, leafOpts{cn: "billing", eku: x509.ExtKeyUsageClientAuth})
	code, err := call(p, srv, &forged)
	if err != nil || code != http.StatusOK {
		t.Fatalf("got %d %v; expected the forged CN to be authorized", code, err)
	}
}

func TestRequireAndVerify(t *testing.T) {
	p := newPKI(t)
	otherCA := newCA(t, "someone else's CA")
	srv := serve(t, ServerConfig(p.serverCert, p.clientCA.pool), Require(trustDomain, []string{billingID}, ok))

	billing := issue(t, leafOpts{cn: "billing", uri: billingID, eku: x509.ExtKeyUsageClientAuth, issuer: p.clientCA})
	// Right CA, CN says "billing", but the identity is the reporting service.
	reporting := issue(t, leafOpts{cn: "billing", uri: reportingID, eku: x509.ExtKeyUsageClientAuth, issuer: p.clientCA})
	foreign := issue(t, leafOpts{cn: "billing", uri: billingID, eku: x509.ExtKeyUsageClientAuth, issuer: otherCA})
	selfSigned := issue(t, leafOpts{cn: "billing", uri: billingID, eku: x509.ExtKeyUsageClientAuth})
	serverOnly := issue(t, leafOpts{cn: "billing", uri: billingID, eku: x509.ExtKeyUsageServerAuth, issuer: p.clientCA})
	otherDomain := issue(t, leafOpts{cn: "billing", uri: "spiffe://evil.test/ns/prod/sa/billing", eku: x509.ExtKeyUsageClientAuth, issuer: p.clientCA})

	tests := []struct {
		name      string
		cert      *tls.Certificate
		handshake bool
		code      int
	}{
		{"no certificate", nil, false, 0},
		{"certificate from another CA", &foreign, false, 0},
		{"self-signed with the right SAN", &selfSigned, false, 0},
		{"serverAuth-only certificate", &serverOnly, false, 0},
		{"valid certificate, wrong SPIFFE ID (CN says billing)", &reporting, true, http.StatusForbidden},
		{"valid certificate, foreign trust domain", &otherDomain, true, http.StatusUnauthorized},
		{"valid certificate, allowed ID", &billing, true, http.StatusOK},
	}
	for _, tt := range tests {
		code, err := call(p, srv, tt.cert)
		if (err == nil) != tt.handshake {
			t.Errorf("%s: err = %v, want handshake ok=%v", tt.name, err, tt.handshake)
			continue
		}
		if code != tt.code {
			t.Errorf("%s: status %d, want %d", tt.name, code, tt.code)
		}
	}
}

func TestVerifyClientCertIfGivenLetsAnonymousThrough(t *testing.T) {
	p := newPKI(t)
	cfg := ServerConfig(p.serverCert, p.clientCA.pool)
	// Often chosen so health checks and browsers can connect without a cert.
	cfg.ClientAuth = tls.VerifyClientCertIfGiven

	var handshakeAuthenticated atomic.Bool
	srv := serve(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshakeAuthenticated.Store(len(r.TLS.VerifiedChains) > 0)
		Require(trustDomain, []string{billingID}, ok).ServeHTTP(w, r)
	}))

	// The handshake succeeds without a certificate...
	code, err := call(p, srv, nil)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	// ...so the handler is the only line of defence, and it must check
	// VerifiedChains, not assume "the TLS layer did it".
	if handshakeAuthenticated.Load() || code != http.StatusUnauthorized {
		t.Fatalf("status %d, verified=%v; want 401 from the handler", code, handshakeAuthenticated.Load())
	}
}

func TestSPIFFEIDParsing(t *testing.T) {
	p := newPKI(t)
	verified := func(uri string) *tls.ConnectionState {
		c := issue(t, leafOpts{uri: uri, eku: x509.ExtKeyUsageClientAuth, issuer: p.clientCA})
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, p.clientCA.cert}}}
	}
	presentedOnly := issue(t, leafOpts{uri: billingID, eku: x509.ExtKeyUsageClientAuth})
	tests := []struct {
		name string
		cs   *tls.ConnectionState
		ok   bool
	}{
		{"valid", verified(billingID), true},
		{"no TLS", nil, false},
		{"presented but not verified", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{presentedOnly.Leaf}}, false},
		{"https scheme", verified("https://example.test/ns/prod/sa/billing"), false},
		{"other trust domain", verified("spiffe://example.test.evil.test/sa/billing"), false},
		{"userinfo", verified("spiffe://admin@example.test/sa/billing"), false},
		{"query", verified("spiffe://example.test/sa/billing?x=1"), false},
		{"no path", verified("spiffe://example.test"), false},
	}
	for _, tt := range tests {
		_, err := SPIFFEID(tt.cs, trustDomain)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrNoIdentity)) {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
}

func ExampleSPIFFEID() {
	id, err := SPIFFEID(&tls.ConnectionState{}, "example.test")
	fmt.Println(id, err)
	// Output:
	// <nil> mtls: no verified client identity
}
