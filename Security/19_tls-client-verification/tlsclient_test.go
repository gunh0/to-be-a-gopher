package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

const apiName = "api.internal.test"

// start serves cert on loopback and records the Authorization header of every
// request it receives.
func start(t *testing.T, cert tls.Certificate) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var seen atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Authorization"))
		io.WriteString(w, "ok")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &seen
}

func get(c *http.Client, url string) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer prod-token-7f3a")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func TestInsecureSkipVerifyHandsTokenToImpostor(t *testing.T) {
	// The impostor has no access to any CA: a self-signed certificate.
	mitm, seen := start(t, issue(t, nil, newKey(t), apiName, []string{apiName}))
	if err := get(NewClientUnsafe(), mitm.URL); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != "Bearer prod-token-7f3a" {
		t.Fatal("expected the bearer token to reach the impostor")
	}
}

func TestVerifyingClientRejectsImpostor(t *testing.T) {
	ca := newCA(t, "internal CA")
	mitm, seen := start(t, issue(t, nil, newKey(t), apiName, []string{apiName}))
	c, _ := NewClient(Config{Roots: ca.pool, ServerName: apiName})

	err := get(c, mitm.URL)
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want x509.UnknownAuthorityError", err)
	}
	if seen.Load() != nil {
		t.Fatal("request reached the impostor")
	}
}

func TestVerifyingClientAcceptsInternalCA(t *testing.T) {
	ca := newCA(t, "internal CA")
	srv, _ := start(t, issue(t, ca, newKey(t), apiName, []string{apiName}))
	c, _ := NewClient(Config{Roots: ca.pool, ServerName: apiName})
	if err := get(c, srv.URL); err != nil {
		t.Fatal(err)
	}
}

func TestHostnameIsVerified(t *testing.T) {
	ca := newCA(t, "internal CA")
	// A real certificate from the trusted CA, for a different service.
	other, _ := start(t, issue(t, ca, newKey(t), "metrics.internal.test", []string{"metrics.internal.test"}))

	c, _ := NewClient(Config{Roots: ca.pool, ServerName: apiName})
	var hostErr x509.HostnameError
	if err := get(c, other.URL); !errors.As(err, &hostErr) {
		t.Fatalf("err = %v, want x509.HostnameError", err)
	}

	// The hand-rolled verifier checks the chain but not the name.
	if err := get(NewClientNoHostnameUnsafe(ca.pool), other.URL); err != nil {
		t.Fatalf("expected the no-hostname verifier to accept: %v", err)
	}
}

func TestHostnameMatchingRules(t *testing.T) {
	ca := newCA(t, "internal CA")
	wild := issue(t, ca, newKey(t), "ignored", []string{"*.internal.test"}).Leaf
	cnOnly := issue(t, ca, newKey(t), apiName, nil).Leaf
	tests := []struct {
		cert *x509.Certificate
		host string
		ok   bool
	}{
		{wild, "api.internal.test", true},
		{wild, "a.b.internal.test", false}, // a wildcard covers one label
		{wild, "internal.test", false},
		{wild, "API.internal.test", true}, // case-insensitive
		{cnOnly, apiName, false},          // CN is ignored since Go 1.15
	}
	for _, tt := range tests {
		if err := tt.cert.VerifyHostname(tt.host); (err == nil) != tt.ok {
			t.Errorf("SANs %v, CN %q, host %q: err = %v, want ok=%v",
				tt.cert.DNSNames, tt.cert.Subject.CommonName, tt.host, err, tt.ok)
		}
	}
}

func TestPinning(t *testing.T) {
	ca := newCA(t, "internal CA")
	primary, backup := newKey(t), newKey(t)
	pins := []string{
		SPKIPin(issue(t, nil, primary, "x", nil).Leaf),
		SPKIPin(issue(t, nil, backup, "x", nil).Leaf),
	}
	c, err := NewClient(Config{Roots: ca.pool, ServerName: apiName, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}

	legit, _ := start(t, issue(t, ca, primary, apiName, []string{apiName}))
	if err := get(c, legit.URL); err != nil {
		t.Fatalf("primary key: %v", err)
	}
	// The CA (or someone who compromised it) issues a valid certificate for
	// the right name with a different key: chain and hostname pass, pin fails.
	misissued, seen := start(t, issue(t, ca, newKey(t), apiName, []string{apiName}))
	if err := get(c, misissued.URL); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
	if seen.Load() != nil {
		t.Fatal("request reached the mis-issued server")
	}
	// Key rotation to the pre-pinned backup works without a client release.
	rotated, _ := start(t, issue(t, ca, backup, apiName, []string{apiName}))
	if err := get(c, rotated.URL); err != nil {
		t.Fatalf("backup key: %v", err)
	}
}

func TestPinningRequiresBackup(t *testing.T) {
	if _, err := NewClient(Config{Pins: []string{"only-one"}}); err == nil {
		t.Fatal("a single pin must be rejected")
	}
}

func TestVerifyConnectionRunsOnResumption(t *testing.T) {
	ca := newCA(t, "internal CA")
	srv, _ := start(t, issue(t, ca, newKey(t), apiName, []string{apiName}))

	var peerCalls, connCalls atomic.Int32
	cfg := &tls.Config{
		RootCAs:            ca.pool,
		ServerName:         apiName,
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
			peerCalls.Add(1)
			return nil
		},
		VerifyConnection: func(tls.ConnectionState) error {
			connCalls.Add(1)
			return nil
		},
	}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
	for range 2 {
		if err := get(c, srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	// Second connection resumed: VerifyPeerCertificate skipped, VerifyConnection ran.
	if peerCalls.Load() != 1 || connCalls.Load() != 2 {
		t.Fatalf("VerifyPeerCertificate=%d VerifyConnection=%d, want 1 and 2", peerCalls.Load(), connCalls.Load())
	}
}

func TestTestServersNeedNoSkipVerify(t *testing.T) {
	// httptest servers come with a client that trusts their certificate.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func ExampleNewClient() {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	roots := x509.NewCertPool() // only the CA this client needs, not the system pool
	roots.AddCert(srv.Certificate())
	c, _ := NewClient(Config{
		Roots: roots,
		Pins:  []string{SPKIPin(srv.Certificate()), "pin-of-the-offline-backup-key"},
	})
	resp, err := c.Get(srv.URL)
	if err != nil {
		fmt.Println(err)
		return
	}
	resp.Body.Close()
	fmt.Println(resp.Status, resp.TLS.HandshakeComplete)
	// Output:
	// 200 OK true
}
