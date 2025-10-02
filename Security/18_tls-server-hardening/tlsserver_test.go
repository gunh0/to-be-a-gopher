package tlsserver

import (
	"crypto/fips140"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func start(t *testing.T, cfg *tls.Config, h http.Handler) *httptest.Server {
	t.Helper()
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// dial performs a raw TLS handshake with a client limited to [minV, maxV]
// and, if suites is non-nil, to those TLS 1.0–1.2 cipher suites.
func dial(srv *httptest.Server, ca *testCA, minV, maxV uint16, suites []uint16) (tls.ConnectionState, error) {
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
		RootCAs:      ca.pool,
		ServerName:   "localhost",
		MinVersion:   minV,
		MaxVersion:   maxV,
		CipherSuites: suites,
	})
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

func hardened(t *testing.T, ca *testCA) (*httptest.Server, *CertReloader) {
	t.Helper()
	_, c, k := ca.serverCert(t, 1)
	r, err := NewCertReloader(c, k, nil)
	if err != nil {
		t.Fatal(err)
	}
	return start(t, HardenedConfig(r.GetCertificate), nil), r
}

func TestLegacyConfigAcceptsTLS10(t *testing.T) {
	ca := newCA(t, "test CA")
	cert, _, _ := ca.serverCert(t, 1)
	srv := start(t, LegacyConfigUnsafe(cert), nil)

	cs, err := dial(srv, ca, tls.VersionTLS10, tls.VersionTLS10, nil)
	if fips140.Enabled() {
		// FIPS 140-3 mode filters TLS 1.0/1.1 out even when configured.
		if err == nil {
			t.Fatal("TLS 1.0 negotiated in FIPS mode")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS10 {
		t.Fatalf("negotiated %s", tls.VersionName(cs.Version))
	}
}

func TestGoDefaultServerRejectsTLS10And11(t *testing.T) {
	ca := newCA(t, "test CA")
	cert, _, _ := ca.serverCert(t, 1)
	// No MinVersion: the default for servers is TLS 1.2 since Go 1.22.
	srv := start(t, &tls.Config{Certificates: []tls.Certificate{cert}}, nil)
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if _, err := dial(srv, ca, v, v, nil); err == nil {
			t.Errorf("%s accepted by default server", tls.VersionName(v))
		}
	}
}

func TestHardenedVersions(t *testing.T) {
	ca := newCA(t, "test CA")
	srv, _ := hardened(t, ca)
	tests := []struct {
		v  uint16
		ok bool
	}{
		{tls.VersionTLS10, false},
		{tls.VersionTLS11, false},
		{tls.VersionTLS12, true},
		{tls.VersionTLS13, true},
	}
	for _, tt := range tests {
		cs, err := dial(srv, ca, tt.v, tt.v, nil)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tls.VersionName(tt.v), err, tt.ok)
			continue
		}
		if tt.ok && cs.Version != tt.v {
			t.Errorf("%s: negotiated %s", tls.VersionName(tt.v), tls.VersionName(cs.Version))
		}
	}
	// A default client gets TLS 1.3 and the hybrid post-quantum group.
	cs, err := dial(srv, ca, 0, 0, nil)
	if err != nil || cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("default client: %s %v %v", tls.VersionName(cs.Version), cs.CurveID, err)
	}
}

func TestCBCOnlyClient(t *testing.T) {
	ca := newCA(t, "test CA")
	cbc := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}

	// Go's default TLS 1.2 list still contains ECDHE CBC-SHA1 suites.
	cert, _, _ := ca.serverCert(t, 1)
	def := start(t, &tls.Config{Certificates: []tls.Certificate{cert}}, nil)
	cs, err := dial(def, ca, tls.VersionTLS12, tls.VersionTLS12, cbc)
	switch {
	case fips140.Enabled(): // CBC-SHA1 is not an approved suite
		if err == nil {
			t.Fatal("CBC-SHA1 negotiated in FIPS mode")
		}
	case err != nil || cs.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		t.Fatalf("default server with CBC-only client: %v %v", tls.CipherSuiteName(cs.CipherSuite), err)
	}

	srv, _ := hardened(t, ca)
	if _, err := dial(srv, ca, tls.VersionTLS12, tls.VersionTLS12, cbc); err == nil {
		t.Fatal("hardened server negotiated a CBC suite")
	}
}

func TestHardenedSuitesAreSecure(t *testing.T) {
	insecure := map[uint16]bool{}
	for _, s := range tls.InsecureCipherSuites() {
		insecure[s.ID] = true
	}
	for _, id := range HardenedConfig(nil).CipherSuites {
		if insecure[id] {
			t.Errorf("%s is in tls.InsecureCipherSuites", tls.CipherSuiteName(id))
		}
	}
}

func TestCertReloadRotatesWithoutRestart(t *testing.T) {
	ca := newCA(t, "test CA")
	srv, reloader := hardened(t, ca)

	serial := func() int64 {
		t.Helper()
		cs, err := dial(srv, ca, 0, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		return cs.PeerCertificates[0].SerialNumber.Int64()
	}
	if got := serial(); got != 1 {
		t.Fatalf("serial %d, want 1", got)
	}
	_, c2, k2 := ca.serverCert(t, 2)
	if err := reloader.Load(c2, k2); err != nil {
		t.Fatal(err)
	}
	if got := serial(); got != 2 {
		t.Fatalf("after reload serial %d, want 2", got)
	}
}

func TestCertReloadRejectsBadInputAndKeepsServing(t *testing.T) {
	ca := newCA(t, "test CA")
	_, c1, k1 := ca.serverCert(t, 1)
	_, c2, _ := ca.serverCert(t, 2)
	expired, expiredKey := ca.serverLeaf(t, 3, time.Now().Add(-time.Minute))

	r, err := NewCertReloader(c1, k1, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string][2][]byte{
		"key from another pair": {c2, k1},
		"expired certificate":   {expired, expiredKey},
		"garbage":               {[]byte("not pem"), k1},
	}
	for name, in := range bad {
		if err := r.Load(in[0], in[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cur, _ := r.GetCertificate(nil)
	if cur.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("serving serial %d after failed reloads, want 1", cur.Leaf.SerialNumber.Int64())
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	ca := newCA(t, "test CA")
	_, c, k := ca.serverCert(t, 1)
	r, _ := NewCertReloader(c, k, nil)
	h := HSTS(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	tlsSrv := start(t, HardenedConfig(r.GetCertificate), h)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool, ServerName: "localhost"}}}
	resp, err := client.Get(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("HSTS = %q", got)
	}

	plain := httptest.NewServer(h)
	defer plain.Close()
	resp, err = http.Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over plain HTTP (RFC 6797 section 7.2)")
	}
}

func TestNewServerHasTimeouts(t *testing.T) {
	ca := newCA(t, "test CA")
	_, c, k := ca.serverCert(t, 1)
	r, _ := NewCertReloader(c, k, nil)
	s := NewServer(":8443", http.NotFoundHandler(), r)
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 {
		t.Fatalf("missing timeouts: %+v", s)
	}
	if s.TLSConfig.MinVersion != tls.VersionTLS12 || s.TLSConfig.GetCertificate == nil {
		t.Fatal("NewServer must use HardenedConfig")
	}
}

func TestTicketKeyRotation(t *testing.T) {
	ca := newCA(t, "test CA")
	_, c, k := ca.serverCert(t, 1)
	r, _ := NewCertReloader(c, k, nil)
	cfg := HardenedConfig(r.GetCertificate)
	keyA, keyB := [32]byte{'A'}, [32]byte{'B'}
	RotateTicketKeys(cfg, keyA)
	srv := start(t, cfg, nil)
	// httptest clones cfg in StartTLS; rotate on the live config.
	live := srv.TLS

	client := &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true, // new connection per request, so resumption is visible
		TLSClientConfig: &tls.Config{
			RootCAs:            ca.pool,
			ServerName:         "localhost",
			ClientSessionCache: tls.NewLRUClientSessionCache(4),
		},
	}}
	resumed := func() bool {
		t.Helper()
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body) // reading lets the client process the TLS 1.3 ticket
		resp.Body.Close()
		return resp.TLS.DidResume
	}

	if resumed() {
		t.Fatal("first connection cannot resume")
	}
	if !resumed() {
		t.Fatal("second connection should resume with a ticket under key A")
	}
	RotateTicketKeys(live, keyB, keyA) // B issues, A still decrypts
	if !resumed() {
		t.Fatal("ticket under the previous key should still resume")
	}
	RotateTicketKeys(live, keyB) // A retired
	resumed()                    // whatever ticket the client holds now is under B
	RotateTicketKeys(live, [32]byte{'C'})
	if resumed() {
		t.Fatal("a ticket under a retired key must not resume")
	}
}

func ExampleHardenedConfig() {
	cfg := HardenedConfig(nil)
	fmt.Println(tls.VersionName(cfg.MinVersion), cfg.CurvePreferences == nil)
	for _, id := range cfg.CipherSuites[:2] {
		fmt.Println(tls.CipherSuiteName(id))
	}
	// Output:
	// TLS 1.2 true
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}
