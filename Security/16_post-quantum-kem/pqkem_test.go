package pqkem

import (
	"bytes"
	"crypto/fips140"
	"crypto/mlkem"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// handshake starts a loopback HTTPS server with serverCfg, connects with the
// httptest client (which trusts the server's certificate) after applying
// clientMod, and returns the negotiated connection state.
func handshake(t *testing.T, serverCfg *tls.Config, clientMod func(*tls.Config)) (tls.ConnectionState, error) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = serverCfg
	srv.StartTLS()
	defer srv.Close()

	client := srv.Client()
	if clientMod != nil {
		clientMod(client.Transport.(*http.Transport).TLSClientConfig)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	resp.Body.Close()
	return *resp.TLS, nil
}

// classicalFallback is the group a non-PQ handshake lands on: X25519, or
// P-256 in FIPS 140-3 mode, where X25519 alone is not an approved group
// (chapter 17).
func classicalFallback() tls.CurveID {
	if fips140.Enabled() {
		return tls.CurveP256
	}
	return tls.X25519
}

func TestDefaultConfigNegotiatesHybrid(t *testing.T) {
	cs, err := handshake(t, DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 || !IsPostQuantum(cs) {
		t.Fatalf("version %x, group %v; want TLS 1.3 with X25519MLKEM768", cs.Version, cs.CurveID)
	}
}

func TestExplicitClassicalCurvesDisablePQ(t *testing.T) {
	cs, err := handshake(t, ClassicalCurvesUnsafe(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.CurveID != classicalFallback() || IsPostQuantum(cs) {
		t.Fatalf("group %v; expected the silent fallback to %v", cs.CurveID, classicalFallback())
	}
}

func TestTLS12CannotBePostQuantum(t *testing.T) {
	cs, err := handshake(t, DefaultConfig(), func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS12 || IsPostQuantum(cs) {
		t.Fatalf("version %x group %v; TLS 1.2 has no hybrid groups", cs.Version, cs.CurveID)
	}
}

func TestPQOnlyRefusesClassicalClient(t *testing.T) {
	if _, err := handshake(t, PQOnlyConfig(), func(c *tls.Config) {
		c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}); err == nil {
		t.Fatal("classical-only client should fail against a PQ-only server")
	}
	cs, err := handshake(t, PQOnlyConfig(), nil)
	if err != nil || !IsPostQuantum(cs) {
		t.Fatalf("default client against PQ-only server: %v %v", cs.CurveID, err)
	}
}

// TestGODEBUGTlsmlkem0 shows the operational kill switch. Unlike fips140,
// tlsmlkem is not fixed at startup: the runtime re-reads GODEBUG when the
// process changes it, so t.Setenv is enough here. In production it is set in
// the environment, or with a godebug line in go.mod / //go:debug in main.
func TestGODEBUGTlsmlkem0(t *testing.T) {
	t.Setenv("GODEBUG", "tlsmlkem=0")
	cs, err := handshake(t, DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cs.CurveID != classicalFallback() {
		t.Fatalf("group %v; want %v with tlsmlkem=0", cs.CurveID, classicalFallback())
	}
}

func TestHybridKEMRoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey()
	if len(pub) != PublicKeySize {
		t.Fatalf("public key %d bytes", len(pub))
	}
	sender, ct, err := Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(sender) != SharedKeySize || !bytes.Equal(sender, receiver) {
		t.Fatal("shared keys differ")
	}
	again, _, _ := Encapsulate(pub)
	if bytes.Equal(sender, again) {
		t.Fatal("two encapsulations produced the same key")
	}
}

func TestMLKEMImplicitRejection(t *testing.T) {
	// A flipped bit in the ML-KEM ciphertext is NOT an error. Code that treats
	// "Decapsulate returned nil" as "the peer is authentic" is wrong.
	dk, _ := mlkem.GenerateKey768()
	ss, ct := dk.EncapsulationKey().Encapsulate()
	ct[0] ^= 1
	got, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(got, ss) {
		t.Fatal("tampered ciphertext yielded the original secret")
	}

	// Same for the hybrid: the key silently differs, so key confirmation
	// (an AEAD or a transcript MAC) is what detects tampering.
	k, _ := GenerateKey()
	sender, hct, _ := Encapsulate(k.PublicKey())
	hct[10] ^= 1
	receiver, err := k.Decapsulate(hct)
	if err != nil || bytes.Equal(sender, receiver) {
		t.Fatalf("err=%v equal=%v; want nil error and different keys", err, bytes.Equal(sender, receiver))
	}
}

func TestCombinerBindsX25519Transcript(t *testing.T) {
	k, _ := GenerateKey()
	_, ct, _ := Encapsulate(k.PublicKey())
	base, _ := k.Decapsulate(ct)

	// Replace the X25519 ciphertext with another valid public key.
	other, _ := GenerateKey()
	mixed := append(bytes.Clone(ct[:mlkem.CiphertextSize768]), other.x.PublicKey().Bytes()...)
	mixedKey, err := k.Decapsulate(mixed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, mixedKey) {
		t.Fatal("changing the X25519 share must change the key")
	}
}

func TestMalformedInputs(t *testing.T) {
	k, _ := GenerateKey()
	pub := k.PublicKey()
	lowOrder := append(bytes.Clone(pub[:mlkem.EncapsulationKeySize768]), make([]byte, 32)...) // X25519 u=0
	for name, p := range map[string][]byte{"short": pub[:100], "long": append(bytes.Clone(pub), 0), "low-order X25519": lowOrder} {
		if _, _, err := Encapsulate(p); !errors.Is(err, ErrMalformed) {
			t.Errorf("Encapsulate(%s): err = %v", name, err)
		}
	}
	if _, err := k.Decapsulate(make([]byte, CiphertextSize-1)); !errors.Is(err, ErrMalformed) {
		t.Errorf("short ciphertext: err = %v", err)
	}
}

func ExampleEncapsulate() {
	recipient, _ := GenerateKey()
	key, ct, _ := Encapsulate(recipient.PublicKey())
	same, _ := recipient.Decapsulate(ct)
	fmt.Println(len(recipient.PublicKey()), len(ct), bytes.Equal(key, same))
	// Output:
	// 1216 1120 true
}
