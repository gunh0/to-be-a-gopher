package sigs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestECDSANonceReuseRecoversPrivateKey(t *testing.T) {
	victim := newP256(t)
	k := big.NewInt(0x5eed) // any repeated k, not just a small one

	z1 := sha256.Sum256([]byte("firmware v1.0"))
	z2 := sha256.Sum256([]byte("firmware v1.1"))
	sig1, err := SignWithNonceUnsafe(victim, z1[:], k)
	if err != nil {
		t.Fatal(err)
	}
	sig2, _ := SignWithNonceUnsafe(victim, z2[:], k)

	// Both are genuine, standard-verifying signatures.
	if !ecdsa.VerifyASN1(&victim.PublicKey, z1[:], sig1) || !ecdsa.VerifyASN1(&victim.PublicKey, z2[:], sig2) {
		t.Fatal("fixture signatures should verify")
	}

	d, err := RecoverKeyFromNonceReuse(z1[:], sig1, z2[:], sig2)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := victim.Bytes()
	if !bytes.Equal(d, want) {
		t.Fatal("recovered scalar differs from the private key")
	}

	// With d, anyone can sign anything the victim's key is trusted for.
	forger, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	evil := sha256.Sum256([]byte("firmware v6.6.6"))
	forged, _ := ecdsa.SignASN1(rand.Reader, forger, evil[:])
	if !ecdsa.VerifyASN1(&victim.PublicKey, evil[:], forged) {
		t.Fatal("forged signature should verify under the victim's public key")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestStdlibECDSANonceSurvivesBrokenRNG(t *testing.T) {
	priv := newP256(t)
	z1 := sha256.Sum256([]byte("message one"))
	z2 := sha256.Sum256([]byte("message two"))

	// A totally broken entropy source. Go's hedged nonce also mixes in the
	// private key and the digest, so different messages still get different
	// nonces and the recovery above does not apply.
	s1, err := ecdsa.SignASN1(zeroReader{}, priv, z1[:])
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := ecdsa.SignASN1(zeroReader{}, priv, z2[:])
	if _, err := RecoverKeyFromNonceReuse(z1[:], s1, z2[:], s2); err == nil {
		t.Fatal("nonces repeated across messages")
	}

	// rand == nil selects RFC 6979 deterministic ECDSA (Go 1.24+).
	d1, err := priv.Sign(nil, z1[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := priv.Sign(nil, z1[:], crypto.SHA256)
	if !bytes.Equal(d1, d2) || !ecdsa.VerifyASN1(&priv.PublicKey, z1[:], d1) {
		t.Fatal("deterministic ECDSA should repeat exactly and verify")
	}
}

func TestEd25519IsDeterministic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("release manifest")
	if !bytes.Equal(ed25519.Sign(priv, msg), ed25519.Sign(priv, msg)) {
		t.Fatal("Ed25519 derives its nonce from key and message; signatures must repeat")
	}
}

func TestECDSASignaturesAreMalleable(t *testing.T) {
	priv := newP256(t)
	z := sha256.Sum256([]byte("pay 10 to bob"))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, z[:])
	twin, err := MalleateECDSA(sig)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig, twin) || !ecdsa.VerifyASN1(&priv.PublicKey, z[:], twin) {
		t.Fatal("(r, n-s) should be a distinct valid signature")
	}
	// A replay cache keyed on the signature bytes sees a "new" request.
	seen := map[[32]byte]bool{sha256.Sum256(sig): true}
	if seen[sha256.Sum256(twin)] {
		t.Fatal("unexpected cache hit")
	}
}

func TestEd25519RejectsNonCanonicalS(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("pay 10 to bob")
	sig := ed25519.Sign(priv, msg)

	// S' = S + L is the same scalar mod L. RFC 8032 requires S < L and Go's
	// Verify enforces it, so Ed25519 signatures are not malleable this way.
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	s := new(big.Int).SetBytes(reverse(sig[32:]))
	s.Add(s, L)
	mod := append(bytes.Clone(sig[:32]), reverse(s.FillBytes(make([]byte, 32)))...)
	if ed25519.Verify(pub, msg, mod) {
		t.Fatal("non-canonical S accepted")
	}
}

func TestECDSARejectsZeroSignature(t *testing.T) {
	// CVE-2022-21449 ("psychic signatures"): Java accepted r = s = 0.
	priv := newP256(t)
	z := sha256.Sum256([]byte("anything"))
	zero, _ := asn1.Marshal(ecdsaSig{big.NewInt(0), big.NewInt(0)})
	if ecdsa.VerifyASN1(&priv.PublicKey, z[:], zero) {
		t.Fatal("r = s = 0 accepted")
	}
}

func forge(header string, claims string, sig []byte) string {
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims)) + "." + b64.EncodeToString(sig)
}

func TestUnsafeVerifierAlgorithmConfusion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string][]byte{"issuer-1": pub} // the public key is public
	claims := `{"sub":"admin","aud":"billing","exp":4102444800}`

	t.Run("alg none", func(t *testing.T) {
		tok := forge(`{"alg":"none","kid":"issuer-1"}`, claims, nil)
		if c, err := VerifyTokenUnsafe(tok, keys); err != nil || c.Sub != "admin" {
			t.Fatalf("expected forged token to pass: %v", err)
		}
	})
	t.Run("HS256 keyed with the public key", func(t *testing.T) {
		h := b64.EncodeToString([]byte(`{"alg":"HS256","kid":"issuer-1"}`))
		p := b64.EncodeToString([]byte(claims))
		m := hmac.New(sha256.New, pub)
		m.Write([]byte(h + "." + p))
		tok := h + "." + p + "." + b64.EncodeToString(m.Sum(nil))
		if c, err := VerifyTokenUnsafe(tok, keys); err != nil || c.Sub != "admin" {
			t.Fatalf("expected forged token to pass: %v", err)
		}
	})
}

func TestPinnedVerifier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(1_760_000_000, 0)
	v := &Verifier{Key: pub, Audience: "billing", Now: func() time.Time { return now }}

	good, err := Issue(priv, Claims{Sub: "alice", Aud: "billing", Exp: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if c, err := v.Verify(good); err != nil || c.Sub != "alice" {
		t.Fatalf("valid token rejected: %v", err)
	}

	otherKey, _ := Issue(otherPriv, Claims{Sub: "alice", Aud: "billing", Exp: now.Add(time.Minute).Unix()})
	expired, _ := Issue(priv, Claims{Sub: "alice", Aud: "billing", Exp: now.Unix()})
	wrongAud, _ := Issue(priv, Claims{Sub: "alice", Aud: "admin", Exp: now.Add(time.Minute).Unix()})
	parts := strings.Split(good, ".")
	hmacPub := hmac.New(sha256.New, pub)
	hmacPub.Write([]byte(parts[0] + "." + parts[1]))

	bad := map[string]string{
		"alg none":       forge(`{"alg":"none"}`, `{"sub":"admin","aud":"billing","exp":4102444800}`, nil),
		"HS256 confused": forge(`{"alg":"HS256"}`, `{"sub":"admin","aud":"billing","exp":4102444800}`, hmacPub.Sum(nil)),
		"other key":      otherKey,
		"expired":        expired,
		"wrong audience": wrongAud,
		"payload swap":   parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"admin","aud":"billing","exp":4102444800}`)) + "." + parts[2],
		"extra field":    signRaw(priv, `{"sub":"alice","aud":"billing","exp":4102444800,"role":"admin"}`),
		"trailing JSON":  signRaw(priv, `{"sub":"alice","aud":"billing","exp":4102444800}{"sub":"admin"}`),
		"four segments":  good + ".x",
		"empty":          "",
	}
	for name, tok := range bad {
		if _, err := v.Verify(tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}
}

func TestIssueRequiresEd25519(t *testing.T) {
	if _, err := Issue(newP256(t), Claims{}); err == nil {
		t.Fatal("ECDSA issuer accepted")
	}
}

func signRaw(priv ed25519.PrivateKey, payload string) string {
	signed := fixedHeader + "." + b64.EncodeToString([]byte(payload))
	return signed + "." + b64.EncodeToString(ed25519.Sign(priv, []byte(signed)))
}

func reverse(b []byte) []byte {
	out := bytes.Clone(b)
	slices.Reverse(out)
	return out
}

func ExampleMalleateECDSA() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	z := sha256.Sum256([]byte("tx: pay 10 to bob"))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, z[:])
	twin, _ := MalleateECDSA(sig)
	fmt.Println(bytes.Equal(sig, twin), ecdsa.VerifyASN1(&priv.PublicKey, z[:], twin))
	// Output:
	// false true
}
