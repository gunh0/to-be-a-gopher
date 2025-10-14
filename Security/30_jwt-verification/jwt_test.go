package jwtverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Fixed, in-process key material: these tests never touch a real issuer.
var (
	edPriv   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	edPub    = edPriv.Public().(ed25519.PublicKey)
	hsSecret = bytes.Repeat([]byte("s"), 32)
	now      = time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)
)

func verifier() *Verifier {
	return &Verifier{
		Keys: map[string]Key{
			"ed1": {Alg: "EdDSA", Public: edPub},
			"hs1": {Alg: "HS256", Secret: hsSecret},
		},
		Issuer:   "https://issuer.example",
		Audience: "api",
		Leeway:   time.Minute,
		Now:      func() time.Time { return now },
	}
}

func payload(sub string, exp time.Time) string {
	return fmt.Sprintf(`{"iss":"https://issuer.example","sub":%q,"aud":"api","exp":%d}`, sub, exp.Unix())
}

// raw builds a token from literal JSON, signing with key ([]byte → HMAC,
// ed25519.PrivateKey → Ed25519, nil → empty signature).
func raw(header, claims string, key any) string {
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	var sig []byte
	switch k := key.(type) {
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	return input + "." + b64.EncodeToString(sig)
}

func valid() string {
	return raw(`{"alg":"EdDSA","kid":"ed1"}`, payload("alice", now.Add(time.Hour)), edPriv)
}

func TestNaiveAcceptsAlgNone(t *testing.T) {
	forged := raw(`{"alg":"none"}`, payload("admin", now.Add(time.Hour)), nil)
	c, err := VerifyNaive(forged, edPub)
	if err != nil || c.Sub != "admin" {
		t.Fatalf("got %+v, %v; expected the unsigned token to be accepted", c, err)
	}
	if _, err := verifier().Verify(forged); !errors.Is(err, ErrKey) && !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("safe verifier: err = %v", err)
	}
}

func TestNaiveAlgorithmConfusion(t *testing.T) {
	// The attacker knows the public key (it is public: JWKS, docs) and uses
	// its bytes as an HMAC secret.
	forged := raw(`{"alg":"HS256","kid":"ed1"}`, payload("admin", now.Add(time.Hour)), []byte(edPub))
	c, err := VerifyNaive(forged, edPub)
	if err != nil || c.Sub != "admin" {
		t.Fatalf("got %+v, %v; expected algorithm confusion to succeed", c, err)
	}
	if _, err := verifier().Verify(forged); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("safe verifier: err = %v, want ErrAlgorithm", err)
	}
}

func TestNaiveIgnoresExpiry(t *testing.T) {
	old := raw(`{"alg":"EdDSA","kid":"ed1"}`, payload("alice", now.Add(-30*24*time.Hour)), edPriv)
	if _, err := VerifyNaive(old, edPub); err != nil {
		t.Fatalf("naive rejected an expired token: %v", err)
	}
	if _, err := verifier().Verify(old); !errors.Is(err, ErrClaims) {
		t.Fatalf("safe verifier: err = %v, want ErrClaims", err)
	}
}

func TestSignatureMalleability(t *testing.T) {
	tok := valid()
	dot := strings.LastIndexByte(tok, '.')
	sig := tok[dot+1:]

	// Ed25519 signatures are 64 bytes = 86 base64url characters; the last
	// character carries 4 unused bits. Setting them gives a different string
	// that lax decoding maps to the same bytes.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, sig[len(sig)-1])
	variants := map[string]string{
		"trailing bits": tok[:dot+1] + sig[:len(sig)-1] + string(alphabet[last|1]),
		"newline":       tok[:dot+1] + sig[:40] + "\n" + sig[40:],
		"padding":       tok + "==",
	}
	for name, v := range variants {
		if v == tok {
			t.Fatalf("%s: variant equals the original", name)
		}
		_, naiveErr := VerifyNaive(v, edPub)
		_, safeErr := verifier().Verify(v)
		if name != "padding" && naiveErr != nil {
			t.Errorf("%s: naive rejected (%v); expected a second valid encoding", name, naiveErr)
		}
		if !errors.Is(safeErr, ErrMalformed) {
			t.Errorf("%s: safe err = %v, want ErrMalformed", name, safeErr)
		}
	}
}

func TestDuplicateClaimNames(t *testing.T) {
	// The issuer built JSON by concatenation and signed it honestly; the
	// user-controlled part added a second "sub". encoding/json matches
	// names case-insensitively with Unicode folding and keeps the last one.
	for _, dup := range []string{`"sub":"admin"`, `"SUB":"admin"`, `"ſub":"admin"`} {
		claims := strings.TrimSuffix(payload("alice", now.Add(time.Hour)), "}") + "," + dup + "}"
		tok := raw(`{"alg":"EdDSA","kid":"ed1"}`, claims, edPriv)

		c, err := VerifyNaive(tok, edPub)
		if err != nil || c.Sub != "admin" {
			t.Errorf("%s: naive got %+v, %v; expected the last duplicate to win", dup, c, err)
		}
		if _, err := verifier().Verify(tok); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: safe err = %v, want ErrMalformed", dup, err)
		}
	}
}

func TestVerifier(t *testing.T) {
	ed := `{"alg":"EdDSA","kid":"ed1"}`
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"valid EdDSA", valid(), nil},
		{"valid HS256", raw(`{"alg":"HS256","kid":"hs1"}`, payload("bob", now.Add(time.Hour)), hsSecret), nil},
		{"expired within leeway", raw(ed, payload("alice", now.Add(-30*time.Second)), edPriv), nil},
		{"expired beyond leeway", raw(ed, payload("alice", now.Add(-2*time.Minute)), edPriv), ErrClaims},
		{"audience array", raw(ed, `{"iss":"https://issuer.example","aud":["web","api"],"exp":1900000000}`, edPriv), nil},
		{"wrong audience", raw(ed, `{"iss":"https://issuer.example","aud":"web","exp":1900000000}`, edPriv), ErrClaims},
		{"wrong issuer", raw(ed, `{"iss":"https://evil.example","aud":"api","exp":1900000000}`, edPriv), ErrClaims},
		{"missing exp", raw(ed, `{"iss":"https://issuer.example","aud":"api"}`, edPriv), ErrClaims},
		{"exp overflow", raw(ed, `{"iss":"https://issuer.example","aud":"api","exp":1e300}`, edPriv), ErrClaims},
		{"nbf in future", raw(ed, `{"iss":"https://issuer.example","aud":"api","exp":1900000000,"nbf":1800000000}`, edPriv), ErrClaims},
		{"alg none with kid", raw(`{"alg":"none","kid":"ed1"}`, payload("admin", now.Add(time.Hour)), nil), ErrAlgorithm},
		{"HS256 key used as EdDSA", raw(`{"alg":"EdDSA","kid":"hs1"}`, payload("admin", now.Add(time.Hour)), edPriv), ErrAlgorithm},
		{"unknown kid", raw(`{"alg":"EdDSA","kid":"../../dev/null"}`, payload("admin", now.Add(time.Hour)), edPriv), ErrKey},
		{"missing kid", raw(`{"alg":"EdDSA"}`, payload("alice", now.Add(time.Hour)), edPriv), ErrKey},
		{"wrong signing key", raw(ed, payload("admin", now.Add(time.Hour)), ed25519.NewKeyFromSeed(make([]byte, 32))), ErrSignature},
		{"crit header", raw(`{"alg":"EdDSA","kid":"ed1","crit":["exp"]}`, payload("alice", now.Add(time.Hour)), edPriv), ErrMalformed},
		{"four segments", valid() + ".x", ErrMalformed},
		{"tampered payload", strings.Replace(valid(), b64.EncodeToString([]byte(payload("alice", now.Add(time.Hour)))), b64.EncodeToString([]byte(payload("admin", now.Add(time.Hour)))), 1), ErrSignature},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier().Verify(tt.token)
			if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestShortHMACSecretRejected(t *testing.T) {
	v := verifier()
	v.Keys["weak"] = Key{Alg: "HS256", Secret: []byte("secret")}
	tok := raw(`{"alg":"HS256","kid":"weak"}`, payload("alice", now.Add(time.Hour)), []byte("secret"))
	if _, err := v.Verify(tok); !errors.Is(err, ErrKey) {
		t.Fatalf("err = %v, want ErrKey for a 48-bit secret", err)
	}
}

func TestSignRefusesMismatchedAlgorithm(t *testing.T) {
	if _, err := Sign("HS256", "ed1", Claims{}, edPriv); !errors.Is(err, ErrAlgorithm) {
		t.Fatalf("err = %v", err)
	}
}

func ExampleVerifier_Verify() {
	exp := float64(now.Add(time.Hour).Unix())
	tok, _ := Sign("EdDSA", "ed1", Claims{Iss: "https://issuer.example", Sub: "alice", Aud: Audience{"api"}, Exp: &exp}, edPriv)

	c, err := verifier().Verify(tok)
	fmt.Println(c.Sub, err)

	_, err = verifier().Verify(raw(`{"alg":"none","kid":"ed1"}`, payload("admin", now.Add(time.Hour)), nil))
	fmt.Println(err)
	// Output:
	// alice <nil>
	// jwt: algorithm not allowed for this key: token says "none", key "ed1" is pinned to "EdDSA"
}
