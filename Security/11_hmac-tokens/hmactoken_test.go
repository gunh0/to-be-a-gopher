package hmactoken

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var (
	t0      = time.Date(2025, 9, 9, 12, 0, 0, 0, time.UTC)
	master1 = Key{ID: "k1", Secret: bytes.Repeat([]byte{0x11}, 32)}
	master2 = Key{ID: "k2", Secret: bytes.Repeat([]byte{0x22}, 32)}
)

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

func signer(t *testing.T, purpose string, active Key, prev ...Key) *Signer {
	t.Helper()
	s, err := NewSigner(purpose, active, prev...)
	if err != nil {
		t.Fatal(err)
	}
	s.Clock = clock(t0)
	return s
}

func TestUnsignedTokenIsForgeable(t *testing.T) {
	tok := EncodeUnsigned(UnsignedClaims{Subject: "alice", Expires: t0.Unix()})

	// The client decodes, edits and re-encodes. No key involved.
	c, _ := DecodeUnsigned(tok)
	c.Admin = true
	c.Expires = t0.AddDate(10, 0, 0).Unix()
	forged := EncodeUnsigned(c)

	got, err := DecodeUnsigned(forged)
	if err != nil || !got.Admin {
		t.Fatalf("expected the edited token to be accepted: %+v %v", got, err)
	}
}

func TestAmbiguousMACForgery(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 32)
	issued := time.Unix(1_760_000_000, 0).Add(-time.Hour)

	// The attacker registers as "bob1" and requests a token valid for 1h.
	own := SignAmbiguous(key, "bob1", issued.Add(time.Hour))
	parts := strings.Split(own, "|") // ["bob1", "1760000000", tag]

	// Move the trailing "1" from the user name into the expiry.
	forged := "bob|1" + parts[1] + "|" + parts[2]

	user, err := VerifyAmbiguous(key, forged, issued.AddDate(100, 0, 0))
	if err != nil || user != "bob" {
		t.Fatalf("expected a forged token for bob valid a century later: %q %v", user, err)
	}
}

func TestSignerRoundTrip(t *testing.T) {
	s := signer(t, "password-reset", master1)
	tok, err := s.Issue("alice@example.com", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(tok)
	if err != nil || c.Subject != "alice@example.com" || !c.Expires.Equal(t0.Add(15*time.Minute)) {
		t.Fatalf("Verify = %+v, %v", c, err)
	}
	if strings.ContainsAny(tok, "+/= ") {
		t.Fatalf("token is not URL-safe: %s", tok)
	}
}

func TestSignerRejectsTampering(t *testing.T) {
	s := signer(t, "password-reset", master1)
	tok, _ := s.Issue("alice@example.com", 15*time.Minute)
	other, _ := s.Issue("mallory@example.com", 24*time.Hour)
	p := strings.Split(tok, ".")
	q := strings.Split(other, ".")

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}

	cases := map[string]string{
		"payload byte changed":  p[0] + "." + p[1] + "." + flip(p[2], 3) + "." + p[3],
		"payload swapped":       p[0] + "." + p[1] + "." + q[2] + "." + p[3],
		"tag swapped":           p[0] + "." + p[1] + "." + p[2] + "." + q[3],
		"unknown key ID":        p[0] + ".k9." + p[2] + "." + p[3],
		"version changed":       "v2." + p[1] + "." + p[2] + "." + p[3],
		"tag truncated":         tok[:len(tok)-2],
		"extra segment":         tok + ".x",
		"tag missing":           p[0] + "." + p[1] + "." + p[2],
		"empty":                 "",
		"unsigned JSON":         EncodeUnsigned(UnsignedClaims{Subject: "alice@example.com"}),
		"ambiguous-format MAC":  SignAmbiguous(master1.Secret, "alice@example.com", t0.Add(time.Hour)),
		"padding added to tag":  tok + "=",
		"whitespace around tag": tok + " ",
	}
	for name, forged := range cases {
		if _, err := s.Verify(forged); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestSignerExpiryAfterMAC(t *testing.T) {
	s := signer(t, "password-reset", master1)
	tok, _ := s.Issue("alice@example.com", 15*time.Minute)

	s.Clock = clock(t0.Add(14 * time.Minute))
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	s.Clock = clock(t0.Add(15 * time.Minute))
	if _, err := s.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}

	// An expired token with a forged far-future payload is reported as
	// invalid, not as expired or valid: the expiry is never read from
	// unauthenticated bytes.
	p := strings.Split(tok, ".")
	future, _ := signer(t, "password-reset", master2).Issue("alice@example.com", 365*24*time.Hour)
	forged := p[0] + "." + p[1] + "." + strings.Split(future, ".")[2] + "." + p[3]
	if _, err := s.Verify(forged); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestPurposeSeparation(t *testing.T) {
	session := signer(t, "session", master1)
	reset := signer(t, "password-reset", master1) // same master secret

	tok, _ := session.Issue("alice@example.com", time.Hour)
	if _, err := reset.Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("session token accepted as a reset token: %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	old := signer(t, "session", master1)
	tokOld, _ := old.Issue("alice@example.com", time.Hour)

	rotating := signer(t, "session", master2, master1) // k2 active, k1 still verifies
	if _, err := rotating.Verify(tokOld); err != nil {
		t.Fatalf("token from the previous key rejected during rotation: %v", err)
	}
	tokNew, _ := rotating.Issue("alice@example.com", time.Hour)
	if !strings.HasPrefix(tokNew, "v1.k2.") {
		t.Fatalf("new token not issued with the active key: %s", tokNew)
	}

	retired := signer(t, "session", master2) // k1 removed
	if _, err := retired.Verify(tokOld); !errors.Is(err, ErrInvalid) {
		t.Fatalf("token from a retired key accepted: %v", err)
	}
	if _, err := retired.Verify(tokNew); err != nil {
		t.Fatal(err)
	}
}

func TestStrictBase64(t *testing.T) {
	s := signer(t, "session", master1)
	tok, _ := s.Issue("alice@example.com", time.Hour)

	// A 32-byte tag is 43 characters carrying 258 bits: the last character
	// has 2 unused bits. Setting one gives a different string with the same
	// bytes under lenient decoding.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, tok[len(tok)-1])
	variant := tok[:len(tok)-1] + string(alphabet[last^1])

	a, err1 := base64.RawURLEncoding.DecodeString(tok[strings.LastIndexByte(tok, '.')+1:])
	b, err2 := base64.RawURLEncoding.DecodeString(variant[strings.LastIndexByte(variant, '.')+1:])
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		t.Fatalf("expected lenient decoding to accept both spellings: %v %v", err1, err2)
	}
	if _, err := s.Verify(variant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical spelling accepted: %v", err)
	}
}

func TestNewSignerValidation(t *testing.T) {
	for name, keys := range map[string][]Key{
		"short secret":  {{ID: "k1", Secret: []byte("short")}},
		"empty ID":      {{ID: "", Secret: master1.Secret}},
		"dot in ID":     {{ID: "k.1", Secret: master1.Secret}},
		"duplicate IDs": {master1, master1},
	} {
		if _, err := NewSigner("session", keys[0], keys[1:]...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := signer(t, "session", master1)
	if _, err := s.Issue("", time.Hour); err == nil {
		t.Error("empty subject accepted")
	}
}

func ExampleSigner() {
	s, _ := NewSigner("password-reset", Key{ID: "k1", Secret: bytes.Repeat([]byte{0x11}, 32)})
	s.Clock = func() time.Time { return time.Date(2025, 9, 9, 12, 0, 0, 0, time.UTC) }

	tok, _ := s.Issue("alice@example.com", 15*time.Minute)
	c, err := s.Verify(tok)
	fmt.Println(c.Subject, c.Expires.UTC().Format(time.RFC3339), err)

	_, err = s.Verify(tok[:len(tok)-1] + "A")
	fmt.Println(err)
	// Output:
	// alice@example.com 2025-09-09T12:15:00Z <nil>
	// hmactoken: invalid token
}
