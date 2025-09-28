package kdf

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHKDFRFC5869Vector(t *testing.T) {
	// RFC 5869, Appendix A.1 (Basic test case with SHA-256).
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := unhex("000102030405060708090a0b0c")
	info := string(unhex("f0f1f2f3f4f5f6f7f8f9"))

	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"); !bytes.Equal(prk, want) {
		t.Fatalf("PRK = %x", prk)
	}
	okm, err := hkdf.Expand(sha256.New, prk, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if want := unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"); !bytes.Equal(okm, want) {
		t.Fatalf("OKM = %x", okm)
	}
}

func TestSharedKeyLetsWebhookPartnerDecrypt(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	app := NewSharedKeyUnsafe(master)

	stored, err := SealRecord(app.EncryptionKey(), []byte("ssn=078-05-1120"))
	if err != nil {
		t.Fatal(err)
	}

	// The partner was given a key to verify webhook signatures, nothing more.
	partnerKey := app.WebhookVerificationKey()
	pt, err := OpenRecord(partnerKey, stored)
	if err != nil || string(pt) != "ssn=078-05-1120" {
		t.Fatalf("expected the partner to read the record: %q %v", pt, err)
	}
}

func TestSeparatedKeysContainPartnerCompromise(t *testing.T) {
	kr := newKeyring(t)
	encKey, _ := kr.Key(RecordEncryption)
	macKey, _ := kr.Key(WebhookMAC)

	stored, _ := SealRecord(encKey, []byte("ssn=078-05-1120"))
	if _, err := OpenRecord(macKey, stored); err == nil {
		t.Fatal("webhook key must not decrypt records")
	}
}

func TestTenantIDCollidesWithSystemLabel(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)

	systemWebhookKey, _ := SystemKeyUnsafe(master, "webhook-mac")
	// Self-service signup: the tenant picks its own ID, and the product lets
	// tenants export their key for client-side encryption.
	exported, _ := TenantKeyUnsafe(master, "webhook-mac")

	body := []byte(`{"event":"payout.completed","amount":100000}`)
	if !hmac.Equal(SignWebhook(exported, body), SignWebhook(systemWebhookKey, body)) {
		t.Fatal("expected the tenant to be able to forge system webhooks")
	}
}

func TestKeyringSeparatesPurposesAndTenants(t *testing.T) {
	kr := newKeyring(t)
	keys := map[string][]byte{}
	add := func(name string, p Purpose, ctx ...string) {
		k, err := kr.Key(p, ctx...)
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = k
	}
	add("record", RecordEncryption)
	add("webhook", WebhookMAC)
	add("cookie", CookieMAC)
	add("tenant acme", TenantEncryption, "acme")
	add("tenant globex", TenantEncryption, "globex")
	add("tenant named like a label", TenantEncryption, "webhook-mac/hmac-sha256")
	add("tenant ab|c", TenantEncryption, "ab", "c")
	add("tenant a|bc", TenantEncryption, "a", "bc")

	seen := map[string]string{}
	for name, k := range keys {
		if len(k) != 32 {
			t.Errorf("%s: %d-byte key", name, len(k))
		}
		if other, dup := seen[string(k)]; dup {
			t.Errorf("%s and %s derived the same key", name, other)
		}
		seen[string(k)] = name
	}
}

func TestKeyringIsDeterministic(t *testing.T) {
	master := make([]byte, 32)
	rand.Read(master)
	a, _ := NewKeyring(master, []byte("app-salt-v1"))
	b, _ := NewKeyring(master, []byte("app-salt-v1"))
	ka, _ := a.Key(TenantEncryption, "acme")
	kb, _ := b.Key(TenantEncryption, "acme")
	if !bytes.Equal(ka, kb) {
		t.Fatal("same master, salt, purpose and context must give the same key")
	}
}

func TestExpandOutputsArePrefixesWithoutLengthInInfo(t *testing.T) {
	prk := make([]byte, 32)
	rand.Read(prk)
	short, _ := hkdf.Expand(sha256.New, prk, "session", 16)
	long, _ := hkdf.Expand(sha256.New, prk, "session", 32)
	if !bytes.Equal(short, long[:16]) {
		t.Fatal("HKDF-Expand with equal info should produce prefix-related outputs")
	}
	// Info() encodes the length, so two purposes differing only in size could
	// not produce related keys.
	if Info(Purpose{"x", 16}) == Info(Purpose{"x", 32}) {
		t.Fatal("Info must encode the output length")
	}
}

func TestShortMasterRejected(t *testing.T) {
	if _, err := NewKeyring(make([]byte, 16), nil); !errors.Is(err, ErrShortSecret) {
		t.Fatalf("err = %v, want ErrShortSecret", err)
	}
	var zero Purpose
	if _, err := newKeyring(t).Key(zero); err == nil {
		t.Fatal("zero Purpose must be rejected")
	}
}

func TestHKDFOverPINFallsToExhaustiveSearch(t *testing.T) {
	key, _ := KeyFromPasswordUnsafe("4831")
	stolen, _ := SealRecord(key, []byte("backup archive"))

	// 10 000 candidates, two HMACs and one GCM open each: milliseconds.
	for i := range 10_000 {
		pin := fmt.Sprintf("%04d", i)
		k, _ := KeyFromPasswordUnsafe(pin)
		if _, err := OpenRecord(k, stolen); err == nil {
			if pin != "4831" {
				t.Fatalf("wrong PIN %s opened the record", pin)
			}
			return
		}
	}
	t.Fatal("exhaustive search should have found the PIN")
}

func newKeyring(t *testing.T) *Keyring {
	t.Helper()
	master := make([]byte, 32)
	rand.Read(master)
	kr, err := NewKeyring(master, []byte("app-salt-v1"))
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func ExampleInfo() {
	fmt.Printf("%q\n", Info(TenantEncryption, "acme"))
	// Output:
	// "\x00 \x00\x00\x00&github.com/gunh0/to-be-a-gopher/kdf/v1\x00\x00\x00\x16tenant-enc/aes-256-gcm\x00\x00\x00\x04acme"
}
