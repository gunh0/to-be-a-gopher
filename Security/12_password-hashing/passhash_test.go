package passhash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testParams keep Argon2id fast under -race. They are below every production
// recommendation and exist only so the tests finish in milliseconds.
var testParams = Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestUnsaltedHashIsIdenticalAcrossUsers(t *testing.T) {
	alice := HashSHA256Unsafe("Summer2025!")
	bob := HashSHA256Unsafe("Summer2025!")
	if alice != bob {
		t.Fatal("expected identical hashes for identical passwords")
	}
	// A table built once, before the breach, answers instantly.
	table := map[string]string{}
	for _, guess := range []string{"123456", "password", "Summer2025!", "qwerty"} {
		table[HashSHA256Unsafe(guess)] = guess
	}
	if table[alice] != "Summer2025!" {
		t.Fatal("precomputed lookup should recover the password")
	}
}

func TestSaltedFastHashFallsToDictionary(t *testing.T) {
	salt := []byte("per-user-salt-01")
	leaked := HashSaltedSHA256Unsafe("letmein42", salt)

	// One SHA-256 per guess: the whole dictionary costs microseconds here and
	// billions of guesses per second on a GPU.
	var found string
	for i := range 100_000 {
		guess := fmt.Sprintf("letmein%d", i)
		if HashSaltedSHA256Unsafe(guess, salt) == leaked {
			found = guess
			break
		}
	}
	if found != "letmein42" {
		t.Fatalf("dictionary attack failed: %q", found)
	}
}

func TestArgon2idRoundTripAndUniqueSalt(t *testing.T) {
	h1, err := Hash("correct horse", testParams)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := Hash("correct horse", testParams)
	if h1 == h2 {
		t.Fatal("same password produced the same encoded hash: salt is not random")
	}
	if !strings.HasPrefix(h1, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected PHC prefix: %s", h1)
	}
	for _, tt := range []struct {
		pw   string
		want bool
	}{{"correct horse", true}, {"correct horsf", false}, {"", false}} {
		ok, _, err := Verify(tt.pw, h1, testParams)
		if err != nil || ok != tt.want {
			t.Errorf("Verify(%q) = %v, %v; want %v", tt.pw, ok, err, tt.want)
		}
	}
}

func TestParseRejectsMalformedAndAbusiveHashes(t *testing.T) {
	good, err := Hash("pw", testParams)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Split(good, "$")
	salt, key := f[4], f[5]
	bad := map[string]string{
		"argon2i":          "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"old version":      "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"reordered":        "$argon2id$v=19$t=1,m=64,p=1$" + salt + "$" + key,
		"leading zero":     "$argon2id$v=19$m=064,t=1,p=1$" + salt + "$" + key,
		"4 GiB memory":     "$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + key,
		"zero passes":      "$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"padded base64":    "$argon2id$v=19$m=64,t=1,p=1$" + salt + "==$" + key,
		"short salt":       "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$" + key,
		"extra field":      good + "$x",
		"missing hash":     "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"m below 8*p":      "$argon2id$v=19$m=8,t=1,p=4$" + salt + "$" + key,
		"empty":            "",
		"bcrypt hash here": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
	}
	for name, enc := range bad {
		if _, _, _, err := Parse(enc); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%s: err = %v, want ErrMalformedHash", name, err)
		}
	}
}

func TestLoginRehashesOutdatedParams(t *testing.T) {
	old := testParams
	stored, err := Hash("hunter2", old)
	if err != nil {
		t.Fatal(err)
	}
	policy := testParams
	policy.Time = 2 // policy was raised after this hash was written

	ok, upgraded, err := Login("hunter2", stored, policy)
	if err != nil || !ok || upgraded == "" {
		t.Fatalf("Login = %v, %q, %v; want ok with a new hash", ok, upgraded, err)
	}
	p, _, _, err := Parse(upgraded)
	if err != nil || p.Time != 2 {
		t.Fatalf("upgraded hash params = %+v, %v", p, err)
	}

	// Already at policy: nothing to write.
	if ok, again, _ := Login("hunter2", upgraded, policy); !ok || again != "" {
		t.Fatalf("second login rehashed again: %q", again)
	}
	// Wrong password never triggers a rehash.
	if ok, again, _ := Login("wrong", stored, policy); ok || again != "" {
		t.Fatal("wrong password produced a rehash")
	}
}

func TestBcryptTruncationMakesPasswordIrrelevant(t *testing.T) {
	user := "00u1a2b3c4"
	username := "firstname.lastname@international-subsidiary.example-corporation.com" // 67 bytes
	key, err := BcryptCacheKeyUnsafe(user, username, "the-real-password", bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !BcryptCompareUnsafe(key, user, username, "anything at all") {
		t.Fatal("expected an arbitrary password to match once it falls past byte 72")
	}
}

func TestBcryptSafeRejectsOverlongInput(t *testing.T) {
	long := strings.Repeat("a", 72)
	h, err := BcryptHash(long, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !BcryptVerify(h, long) {
		t.Fatal("72-byte password should verify")
	}
	// The library alone accepts a 73-byte candidate sharing the first 72 bytes.
	if bcrypt.CompareHashAndPassword(h, []byte(long+"X")) != nil {
		t.Fatal("expected CompareHashAndPassword to ignore byte 73")
	}
	if BcryptVerify(h, long+"X") {
		t.Fatal("BcryptVerify accepted a 73-byte password")
	}
	if _, err := BcryptHash(long+"X", bcrypt.MinCost); !errors.Is(err, ErrTooLong) {
		t.Fatalf("err = %v, want ErrTooLong", err)
	}
	// 24 three-byte runes are 72 bytes: the limit is bytes, not characters.
	if _, err := BcryptHash(strings.Repeat("한", 25), bcrypt.MinCost); !errors.Is(err, ErrTooLong) {
		t.Fatalf("25 Hangul syllables (75 bytes): err = %v, want ErrTooLong", err)
	}
}

func TestPBKDF2KnownAnswer(t *testing.T) {
	// RFC 7914 section 11, PBKDF2-HMAC-SHA256, c=1.
	want, _ := hex.DecodeString("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
	got, err := PBKDF2SHA256("passwd", []byte("salt"), 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PBKDF2 = %x", got)
	}
}

func BenchmarkSaltedSHA256(b *testing.B) {
	salt := []byte("per-user-salt-01")
	for b.Loop() {
		HashSaltedSHA256Unsafe("letmein42", salt)
	}
}

func BenchmarkArgon2idOWASP(b *testing.B) {
	for b.Loop() {
		if _, err := Hash("letmein42", OWASPParams); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPBKDF2OWASP(b *testing.B) {
	salt := []byte("per-user-salt-01")
	for b.Loop() {
		if _, err := PBKDF2SHA256("letmein42", salt, OWASPPBKDF2Iterations, sha256.Size); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleParse() {
	p, salt, key, err := Parse("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$4oHbZlmJdz+5XlDjZaWWPkHH9gJcVDWzfDUz/I3vLv8")
	fmt.Println(p.Memory, p.Time, p.Threads, len(salt), len(key), err)
	// Output:
	// 19456 2 1 16 32 <nil>
}
