package hashing

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/maphash"
	"strconv"
	"testing"
)

// fnvCollision finds two distinct inputs with equal 32-bit FNV-1a keys by a
// plain birthday search over pseudo-random names. It is deterministic and
// needs on the order of 2^16 tries.
func fnvCollision(t *testing.T) (a, b []byte) {
	t.Helper()
	seen := make(map[uint32]string)
	for i := range 1 << 20 {
		r := sha256.Sum256([]byte(strconv.Itoa(i)))
		s := "invoice-" + hex.EncodeToString(r[:6]) + ".pdf"
		k := KeyUnsafe([]byte(s))
		if prev, ok := seen[k]; ok {
			return []byte(prev), []byte(s)
		}
		seen[k] = s
	}
	t.Fatal("no collision found")
	return nil, nil
}

func TestStoreUnsafeCollision(t *testing.T) {
	attacker, victim := fnvCollision(t)
	t.Logf("FNV-1a collision: %q and %q", attacker, victim)

	var s StoreUnsafe
	s.Put(attacker) // uploaded first
	k, stored := s.Put(victim)
	if stored {
		t.Fatal("expected the victim's upload to be de-duplicated")
	}
	if !bytes.Equal(s.Get(k), attacker) {
		t.Fatal("expected the victim's key to resolve to the attacker's blob")
	}
}

func TestStoreKeepsDistinctContent(t *testing.T) {
	a, b := fnvCollision(t)
	var s Store
	ida, _ := s.Put(a)
	idb, stored := s.Put(b)
	if !stored || ida == idb || !bytes.Equal(s.Get(idb), b) {
		t.Fatal("SHA-256 store confused two different blobs")
	}
	if _, stored := s.Put(b); stored {
		t.Fatal("identical content was not de-duplicated")
	}
}

// mdPad returns the SHA-256 padding for a message of n bytes: 0x80, zeros up
// to 56 mod 64, then the bit length as a 64-bit big-endian integer.
func mdPad(n int) []byte {
	pad := []byte{0x80}
	for (n+len(pad))%64 != 56 {
		pad = append(pad, 0)
	}
	return binary.BigEndian.AppendUint64(pad, uint64(n)*8)
}

// TestSHA256TagIsInternalState demonstrates the precondition of a length
// extension without performing one: after hashing key||msg||pad, the hash
// object's serialised chaining value is byte-for-byte the published tag. A
// tag from SignUnsafe is therefore a snapshot from which hashing can resume.
func TestSHA256TagIsInternalState(t *testing.T) {
	key := []byte("server-side-secret")
	msg := []byte("user=alice&role=viewer")
	tag := SignUnsafe(key, msg)

	h := sha256.New()
	h.Write(key)
	h.Write(msg)
	h.Write(mdPad(len(key) + len(msg)))
	state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Layout: 4-byte magic "sha\x03", eight 32-bit chaining words, ...
	if string(state[:4]) != "sha\x03" {
		t.Fatalf("unexpected state format %q", state[:4])
	}
	if !bytes.Equal(state[4:36], tag[:]) {
		t.Fatal("expected the tag to equal the chaining value")
	}

	hm := Sign(key, msg)
	if bytes.Equal(state[4:36], hm) {
		t.Fatal("HMAC tag must not equal the plain chaining value")
	}
}

func TestSignVerify(t *testing.T) {
	key := []byte("server-side-secret")
	msg := []byte("user=alice&role=viewer")
	tag := Sign(key, msg)
	if !Verify(key, msg, tag) {
		t.Fatal("valid tag rejected")
	}
	ext := append(append(append([]byte{}, msg...), mdPad(len(key)+len(msg))...), "&role=admin"...)
	for _, tt := range []struct {
		name string
		key  []byte
		msg  []byte
	}{
		{"other key", []byte("other"), msg},
		{"extended message", key, ext},
		{"modified message", key, []byte("user=alice&role=admin")},
	} {
		if Verify(tt.key, tt.msg, tag) {
			t.Errorf("%s: tag accepted", tt.name)
		}
	}
}

func TestKnownAnswers(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"SHA-256(abc)", sum(sha256.Sum256([]byte("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"SHA3-256('')", sum(sha3.Sum256(nil)), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
	}
	for _, tt := range tests {
		if hex.EncodeToString(tt.got) != tt.want {
			t.Errorf("%s = %x", tt.name, tt.got)
		}
	}
}

func sum(b [32]byte) []byte { return b[:] }

// TestMaphashIsPerProcess: hash/maphash is seeded randomly, so its values are
// neither stable across processes (useless as content IDs) nor secret-keyed
// in a way that makes them MACs. It is a hash-table hash.
func TestMaphashIsPerProcess(t *testing.T) {
	data := []byte("invoice-1.pdf")
	a := maphash.Bytes(maphash.MakeSeed(), data)
	b := maphash.Bytes(maphash.MakeSeed(), data)
	if a == b { // probability 2^-64
		t.Fatal("two independently seeded maphash values agree")
	}
}

func ExampleContentID() {
	fmt.Println(ContentID([]byte("abc")))
	fmt.Printf("%08x\n", KeyUnsafe([]byte("abc")))
	// Output:
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	// 1a47e90b
}
