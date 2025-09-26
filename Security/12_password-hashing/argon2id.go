// Package passhash contrasts fast hashes used for password storage with
// memory-hard Argon2id stored in the PHC string format, and shows the bcrypt
// and PBKDF2 details that still bite when those are required.
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id cost parameters. Memory is in KiB, as in RFC 9106
// and in the PHC string ("m=19456" is 19 MiB).
type Params struct {
	Memory  uint32 // m, KiB
	Time    uint32 // t, passes over memory
	Threads uint8  // p, lanes
	SaltLen int    // bytes
	KeyLen  int    // bytes
}

// OWASPParams is the OWASP Password Storage Cheat Sheet minimum for Argon2id:
// m=19 MiB, t=2, p=1. It is chosen over RFC 9106's "first recommended" option
// (t=1, p=4, m=2 GiB) because a login endpoint runs many hashes concurrently;
// 2 GiB per attempt turns the password check into a memory-exhaustion lever.
// RFC 9106's second option (t=3, p=4, m=64 MiB) is a reasonable step up when
// the hosts have the memory for it.
var OWASPParams = Params{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

// Limits applied when parsing a stored hash. The parameters in a PHC string
// drive how much memory and CPU Verify spends, so a hash imported from another
// system or written by an attacker with database access must not be able to
// demand gigabytes per login (CWE-400).
const (
	maxMemory  = 1 << 20 // 1 GiB in KiB
	maxTime    = 16
	minSaltLen = 16
	maxSaltLen = 64
	minKeyLen  = 16
	maxKeyLen  = 64
)

// ErrMalformedHash reports a stored hash that is not a well-formed argon2id
// PHC string within the accepted limits.
var ErrMalformedHash = errors.New("passhash: malformed or out-of-policy argon2id hash")

var b64 = base64.RawStdEncoding // PHC strings use unpadded standard base64.

// Hash derives an Argon2id hash with a fresh random salt and encodes it as a
// PHC string: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>.
func Hash(password string, p Params) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(p.KeyLen))
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify checks password against a stored PHC string. needsRehash is true when
// the password matched but the stored parameters differ from policy, so the
// caller can re-hash while it still holds the plaintext (the only moment it
// can). The comparison is constant-time.
func Verify(password, encoded string, policy Params) (ok, needsRehash bool, err error) {
	p, salt, want, err := Parse(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = p.Memory != policy.Memory || p.Time != policy.Time ||
		p.Threads != policy.Threads || len(salt) != policy.SaltLen || len(want) != policy.KeyLen
	return true, needsRehash, nil
}

// Parse decodes a PHC string strictly: exact field count, the argon2id
// algorithm identifier, version 19, parameters in m,t,p order and within
// limits, and canonical unpadded base64.
func Parse(encoded string) (p Params, salt, key []byte, err error) {
	f := strings.Split(encoded, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" || f[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, ErrMalformedHash
	}
	m, t, th, ok := parseMTP(f[3])
	if !ok {
		return p, nil, nil, ErrMalformedHash
	}
	if salt, err = b64.Strict().DecodeString(f[4]); err != nil {
		return p, nil, nil, ErrMalformedHash
	}
	if key, err = b64.Strict().DecodeString(f[5]); err != nil {
		return p, nil, nil, ErrMalformedHash
	}
	p = Params{Memory: m, Time: t, Threads: th, SaltLen: len(salt), KeyLen: len(key)}
	if p.validate() != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	return p, salt, key, nil
}

func parseMTP(s string) (m, t uint32, p uint8, ok bool) {
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	vals := [3]uint64{}
	for i, name := range []string{"m=", "t=", "p="} {
		num, found := strings.CutPrefix(parts[i], name)
		if !found {
			return 0, 0, 0, false
		}
		v, err := strconv.ParseUint(num, 10, 32)
		if err != nil || strconv.FormatUint(v, 10) != num { // reject "+1", "01"
			return 0, 0, 0, false
		}
		vals[i] = v
	}
	if vals[2] == 0 || vals[2] > 255 {
		return 0, 0, 0, false
	}
	return uint32(vals[0]), uint32(vals[1]), uint8(vals[2]), true
}

func (p Params) validate() error {
	switch {
	case p.Time < 1 || p.Time > maxTime,
		p.Threads < 1,
		p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory, // RFC 9106: m >= 8p
		p.SaltLen < minSaltLen || p.SaltLen > maxSaltLen,
		p.KeyLen < minKeyLen || p.KeyLen > maxKeyLen:
		return fmt.Errorf("%w: parameters %+v outside limits", ErrMalformedHash, p)
	}
	return nil
}

// Login is the rehash-on-login flow: verify against the stored hash and, when
// the stored parameters are outdated, return a replacement hash to persist.
// newHash is empty when nothing needs to be written.
func Login(password, stored string, policy Params) (ok bool, newHash string, err error) {
	ok, rehash, err := Verify(password, stored, policy)
	if err != nil || !ok || !rehash {
		return ok, "", err
	}
	newHash, err = Hash(password, policy)
	return true, newHash, err
}
