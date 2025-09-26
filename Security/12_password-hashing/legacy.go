package passhash

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// HashSHA256Unsafe is the classic mistake: an unsalted fast hash. Equal
// passwords produce equal hashes across users and across breaches, so one
// precomputed table cracks all of them at once (CWE-759). SHA-256 is designed
// to be fast; a GPU computes billions per second (CWE-916).
func HashSHA256Unsafe(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// HashSaltedSHA256Unsafe adds a per-user salt. That defeats precomputation,
// but each guess still costs one SHA-256 call, so an offline dictionary attack
// on a leaked table runs at hardware speed. A salt is necessary, not
// sufficient (CWE-916).
func HashSaltedSHA256Unsafe(password string, salt []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// bcryptMaxInput is the number of key bytes bcrypt's Blowfish key schedule
// consumes. Everything after byte 72 is ignored by the algorithm itself.
const bcryptMaxInput = 72

// ErrTooLong is returned by the bcrypt helpers for inputs bcrypt cannot fully
// absorb.
var ErrTooLong = errors.New("passhash: input exceeds bcrypt's 72-byte limit")

// BcryptCacheKeyUnsafe hashes a composite "userID:username:password" string,
// truncating it to 72 bytes because bcrypt.GenerateFromPassword in current
// x/crypto releases refuses longer input. With a long username the password
// falls outside the 72 bytes and stops mattering: the Okta AD/LDAP delegated
// authentication advisory (October 2024) was this construction.
func BcryptCacheKeyUnsafe(userID, username, password string, cost int) ([]byte, error) {
	in := []byte(userID + ":" + username + ":" + password)
	if len(in) > bcryptMaxInput {
		in = in[:bcryptMaxInput]
	}
	return bcrypt.GenerateFromPassword(in, cost)
}

// BcryptCompareUnsafe verifies a composite key with CompareHashAndPassword,
// which does not apply the 72-byte check: a longer candidate is compared on
// its first 72 bytes only.
func BcryptCompareUnsafe(hash []byte, userID, username, password string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(userID+":"+username+":"+password)) == nil
}

// BcryptHash hashes only the password and rejects input bcrypt would
// silently shorten. Policy should cap passwords at 72 bytes up front (UTF-8
// bytes, not characters) or use Argon2id, which has no such limit.
func BcryptHash(password string, cost int) ([]byte, error) {
	if len(password) > bcryptMaxInput {
		return nil, ErrTooLong
	}
	return bcrypt.GenerateFromPassword([]byte(password), cost)
}

// BcryptVerify applies the same limit on the verify path, which the library
// does not.
func BcryptVerify(hash []byte, password string) bool {
	if len(password) > bcryptMaxInput {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

// OWASPPBKDF2Iterations is the OWASP Password Storage Cheat Sheet figure for
// PBKDF2-HMAC-SHA256.
const OWASPPBKDF2Iterations = 600_000

// PBKDF2SHA256 uses crypto/pbkdf2 (standard library since Go 1.24). PBKDF2 is
// not memory-hard, so GPUs and ASICs attack it far more cheaply than Argon2id;
// it is the choice when a FIPS 140-3 boundary rules out Argon2id. In
// GODEBUG=fips140=only mode the standard library additionally rejects salts
// shorter than 128 bits and keys shorter than 112 bits.
func PBKDF2SHA256(password string, salt []byte, iter, keyLen int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, iter, keyLen)
}
