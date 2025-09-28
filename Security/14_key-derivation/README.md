# 14. Key Derivation & Separation

> **Abstract.** Most systems start from one high-entropy secret and need many keys: record encryption, MAC keys, cookie keys, one key per tenant. HKDF (RFC 5869, `crypto/hkdf` since Go 1.24) turns one secret into any number of independent keys, but only if the `info` string is a fixed, unambiguous description of **what the key is for**. The failures are not in HKDF; they are in reusing one key for two algorithms (whoever can verify can decrypt), in letting user-controlled strings become labels (a tenant named `webhook-mac` gets the webhook key), and in feeding passwords to a KDF that has no work factor.

| | |
|---|---|
| Weaknesses | [CWE-320](https://cwe.mitre.org/data/definitions/320.html) Key Management Errors, [CWE-323](https://cwe.mitre.org/data/definitions/323.html) Reusing a Nonce, Key Pair in Encryption, [CWE-916](https://cwe.mitre.org/data/definitions/916.html) Use of Password Hash With Insufficient Computational Effort |
| Go packages | `crypto/hkdf` (1.24), `crypto/hmac`, `crypto/sha256`, `crypto/cipher` |
| Code | [`kdf.go`](kdf.go), [`kdf_test.go`](kdf_test.go) |

## 1. Threat model

A service holds one master secret (from a KMS, a sealed config, or a key exchange). It derives keys for several algorithms and hands some of them out: a webhook verification key to a partner, a per-tenant key for client-side encryption, a key to a sidecar. The attacker is one of those recipients, or controls an input to derivation (a tenant name, a user ID). They want a key they were not given.

## 2. What the standard library provides

`crypto/hkdf` (promoted from `x/crypto/hkdf` in Go 1.24) is generic over the hash:

| Function | RFC 5869 step | Use |
|---|---|---|
| `hkdf.Extract(h, secret, salt)` | Extract | Concentrate a non-uniform secret (ECDH output) into a pseudorandom key (PRK) |
| `hkdf.Expand(h, prk, info, n)` | Expand | Derive `n` bytes for one purpose; `info` is the domain separator |
| `hkdf.Key(h, secret, salt, info, n)` | Both | One-shot |

`info` is a `string`; `n` is limited to 255 × hash size. In `GODEBUG=fips140=only` mode the secret must be at least 112 bits and the hash SHA-2 or SHA-3 (chapter 17). `TestHKDFRFC5869Vector` checks the package against RFC 5869 test case 1.

Two properties drive the design below:

- Different `info` values give **computationally independent** keys; learning one says nothing about another.
- Same `info`, different length: the shorter output is a **prefix** of the longer one (`TestExpandOutputsArePrefixesWithoutLengthInInfo`). Encode the length in `info`, as TLS 1.3's `HkdfLabel` does.

## 3. Insecure pattern

**One key, two algorithms.** [`SharedKeyUnsafe`](kdf.go) uses the same 32 bytes for AES-GCM records and HMAC-SHA256 webhook signatures. HMAC verification needs the signing key, so the partner who verifies webhooks receives it, and `TestSharedKeyLetsWebhookPartnerDecrypt` shows that partner opening a stored record. Even with no key distribution, one key in two algorithms breaks the independence assumption both security proofs rely on.

**User input as the label.** [`SystemKeyUnsafe`](kdf.go) and [`TenantKeyUnsafe`](kdf.go) both pass a bare string as `info`:

```go
hkdf.Key(sha256.New, master, nil, "webhook-mac", 32) // system key
hkdf.Key(sha256.New, master, nil, tenantID, 32)      // tenant key; tenantID chosen at signup
```

A tenant registering `webhook-mac` is issued the system webhook key and can sign payout events (`TestTenantIDCollidesWithSystemLabel`). Plain concatenation (`purpose + tenantID`) has the same flaw with one extra step.

**Passwords through HKDF.** [`KeyFromPasswordUnsafe`](kdf.go) derives a file key from a PIN with HKDF. HKDF adds no cost per guess: `TestHKDFOverPINFallsToExhaustiveSearch` tries all 10 000 PINs against a stolen ciphertext in well under a second, even under the race detector.

## 4. Secure pattern

[`Keyring`](kdf.go) runs Extract once and Expand per key:

```go
kr, _ := kdf.NewKeyring(master, []byte("app-salt-v1"))
enc, _ := kr.Key(kdf.RecordEncryption)
mac, _ := kr.Key(kdf.WebhookMAC)
acme, _ := kr.Key(kdf.TenantEncryption, "acme")
```

1. **Purposes are a closed set.** `Purpose` has unexported fields, so only the package's declared values exist; a label names one algorithm (`record-enc/aes-256-gcm`). User data can only appear as context, never as the label.
2. **Info is an unambiguous encoding**: output length, then length-prefixed `domain`, `label` and each context value ([`Info`](kdf.go)). `("ab","c")` and `("a","bc")`, or a tenant called `webhook-mac/hmac-sha256`, all produce distinct keys (`TestKeyringSeparatesPurposesAndTenants`).
3. **A domain string with a version** (`.../kdf/v1`) lets the scheme change without colliding with old keys. Put a key version in the context to rotate one purpose without touching the others.
4. **Derivation is deterministic**, so per-tenant keys need no storage: re-derive on demand from the master.
5. **Salt**: optional when the master is already uniformly random; when it is a Diffie-Hellman output, use a fixed, application-specific salt (or the protocol transcript, chapter 16).
6. **Passwords** go through Argon2id or PBKDF2 first (chapter 12); HKDF may expand that output into several keys.

## 5. Where the protection ends

- **The master secret is a single point of failure.** Every derived key falls with it. Keep it in a KMS/HSM and derive inside, or hold only derived keys in the application.
- **Rotation is not free.** A new master changes every derived key; data must be re-encrypted, or each ciphertext must carry the key version used.
- **HKDF does not hide low entropy.** A 6-digit code, a timestamp or a UUIDv1 as `secret` stays guessable.
- **Context is not secret.** Tenant IDs in `info` are fine; secrets belong in the `secret` argument.
- **Asymmetric keys** follow the same rule: one key pair, one purpose. Do not sign and decrypt with the same RSA key, or sign two protocols' messages with one key unless the signed bytes carry a context string (chapter 15).

## 6. Verification

```bash
go test -race -v ./Security/14_key-derivation/
```

| Test | Shows |
|---|---|
| `TestHKDFRFC5869Vector` | `crypto/hkdf` Extract/Expand match RFC 5869 A.1 |
| `TestSharedKeyLetsWebhookPartnerDecrypt` | The holder of the "verification" key decrypts stored data |
| `TestSeparatedKeysContainPartnerCompromise` | With derived keys the webhook key cannot open records |
| `TestTenantIDCollidesWithSystemLabel` | A tenant ID equal to a system label yields the system key |
| `TestKeyringSeparatesPurposesAndTenants` | Purposes, tenants, label-shaped tenant IDs and split contexts all give distinct keys |
| `TestKeyringIsDeterministic` | Keys can be re-derived instead of stored |
| `TestExpandOutputsArePrefixesWithoutLengthInInfo` | Expand outputs share prefixes unless the length is in `info` |
| `TestShortMasterRejected` | Sub-256-bit masters and the zero `Purpose` are refused |
| `TestHKDFOverPINFallsToExhaustiveSearch` | HKDF over a PIN is brute-forced in milliseconds |

## 7. Checklist

- [ ] Every key is used by exactly one algorithm for one purpose.
- [ ] Keys handed to third parties are derived, never the master or a sibling key.
- [ ] HKDF `info` labels are constants; user data enters only as length-prefixed context.
- [ ] `info` encodes the output length and a scheme version.
- [ ] Passwords never reach HKDF without a password-hashing KDF first.
- [ ] Ciphertexts or tokens record which key version produced them.

## References

- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- H. Krawczyk — [Cryptographic Extraction and Key Derivation: The HKDF Scheme](https://eprint.iacr.org/2010/264) (CRYPTO 2010)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) section 7.1, `HKDF-Expand-Label`
- NIST [SP 800-108r1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) Key Derivation Using Pseudorandom Functions; [SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final) Key-Derivation Methods in Key-Establishment Schemes
- [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf), [Go 1.24 release notes](https://go.dev/doc/go1.24)
