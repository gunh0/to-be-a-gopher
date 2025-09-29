# 15. Digital Signatures

> **Abstract.** Signature algorithms in Go's standard library are hard to misuse at the primitive level: ECDSA nonces are generated internally from the private key, the message and fresh entropy, Ed25519 is deterministic by construction, and verifiers reject zero and non-canonical values. What still breaks is everything around the primitive. A hand-rolled or hardware signer that repeats one ECDSA nonce gives away the private key from two signatures. ECDSA signatures are malleable, so they cannot serve as identifiers. And a verifier that reads the algorithm from the token, or parses before it verifies, lets the attacker pick `none` or turn a public key into an HMAC secret.

| | |
|---|---|
| Weaknesses | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) Improper Verification of Cryptographic Signature, [CWE-323](https://cwe.mitre.org/data/definitions/323.html) Reusing a Nonce, Key Pair in Encryption, [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm |
| Go packages | `crypto/ed25519`, `crypto/ecdsa`, `crypto/ecdh`, `crypto` (`SignMessage`, `MessageSigner`, 1.25) |
| Code | [`ecdsa.go`](ecdsa.go), [`token.go`](token.go), [`sigs_test.go`](sigs_test.go) |

## 1. Threat model

Signed artifacts (tokens, firmware, webhooks, release manifests) cross trust boundaries. The attacker sees signatures, can submit arbitrary tokens to verifiers and knows the public keys. In the nonce scenario the attacker also sees two signatures from a signer with a broken nonce source (an HSM firmware bug, a custom implementation, a VM snapshot replaying RNG state). They want to forge signatures, recover the signing key, or get a verifier to accept unsigned data.

## 2. What the standard library guarantees

| Algorithm | Nonce | Malleability | Verifier checks |
|---|---|---|---|
| Ed25519 (`crypto/ed25519`) | Derived from key and message (RFC 8032); no RNG at signing | `Verify` rejects S ≥ L | Strict 64-byte signature |
| ECDSA (`crypto/ecdsa`) | Hedged: entropy plus private key and digest through an HMAC-DRBG (Go 1.24+); `PrivateKey.Sign(nil, …)` gives RFC 6979 deterministic signatures | (r, s) and (r, n−s) both valid | r, s ∈ [1, n−1], strict DER |
| RSA (`crypto/rsa`) | PSS uses a random salt; PKCS #1 v1.5 is deterministic | n/a | v1.5 verification compares the full re-encoded block, so the Bleichenbacher 2006 e=3 forgery does not apply; keys < 1024 bits rejected since 1.24 |

ECDSA's internal nonce derivation means even a constant-output `rand` reader does not repeat nonces across different messages (`TestStdlibECDSANonceSurvivesBrokenRNG`). The precise construction is the "hedged" signing of draft-irtf-cfrg-det-sigs-with-noise, not RFC 6979, unless `rand` is nil.

Go 1.25 added `crypto.MessageSigner` and `crypto.SignMessage(signer, rand, msg, opts)`: if the signer can sign whole messages (a KMS or HSM that hashes on its side), it is asked to; otherwise the message is hashed with `opts.HashFunc()` and passed to `Signer.Sign`, and with `crypto.Hash(0)` it is passed unhashed, which is what Ed25519 needs. Code that accepts any `crypto.Signer` no longer needs a type switch to sign a message.

Choice for new designs: **Ed25519** unless a FIPS boundary or ecosystem dictates otherwise (Ed25519 is approved in FIPS 186-5); then ECDSA P-256, or RSA-PSS with ≥ 3072-bit keys. Prefer PSS over PKCS #1 v1.5 for new RSA designs: it has a security proof and no padding-parsing history.

## 3. Insecure pattern

**Nonce reuse.** [`SignWithNonceUnsafe`](ecdsa.go) is textbook ECDSA with a caller-supplied k (the standard library offers no such API; the fixture computes kG through `crypto/ecdh`). Its signatures pass `ecdsa.VerifyASN1`. Two of them with the same k give two linear equations in two unknowns:

```
s1 = k⁻¹(z1 + r·d)    s2 = k⁻¹(z2 + r·d)    (mod n)
k  = (z1 − z2)/(s1 − s2)
d  = (s1·k − z1)/r
```

[`RecoverKeyFromNonceReuse`](ecdsa.go) does that, and the test then signs "firmware v6.6.6" with the recovered key under the victim's public key. Sony's PS3 used a constant k (fail0verflow, 27C3, 2010). Lattice attacks extend this to nonces that are merely biased by a few bits across many signatures.

**Malleability.** [`MalleateECDSA`](ecdsa.go) turns (r, s) into (r, n−s), a different, valid signature without the key. A replay cache or a transaction ID keyed on signature bytes treats it as new (Bitcoin's transaction malleability, 2014).

**Letting the token choose.** [`VerifyTokenUnsafe`](token.go) parses the header, looks up key bytes by `kid`, and dispatches on `alg`:

```go
switch strings.ToLower(h.Alg) {
case "none":  // accepted
case "hs256": hmac.New(sha256.New, key)   // key is the issuer's PUBLIC key
case "eddsa": ed25519.Verify(key, signed, sig)
}
```

`alg: none` passes with no signature; `alg: HS256` passes with an HMAC keyed by the public key, which the attacker has. This is the 2015 JWT algorithm-confusion class (e.g. CVE-2015-9235).

## 4. Secure pattern

[`Verifier`](token.go) is configured with **one** Ed25519 public key and an audience. `Verify`:

1. Requires the header segment to equal the one fixed header byte for byte. The algorithm comes from configuration, never from the token; there is no `kid` lookup across algorithms.
2. Verifies the signature over the **raw transmitted bytes** `header.payload` before anything parses them.
3. Only then decodes the payload, rejecting unknown fields and trailing JSON, and checks `aud` and `exp` against an injected clock.

Rotation is a list of pinned Ed25519 keys, tried in turn, all of the same algorithm. [`Issue`](token.go) refuses non-Ed25519 signers and signs through `crypto.SignMessage`, so swapping an in-memory key for an HSM-backed `crypto.MessageSigner` needs no code change.

"Verify, then parse" also covers formats beyond JSON: X.509, ASN.1, protobuf. A parser running on unauthenticated input is attack surface, and verifying a re-serialisation instead of the received bytes lets two parsers disagree about what was signed.

For ECDSA, use `ecdsa.SignASN1(rand.Reader, …)` or the deterministic `priv.Sign(nil, digest, crypto.SHA256)`; never compute k yourself, and never use signature bytes as identifiers (hash the signed message instead, or normalise to low-s if a protocol requires it).

## 5. Where the guarantees end

- **External signers.** HSMs, KMSs, smart cards and other-language libraries generate their own nonces; Go's hedging protects only signatures Go computes.
- **What the signature covers.** A valid signature on `{"sub":"alice"}` says nothing about audience, expiry, or which protocol it was meant for. Put context (purpose string, audience, version) inside the signed bytes; reuse one key across protocols only with such a context (chapter 14).
- **Key distribution.** Pinning a key is only as good as the channel that delivered it: X.509 chains (chapter 19), mTLS identities (chapter 20).
- **Post-quantum signatures** (ML-DSA, FIPS 204) are not in the Go 1.25 standard library; chapter 16 covers the key-exchange side.

## 6. Verification

```bash
go test -race -v ./Security/15_digital-signatures/
```

| Test | Shows |
|---|---|
| `TestECDSANonceReuseRecoversPrivateKey` | Two valid signatures with one k yield d; the recovered key forges under the victim's public key |
| `TestStdlibECDSANonceSurvivesBrokenRNG` | With an all-zero `rand`, Go still uses distinct nonces per message; `Sign(nil, …)` is RFC 6979 deterministic |
| `TestEd25519IsDeterministic` | Same key and message, same signature |
| `TestECDSASignaturesAreMalleable` | (r, n−s) verifies and defeats a signature-keyed replay cache |
| `TestEd25519RejectsNonCanonicalS` | S + L is rejected |
| `TestECDSARejectsZeroSignature` | r = s = 0 (CVE-2022-21449 in Java) is rejected |
| `TestUnsafeVerifierAlgorithmConfusion` | `alg: none` and HS256-with-public-key forgeries pass the naive verifier |
| `TestPinnedVerifier` | The pinned verifier rejects both forgeries, other keys, expiry, wrong audience, payload swaps, extra fields and trailing JSON |
| `TestIssueRequiresEd25519` | The issuer refuses a key of the wrong algorithm |

## 7. Checklist

- [ ] The verifier's key and algorithm come from configuration; token headers are ignored or must match exactly.
- [ ] No `alg: none`, no symmetric/asymmetric algorithm mixing under one key ID.
- [ ] Signatures are verified over received bytes before parsing; parsing is strict.
- [ ] No hand-written ECDSA, no externally supplied nonce, no signature bytes used as IDs.
- [ ] Signed payloads include audience, expiry and a purpose/context string.
- [ ] New RSA designs use PSS; new designs generally use Ed25519.

## References

- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) Deterministic DSA and ECDSA; [draft-irtf-cfrg-det-sigs-with-noise](https://datatracker.ietf.org/doc/draft-irtf-cfrg-det-sigs-with-noise/)
- NIST [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) Digital Signature Standard
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) JSON Web Token Best Current Practices
- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235), [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449)
- fail0verflow — *Console Hacking 2010: PS3 Epic Fail*, 27th Chaos Communication Congress
- [`crypto.SignMessage`](https://pkg.go.dev/crypto#SignMessage), [Go 1.25 release notes](https://go.dev/doc/go1.25); [`ecdsa.PrivateKey.Sign`](https://pkg.go.dev/crypto/ecdsa#PrivateKey.Sign)
