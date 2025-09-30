# 16. Post-Quantum Key Exchange

> **Abstract.** Encrypted traffic recorded today can be decrypted later by anyone who eventually breaks its key exchange; for X25519 and ECDH that is a large enough quantum computer. Go 1.24 made the hybrid X25519MLKEM768 group the default in `crypto/tls` and shipped `crypto/mlkem` (FIPS 203), so a Go 1.24+ client and server already agree on a post-quantum key without configuration. The usual way to lose that is configuration: an explicit `CurvePreferences` list copied from an older hardening guide replaces the default and silently falls back to X25519. For protocols outside TLS, a hybrid KEM has to hash **both** shared secrets **and** the transcript, and must not treat a successful ML-KEM decapsulation as proof of anything.

| | |
|---|---|
| Weaknesses | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm, [CWE-326](https://cwe.mitre.org/data/definitions/326.html) Inadequate Encryption Strength |
| Go packages | `crypto/mlkem` (1.24), `crypto/tls` (`X25519MLKEM768` 1.24, `ConnectionState.CurveID` 1.25), `crypto/ecdh`, `crypto/sha3` (1.24) |
| Code | [`hybrid.go`](hybrid.go), [`tlsconfig.go`](tlsconfig.go), [`pqkem_test.go`](pqkem_test.go) |

## 1. Threat model

A passive adversary records TLS or application-level key exchanges now ("harvest now, decrypt later") and stores them until a cryptographically relevant quantum computer can solve the elliptic-curve discrete logarithm. Anything whose confidentiality must outlive that date is at risk today: health records, long-lived secrets, government and financial data. Authentication is not retroactively breakable this way; key exchange is, which is why key exchange migrates first.

## 2. What Go provides

| Version | Change |
|---|---|
| 1.23 | `X25519Kyber768Draft00` enabled by default in `crypto/tls` (pre-standard) |
| 1.24 | `crypto/mlkem`: ML-KEM-768 and ML-KEM-1024 (FIPS 203). `crypto/tls` switches the default to the standardised hybrid `X25519MLKEM768` (codepoint 0x11EC) and removes the Kyber draft. `crypto/sha3` in the standard library |
| 1.25 | `tls.ConnectionState.CurveID` reports the negotiated group, so PQ coverage can be measured |

Default key-exchange preference in Go 1.25 when `CurvePreferences` is nil: X25519MLKEM768, X25519, P-256, P-384, P-521. Hybrid groups exist only in TLS 1.3. The client key share grows by 1 184 bytes (ML-KEM-768 encapsulation key) and the server's by 1 088 bytes (ciphertext), so the ClientHello no longer fits one packet; some middleboxes mishandle that, which is why the escape hatch exists:

- `GODEBUG=tlsmlkem=0` (environment, `godebug` line in `go.mod`, or `//go:debug tlsmlkem=0` in package main) restores the pre-1.24 default.
- An explicit `Config.CurvePreferences` list. Its **order is ignored**; Go applies its own preference among the listed groups.

In FIPS 140-3 mode (chapter 17) X25519MLKEM768 remains allowed, alongside the NIST curves; X25519 alone does not.

`mlkem` API in one line: `dk, _ := mlkem.GenerateKey768(); ss, ct := dk.EncapsulationKey().Encapsulate(); ss2, _ := dk.Decapsulate(ct)`.

## 3. Insecure pattern

[`ClassicalCurvesUnsafe`](tlsconfig.go):

```go
&tls.Config{
	MinVersion:       tls.VersionTLS12,
	CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, // "disable weak curves"
}
```

Before 1.24 this was harmless. Since 1.24 it is a downgrade: both peers support X25519MLKEM768 but the server will not select it, the handshake completes with X25519, and nothing is logged (`TestExplicitClassicalCurvesDisablePQ`).

Two assumptions fail in hand-built protocols:

- **"Decapsulate returned no error, so the ciphertext is authentic."** ML-KEM uses implicit rejection: a modified ciphertext yields a pseudorandom, wrong key and `err == nil` (`TestMLKEMImplicitRejection`). Tampering shows up only when the key is used.
- **"XOR or concatenate the two secrets."** `ssM ⊕ ssX` (or `H(ssM ‖ ssX)`) keeps passive secrecy if either secret is strong, but the result does not depend on which ciphertexts or public keys produced it. X25519 on its own is not an IND-CCA KEM, so without the transcript the hybrid does not inherit ML-KEM's chosen-ciphertext security (Giacon, Heuer, Poettering 2018).

## 4. Secure pattern

**TLS.** Leave `CurvePreferences` nil ([`DefaultConfig`](tlsconfig.go)) and let PQ coverage improve with each Go release. Measure it: `resp.TLS.CurveID == tls.X25519MLKEM768` ([`IsPostQuantum`](tlsconfig.go)), exported as a metric per client population. Where both ends are known to be hybrid-capable (internal service mesh), [`PQOnlyConfig`](tlsconfig.go) pins TLS 1.3 and `X25519MLKEM768` so a classical-only peer fails the handshake instead of silently downgrading.

**Custom protocols.** [`Encapsulate`](hybrid.go) / [`Decapsulate`](hybrid.go) build an X25519 + ML-KEM-768 hybrid KEM:

```go
ssM, ctM := ekM.Encapsulate()                 // ML-KEM-768
eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
ssX, _ := eph.ECDH(pkX)                       // X25519 as a KEM; errors on low-order points
key := SHA3-256(label ‖ ssM ‖ ssX ‖ ctM ‖ ctX ‖ ekM ‖ pkX)
```

- **Both secrets**: the key stays secret while either component holds, ML-KEM against quantum attackers and X25519 against an implementation or cryptanalytic surprise in the newer scheme.
- **Transcript**: hashing both ciphertexts and the full recipient public key binds the key to this exchange (`TestCombinerBindsX25519Transcript`). X-Wing (draft-connolly-cfrg-xwing-kem) omits `ctM`/`ekM` because ML-KEM already binds them; including them costs microseconds and removes that dependency. All fields are fixed-size, so concatenation is unambiguous.
- **Domain label** separates this combiner from any other SHA3-256 use (chapter 14).
- **Key confirmation**: use the key in an AEAD (chapter 13) or MAC the transcript before trusting it; that is where implicit rejection becomes a detected failure.

Prefer an existing protocol (TLS 1.3, HPKE) over a custom one; build this only where none fits.

## 5. Where the protection ends

- **Authentication is still classical.** Certificates and signatures are ECDSA/RSA/Ed25519; ML-DSA (FIPS 204) is not in the Go 1.25 standard library. That is acceptable for now: forging a signature requires a quantum computer *during* the handshake, not later.
- **TLS 1.2 peers** get classical ECDHE regardless (`TestTLS12CannotBePostQuantum`). So do non-Go peers that do not offer the hybrid group.
- **Terminating proxies** (load balancers, CDNs, service-mesh sidecars) negotiate their own key exchange; check each hop.
- **Symmetric crypto** needs no change beyond 256-bit keys for long-term data (Grover's algorithm at most halves the effective key length).

## 6. Verification

```bash
go test -race -v ./Security/16_post-quantum-kem/
```

| Test | Shows |
|---|---|
| `TestDefaultConfigNegotiatesHybrid` | A default Go server and client negotiate TLS 1.3 with `X25519MLKEM768` (`ConnectionState.CurveID`) |
| `TestExplicitClassicalCurvesDisablePQ` | An explicit classical `CurvePreferences` list silently falls back to X25519 (P-256 in FIPS mode) |
| `TestTLS12CannotBePostQuantum` | A TLS 1.2 handshake cannot use the hybrid group |
| `TestPQOnlyRefusesClassicalClient` | The PQ-only config fails classical-only clients and accepts default ones |
| `TestGODEBUGTlsmlkem0` | `GODEBUG=tlsmlkem=0` turns the hybrid default off |
| `TestHybridKEMRoundTrip` | Both sides derive the same 32-byte key; each encapsulation is fresh |
| `TestMLKEMImplicitRejection` | A tampered ML-KEM (and hybrid) ciphertext gives `err == nil` and a different key |
| `TestCombinerBindsX25519Transcript` | Swapping the X25519 share changes the derived key |
| `TestMalformedInputs` | Wrong sizes and a low-order X25519 point are rejected |

## 7. Checklist

- [ ] No explicit `CurvePreferences` unless it includes `tls.X25519MLKEM768`, with a comment saying why it is set.
- [ ] `GODEBUG=tlsmlkem=0` appears only with a ticket explaining which middlebox needs it.
- [ ] Servers log or export `ConnectionState().CurveID`.
- [ ] Every TLS hop (proxy, sidecar, CDN) is checked for hybrid support.
- [ ] Custom hybrids hash both secrets, both ciphertexts and the public key under a domain label, and confirm the key before use.
- [ ] Data with a long confidentiality lifetime has been inventoried.

## References

- NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) Module-Lattice-Based Key-Encapsulation Mechanism Standard (2024)
- [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/) Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLS 1.3; [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) X-Wing: general-purpose hybrid post-quantum KEM
- F. Giacon, F. Heuer, B. Poettering — [KEM Combiners](https://eprint.iacr.org/2018/024) (PKC 2018)
- [Go 1.24 release notes](https://go.dev/doc/go1.24), [Go 1.25 release notes](https://go.dev/doc/go1.25), [`crypto/mlkem`](https://pkg.go.dev/crypto/mlkem), [`tls.Config.CurvePreferences`](https://pkg.go.dev/crypto/tls#Config)
- [tldr.fail](https://tldr.fail/) — middleboxes that break on large ClientHellos
- NIST [IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) (initial public draft) Transition to Post-Quantum Cryptography Standards
