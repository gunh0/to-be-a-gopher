# 18. TLS Server Configuration

> **Abstract.** A zero-value `tls.Config` on a Go 1.25 server is already a reasonable configuration: TLS 1.2 minimum, TLS 1.3 preferred, ECDHE-only key exchange, no RC4 or 3DES, no renegotiation, no compression, hybrid post-quantum key exchange. Most weak Go TLS servers are weak because someone *configured* them: `MinVersion: tls.VersionTLS10` for an old client, an explicit cipher list copied from a 2016 guide that also freezes out every later improvement, a certificate loaded once at startup that expires on a Sunday. Harden by subtraction (AEAD-only TLS 1.2 suites), leave the rest to the defaults, and make certificate and ticket-key rotation part of the design.

| | |
|---|---|
| Weaknesses | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) Inadequate Encryption Strength, [CWE-327](https://cwe.mitre.org/data/definitions/327.html) Use of a Broken or Risky Cryptographic Algorithm, [CWE-757](https://cwe.mitre.org/data/definitions/757.html) Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade') |
| Go packages | `crypto/tls`, `net/http`, `net/http/httptest`, `sync/atomic` |
| Code | [`tlsserver.go`](tlsserver.go), [`tlsserver_test.go`](tlsserver_test.go), [`pki_test.go`](pki_test.go) |

## 1. Threat model

A network attacker between client and server can observe, drop and modify packets, and can act as a client. They want to force a weaker protocol version or cipher (downgrade), decrypt recorded traffic later (no forward secrecy, leaked ticket keys), or cause an outage (expired certificate). Clients are a mix of current browsers, service-to-service Go clients and, sometimes, a legacy device that someone wants to keep working.

## 2. What Go's defaults already do

| Default | Since | GODEBUG to revert |
|---|---|---|
| SSL 3.0 removed | Go 1.14 | none |
| Clients: minimum TLS 1.2 | Go 1.18 | none (set `MinVersion`) |
| Cipher suite order chosen by Go; `PreferServerCipherSuites` ignored | Go 1.17 | none |
| Servers: minimum TLS 1.2 | Go 1.22 | `tls10server=1` |
| RSA key exchange suites (no forward secrecy) removed from defaults | Go 1.22 | `tlsrsakex=1` |
| 3DES suites removed from defaults | Go 1.23 | `tls3des=1` |
| X25519MLKEM768 hybrid key exchange enabled | Go 1.24 | `tlsmlkem=0` |
| SHA-1 signature algorithms disabled in TLS 1.2 (RFC 9155) | Go 1.25 | `tlssha1=1` |

Never supported: TLS compression (CRIME), server-side renegotiation, export ciphers. RC4 is not in the default list and appears only in `tls.InsecureCipherSuites()`. TLS 1.3 suites are not configurable and are all AEADs. GODEBUG defaults follow the `go` line of the main module's `go.mod`, so an old `go` line can silently re-enable old behaviour.

What remains: the default TLS 1.2 list still contains ECDHE CBC-SHA1 suites for compatibility (`TestCBCOnlyClient`). They are not broken in Go's implementation, but they are MAC-then-encrypt constructions with a history of padding-oracle and timing attacks, and a TLS 1.2 client that only offers CBC in 2025 is unusual.

## 3. Insecure pattern

[`LegacyConfigUnsafe`](tlsserver.go):

```go
&tls.Config{
	MinVersion:   tls.VersionTLS10,                   // RFC 8996: TLS 1.0/1.1 deprecated
	CipherSuites: []uint16{ /* CBC-SHA1 suites */ }, // freezes the list forever
	PreferServerCipherSuites: true,                   // no-op since Go 1.17
}
```

- `MinVersion: tls.VersionTLS10` lets any client (or a downgrading attacker against a client that falls back) negotiate TLS 1.0 (`TestLegacyConfigAcceptsTLS10`). TLS 1.0/1.1 rely on MD5/SHA-1 in the handshake PRF and signatures, and PCI DSS has required disabling early TLS since 2018.
- An explicit `CipherSuites` list replaces Go's default for the life of the binary. Every later default improvement (RSA-kex removal in 1.22, 3DES in 1.23) no longer reaches it.
- `PreferServerCipherSuites` does nothing; its presence signals a copied config whose other lines deserve the same scrutiny.
- `tls.LoadX509KeyPair` once in `main` means certificate renewal requires a restart, so renewals get postponed, so certificates expire.

## 4. Secure pattern

[`HardenedConfig`](tlsserver.go) and [`NewServer`](tlsserver.go):

```go
&tls.Config{
	MinVersion:     tls.VersionTLS12,
	CipherSuites:   []uint16{ /* ECDHE + AES-GCM / ChaCha20-Poly1305 only */ },
	GetCertificate: reloader.GetCertificate,
	// CurvePreferences: nil — keep X25519MLKEM768 (chapter 16)
}
```

1. **TLS 1.2 minimum**; TLS 1.3 is negotiated with every modern client. If all clients are known to be TLS 1.3 (internal services), set `MinVersion: tls.VersionTLS13`.
2. **AEAD-only TLS 1.2 suites** with ECDHE. This is the one place an explicit list adds value; `TestHardenedSuitesAreSecure` asserts that nothing in it appears in `tls.InsecureCipherSuites()`.
3. **Leave `CurvePreferences` nil** so post-quantum key exchange stays on.
4. **Certificate hot reload** with [`CertReloader`](tlsserver.go): an `atomic.Pointer[tls.Certificate]` behind `GetCertificate`. `Load` validates first (key matches certificate, validity window) and keeps serving the old certificate if the new one is bad, so rotation can be automated (ACME, cert-manager, a SIGHUP handler) without risking an outage.
5. **HSTS** ([`HSTS`](tlsserver.go)): `Strict-Transport-Security: max-age=63072000; includeSubDomains` on TLS responses only. It protects the next visit from an SSL-stripping attacker; TLS settings cannot.
6. **Session ticket keys.** Without explicit keys Go rotates ticket keys daily and drops them after seven days. A fleet that shares keys via `SetSessionTicketKeys` must rotate them itself ([`RotateTicketKeys`](tlsserver.go): new key first, previous keys kept for decryption, retired keys removed). A static ticket key is a long-term secret: in TLS 1.2 the ticket carries the session's master secret, so that key decrypts recorded sessions. TLS 1.3 resumption in Go always adds a fresh (EC)DHE exchange, which limits the damage.
7. **Timeouts** on the `http.Server` (chapter 21): the TLS handshake is itself a slow-client target.

## 5. Where the guarantee ends

- **Client authentication** is chapter 20; **client-side verification** is chapter 19.
- **TLS terminated elsewhere** (load balancer, CDN, ingress) means this config protects only the last hop; harden the terminator too.
- **Certificate private keys** on disk are as safe as the host. `GetCertificate` can also fetch from a KMS-backed `crypto.Signer`.
- **OCSP stapling and CT** are not configured here; Go supports stapling via `Certificate.OCSPStaple`.
- **FIPS mode** (chapter 17) narrows the suites further (no ChaCha20-Poly1305).

## 6. Verification

```bash
go test -race -v ./Security/18_tls-server-hardening/
```

| Test | Shows |
|---|---|
| `TestLegacyConfigAcceptsTLS10` | The "compatibility" config negotiates TLS 1.0 (under `GODEBUG=fips140=on` Go refuses it regardless, and the test asserts that instead) |
| `TestGoDefaultServerRejectsTLS10And11` | A zero-value server config rejects TLS 1.0/1.1 (Go 1.22+) |
| `TestHardenedVersions` | TLS 1.0/1.1 rejected, 1.2/1.3 accepted; default clients get TLS 1.3 with X25519MLKEM768 |
| `TestCBCOnlyClient` | Go's default still accepts ECDHE-CBC-SHA1; the hardened config does not |
| `TestHardenedSuitesAreSecure` | No hardened suite is in `tls.InsecureCipherSuites()` |
| `TestCertReloadRotatesWithoutRestart` | New handshakes see the new certificate after `Load` |
| `TestCertReloadRejectsBadInputAndKeepsServing` | Mismatched key, expired certificate and garbage are rejected; the old certificate stays |
| `TestHSTSOnlyOverTLS` | HSTS on HTTPS responses, absent on plain HTTP |
| `TestNewServerHasTimeouts` | The assembled server has all four timeouts |
| `TestTicketKeyRotation` | Tickets resume under current or previous keys, not under retired ones |

The tests use an in-process ECDSA CA ([`pki_test.go`](pki_test.go)) and `httptest.NewUnstartedServer` with `srv.TLS` set before `StartTLS`.

## 7. Checklist

- [ ] No `MinVersion` below `tls.VersionTLS12`; no `tls10server`, `tlsrsakex`, `tls3des` or `tlssha1` GODEBUG overrides.
- [ ] `CipherSuites` is either nil or AEAD-only; nothing from `tls.InsecureCipherSuites()`.
- [ ] No `PreferServerCipherSuites`, no explicit `CurvePreferences` without X25519MLKEM768.
- [ ] Certificates are reloaded without restart, validated before use, and monitored for expiry.
- [ ] HSTS is set on HTTPS responses.
- [ ] Shared session ticket keys have a rotation schedule.
- [ ] `go.mod`'s `go` line is current, so GODEBUG defaults are current.

## References

- [`crypto/tls.Config`](https://pkg.go.dev/crypto/tls#Config), [GODEBUG history](https://go.dev/doc/godebug)
- Release notes: [Go 1.17](https://go.dev/doc/go1.17), [Go 1.18](https://go.dev/doc/go1.18), [Go 1.22](https://go.dev/doc/go1.22), [Go 1.23](https://go.dev/doc/go1.23), [Go 1.25](https://go.dev/doc/go1.25)
- [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) Deprecating TLS 1.0 and TLS 1.1; [RFC 9155](https://www.rfc-editor.org/rfc/rfc9155) Deprecating MD5 and SHA-1 Signature Hashes in TLS 1.2
- [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) Recommendations for Secure Use of TLS and DTLS (BCP 195)
- [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) HTTP Strict Transport Security
- Mozilla — [Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
