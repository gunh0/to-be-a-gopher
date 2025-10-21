# 37. Log Injection & Forging

> **Abstract.** The `log` package writes the formatted message verbatim, adding at most a trailing newline. A `%s` argument containing `\n` therefore ends the real entry and starts one written by the attacker, timestamp and all; an argument containing ANSI escape sequences is executed by the terminal of whoever tails the log. `log/slog` (Go 1.21) removes the class for values passed as attributes: `TextHandler` quotes any value or key that needs it with `strconv.Quote` rules, and `JSONHandler` escapes control characters as JSON requires. The residual gaps are narrow but real — messages built with `fmt.Sprintf`, Unicode format characters such as the bidi override U+202E (which JSON leaves raw), and whatever the downstream log viewer does with the text.

| | |
|---|---|
| Weaknesses | [CWE-117](https://cwe.mitre.org/data/definitions/117.html) Improper Output Neutralization for Logs, [CWE-150](https://cwe.mitre.org/data/definitions/150.html) Improper Neutralization of Escape, Meta, or Control Sequences |
| Go packages | `log`, `log/slog`, `strconv`, `unicode` |
| Code | [`loginject.go`](loginject.go), [`loginject_test.go`](loginject_test.go) |

## 1. Threat model

The attacker controls a string that the service logs: a user name on a failed login, a `User-Agent`, a URL path, an error message from upstream. They want to (a) forge entries that mislead incident responders or SIEM rules ("login ok user=admin"), (b) hide their own entries, or (c) attack the person reading the log through terminal escape sequences or a log viewer that renders HTML.

## 2. What Go guarantees

| Sink | `\n` / `\r` | ESC `\x1b` | U+2028 | U+202E (bidi) | Keys |
|---|---|---|---|---|---|
| `log.Printf("%s")` | **raw** — new entry | **raw** | raw | raw | n/a |
| `log.Printf("%q")` | `\n` | `\x1b` | `\u2028` | `\u202e` | n/a |
| `slog.TextHandler` | value quoted: `"…\n…"` | `\x1b` | `\u2028` | `\u202e` | quoted if needed |
| `slog.JSONHandler` | `\n` | `\u001b` | `\u2028` | **raw** | JSON-escaped |

Every cell is asserted by a test. Two properties matter beyond escaping: TextHandler quoting keeps **fields delimited** (a value `a" admin="true` cannot create an `admin` attribute), and JSON output is **lossless** (the original bytes decode back exactly, which forensic work needs).

After `slog.SetDefault(...)`, the `log` package's default logger writes through the slog handler, so legacy `log.Printf` call sites get their whole message quoted as `msg="…"` (`TestSetDefaultRoutesLogPackageThroughHandler`).

Go's loggers never interpret message content: there is no lookup or template syntax, so the Log4Shell class (CVE-2021-44228) does not exist here. The risk is purely in what the bytes do to readers and parsers.

## 3. Insecure pattern

```go
l.Printf("login failed user=%s ip=%s", user, ip)
// user = "bob\n2025/10/01 12:00:00 login ok user=admin ip=10.0.0.1"
```

Output with `log.LstdFlags`:

```
2025/10/14 09:12:44 login failed user=bob
2025/10/01 12:00:00 login ok user=admin ip=10.0.0.1 ip=203.0.113.7
```

Both lines match the entry format. With `"\x1b[2K\r\x1b[32mlogin ok…"` a terminal erases the real line and prints a green fake one; `less -R`, `tail -f` and CI log viewers that interpret ANSI are all affected.

## 4. Secure pattern

1. **Structured logging with a constant message.** Untrusted data goes only into typed attributes:
   ```go
   l.Warn("login failed", slog.String("user", user), slog.String("ip", ip))
   ```
   `{"level":"WARN","msg":"login failed","user":"bob\nlogin ok user=admin","ip":"203.0.113.7"}`
2. **Never use untrusted data as a key or in the message.** TextHandler quotes odd keys, but a schema where attackers choose field names defeats every downstream query.
3. **Legacy `log` call sites:** switch `%s`/`%v` to `%q` for anything external, or route `log` through slog with `slog.SetDefault`.
4. **Neutralise format characters** for JSON logs that humans read: `EscapeFormatChars` as `ReplaceAttr` rewrites Unicode category Cf (bidi controls, zero-width, tag characters) to `\uXXXX` text.
5. **Plain-text sinks** (terminal output, syslog, email subjects): `Sanitize` applies Go string-literal escaping without quotes, leaving only printable runes.

## 5. Where the guarantee ends

- **`fmt.Sprintf` inside slog.** `slog.Info(fmt.Sprintf("user %s failed", u))` makes attacker text the message. TextHandler still quotes it, but the message is no longer constant — searches, alert rules and log-based metrics keyed on it break, and attackers can shape it.
- **`slog.Any` with custom types.** Values implementing `LogValuer`, `fmt.Stringer`, `json.Marshaler` or `encoding.TextMarshaler` decide their own output; the handler escapes the result, but secrets inside are logged (chapter 38).
- **Custom handlers** and third-party logging libraries may not escape at all. Test them with the payloads in this chapter.
- **Downstream rendering.** A log viewer that renders HTML turns a logged `<script>` into stored XSS against operators (chapter 25); CSV exports of logs are subject to formula injection.
- **Volume.** Logging every attacker-supplied byte is itself a resource-exhaustion vector; truncate long values and rate-limit noisy events (chapter 28).
- **Sensitive data.** Escaping does not make it acceptable to log passwords, tokens or full request bodies (chapter 38).

## 6. Verification

```bash
go test -v ./Security/37_log-injection/
```

| Test | Shows |
|---|---|
| `TestUnsafePassesANSIToTerminal` | Raw ESC and CR reach the output |
| `TestUnsafeForgesEntry` | One call produces two lines that both match the `LstdFlags` entry format |
| `TestQuotedStaysOnOneLine` | `%q` neutralises newline, ANSI and bidi payloads |
| `TestSlogHandlersEncodeValues` | Text and JSON handlers keep one line per entry; JSON round-trips the exact input; quoting prevents field injection |
| `TestSlogTextQuotesKeys` | A key containing `\n` is quoted |
| `TestJSONLeavesFormatCharsRaw` | JSONHandler emits U+202E raw; `EscapeFormatChars` rewrites it, U+200B and a tag character |
| `TestSanitize` | Control, ANSI, bidi and invalid UTF-8 escaped; printable non-ASCII kept |
| `TestSetDefaultRoutesLogPackageThroughHandler` | A legacy `log.Printf("%s")` call is neutralised by `slog.SetDefault` |
| `Example` | The same input through `%s`, `%q`, JSON and `Sanitize` |

## 7. Checklist

- [ ] Log messages are constants; variable data is in attributes.
- [ ] No `log.Printf("%s"/"%v")` with external input; `log` is routed through slog or uses `%q`.
- [ ] JSON logs read by humans pass through a `ReplaceAttr` that neutralises format characters.
- [ ] Attribute keys are never derived from input.
- [ ] Log viewers escape HTML and do not interpret ANSI from log content.
- [ ] Long values are truncated; secrets are never logged (chapter 38).

## References

- Package [`log/slog`](https://pkg.go.dev/log/slog) — [`TextHandler`](https://pkg.go.dev/log/slog#TextHandler.Handle), [`JSONHandler`](https://pkg.go.dev/log/slog#JSONHandler.Handle), [`SetDefault`](https://pkg.go.dev/log/slog#SetDefault); package [`log`](https://pkg.go.dev/log)
- Go Blog — [Structured Logging with slog](https://go.dev/blog/slog) (2023)
- OWASP — [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), [Log Injection](https://owasp.org/www-community/attacks/Log_Injection)
- Boucher & Anderson — [Trojan Source: Invisible Vulnerabilities](https://trojansource.codes/) ([CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574))
- Unicode Technical Standard #39 — [Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/)
