# 25. Contextual Auto-Escaping

> **Abstract.** `text/template` and `html/template` share a syntax and an API, and differ in the one thing that matters for HTML: `html/template` parses the template's markup and escapes every action for the context it lands in — HTML-encoding in element bodies and attributes, percent-encoding and scheme filtering in URLs (`javascript:` becomes `#ZgotmplZ`), JSON with `<`/`>`/`&` escaped inside `<script>`, and `ZgotmplZ` for unsafe CSS. `text/template` does none of it. The escaper can be switched off per value with the typed strings `template.HTML`, `template.URL`, `template.JS`, `template.CSS`, `template.HTMLAttr`: they are assertions that a value is already safe, and feeding them user input turns the strongest XSS defence in the standard library back into string concatenation.

| | |
|---|---|
| Weaknesses | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) Improper Neutralization of Input During Web Page Generation (Cross-site Scripting), [CWE-116](https://cwe.mitre.org/data/definitions/116.html) Improper Encoding or Escaping of Output |
| Go packages | `html/template`, `text/template`, `encoding/json`, `net/url` |
| Code | [`render.go`](render.go), [`autoescape_test.go`](autoescape_test.go) |

## 1. Threat model

Users submit content (comments, profile fields, display names) that is stored and later rendered to other users. The attacker controls every field and knows the template. Their goal is script execution in the victim's session: read tokens, act as the victim, or rewrite the page. The vulnerable code is a template that places those fields in HTML, attributes, URLs, inline script, or inline style.

## 2. What the standard library does

`html/template` builds a context-tracking state machine over the template text at parse time, then inserts an escaper chain for each action. The same template rendered with hostile input ([`RenderHTML`](render.go)):

| Context in template | Hostile value | `html/template` output | `text/template` output |
|---|---|---|---|
| `<p>{{.Body}}</p>` | `<img src=x onerror=alert(1)>` | `&lt;img src=x onerror=alert(1)&gt;` | unchanged |
| `title="{{.Author}}"` | `"><script>alert(1)</script>` | `&#34;&gt;&lt;script&gt;…` | breaks out of the attribute |
| `href="{{.Website}}"` | `javascript:alert(document.cookie)` | `#ZgotmplZ` | unchanged |
| `style="border-color: {{.Color}}"` | `red; background: url(javascript:…)` | `ZgotmplZ` | unchanged |
| `<script>var c = {{.}};</script>` | struct with `</script>` in a field | JSON, `<` as `<` | Go's `%v` formatting, raw `</script>` |

Details worth knowing:

- **URL filtering** applies to attributes that hold URLs (`href`, `src`, `action`, …). Allowed schemes are `http`, `https` and `mailto`; anything else (case-insensitive, after leading whitespace) is replaced with `#ZgotmplZ`. Relative and scheme-relative URLs (`//evil.example`) pass: the escaper prevents script execution, not off-site links.
- **In `<script>`**, values are JSON-encoded, then `<`, `>`, `&`, and U+2028/2029 are escaped so the result can neither close the script element nor break a JS string. The output is still valid JSON (the test parses it back).
- **JS template literals**: after [CVE-2023-24538](https://nvd.nist.gov/vuln/detail/CVE-2023-24538) actions inside backticks were first rejected with `ErrJSTemplate`; current releases escape them correctly and `ErrJSTemplate` is deprecated.
- **Typed strings** (`template.HTML`, `.URL`, `.JS`, `.CSS`, `.HTMLAttr`, `.JSStr`, `.Srcset`) are inserted without escaping in their matching context. They are the only way to get raw markup out of `html/template`.

## 3. Insecure pattern

```go
// 1. The wrong package: identical template text, no escaping.
import "text/template"

// 2. The right package, escaping disabled by the caller.
data := struct {
	Website template.URL  // "javascript:alert(document.cookie)"
	Body    template.HTML // "<img src=x onerror=alert(1)>"
}{template.URL(c.Website), template.HTML(c.Body)}
```

[`RenderText`](render.go) and [`RenderRichInsecure`](render.go). Pattern 2 usually comes from a requirement ("comments may contain formatting") or from a value that "was escaped earlier", which is the double-encoding/mis-encoding trap CWE-116 describes: escaping is only correct for the context where it is applied.

`text/template` also appears by accident: one file imports `text/template` and the rest of the codebase assumes everything named `template` escapes. `go vet` does not flag it.

## 4. Secure pattern

1. **Import `html/template`** for anything that ends up in a browser, including HTML e-mail bodies.
2. **Never convert user input to a typed string.** Keep structure in the template and data as plain strings ([`RenderRichSafe`](render.go) renders paragraphs with `{{range}}` instead of building `<p>` in Go).
3. **If rich HTML is a requirement, sanitize** with a vetted allowlist sanitizer (bluemonday is the common Go choice) and only then convert to `template.HTML`, in one audited function.
4. **Apply a URL policy** on top of the escaper: `#ZgotmplZ` stops `javascript:`, not `//evil.example`. [`CheckWebsite`](render.go) requires an absolute `http(s)` URL with a host.
5. **Pass data to scripts as `{{.}}` inside `<script>`** (or a `data-` attribute), never by building JS strings.
6. **Add CSP** (chapter 23) so that a missed injection does not execute.

## 5. Where auto-escaping ends

- **Template text is trusted.** Templates parsed from user input (`template.New("").Parse(userString)`) are code injection, not XSS.
- **Client-side rendering** (`innerHTML`, `eval`, framework escape hatches) re-introduces XSS after the server's correct output.
- **Response type.** Escaped HTML served as `text/html` is safe; user bytes served without a `Content-Type` are sniffed by the server (chapter 23).
- **`ZgotmplZ` is a failure signal**, not a sanitized value; monitor for it rather than shipping it.
- **Open redirects** use URLs the escaper considers safe; chapter 26.

## 6. Verification

```bash
go test -v ./Security/25_html-template-xss/
```

| Test | Shows |
|---|---|
| `TestTextTemplateDoesNotEscape` | All four payloads appear raw in `text/template` output |
| `TestHTMLTemplateEscapesPerContext` | CSS, URL, attribute, body and script contexts each escaped differently; only the template's own `<script` remains |
| `TestDangerousURLSchemesFiltered` | `javascript:` (any case, leading space), `vbscript:`, `data:` → `#ZgotmplZ`; `https`, `mailto` and `//host` pass |
| `TestTypedStringsDisableEscaping` | `template.HTML`, `template.URL` and `template.JS` insert attacker input verbatim |
| `TestRenderRichSafe` | Paragraph structure from the template; markup in data escaped; bad website dropped |
| `TestCheckWebsite` | URL policy rejects `javascript:`, scheme-relative, relative and opaque `https:host` |
| `TestJSONInScriptRoundTrips` | `</script>`, `<!--`, `&`, U+2028 survive as valid JSON with a single closing tag |
| `ExampleRenderHTML` | Full escaped output of one comment |

## 7. Checklist

- [ ] `grep -rn '"text/template"'` returns only non-HTML uses.
- [ ] Every `template.HTML(`, `template.URL(`, `template.JS(`, `template.CSS(`, `template.HTMLAttr(` conversion takes a constant or sanitizer output, never request data.
- [ ] Links from users pass an explicit scheme and host policy.
- [ ] Data reaches inline scripts only through `{{.}}` in a `<script>` block or `data-` attributes.
- [ ] `ZgotmplZ` in rendered output is logged and investigated.

## References

- Go documentation — [`html/template`](https://pkg.go.dev/html/template) (Contexts, Typed Strings, Security Model)
- [CVE-2023-24538](https://nvd.nist.gov/vuln/detail/CVE-2023-24538) — backticks as JS string delimiters in `html/template`
- Samuel, Saxena, Song — *Context-Sensitive Auto-Sanitization in Web Templating Languages Using Type Qualifiers* (ACM CCS 2011), the design behind `html/template`
- OWASP — [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
