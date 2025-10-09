package autoescape

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"os"
	"strings"
	"testing"
)

var hostile = Comment{
	Author:  `"><script>alert(1)</script>`,
	Body:    `<img src=x onerror=alert(1)>`,
	Website: `javascript:alert(document.cookie)`,
	Color:   `red; background: url(javascript:alert(1))`,
}

func render(t *testing.T, fn func(*strings.Builder) error) string {
	t.Helper()
	var b strings.Builder
	if err := fn(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestTextTemplateDoesNotEscape(t *testing.T) {
	out := render(t, func(b *strings.Builder) error { return RenderText(b, hostile) })
	for _, raw := range []string{
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`href="javascript:alert(document.cookie)"`,
		`url(javascript:alert(1))`,
	} {
		if !strings.Contains(out, raw) {
			t.Errorf("text/template output lacks raw %q:\n%s", raw, out)
		}
	}
}

func TestHTMLTemplateEscapesPerContext(t *testing.T) {
	out := render(t, func(b *strings.Builder) error { return RenderHTML(b, hostile) })
	tests := []struct {
		context, want string
	}{
		{"CSS value", `style="border-color: ZgotmplZ"`},
		{"URL attribute", `href="#ZgotmplZ"`},
		{"quoted attribute", `title="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"`},
		{"element body", `<p>&lt;img src=x onerror=alert(1)&gt;</p>`},
		{"script (JSON)", `"Author":"\"\u003e\u003cscript\u003ealert(1)\u003c/script\u003e"`},
	}
	for _, tt := range tests {
		if !strings.Contains(out, tt.want) {
			t.Errorf("%s: output lacks %q:\n%s", tt.context, tt.want, out)
		}
	}
	if n := strings.Count(out, "<script"); n != 1 {
		t.Errorf("found %d <script tags, want only the template's own:\n%s", n, out)
	}
}

func TestDangerousURLSchemesFiltered(t *testing.T) {
	tmpl := htmltemplate.Must(htmltemplate.New("a").Parse(`<a href="{{.}}">`))
	tests := []struct{ in, want string }{
		{"javascript:alert(1)", `<a href="#ZgotmplZ">`},
		{"JaVaScRiPt:alert(1)", `<a href="#ZgotmplZ">`},
		{" javascript:alert(1)", `<a href="#ZgotmplZ">`},
		{"vbscript:msgbox(1)", `<a href="#ZgotmplZ">`},
		{"data:text/html,<script>alert(1)</script>", `<a href="#ZgotmplZ">`},
		{"https://ok.example/?q=<x>&y", `<a href="https://ok.example/?q=%3cx%3e&amp;y">`},
		{"mailto:user@example.com", `<a href="mailto:user@example.com">`},
		// Not a scheme problem, so not html/template's concern: an
		// off-site, scheme-relative link is rendered as-is.
		{"//evil.example/login", `<a href="//evil.example/login">`},
	}
	for _, tt := range tests {
		var b strings.Builder
		if err := tmpl.Execute(&b, tt.in); err != nil {
			t.Fatal(err)
		}
		if b.String() != tt.want {
			t.Errorf("href=%q rendered %s, want %s", tt.in, b.String(), tt.want)
		}
	}
}

func TestTypedStringsDisableEscaping(t *testing.T) {
	out := render(t, func(b *strings.Builder) error { return RenderRichInsecure(b, hostile) })
	for _, raw := range []string{`<img src=x onerror=alert(1)>`, `href="javascript:alert%28document.cookie%29"`} {
		if !strings.Contains(out, raw) {
			t.Errorf("expected trusted type to pass %q through:\n%s", raw, out)
		}
	}

	var b strings.Builder
	js := htmltemplate.Must(htmltemplate.New("js").Parse(`<script>var n = {{.}};</script>`))
	js.Execute(&b, htmltemplate.JS("1; alert(1)"))
	if b.String() != `<script>var n = 1; alert(1);</script>` {
		t.Errorf("template.JS was not inserted verbatim: %s", b.String())
	}
}

func TestRenderRichSafe(t *testing.T) {
	c := Comment{Author: "<b>eve</b>", Body: "first <i>para</i>\n\nsecond", Website: "javascript:alert(1)"}
	out := render(t, func(b *strings.Builder) error { return RenderRichSafe(b, c) })
	want := `&lt;b&gt;eve&lt;/b&gt;<p>first &lt;i&gt;para&lt;/i&gt;</p><p>second</p>`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}

	c.Website = "https://eve.example/"
	out = render(t, func(b *strings.Builder) error { return RenderRichSafe(b, c) })
	if !strings.HasPrefix(out, `<a href="https://eve.example/" rel="nofollow ugc">`) {
		t.Fatalf("valid website not linked: %s", out)
	}
}

func TestCheckWebsite(t *testing.T) {
	for _, bad := range []string{"javascript:alert(1)", "//evil.example", "/relative", "https:evil.example", "ftp://x.example", ""} {
		if _, err := CheckWebsite(bad); err == nil {
			t.Errorf("CheckWebsite(%q) accepted", bad)
		}
	}
	if _, err := CheckWebsite("https://ok.example/path"); err != nil {
		t.Errorf("CheckWebsite rejected a valid URL: %v", err)
	}
}

func TestJSONInScriptRoundTrips(t *testing.T) {
	c := Comment{Author: "</script><script>alert(1)</script>", Body: "<!--", Website: "a&b", Color: "'\u2028'"}
	out := render(t, func(b *strings.Builder) error { return RenderHTML(b, c) })

	if n := strings.Count(out, "</script>"); n != 1 {
		t.Fatalf("found %d </script>, want only the template's closing tag:\n%s", n, out)
	}
	start := strings.Index(out, "var comment = ") + len("var comment = ")
	end := strings.Index(out, ";</script>")
	var got Comment
	if err := json.Unmarshal([]byte(out[start:end]), &got); err != nil {
		t.Fatalf("script payload is not JSON: %v\n%s", err, out[start:end])
	}
	if got != c {
		t.Fatalf("round trip = %+v, want %+v", got, c)
	}
}

func ExampleRenderHTML() {
	RenderHTML(os.Stdout, Comment{Author: "<b>", Body: "a & b", Website: "javascript:x", Color: "blue"})
	fmt.Println()
	// Output:
	// <article style="border-color: blue"><a href="#ZgotmplZ" title="&lt;b&gt;">&lt;b&gt;</a><p>a &amp; b</p><script>var comment = {"Author":"\u003cb\u003e","Body":"a \u0026 b","Website":"javascript:x","Color":"blue"};</script></article>
}
