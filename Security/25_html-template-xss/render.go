// Package autoescape compares text/template, which never escapes, with
// html/template, which parses the template's HTML and escapes each action for
// the context it appears in (element body, attribute, URL, JavaScript, CSS),
// and shows how the typed strings template.HTML, template.URL and
// template.JS switch that escaping off.
package autoescape

import (
	"errors"
	htmltemplate "html/template"
	"io"
	"net/url"
	"strings"
	texttemplate "text/template"
)

// Comment is user-submitted content. Every field is attacker-controlled.
type Comment struct {
	Author  string
	Body    string
	Website string
	Color   string
}

// pageSrc places user data in five contexts: CSS inside a style attribute, a
// URL attribute, the HTML body, a quoted attribute, and a JavaScript value.
const pageSrc = `<article style="border-color: {{.Color}}">` +
	`<a href="{{.Website}}" title="{{.Author}}">{{.Author}}</a>` +
	`<p>{{.Body}}</p>` +
	`<script>var comment = {{.}};</script>` +
	`</article>`

var (
	textPage = texttemplate.Must(texttemplate.New("page").Parse(pageSrc))
	htmlPage = htmltemplate.Must(htmltemplate.New("page").Parse(pageSrc))
)

// RenderText uses text/template. It is the right package for e-mails and
// config files and the wrong one for HTML: it substitutes values verbatim,
// so every field above is an injection point (CWE-79, CWE-116).
func RenderText(w io.Writer, c Comment) error {
	return textPage.Execute(w, c)
}

// RenderHTML uses html/template with the same template text. The escaper
// HTML-encodes the body and attribute values, percent-encodes and filters the
// URL (javascript: becomes #ZgotmplZ), replaces unsafe CSS with ZgotmplZ, and
// JSON-encodes the struct in the script with <, >, & escaped as < etc.
func RenderHTML(w io.Writer, c Comment) error {
	return htmlPage.Execute(w, c)
}

var richPage = htmltemplate.Must(htmltemplate.New("rich").Parse(
	`<a href="{{.Website}}">{{.Author}}</a><div>{{.Body}}</div>`))

// RenderRichInsecure is what "we need to allow formatting" often turns into:
// user input converted to template.HTML and template.URL. Those types are
// assertions by the programmer that the content is already safe; the escaper
// trusts them and inserts them verbatim.
func RenderRichInsecure(w io.Writer, c Comment) error {
	return richPage.Execute(w, struct {
		Author  string
		Website htmltemplate.URL
		Body    htmltemplate.HTML
	}{c.Author, htmltemplate.URL(c.Website), htmltemplate.HTML(c.Body)})
}

var richSafePage = htmltemplate.Must(htmltemplate.New("rich-safe").Parse(
	`{{if .Website}}<a href="{{.Website}}" rel="nofollow ugc">{{.Author}}</a>{{else}}{{.Author}}{{end}}` +
		`{{range .Paragraphs}}<p>{{.}}</p>{{end}}`))

// RenderRichSafe keeps formatting decisions in the template: the body is
// split into paragraphs as plain strings and each is escaped normally. The
// website must pass CheckWebsite; an invalid one is dropped, not rendered.
func RenderRichSafe(w io.Writer, c Comment) error {
	site, err := CheckWebsite(c.Website)
	if err != nil {
		site = ""
	}
	var paras []string
	for p := range strings.SplitSeq(c.Body, "\n\n") {
		if p = strings.TrimSpace(p); p != "" {
			paras = append(paras, p)
		}
	}
	return richSafePage.Execute(w, struct {
		Author, Website string
		Paragraphs      []string
	}{c.Author, site, paras})
}

// ErrBadURL is returned for links that are not absolute http(s) URLs.
var ErrBadURL = errors.New("autoescape: website must be an absolute http or https URL")

// CheckWebsite enforces a URL policy. html/template only blocks dangerous
// schemes; it does not stop "//evil.example" or "https://evil.example",
// which are valid links. Whether a link may point anywhere is an application
// decision (see chapter 26 for redirects).
func CheckWebsite(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", ErrBadURL
	}
	return u.String(), nil
}
