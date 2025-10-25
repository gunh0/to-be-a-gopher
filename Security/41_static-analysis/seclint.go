// Package seclint is a deliberately small, syntax-only security checker built
// on go/parser and go/ast. It exists to show what separates a useful static
// check from a grep: it understands imports (aliases, dot imports), knows a
// comment from code, and works on a whole package rather than one line.
// Real projects should run go vet, staticcheck and gosec, or write
// golang.org/x/tools/go/analysis passes with type information; this package
// stays within the standard library.
//
// Rules:
//
//	SEC001  crypto/tls.Config with InsecureSkipVerify not literally false (CWE-295)
//	SEC002  math/rand imported in a package that also imports a crypto primitive (CWE-338)
package seclint

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Finding is one diagnostic.
type Finding struct {
	Pos     token.Position
	Rule    string
	Message string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s %s", filepath.Base(f.Pos.Filename), f.Pos.Line, f.Rule, f.Message)
}

// GrepCheck is the line-based check many teams start with: it searches the
// raw text. It flags comments and strings that mention the pattern, misses
// any spelling gofmt does not produce, misses assignments and non-constant
// values, and cannot see imports in other files of the same package.
func GrepCheck(filename string, src []byte) []Finding {
	var out []Finding
	hasCrypto := bytes.Contains(src, []byte(`"crypto/`))
	for i, line := range bytes.Split(src, []byte("\n")) {
		pos := token.Position{Filename: filename, Line: i + 1}
		if bytes.Contains(line, []byte("InsecureSkipVerify: true")) {
			out = append(out, Finding{pos, "SEC001", "InsecureSkipVerify: true"})
		}
		if hasCrypto && bytes.Contains(line, []byte(`"math/rand"`)) {
			out = append(out, Finding{pos, "SEC002", "math/rand next to crypto"})
		}
	}
	return out
}

// CheckDir parses every non-test .go file in dir as one package and runs
// all rules.
func CheckDir(dir string) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return Check(fset, files), nil
}

// Check runs all rules over the files of one package.
func Check(fset *token.FileSet, files []*ast.File) []Finding {
	var out []Finding
	for _, f := range files {
		out = append(out, checkTLS(fset, f)...)
	}
	out = append(out, checkWeakRand(fset, files)...)
	slices.SortFunc(out, func(a, b Finding) int {
		if c := strings.Compare(a.Pos.Filename, b.Pos.Filename); c != 0 {
			return c
		}
		return a.Pos.Line - b.Pos.Line
	})
	return out
}

// importName returns the name under which f imports path: "" if it does
// not, "." for a dot import, otherwise the explicit or default name.
func importName(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return path[strings.LastIndex(path, "/")+1:]
	}
	return ""
}

// isTLSConfig reports whether the type expression denotes tls.Config under
// the file's import name for crypto/tls.
func isTLSConfig(expr ast.Expr, tlsName string) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		id, ok := t.X.(*ast.Ident)
		return ok && id.Name == tlsName && t.Sel.Name == "Config"
	case *ast.Ident:
		return tlsName == "." && t.Name == "Config"
	}
	return false
}

func isFalse(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

func isTrue(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "true"
}

// checkTLS implements SEC001 for composite literals of tls.Config and for
// assignments to a field named InsecureSkipVerify (without type information
// the field name is the best available signal, and it is distinctive).
func checkTLS(fset *token.FileSet, f *ast.File) []Finding {
	tlsName := importName(f, "crypto/tls")
	var out []Finding
	report := func(n ast.Node, value ast.Expr) {
		if isFalse(value) {
			return
		}
		msg := "InsecureSkipVerify set to true: certificate and host name are not verified"
		if !isTrue(value) {
			msg = "InsecureSkipVerify set from a non-constant expression: review"
		}
		out = append(out, Finding{fset.Position(n.Pos()), "SEC001", msg})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if tlsName == "" || !isTLSConfig(n.Type, tlsName) {
				return true
			}
			for _, el := range n.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "InsecureSkipVerify" {
					report(kv, kv.Value)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if ok && sel.Sel.Name == "InsecureSkipVerify" && i < len(n.Rhs) {
					report(n, n.Rhs[i])
				}
			}
		}
		return true
	})
	return out
}

// isCryptoPrimitive reports whether path is a package whose callers handle
// keys, nonces or tokens. crypto/tls and crypto/x509 are excluded: they draw
// their own randomness from crypto/rand, and importing them next to
// math/rand (for retry jitter, say) is common and harmless.
func isCryptoPrimitive(path string) bool {
	switch path {
	case "crypto/tls", "crypto/x509", "crypto/x509/pkix":
		return false
	}
	return strings.HasPrefix(path, "crypto/") || strings.HasPrefix(path, "golang.org/x/crypto/")
}

// checkWeakRand implements SEC002. math/rand is fine for simulations and
// jitter; in a package that also does cryptography it is a strong hint that
// a key, nonce or token is drawn from a predictable generator (chapter 08).
// The check is package-wide: the two imports often live in different files.
func checkWeakRand(fset *token.FileSet, files []*ast.File) []Finding {
	usesCrypto := false
	for _, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if isCryptoPrimitive(p) {
				usesCrypto = true
			}
		}
	}
	if !usesCrypto {
		return nil
	}
	var out []Finding
	for _, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "math/rand" || p == "math/rand/v2" {
				out = append(out, Finding{fset.Position(imp.Pos()), "SEC002",
					p + " imported in a package that uses crypto: use crypto/rand for secrets"})
			}
		}
	}
	return out
}
