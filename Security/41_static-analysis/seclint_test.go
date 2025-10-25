package seclint

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func strs(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s:%d %s", filepath.Base(f.Pos.Filename), f.Pos.Line, f.Rule))
	}
	return out
}

func grepDir(t *testing.T, dir string) []Finding {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []Finding
	for _, e := range entries {
		src, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, GrepCheck(e.Name(), src)...)
	}
	return out
}

func checkDir(t *testing.T, dir string) []string {
	t.Helper()
	fs, err := CheckDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return strs(fs)
}

func TestTLSFixture(t *testing.T) {
	got := checkDir(t, "testdata/tlsclient")
	want := []string{
		"client.go:16 SEC001", // &cryptotls.Config{InsecureSkipVerify: true}, aliased import
		"client.go:25 SEC001", // InsecureSkipVerify: skip (non-constant)
		"client.go:31 SEC001", // cfg.InsecureSkipVerify = true
	}
	if !slices.Equal(got, want) {
		t.Fatalf("AST check:\n got  %q\n want %q", got, want)
	}
}

func TestGrepCheckOnTLSFixture(t *testing.T) {
	got := strs(grepDir(t, "testdata/tlsclient"))
	// Lines 10 and 11 are a comment and a string: false positives.
	// The non-constant value (25) and the assignment (31) are missed.
	want := []string{"client.go:10 SEC001", "client.go:11 SEC001", "client.go:16 SEC001"}
	if !slices.Equal(got, want) {
		t.Fatalf("grep check:\n got  %q\n want %q", got, want)
	}
}

func TestWeakRandIsPackageWide(t *testing.T) {
	if got, want := checkDir(t, "testdata/token"), []string{"token.go:6 SEC002"}; !slices.Equal(got, want) {
		t.Fatalf("AST check = %q, want %q", got, want)
	}
	// math/rand and crypto/hmac live in different files: grep sees neither pair.
	if got := grepDir(t, "testdata/token"); len(got) != 0 {
		t.Fatalf("grep check = %q, want none (that is the point)", strs(got))
	}
}

func TestCleanFixture(t *testing.T) {
	if got := checkDir(t, "testdata/clean"); len(got) != 0 {
		t.Fatalf("false positives: %q", got)
	}
}

func TestDotImport(t *testing.T) {
	src := `package p
import . "crypto/tls"
var c = &Config{InsecureSkipVerify: true}
var d = Config{ServerName: "x"}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "dot.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(Check(fset, []*ast.File{f})); !slices.Equal(got, []string{"dot.go:3 SEC001"}) {
		t.Fatalf("got %q", got)
	}
}

func TestSelfCheck(t *testing.T) {
	// This package's own source mentions InsecureSkipVerify in comments and
	// strings; the AST check must stay quiet, the grep check does not.
	if got := checkDir(t, "."); len(got) != 0 {
		t.Fatalf("AST check on own source: %q", got)
	}
	src, err := os.ReadFile("seclint.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(GrepCheck("seclint.go", src)) == 0 {
		t.Fatal("expected grep false positives on seclint.go")
	}
}

func ExampleCheckDir() {
	fs, err := CheckDir("testdata/tlsclient")
	if err != nil {
		panic(err)
	}
	for _, f := range fs {
		fmt.Println(f)
	}
	// Output:
	// client.go:16: SEC001 InsecureSkipVerify set to true: certificate and host name are not verified
	// client.go:25: SEC001 InsecureSkipVerify set from a non-constant expression: review
	// client.go:31: SEC001 InsecureSkipVerify set to true: certificate and host name are not verified
}
