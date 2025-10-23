package modcheck

import (
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
)

var policy = Policy{Allow: []string{
	"golang.org/x/",
	"github.com/example/",
	"github.com/sirupsen/logrus",
	"github.com/boltdb/bolt",
	"github.com/google/uuid",
}}

func loadFixture(t *testing.T) []Module {
	t.Helper()
	f, err := os.Open("testdata/golist.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mods, err := ParseList(f)
	if err != nil {
		t.Fatal(err)
	}
	return mods
}

// kinds returns "module kind" pairs, sorted, for compact comparisons.
func kinds(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Module+" "+string(f.Kind))
	}
	slices.Sort(out)
	return out
}

func TestParseList(t *testing.T) {
	mods := loadFixture(t)
	if len(mods) != 8 || !mods[0].Main || mods[2].Replace == nil || mods[2].Replace.Path != "github.com/attacker/logrus" {
		t.Fatalf("unexpected parse: %+v", mods)
	}
}

func TestParseListFailsClosed(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"truncated": `{"Path": "golang.org/x/crypto", "Vers`,
		"not json":  "go: updates to go.mod needed",
		"no path":   `{"Version": "v1.0.0"}`,
	} {
		if mods, err := ParseList(strings.NewReader(in)); err == nil {
			t.Errorf("%s: ParseList = %v, nil; want error", name, mods)
		}
	}
}

func TestCheckNaiveMissesReplacements(t *testing.T) {
	got := kinds(CheckNaive(loadFixture(t), policy))
	// Only the typosquat is caught: its required path is not allowlisted.
	want := []string{"github.com/boltdb-go/bolt not-allowed"}
	if !slices.Equal(got, want) {
		t.Fatalf("naive findings = %q, want %q", got, want)
	}
}

func TestCheck(t *testing.T) {
	got := kinds(Check(loadFixture(t), policy))
	want := []string{
		"github.com/boltdb-go/bolt lookalike",
		"github.com/example/internal-lib pseudo-version",
		"github.com/example/legacy deprecated",
		"github.com/example/legacy retracted",
		"github.com/example/shared local-replace",
		"github.com/sirupsen/logrus lookalike", // replaced by github.com/attacker/logrus
		"github.com/sirupsen/logrus replace",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got  %q\n want %q", got, want)
	}
}

func TestCheckAllowReplaceStillChecksTarget(t *testing.T) {
	p := policy
	p.AllowReplace = true
	p.AllowPseudo = true
	got := kinds(Check(loadFixture(t), p))
	if !slices.Contains(got, "github.com/sirupsen/logrus lookalike") {
		t.Fatalf("replacement target escaped the allowlist: %q", got)
	}
	if !slices.Contains(got, "github.com/example/shared local-replace") {
		t.Fatalf("local replacement allowed by AllowReplace: %q", got)
	}
	if slices.Contains(got, "github.com/sirupsen/logrus replace") || slices.Contains(got, "github.com/example/internal-lib pseudo-version") {
		t.Fatalf("policy switches ignored: %q", got)
	}
}

func TestIsPseudoVersion(t *testing.T) {
	tests := map[string]bool{
		"v0.0.0-20250911093012-4f2c9a71d0e8":              true,
		"v1.2.4-0.20250911093012-4f2c9a71d0e8":            true, // after v1.2.3
		"v1.3.0-rc.1.0.20250911093012-4f2c9a71d0e8":       true, // after v1.3.0-rc.1
		"v2.0.0-20250911093012-4f2c9a71d0e8+incompatible": true,
		"v1.2.3":              false,
		"v1.2.3-rc.1":         false,
		"v2.0.0+incompatible": false,
		"v0.0.0-2025-abcdef":  false,
	}
	for v, want := range tests {
		if got := IsPseudoVersion(v); got != want {
			t.Errorf("IsPseudoVersion(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestLookalikeIgnoresMajorVersion(t *testing.T) {
	p := Policy{Allow: []string{"github.com/google/uuid"}}
	got := kinds(Check([]Module{{Path: "github.com/goog1e/uuid/v2", Version: "v2.0.0"}}, p))
	if !slices.Equal(got, []string{"github.com/goog1e/uuid/v2 lookalike"}) {
		t.Fatalf("got %q", got)
	}
}

func TestFromBuildInfo(t *testing.T) {
	text, err := os.ReadFile("testdata/buildinfo.txt")
	if err != nil {
		t.Fatal(err)
	}
	bi, err := debug.ParseBuildInfo(string(text))
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(Check(FromBuildInfo(bi), policy))
	want := []string{
		"github.com/example/shared local-replace",
		"github.com/sirupsen/logrus lookalike",
		"github.com/sirupsen/logrus replace",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n got  %q\n want %q", got, want)
	}
}

func TestRunningBinary(t *testing.T) {
	// The test binary carries build info too; this repository has no
	// replace directives, so the only possible findings are allowlist ones.
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info")
	}
	for _, f := range Check(FromBuildInfo(bi), Policy{Allow: []string{"golang.org/x/"}, AllowPseudo: true}) {
		if f.Kind != NotAllowed && f.Kind != Lookalike {
			t.Errorf("unexpected finding in this repository's own build: %v", f)
		}
	}
}

func ExampleCheck() {
	mods := []Module{
		{Path: "github.com/example/app", Main: true},
		{Path: "github.com/sirupsen/logrus", Version: "v1.9.3",
			Replace: &Module{Path: "github.com/attacker/logrus", Version: "v1.9.3"}},
	}
	p := Policy{Allow: []string{"github.com/sirupsen/logrus"}}
	fmt.Println(len(CheckNaive(mods, p)), "naive findings")
	for _, f := range Check(mods, p) {
		fmt.Println(f)
	}
	// Output:
	// 0 naive findings
	// github.com/sirupsen/logrus: replace: replaced by github.com/attacker/logrus@v1.9.3
	// github.com/sirupsen/logrus: lookalike: github.com/attacker/logrus resembles allowed module github.com/sirupsen/logrus
}
