// Package modcheck is a dependency policy gate over the module graph. Go's
// toolchain already guarantees that every module version is the one the
// checksum database recorded (go.sum + sum.golang.org), but it cannot know
// whether that version should be in the build at all. modcheck reads the
// stream printed by "go list -m -json all" (or the build info embedded in a
// binary) and flags replace directives, local replacements, pseudo-versions,
// retracted or deprecated versions, modules outside an allowlist, and
// lookalike paths of allowlisted modules.
//
// golang.org/x/mod is deliberately not used; the parsing needed here is
// plain encoding/json.
package modcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"runtime/debug"
	"strings"
)

// Module mirrors the fields of cmd/go's Module struct ("go help list") that
// the checks use. Unknown fields in the input are ignored.
type Module struct {
	Path       string
	Version    string
	Replace    *Module
	Main       bool
	Indirect   bool
	Retracted  []string
	Deprecated string
	Sum        string
	Error      *struct{ Err string }
}

// ParseList decodes the concatenated JSON objects printed by
// "go list -m -json all". It fails closed: a decode error or an empty stream
// is an error, never an empty (passing) module list.
func ParseList(r io.Reader) ([]Module, error) {
	dec := json.NewDecoder(r)
	var mods []Module
	for {
		var m Module
		err := dec.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("modcheck: module %d: %w", len(mods)+1, err)
		}
		if m.Path == "" {
			return nil, fmt.Errorf("modcheck: module %d has no path", len(mods)+1)
		}
		mods = append(mods, m)
	}
	if len(mods) == 0 {
		return nil, errors.New("modcheck: no modules in input")
	}
	return mods, nil
}

// FromBuildInfo converts the dependency list embedded in a Go binary (see
// runtime/debug.ReadBuildInfo and "go version -m") into Modules, so the same
// policy can be enforced on the artefact that actually ships.
func FromBuildInfo(bi *debug.BuildInfo) []Module {
	conv := func(d *debug.Module) *Module {
		if d == nil {
			return nil
		}
		m := &Module{Path: d.Path, Version: d.Version, Sum: d.Sum}
		if m.Version == "(devel)" {
			m.Version = "" // directory replacement, as "go list" reports it
		}
		return m
	}
	mods := []Module{{Path: bi.Main.Path, Version: bi.Main.Version, Main: true}}
	for _, d := range bi.Deps {
		m := conv(d)
		m.Replace = conv(d.Replace)
		mods = append(mods, *m)
	}
	return mods
}

// Kind classifies a Finding.
type Kind string

const (
	NotAllowed   Kind = "not-allowed"
	Lookalike    Kind = "lookalike"
	Replaced     Kind = "replace"
	LocalReplace Kind = "local-replace"
	Pseudo       Kind = "pseudo-version"
	Retracted    Kind = "retracted"
	Deprecated   Kind = "deprecated"
	LoadError    Kind = "error"
)

// Finding is one policy violation.
type Finding struct {
	Module string // module path as required in go.mod
	Kind   Kind
	Detail string
}

func (f Finding) String() string { return fmt.Sprintf("%s: %s: %s", f.Module, f.Kind, f.Detail) }

// Policy configures Check.
type Policy struct {
	// Allow lists permitted module paths. An entry ending in "/" is a
	// prefix ("golang.org/x/"); any other entry must match exactly.
	Allow []string
	// AllowReplace permits replace directives whose target is itself
	// allowed. Local directory replacements are never permitted.
	AllowReplace bool
	// AllowPseudo permits pseudo-versions (untagged commits).
	AllowPseudo bool
}

// pseudoRE is the pseudo-version grammar from golang.org/x/mod/module:
// vX.0.0-yyyymmddhhmmss-abcdef123456, vX.Y.Z-pre.0.yyyymmddhhmmss-..., and
// vX.Y.(Z+1)-0.yyyymmddhhmmss-....
var pseudoRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// IsPseudoVersion reports whether v is a pseudo-version.
func IsPseudoVersion(v string) bool { return pseudoRE.MatchString(v) }

// CheckNaive is the check most allowlists start as: it compares the
// required module path against the allowlist and stops. A replace directive
// keeps the required path while swapping the code underneath, so a fork or
// a local directory passes unnoticed.
func CheckNaive(mods []Module, p Policy) []Finding {
	var out []Finding
	for _, m := range mods {
		if !m.Main && !p.allowed(m.Path) {
			out = append(out, Finding{m.Path, NotAllowed, "not in allowlist"})
		}
	}
	return out
}

// Check evaluates every non-main module against p, looking at the module
// whose code is actually compiled: the replacement when there is one.
func Check(mods []Module, p Policy) []Finding {
	var out []Finding
	add := func(m Module, k Kind, format string, args ...any) {
		out = append(out, Finding{m.Path, k, fmt.Sprintf(format, args...)})
	}
	for _, m := range mods {
		if m.Main {
			continue
		}
		if m.Error != nil {
			add(m, LoadError, "%s", m.Error.Err)
		}
		eff := m
		if r := m.Replace; r != nil {
			eff = *r
			switch {
			case r.Version == "":
				// Replacement by a directory: not in go.sum, not in the
				// checksum database, different on every machine.
				add(m, LocalReplace, "replaced by directory %q", r.Path)
			case !p.AllowReplace:
				add(m, Replaced, "replaced by %s@%s", r.Path, r.Version)
			}
		}
		if eff.Version == "" {
			continue // local replacement already reported
		}
		if !p.allowed(eff.Path) {
			if base := p.lookalikeOf(eff.Path); base != "" {
				add(m, Lookalike, "%s resembles allowed module %s", eff.Path, base)
			} else {
				add(m, NotAllowed, "%s not in allowlist", eff.Path)
			}
		}
		if !p.AllowPseudo && IsPseudoVersion(eff.Version) {
			add(m, Pseudo, "%s is an untagged commit", eff.Version)
		}
		if len(m.Retracted) > 0 {
			add(m, Retracted, "%s", strings.Join(m.Retracted, "; "))
		}
		if m.Deprecated != "" {
			add(m, Deprecated, "%s", m.Deprecated)
		}
	}
	return out
}

func (p Policy) allowed(modPath string) bool {
	for _, a := range p.Allow {
		if strings.HasSuffix(a, "/") && strings.HasPrefix(modPath, a) || modPath == a {
			return true
		}
	}
	return false
}

// lookalikeOf returns an exact allowlist entry with the same final path
// element (and major-version suffix stripped) as modPath, such as
// github.com/boltdb/bolt for github.com/boltdb-go/bolt.
func (p Policy) lookalikeOf(modPath string) string {
	name := baseName(modPath)
	for _, a := range p.Allow {
		if !strings.HasSuffix(a, "/") && baseName(a) == name {
			return a
		}
	}
	return ""
}

var majorRE = regexp.MustCompile(`/v[0-9]+$`)

func baseName(modPath string) string {
	return strings.ToLower(path.Base(majorRE.ReplaceAllString(modPath, "")))
}
