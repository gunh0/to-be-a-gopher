// Package version exposes the build information the Go toolchain embeds in
// every binary (module path and version, dependency versions and sums, VCS
// revision, build settings) for a /version endpoint and for release checks.
//
// Two rules drive the design. Publicly, a binary should identify *which
// build* it is (version, revision) and nothing that maps directly to known
// vulnerabilities (Go version, dependency list) or to the build machine
// (paths, linker and cgo flags). Internally, the full record is provenance
// and should be checked before release: a build from a dirty tree, without
// VCS stamping, without -trimpath, or with race instrumentation is not a
// release build.
package version

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"strings"
)

// Dep is one module dependency as recorded in the binary.
type Dep struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	Sum     string `json:"sum,omitempty"`
	Replace string `json:"replace,omitempty"`
}

// Info is the full build record.
type Info struct {
	Path      string            `json:"path"`
	Version   string            `json:"version"`
	GoVersion string            `json:"go_version"`
	Revision  string            `json:"revision,omitempty"`
	Time      string            `json:"time,omitempty"`
	Modified  bool              `json:"modified"`
	Settings  map[string]string `json:"settings"`
	Deps      []Dep             `json:"deps"`
}

// Public is the subset safe to serve without authentication.
type Public struct {
	Version  string `json:"version"`
	Revision string `json:"revision,omitempty"`
	Time     string `json:"time,omitempty"`
}

// FromBuildInfo converts runtime/debug build info into an Info.
func FromBuildInfo(bi *debug.BuildInfo) Info {
	in := Info{
		Path:      bi.Path,
		Version:   bi.Main.Version,
		GoVersion: bi.GoVersion,
		Settings:  map[string]string{},
	}
	for _, s := range bi.Settings {
		in.Settings[s.Key] = s.Value
		switch s.Key {
		case "vcs.revision":
			in.Revision = s.Value
		case "vcs.time":
			in.Time = s.Value
		case "vcs.modified":
			in.Modified = s.Value == "true"
		}
	}
	for _, d := range bi.Deps {
		dep := Dep{Path: d.Path, Version: d.Version, Sum: d.Sum}
		if d.Replace != nil {
			dep.Replace = d.Replace.Path + "@" + d.Replace.Version
		}
		in.Deps = append(in.Deps, dep)
	}
	return in
}

// Read returns the running binary's build information. ok is false for
// binaries built without module support.
func Read() (Info, bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Info{}, false
	}
	return FromBuildInfo(bi), true
}

// Public returns the unauthenticated view.
func (in Info) Public() Public {
	return Public{Version: in.Version, Revision: in.Revision, Time: in.Time}
}

// sensitiveSettings may contain absolute paths of the build machine or
// values injected with -X (API keys are regularly passed this way). The go
// command already omits them when building with -trimpath.
var sensitiveSettings = []string{"-ldflags", "-gcflags", "-asmflags", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS"}

// Redacted returns a copy of the full record with flag settings removed,
// suitable for authenticated operators and inventory systems.
func (in Info) Redacted() Info {
	out := in
	out.Settings = map[string]string{}
	for k, v := range in.Settings {
		out.Settings[k] = v
	}
	for _, k := range sensitiveSettings {
		if _, ok := out.Settings[k]; ok {
			out.Settings[k] = "[REDACTED]"
		}
	}
	out.Deps = append([]Dep(nil), in.Deps...)
	return out
}

// HandlerUnsafe serves debug.BuildInfo.String() to anyone: Go version and
// every dependency version (a vulnerability lookup table, chapter 40), and,
// for builds without -trimpath, -ldflags (including -X values) and cgo flags
// with build-machine paths (CWE-200, CWE-215).
func HandlerUnsafe(bi *debug.BuildInfo) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(bi.String()))
	})
}

// Handler serves Public to everyone and the Redacted full record only when
// authorized returns true (an mTLS identity, an internal network, an admin
// token — decided by the caller).
func Handler(in Info, authorized func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		var v any = in.Public()
		if authorized != nil && authorized(r) {
			v = in.Redacted()
		}
		json.NewEncoder(w).Encode(v)
	})
}

// ReleaseProblems lists reasons why in is not a reproducible, attributable
// release build. An empty result means the record looks like one.
func ReleaseProblems(in Info) []string {
	var p []string
	if in.Revision == "" {
		p = append(p, "no vcs.revision: built with -buildvcs=false or outside a repository")
	}
	if in.Modified || strings.HasSuffix(in.Version, "+dirty") {
		p = append(p, "built from a modified working tree")
	}
	if in.Version == "" || in.Version == "(devel)" {
		p = append(p, "main module has no version (untagged build or -buildvcs=false)")
	}
	if in.Settings["-trimpath"] != "true" {
		p = append(p, "built without -trimpath: build paths are embedded")
	}
	for _, k := range []string{"-race", "-cover", "-asan", "-msan"} {
		if in.Settings[k] == "true" {
			p = append(p, "instrumented build ("+k+")")
		}
	}
	if strings.Contains(in.Settings["-ldflags"], "-X") {
		p = append(p, "-ldflags -X values are recorded in build info and the binary")
	}
	for _, d := range in.Deps {
		if d.Replace != "" {
			p = append(p, "replaced dependency "+d.Path+" => "+d.Replace)
		}
	}
	return p
}
