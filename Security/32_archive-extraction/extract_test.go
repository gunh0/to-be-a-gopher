package extract

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// entry describes one archive member. link != "" makes it a symlink.
type entry struct {
	name, body, link string
	mode             fs.FileMode
}

func zipOf(t testing.TB, entries ...entry) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		fh := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		switch {
		case e.link != "":
			fh.SetMode(fs.ModeSymlink | 0o777)
			e.body = e.link
		case strings.HasSuffix(e.name, "/"):
			fh.SetMode(fs.ModeDir | 0o755)
		case e.mode != 0:
			fh.SetMode(e.mode)
		default:
			fh.SetMode(0o644)
		}
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(e.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func tarOf(t testing.TB, entries ...entry) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		switch {
		case e.link != "":
			hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeSymlink, e.link, 0
		case strings.HasSuffix(e.name, "/"):
			hdr.Typeflag, hdr.Mode = tar.TypeDir, 0o755
		case e.mode != 0:
			hdr.Mode = int64(e.mode.Perm())
			if e.mode&fs.ModeSetuid != 0 {
				hdr.Mode |= 0o4000
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

// dirs returns a fresh destination and its parent, which must stay clean.
func dirs(t *testing.T) (parent, dest string) {
	parent = t.TempDir()
	dest = filepath.Join(parent, "out")
	if err := os.Mkdir(dest, 0o750); err != nil {
		t.Fatal(err)
	}
	return parent, dest
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func skipWithoutSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink tests are skipped on Windows")
	}
}

func TestZipSlipInsecure(t *testing.T) {
	parent, dest := dirs(t)
	zr := zipOf(t, entry{name: "ok.txt", body: "fine"}, entry{name: "../slipped.txt", body: "pwned"})
	if err := ExtractZipInsecure(zr, dest); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(parent, "slipped.txt")) {
		t.Fatal("expected ../slipped.txt to be written outside dest")
	}
}

func TestTarSymlinkThenFileInsecure(t *testing.T) {
	skipWithoutSymlinks(t)
	parent, dest := dirs(t)
	outside := filepath.Join(parent, "outside")
	os.Mkdir(outside, 0o750)

	// Both names pass filepath.IsLocal.
	tr := tarOf(t, entry{name: "link", link: outside}, entry{name: "link/planted.txt", body: "pwned"})
	if err := ExtractTarInsecure(tr, dest); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(outside, "planted.txt")) {
		t.Fatal("expected the write to follow the symlink out of dest")
	}
}

func TestExtractZipRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../slipped.txt", "a/../../slipped.txt", "/abs.txt", `..\slipped.txt`, "a//b.txt", ""} {
		parent, dest := dirs(t)
		_, err := ExtractZip(zipOf(t, entry{name: name, body: "x"}), dest, Limits{})
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("name %q: err = %v, want ErrUnsafeName", name, err)
		}
		if exists(filepath.Join(parent, "slipped.txt")) {
			t.Errorf("name %q: file written outside dest", name)
		}
	}
}

func TestExtractTarSkipsLinks(t *testing.T) {
	skipWithoutSymlinks(t)
	parent, dest := dirs(t)
	outside := filepath.Join(parent, "outside")
	os.Mkdir(outside, 0o750)

	tr := tarOf(t,
		entry{name: "docs/"},
		entry{name: "docs/a.txt", body: "a"},
		entry{name: "link", link: outside},
		entry{name: "link/planted.txt", body: "pwned"},
	)
	rep, err := ExtractTar(tr, dest, Limits{})
	// The link is skipped, so "link/planted.txt" becomes a regular file
	// under dest/link/, never outside.
	if err != nil {
		t.Fatal(err)
	}
	if exists(filepath.Join(outside, "planted.txt")) {
		t.Fatal("write escaped through a symlink")
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0] != "link" || rep.Files != 2 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestExtractIntoPreexistingSymlink(t *testing.T) {
	skipWithoutSymlinks(t)
	parent, dest := dirs(t)
	outside := filepath.Join(parent, "outside")
	os.Mkdir(outside, 0o750)
	// dest already contains a link planted by someone else.
	if err := os.Symlink(outside, filepath.Join(dest, "cache")); err != nil {
		t.Skip(err)
	}
	_, err := ExtractZip(zipOf(t, entry{name: "cache/x.txt", body: "pwned"}), dest, Limits{})
	if err == nil || exists(filepath.Join(outside, "x.txt")) {
		t.Fatalf("err = %v; os.Root must refuse to follow the pre-existing link", err)
	}
}

func TestExtractZipModeBitsIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	_, dest := dirs(t)
	zr := zipOf(t, entry{name: "tool", body: "#!/bin/sh\n", mode: fs.ModeSetuid | 0o777})
	if _, err := ExtractZip(zr, dest, Limits{}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "tool"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(fs.ModeSetuid|0o002|0o111) != 0 {
		t.Fatalf("mode %v carried over from the archive", fi.Mode())
	}
}

func TestLimits(t *testing.T) {
	zeros := strings.Repeat("\x00", 512<<10) // 512 KiB, compresses ~1000:1
	many := make([]entry, 11)
	for i := range many {
		many[i] = entry{name: fmt.Sprintf("f%02d", i), body: "x"}
	}
	tests := []struct {
		name string
		zr   *zip.Reader
		lim  Limits
	}{
		{"entry count", zipOf(t, many...), Limits{MaxFiles: 10}},
		{"per-file size", zipOf(t, entry{name: "big", body: strings.Repeat("a", 2048)}), Limits{MaxFileSize: 1024, MaxRatio: 1 << 20}},
		{"total size", zipOf(t, entry{name: "a", body: strings.Repeat("a", 600)}, entry{name: "b", body: strings.Repeat("b", 600)}), Limits{MaxTotal: 1000, MaxRatio: 1 << 20}},
		{"compression ratio", zipOf(t, entry{name: "bomb", body: zeros}), Limits{MaxRatio: 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, dest := dirs(t)
			if _, err := ExtractZip(tt.zr, dest, tt.lim); !errors.Is(err, ErrLimit) {
				t.Fatalf("err = %v, want ErrLimit", err)
			}
			// No partial file is left behind for the entry that failed.
			var sizes int64
			filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
				if fi, err := d.Info(); err == nil && fi.Mode().IsRegular() {
					sizes += fi.Size()
				}
				return nil
			})
			if sizes > 1024 {
				t.Fatalf("%d bytes left on disk", sizes)
			}
		})
	}

	_, dest := dirs(t)
	if rep, err := ExtractZip(zipOf(t, entry{name: "bomb", body: zeros}), dest, Limits{MaxRatio: 2000}); err != nil || rep.Bytes != 512<<10 {
		t.Fatalf("with a permissive ratio: %+v, %v", rep, err)
	}
}

func TestErrInsecurePathIsOptIn(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("../evil.txt")
	zw.Close()
	open := func() (*zip.Reader, error) {
		return zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	}

	// Default in Go 1.25: no error, the name is the caller's problem.
	if zr, err := open(); err != nil || zr.File[0].Name != "../evil.txt" {
		t.Fatalf("default: err = %v", err)
	}

	// With GODEBUG=zipinsecurepath=0, NewReader reports ErrInsecurePath but
	// still returns a usable reader, so code that ignores the error is not
	// protected.
	t.Setenv("GODEBUG", "zipinsecurepath=0")
	zr, err := open()
	if !errors.Is(err, zip.ErrInsecurePath) || zr == nil || len(zr.File) != 1 {
		t.Fatalf("zipinsecurepath=0: zr=%v err=%v", zr, err)
	}

	t.Setenv("GODEBUG", "tarinsecurepath=0")
	hdr, err := tar.NewReader(tarOf(t, entry{name: "../evil.txt", body: "x"})).Next()
	if !errors.Is(err, tar.ErrInsecurePath) || hdr == nil || hdr.Name != "../evil.txt" {
		t.Fatalf("tarinsecurepath=0: hdr=%v err=%v", hdr, err)
	}
}

func ExampleExtractZip() {
	dest, _ := os.MkdirTemp("", "extract")
	defer os.RemoveAll(dest)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("docs/readme.txt")
	w.Write([]byte("hello"))
	zw.Create("../escape.txt")
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))

	rep, err := ExtractZip(zr, dest, Limits{})
	fmt.Println(rep.Files, err)
	// Output:
	// 1 extract: entry name is not local: "../escape.txt"
}
