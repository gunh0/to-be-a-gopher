// Package extract unpacks zip and tar archives from untrusted sources. The
// insecure extractors show Zip Slip (entry names with "../"), symlink
// entries that redirect later writes, and decompression bombs; the secure
// ones write only regular files and directories through an os.Root, and
// enforce limits on entry count, per-file size, total size and compression
// ratio while copying.
package extract

import (
	"archive/tar"
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractZipInsecure is the Zip Slip pattern (CWE-22): the entry name is
// joined to dest, and Join resolves "../" segments, so "../../.bashrc"
// lands outside dest. It also trusts the archive's mode bits and has no
// size limits.
func ExtractZipInsecure(zr *zip.Reader, dest string) error {
	for _, f := range zr.File {
		path := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ExtractTarInsecure checks names with filepath.IsLocal, which stops "../"
// but not the two-step attack: a symlink entry "link -> /some/dir" followed
// by a file entry "link/payload". Each name is local; the second write goes
// through the first entry's link (CWE-59).
func ExtractTarInsecure(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if !filepath.IsLocal(hdr.Name) {
			return fmt.Errorf("extract: unsafe name %q", hdr.Name)
		}
		path := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, path); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return err
			}
		}
	}
}

// Limits bound the work an archive can cause. Zero values are replaced by
// the defaults in DefaultLimits.
type Limits struct {
	MaxFiles    int   // entries extracted
	MaxFileSize int64 // bytes per file, as actually decompressed
	MaxTotal    int64 // bytes across all files
	MaxRatio    int64 // decompressed/compressed per zip entry
}

// DefaultLimits are conservative starting points; size them per use case.
var DefaultLimits = Limits{MaxFiles: 1000, MaxFileSize: 64 << 20, MaxTotal: 256 << 20, MaxRatio: 100}

// Errors returned by the safe extractors.
var (
	ErrUnsafeName = errors.New("extract: entry name is not local")
	ErrLimit      = errors.New("extract: archive exceeds limits")
)

// Report lists what was extracted and what was deliberately skipped.
type Report struct {
	Files   int
	Bytes   int64
	Skipped []string // symlinks, hard links, devices, FIFOs
}

// localName converts an archive name (always slash-separated) to an OS path
// under the root. Backslashes are refused (the zip format mandates "/", and
// on Windows "\" is a separator), and filepath.Localize rejects "", ".",
// "..", empty elements and absolute paths.
func localName(name string) (string, error) {
	if strings.Contains(name, `\`) {
		return "", fmt.Errorf("%w: %q", ErrUnsafeName, name)
	}
	p, err := filepath.Localize(strings.TrimSuffix(name, "/"))
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrUnsafeName, name)
	}
	return p, nil
}

type extractor struct {
	root *os.Root
	lim  Limits
	rep  Report
}

func newExtractor(dest string, lim Limits) (*extractor, error) {
	d := DefaultLimits
	if lim.MaxFiles == 0 {
		lim.MaxFiles = d.MaxFiles
	}
	if lim.MaxFileSize == 0 {
		lim.MaxFileSize = d.MaxFileSize
	}
	if lim.MaxTotal == 0 {
		lim.MaxTotal = d.MaxTotal
	}
	if lim.MaxRatio == 0 {
		lim.MaxRatio = d.MaxRatio
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return nil, err
	}
	return &extractor{root: root, lim: lim}, nil
}

func (e *extractor) dir(name string) error {
	p, err := localName(name)
	if err != nil {
		return err
	}
	return e.root.MkdirAll(p, 0o750)
}

// file writes one regular file. maxBytes is the tightest of the per-file,
// remaining-total and ratio limits; reading maxBytes+1 detects overflow
// without trusting any size field in the archive header.
func (e *extractor) file(name string, r io.Reader, maxBytes int64) error {
	p, err := localName(name)
	if err != nil {
		return err
	}
	if e.rep.Files >= e.lim.MaxFiles {
		return fmt.Errorf("%w: more than %d files", ErrLimit, e.lim.MaxFiles)
	}
	if err := e.root.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	// O_EXCL: never overwrite, and never open an existing symlink.
	// Mode is fixed: setuid, setgid and world-writable bits from the
	// archive are not reproduced.
	out, err := e.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, maxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxBytes {
		err = fmt.Errorf("%w: %q decompresses to more than %d bytes", ErrLimit, name, maxBytes)
	}
	if err != nil {
		e.root.Remove(p) // do not leave a truncated file behind
		return err
	}
	e.rep.Files++
	e.rep.Bytes += n
	return nil
}

func (e *extractor) budget() int64 {
	return min(e.lim.MaxFileSize, e.lim.MaxTotal-e.rep.Bytes)
}

// ExtractZip extracts zr into dest. It stops at the first unsafe name or
// exceeded limit; dest may then hold a partial result, so extract into a new
// temporary directory and move it into place only on success.
func ExtractZip(zr *zip.Reader, dest string, lim Limits) (Report, error) {
	e, err := newExtractor(dest, lim)
	if err != nil {
		return Report{}, err
	}
	defer e.root.Close()
	if len(zr.File) > e.lim.MaxFiles {
		// The central directory is already parsed; refuse before any work.
		return e.rep, fmt.Errorf("%w: %d entries", ErrLimit, len(zr.File))
	}
	for _, f := range zr.File {
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := e.dir(f.Name); err != nil {
				return e.rep, err
			}
		case mode.IsRegular():
			limit := e.budget()
			if f.CompressedSize64 > 0 && int64(f.CompressedSize64) <= limit/e.lim.MaxRatio {
				limit = int64(f.CompressedSize64) * e.lim.MaxRatio
			}
			rc, err := f.Open()
			if err != nil {
				return e.rep, err
			}
			err = e.file(f.Name, rc, limit)
			rc.Close()
			if err != nil {
				return e.rep, err
			}
		default:
			e.rep.Skipped = append(e.rep.Skipped, f.Name)
		}
	}
	return e.rep, nil
}

// ExtractTar extracts a tar stream into dest with the same policy. A tar
// entry has no per-entry compression, so the ratio limit does not apply;
// for .tar.gz, bound the gzip stream's output as in chapter 22.
func ExtractTar(r io.Reader, dest string, lim Limits) (Report, error) {
	e, err := newExtractor(dest, lim)
	if err != nil {
		return Report{}, err
	}
	defer e.root.Close()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return e.rep, nil
		}
		if err != nil {
			return e.rep, err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			err = e.dir(hdr.Name)
		case tar.TypeReg:
			err = e.file(hdr.Name, tr, e.budget())
		default: // symlinks, hard links, devices, FIFOs, unknown types
			e.rep.Skipped = append(e.rep.Skipped, hdr.Name)
		}
		if err != nil {
			return e.rep, err
		}
	}
}
