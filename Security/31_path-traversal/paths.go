// Package pathsafe compares ways of opening a user-named file under a base
// directory: string joining, Clean plus a prefix check, filepath.IsLocal
// (Go 1.20) and filepath.Localize (Go 1.23), and os.Root (Go 1.24), the only
// one that also stops symbolic links from leading out of the directory.
package pathsafe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotLocal is returned for names that are absolute, contain "..", or are
// otherwise not confined to the base directory.
var ErrNotLocal = errors.New("pathsafe: name escapes the base directory")

// ReadJoin is the textbook bug (CWE-22): filepath.Join cleans the result,
// which resolves "../" segments instead of rejecting them, so
// Join("/srv/files", "../../etc/passwd") is "/etc/passwd".
func ReadJoin(base, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(base, name))
}

// ReadCleanPrefix is the common "fix": clean, then check the prefix. Cleaning
// is lexical normalisation, not a security check, and a string prefix is not
// a path prefix: base "/srv/files" accepts "/srv/files-private/key". It
// also follows symlinks inside base to anywhere.
func ReadCleanPrefix(base, name string) ([]byte, error) {
	p := filepath.Clean(filepath.Join(base, name))
	if !strings.HasPrefix(p, filepath.Clean(base)) {
		return nil, ErrNotLocal
	}
	return os.ReadFile(p)
}

// ReadIsLocal rejects non-local names with filepath.IsLocal (Go 1.20):
// absolute paths, "..", empty names, and on Windows reserved names such as
// NUL. The check is purely lexical: a symlink inside base that points
// outside (CWE-59) is still followed.
func ReadIsLocal(base, name string) ([]byte, error) {
	if !filepath.IsLocal(name) {
		return nil, ErrNotLocal
	}
	return os.ReadFile(filepath.Join(base, name))
}

// ReadInRoot opens base as an os.Root and reads name inside it. Every path
// component is resolved relative to the directory handle, ".." cannot leave
// the root, and symbolic links are followed only while they stay inside it
// (absolute symlinks are refused outright). Root.ReadFile is new in Go 1.25;
// on 1.24, use root.Open and io.ReadAll.
func ReadInRoot(base, name string) ([]byte, error) {
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}
