package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

// ErrSecretSource is returned when a secret source is missing or unsafe.
var ErrSecretSource = errors.New("secrets: unsafe or missing secret source")

// MaxSecretFile bounds how much FromFile reads.
const MaxSecretFile = 64 << 10

// FromEnv reads key from the environment and then removes it from the
// process environment, so child processes started with a nil exec.Cmd.Env
// (which inherit os.Environ) do not receive it (chapter 33). On Linux the
// original value remains visible in /proc/<pid>/environ to the same user;
// prefer files or a secret manager for anything long-lived.
func FromEnv(key string) (Secret, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return Secret{}, fmt.Errorf("%w: %s not set", ErrSecretSource, key)
	}
	if err := os.Unsetenv(key); err != nil {
		return Secret{}, err
	}
	return New(v), nil
}

// FromFile reads a secret from a file such as a mounted Kubernetes or Docker
// secret. On Unix it refuses files that are readable or writable by group or
// others, and it trims one trailing newline (editors add one).
func FromFile(path string) (Secret, error) {
	f, err := os.Open(path)
	if err != nil {
		return Secret{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Secret{}, err
	}
	if !fi.Mode().IsRegular() {
		return Secret{}, fmt.Errorf("%w: %s is not a regular file", ErrSecretSource, path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return Secret{}, fmt.Errorf("%w: %s has mode %v", ErrSecretSource, path, fi.Mode().Perm())
	}
	if fi.Size() > MaxSecretFile {
		return Secret{}, fmt.Errorf("%w: %s too large", ErrSecretSource, path)
	}
	buf := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		clear(buf)
		return Secret{}, err
	}
	trimmed := bytes.TrimSuffix(bytes.TrimSuffix(buf, []byte("\n")), []byte("\r"))
	s := FromBytes(trimmed)
	clear(buf) // FromBytes cleared only the trimmed view
	return s, nil
}
