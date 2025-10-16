# 32. Archive Extraction (Zip Slip & Bombs)

> **Abstract.** An archive is a list of file names, link targets, modes and sizes chosen by its author, so extracting one is path traversal (chapter 31) and decompression amplification (chapter 22) at once, plus a twist of its own: an entry can be a **symlink** that redirects a later entry's write, and each name on its own looks harmless. Go's `archive/zip` and `archive/tar` do not protect the extractor by default. Since Go 1.20 they *can* flag non-local names with `ErrInsecurePath`, but only when `GODEBUG=zipinsecurepath=0` / `tarinsecurepath=0` is set, and even then `zip.NewReader` returns a fully usable reader alongside the error and `tar.Reader.Next` returns the header. A safe extractor writes only regular files and directories, through an `os.Root`, with `O_EXCL`, fixed permissions, and limits on entry count, per-file size, total size and compression ratio measured on the bytes actually decompressed.

| | |
|---|---|
| Weaknesses | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'), [CWE-409](https://cwe.mitre.org/data/definitions/409.html) Improper Handling of Highly Compressed Data (Data Amplification), [CWE-59](https://cwe.mitre.org/data/definitions/59.html) Improper Link Resolution Before File Access ('Link Following') |
| Go packages | `archive/zip`, `archive/tar`, `os`, `path/filepath`, `io` |
| Code | [`extract.go`](extract.go), [`extract_test.go`](extract_test.go) |

## 1. Threat model

A service accepts archives from users or third parties: plugin uploads, document formats that are zip containers (`.docx`, `.jar`, `.apk`), CI artifacts, container layers, backups. The attacker builds the archive byte by byte: names with `../` or absolute paths, backslashes, symlink and hard-link entries, setuid modes, headers whose sizes lie, millions of entries, and highly compressible content. Goals: write outside the extraction directory (overwrite code or configuration, drop a cron job or SSH key), read files through links, or exhaust disk, memory, inodes or CPU.

## 2. What the standard library does

| Behaviour | `archive/zip` | `archive/tar` |
|---|---|---|
| Path validation by default | None | None |
| Opt-in check (Go 1.20) | `GODEBUG=zipinsecurepath=0`: `NewReader`/`OpenReader` return the reader **and** `ErrInsecurePath` if any name is non-local (`filepath.IsLocal`) or contains `\` | `GODEBUG=tarinsecurepath=0`: `Next` returns the header **and** `ErrInsecurePath` for a non-local name |
| Symlinks | A file entry with `ModeSymlink`; the content is the target | `TypeSymlink` / `TypeLink` with `Linkname`; never validated |
| Sizes | Header sizes are declarations: reading past the declared size returns `ErrFormat` (fewer bytes: `io.ErrUnexpectedEOF`), but a declared 4 GiB is honoured | `Header.Size` bounds reads of that entry; no total limit |
| Entry count | `NewReader` parses the whole central directory up front | Streaming; unbounded |

The `GODEBUG` setting can be applied per binary with a `//go:debug zipinsecurepath=0` line in the main package or a `godebug` block in `go.mod` (Go 1.23). The package documentation states a future release may enable the check by default. Either way it is a tripwire, not an extractor: it says nothing about symlinks, sizes or modes, and code that ignores the error proceeds with the same entries.

## 3. Insecure pattern

```go
for _, f := range zr.File {
	path := filepath.Join(dest, f.Name)          // "../../x" escapes: Zip Slip
	out, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, f.Mode()) // setuid bits from the archive
	io.Copy(out, rc)                             // no size limit
}

// tar, with an IsLocal check that looks sufficient:
//   entry 1: "link"             -> symlink to /etc/cron.d
//   entry 2: "link/job"         -> regular file, name is local, write follows the link
```

[`ExtractZipInsecure`](extract.go) and [`ExtractTarInsecure`](extract.go). Both are exploited in the tests with archives built in memory: `../slipped.txt` appears in the parent of the destination, and the symlink-then-file pair writes into a directory outside it even though every name passes `filepath.IsLocal`.

## 4. Secure pattern

[`ExtractZip`](extract.go) and [`ExtractTar`](extract.go):

| Control | How |
|---|---|
| Names | Reject `\`; `filepath.Localize` rejects `..`, `.`, empty elements and absolute paths; any failure aborts with `ErrUnsafeName` |
| Containment | All writes through `os.OpenRoot(dest)`: `Root.MkdirAll` (Go 1.25) and `Root.OpenFile`; a pre-existing symlink in `dest` cannot be followed out |
| Entry types | Only regular files and directories; symlinks, hard links, devices and FIFOs are skipped and listed in `Report.Skipped` |
| Overwrites | `O_CREATE\|O_EXCL`: never replace an existing file, never open through a link |
| Modes | Fixed `0o640`/`0o750`; setuid/setgid/world-writable bits are not reproduced |
| Entry count | `len(zr.File)` checked before any work; tar counted while streaming |
| Sizes | Copy at most `limit+1` bytes per file and fail if reached; `limit = min(MaxFileSize, MaxTotal − written, CompressedSize × MaxRatio)`; header sizes are never trusted for the decision |
| Cleanup | A file that hits a limit is removed; extract into a fresh temporary directory and move it into place only on success |

For `.tar.gz`, wrap the gzip reader with a decompressed-size limit (chapter 22's `GunzipLimited` pattern) before `tar.NewReader`; `MaxTotal` then bounds what reaches disk.

## 5. Where the extractor ends

- **Links are skipped, not reproduced.** If the archive format legitimately needs symlinks, create them only after all files, only with relative targets that resolve inside the root, and still never write through them.
- **Nested archives** (a zip inside a zip) multiply limits; apply a global budget, not a per-archive one.
- **Zip parser differentials**: the local file header and the central directory can disagree on name and size; `archive/zip` reads names from the central directory. Other tools (or a scanner that approved the file) may read the local headers instead.
- **Inodes and directory depth** are resources too: a million empty directories passes byte limits. Count directories against `MaxFiles` if that matters.

## 6. Verification

```bash
go test -v ./Security/32_archive-extraction/
```

| Test | Shows |
|---|---|
| `TestZipSlipInsecure` | `../slipped.txt` written outside the destination |
| `TestTarSymlinkThenFileInsecure` | Symlink entry plus `link/planted.txt` writes outside, despite `IsLocal` on both names |
| `TestExtractZipRejectsTraversal` | `../`, nested `../../`, absolute, backslash, `//` and empty names → `ErrUnsafeName`, nothing outside |
| `TestExtractTarSkipsLinks` | The same symlink pair: link skipped and reported, file lands inside |
| `TestExtractIntoPreexistingSymlink` | A link already present in `dest` is not followed (`os.Root`) |
| `TestExtractZipModeBitsIgnored` | setuid `0o4777` entry is written without setuid, exec or world-write bits |
| `TestLimits` | Entry count, per-file size, total size and a 512 KiB ~1000:1 entry against `MaxRatio` 100; the failing entry leaves no partial file |
| `TestErrInsecurePathIsOptIn` | Default: no error. `zipinsecurepath=0`: `ErrInsecurePath` *and* a reader with the entry; `tarinsecurepath=0`: error *and* header |
| `ExampleExtractZip` | One good file extracted, then `../escape.txt` stops the run |

Symlink and permission tests are skipped on Windows.

## 7. Checklist

- [ ] Archive names never reach `filepath.Join` + `os.Create`; extraction goes through `os.Root`.
- [ ] Only regular files and directories are materialised; links, devices and FIFOs are skipped or rejected.
- [ ] Files are created with `O_EXCL` and fixed permissions.
- [ ] Entry count, per-file size, total size and compression ratio are limited using bytes actually read.
- [ ] Extraction happens in a fresh directory that is discarded on failure.
- [ ] `GODEBUG=zipinsecurepath=0`/`tarinsecurepath=0` (or a `godebug` block in `go.mod`) is set as defence in depth, and `ErrInsecurePath` is treated as fatal.

## References

- Go documentation — [`zip.NewReader`](https://pkg.go.dev/archive/zip#NewReader), [`zip.ErrInsecurePath`](https://pkg.go.dev/archive/zip#pkg-variables), [`tar.Reader.Next`](https://pkg.go.dev/archive/tar#Reader.Next), [`os.Root`](https://pkg.go.dev/os#Root); [Go 1.20 release notes](https://go.dev/doc/go1.20) (`ErrInsecurePath`); [Go, Backwards Compatibility, and GODEBUG](https://go.dev/doc/godebug)
- Snyk — [Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability) (2018)
- David Fifield — [A better zip bomb](https://www.bamsoftware.com/hacks/zipbomb/) (WOOT 2019), overlapping-entry bombs and parser differentials
- OWASP — [File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
