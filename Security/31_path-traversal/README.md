# 31. Path Traversal

> **Abstract.** `filepath.Join(base, userInput)` does not confine anything: `Join` cleans its result, which *resolves* `../` instead of rejecting it, so `Join("/srv/files", "../../etc/passwd")` is `/etc/passwd`. `filepath.Clean` is normalisation, not validation, and a string-prefix check on the result accepts sibling directories (`/srv/files-private`). Go 1.20's `filepath.IsLocal` and 1.23's `filepath.Localize` are correct *lexical* checks, but no lexical check sees symbolic links: a link inside the directory leads anywhere. Go 1.24's `os.Root` is the first standard-library API that enforces the boundary at open time, resolving every component relative to a directory handle and refusing `..` and symlinks that leave the root; Go 1.25 extends it with `ReadFile`, `WriteFile`, `MkdirAll`, `RemoveAll`, `Rename`, `Link`, `Symlink`, `Readlink`, `Chmod`, `Chown`, `Lchown` and `Chtimes`.

| | |
|---|---|
| Weaknesses | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'), [CWE-23](https://cwe.mitre.org/data/definitions/23.html) Relative Path Traversal, [CWE-59](https://cwe.mitre.org/data/definitions/59.html) Improper Link Resolution Before File Access ('Link Following') |
| Go packages | `os`, `path/filepath`, `io/fs`, `net/http` |
| Code | [`paths.go`](paths.go), [`serve.go`](serve.go), [`pathsafe_test.go`](pathsafe_test.go) |

## 1. Threat model

A service reads or writes files named by a request: downloads, attachments, templates, per-tenant directories, upload destinations. The attacker controls the name (URL path, form field, archive entry; chapter 32) and possibly the contents of the directory: they may upload a file, or a symlink arrives through an extracted archive, a shared volume, or another tenant. Goals: read secrets outside the directory (keys, `/proc/self/environ`, source), or write there (overwriting configuration, planting code).

## 2. What Go provides

| API | Version | What it guarantees | What it does not |
|---|---|---|---|
| `filepath.Join`, `Clean` | 1.0 | Lexical normalisation | Any confinement; `..` is resolved, not refused |
| `filepath.IsLocal(path)` | 1.20 | Lexically local: not absolute, no escaping `..`, not empty; on Windows no reserved names (`NUL`, `COM1`) | Symlinks |
| `filepath.Localize(path)` | 1.23 | Converts a slash-separated `io/fs`-valid path to an OS path; rejects `.`/`..` elements, and on Windows `\` and reserved names | Symlinks |
| `os.Root`, `os.OpenRoot`, `os.OpenInRoot` | 1.24 | Every operation stays under the directory; `..` and symlinks may not leave it; absolute symlinks are refused | Bind mounts, `/proc` special files, device files (documented limitations) |
| `os.Root` additions | 1.25 | `ReadFile`, `WriteFile`, `MkdirAll`, `RemoveAll`, `Rename`, `Link`, `Symlink`, `Readlink`, `Chmod`, `Chown`, `Lchown`, `Chtimes` | On Unix, `Chmod`/`Chown`/`Chtimes` can race with a file being swapped for a symlink |
| `os.DirFS(dir)` | 1.16 | Rejects invalid `io/fs` names | Documented: follows symlinks out of the tree like `os.Open` |
| `http.FileServer(http.Dir)` | 1.0 | Cleans the URL path rooted at `/` | Follows symlinks |
| `http.FileServerFS(fsys)` | 1.22 | Serves any `fs.FS`; with `root.FS()` (1.24) it inherits the root's guarantees | |

One more trap: `ServeMux` redirects request paths containing `..`, which suggests traversal is handled by the router. It is not. Wildcard values are **unescaped**, so `/files/..%2F..%2Fetc%2Fpasswd` matches `/files/{name...}` without a redirect and `r.PathValue("name")` returns `../../etc/passwd`.

## 3. Insecure pattern

```go
os.ReadFile(filepath.Join(base, r.PathValue("name")))            // ReadJoin

p := filepath.Clean(filepath.Join(base, name))
if !strings.HasPrefix(p, base) { return errBad }                   // ReadCleanPrefix
os.ReadFile(p)                                                     // "../public-private/key"

if !filepath.IsLocal(name) { return errBad }                        // ReadIsLocal
os.ReadFile(filepath.Join(base, name))                             // base/escape -> ../secret
```

The tests build a temporary tree with a secret outside the base, a sibling directory whose name shares the base's prefix, and three symlinks (relative escaping, relative inside, absolute inside), then show which function leaks what: `ReadJoin` and the HTTP handler leak via `../` and `%2F`, the prefix check via the sibling and the symlink, `IsLocal` via the symlink, and `http.FileServer(http.Dir(base))` via the symlink.

## 4. Secure pattern

```go
root, err := os.OpenRoot(base)     // once, at start-up
defer root.Close()

name, err := filepath.Localize(r.PathValue("name"))   // URL path → OS path, 400 if invalid
data, err := root.ReadFile(name)                      // Go 1.25; 404 on any error
```

- **[`ReadInRoot`](paths.go)** — `os.OpenRoot` + `Root.ReadFile`. Names that stay inside (`docs/../hello.txt`, a relative symlink to `docs/readme.txt`) work; everything that leaves fails.
- **[`Download`](serve.go)** — `Localize` first to reject malformed names with a clear 400, then the root for the actual boundary. Error details are not echoed to the client.
- **[`Static`](serve.go)** — `http.FileServerFS(root.FS())`: the standard file server, with every open going through the root.
- **Writes** go through the root too: `root.MkdirAll`, `root.WriteFile` (both Go 1.25) cannot create anything outside it.

Keep the `os.Root` open for the life of the server: it holds a directory handle, so renaming or replacing the directory path afterwards does not redirect it.

## 5. Where the boundary ends

- **The root itself.** `os.Root` confines names *below* a directory; if attackers can write into that directory, they can still overwrite anything inside it. Separate user-writable and application directories.
- **`/proc`, devices and mounts** are explicitly outside `os.Root`'s guarantees; do not root a user-controlled tree at a place where those can appear.
- **Archives** produce names and symlinks at scale; chapter 32 extracts them through `os.Root`.
- **Information leaks.** Distinguishing "not found" from "escapes the root" tells an attacker what exists outside; return the same error.

## 6. Verification

```bash
go test -v ./Security/31_path-traversal/
```

| Test | Shows |
|---|---|
| `TestReadJoinTraversal` | `Join` resolves `../secret.txt` out of the base |
| `TestReadCleanPrefixBypasses` | String-prefix check accepts `../public-private/key.txt` |
| `TestLexicalChecksFollowSymlinks` | Prefix check and `IsLocal` both read the secret through `base/escape` |
| `TestReadIsLocalRejectsLexicalEscapes` | `IsLocal` refuses `..`, empty and absolute names |
| `TestReadInRoot` | Inside paths and inside symlinks work; `..`, escaping symlink, absolute symlink, sibling and absolute names fail |
| `TestIsLocalAndLocalize` | Where the two lexical checks differ (`a/../b`, `a/./b`) |
| `TestDownloadInsecureEncodedSlashes` | Literal `../` is redirected by `ServeMux`; `..%2F` reaches the handler as `../` and leaks |
| `TestDownloadSafe` | Encoded traversal → 400, escaping symlink → 404, no secret in any body |
| `TestFileServerAndSymlinks` | `http.Dir` serves the secret via symlink; `FileServerFS(root.FS())` does not |
| `TestRootWriteMethods` | Go 1.25 `MkdirAll`/`WriteFile`/`RemoveAll` on a root cannot touch the parent directory |

Symlink tests are skipped on Windows.

## 7. Checklist

- [ ] No `filepath.Join(base, userInput)` reaches `os.Open*`, `os.ReadFile`, `os.Create` or `os.Remove*`.
- [ ] Directories that serve or store user-named files are opened once as `os.Root`; all access goes through it.
- [ ] URL-derived names pass `filepath.Localize` (or `IsLocal`) for early rejection, but the root is the control.
- [ ] `http.FileServer(http.Dir(...))` and `os.DirFS` are not used on directories that may contain untrusted symlinks; use `http.FileServerFS(root.FS())`.
- [ ] Errors for missing and forbidden paths are indistinguishable to the client.

## References

- Go Blog — [Traversal-resistant file APIs](https://go.dev/blog/osroot) (2025)
- Go documentation — [`os.Root`](https://pkg.go.dev/os#Root), [`filepath.IsLocal`](https://pkg.go.dev/path/filepath#IsLocal), [`filepath.Localize`](https://pkg.go.dev/path/filepath#Localize), [`os.DirFS`](https://pkg.go.dev/os#DirFS), [`http.FileServerFS`](https://pkg.go.dev/net/http#FileServerFS)
- Release notes — [Go 1.20](https://go.dev/doc/go1.20) (`IsLocal`), [Go 1.23](https://go.dev/doc/go1.23) (`Localize`), [Go 1.24](https://go.dev/doc/go1.24) (`os.Root`), [Go 1.25](https://go.dev/doc/go1.25) (`os.Root` methods)
- OWASP — [Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
