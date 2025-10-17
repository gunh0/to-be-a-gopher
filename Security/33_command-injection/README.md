# 33. Command Injection

> **Abstract.** `os/exec` does not use a shell: `exec.Command(name, args...)` hands an argv vector to the kernel, so `;`, `|`, `$(...)` and backticks inside an argument are inert bytes. Classic shell injection only comes back when a program re-introduces a shell (`sh -c` plus string building). What `os/exec` cannot prevent is **argument injection**: an attacker-chosen operand that begins with `-` is parsed by the child as an option, and options such as `git --upload-pack=` or `ssh -oProxyCommand=` execute programs by design. The remaining exposures are the binary lookup (`PATH`, fixed for the current directory in Go 1.19 with `exec.ErrDot`) and the environment, which a child inherits in full unless `Cmd.Env` says otherwise.

| | |
|---|---|
| Weaknesses | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) OS Command Injection, [CWE-88](https://cwe.mitre.org/data/definitions/88.html) Argument Injection or Modification, [CWE-426](https://cwe.mitre.org/data/definitions/426.html) Untrusted Search Path |
| Go packages | `os/exec`, `net/url` |
| Code | [`command.go`](command.go), [`cmdinject_test.go`](cmdinject_test.go) |

## 1. Threat model

A service shells out to a helper: `git clone` for a user-supplied repository, an image converter for an upload, `tar` for a backup. The attacker controls one argument (a URL, a filename, a branch name) and possibly files in the working directory. Their goal is code execution as the service user, or theft of credentials the service holds in its environment.

## 2. What Go guarantees

| Concern | `system()` / `sh -c` | `exec.Command` |
|---|---|---|
| Metacharacters `; & \| $() `` > <` | Parsed by the shell | Passed literally as part of one argv element |
| Globbing, `~`, `$VAR` expansion | Performed | Not performed |
| Word splitting on spaces | Performed | Not performed: one Go string is one argument |
| Program lookup | Shell searches `PATH` | `exec.LookPath`; since **Go 1.19** a match found via `.` or an empty `PATH` element is refused with `exec.ErrDot` |
| Environment | Inherited | Inherited **when `Cmd.Env == nil`**; otherwise exactly `Cmd.Env` (last duplicate key wins) |

The `os/exec` documentation states it plainly: the package "intentionally does not invoke the system shell and does not expand any glob patterns or handle other expansions, pipelines, or redirections". The Go 1.19 lookup change followed the 2021 [PATH security](https://go.dev/blog/path-security) analysis (CVE-2021-3115 was `go get` running a planted binary from the current directory on Windows). The old behaviour can be restored with `GODEBUG=execerrdot=0`, which should never appear in production configuration.

## 3. Insecure pattern

**Re-introducing the shell.** [`ShellEchoUnsafe`](command.go) builds a script by concatenation:

```go
exec.Command("sh", "-c", "echo hello "+name)
// name = "world; echo INJECTED"  →  two commands run
```

**Argument injection, no shell involved.** [`CloneUnsafe`](command.go) is the shape most Go code actually has:

```go
exec.Command("git", "clone", repoURL, dir)
// repoURL = "--upload-pack=touch /tmp/pwned"  →  git runs the program
```

Each argv element is intact, yet the child's option parser sees `--upload-pack=...` before any operand. The same class covers `ssh -oProxyCommand=`, `curl -o`/`-K`, GNU `tar --checkpoint-action=exec=`, `rsync -e`, `find -exec`. Real cases: CVE-2017-1000117 (git `ssh://-oProxyCommand=...`), CVE-2022-24439 (GitPython `--upload-pack`).

**Inheriting everything.** A `Cmd` with `Env == nil` passes every variable of the parent to the child, including `AWS_SECRET_ACCESS_KEY`, database passwords and CI tokens, to a program that may log its environment, crash-dump it, or be the attacker's (chapter 38).

## 4. Secure pattern

1. **Do not use a shell.** Call the program directly. If a pipeline is needed, build it with two `exec.Cmd`s and `StdoutPipe`, or keep the script constant and pass input as positional parameters ([`ShellEchoSafe`](command.go)):
   ```go
   exec.Command("sh", "-c", `echo hello "$1"`, "sh", name) // $0="sh", $1=name
   ```
2. **Validate operands, then end option parsing.** [`CloneSafe`](command.go) rejects anything starting with `-`, NUL or empty, accepts only `https://host/...` URLs without userinfo, and inserts `--`:
   ```go
   exec.Command(git, "clone", "--", repoURL, dir)
   ```
   `--` is the POSIX end-of-options marker; validation is still required because not every program honours it and some operands are dangerous by themselves (`ext::sh -c ...` is a git transport, `file:///` a local read).
3. **Prefer `--opt=value` over `--opt value`** for flags you set yourself, so a value can never be shifted into a separate option.
4. **Pin the binary.** Use an absolute path from configuration, or resolve once at startup with `exec.LookPath` and treat `exec.ErrDot` as fatal.
5. **Scope the environment.** Set `cmd.Env = FilterEnv(os.Environ(), "PATH", "HOME", ...)` — an allowlist, not a denylist. Use `cmd.Environ()` (Go 1.19) to inspect what a `Cmd` will pass.
6. **Bound execution.** `exec.CommandContext` with a deadline, `Cmd.WaitDelay` (Go 1.20) for children that keep pipes open, and limited output buffers (chapter 22).

## 5. Where the guarantee ends

- **Windows.** There is no argv at the kernel level: Go joins arguments into one command line with `syscall.EscapeArg`, and each program re-parses it. `.bat`/`.cmd` files run through `cmd.exe`, which has its own metacharacters (the 2024 "BatBadBut" disclosure). Never pass untrusted arguments to batch files.
- **The child is a second interpreter.** `git -c`, `ffmpeg` filter graphs, ImageMagick coders, `awk` programs and `sed` scripts are languages. Allowlisting the *value* matters more than its position.
- **`--` is per-program.** Some tools treat `--` as an operand or ignore it; read the manual of the exact binary you run.
- **Explicit relative paths** (`./tool`, `bin/tool`) bypass `PATH` entirely and still resolve against the working directory; `ErrDot` only covers lookups through `PATH`.
- **Environment-driven behaviour.** `LD_PRELOAD`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `PAGER`, `EDITOR` change what a child executes. An allowlisted environment closes these too.
- **File descriptors.** `Cmd.ExtraFiles` and inherited stdio give the child access to whatever they point to; the Go runtime opens files with `O_CLOEXEC`, but descriptors created by cgo or `syscall` may not be.

## 6. Verification

```bash
go test -v ./Security/33_command-injection/
```

The tests never run git or a shell payload. Argument handling is observed with a **helper process**: the test binary re-executes itself (`os.Args[0]`) with `CMDINJECT_HELPER` set and prints the argv it received, classified getopt-style as `option` or `operand`. Only the two shell tests invoke `sh`, with `echo`.

| Test | Shows |
|---|---|
| `TestShellEchoUnsafeRunsInjectedCommand` | `sh -c` + concatenation executes a second command |
| `TestShellEchoSafeKeepsInputAsData` | The same input as `"$1"` is printed, not executed |
| `TestExecCommandHasNoShell` | `;`, `$(...)` and backticks arrive as literal argv elements |
| `TestCloneUnsafeArgumentInjection` | A "URL" lands in option position without any shell |
| `TestCloneSafeEndOfOptions` | After `--`, the child treats every value as an operand |
| `TestCloneSafeRejects` | `-`-prefixed values, `ssh://-o…`, `ext::`, `file://`, `http://`, userinfo, NUL |
| `TestLookPathRefusesCurrentDirectory` | `PATH=.` lookup yields `exec.ErrDot` from `LookPath` and `Command` |
| `TestNilEnvInheritsSecrets` | `Env == nil` leaks a token to the child; `FilterEnv` does not |
| `ExampleCloneUnsafe` | The argv that reaches git, and the safe constructor refusing it |

## 7. Checklist

- [ ] No `sh -c`, `bash -c` or `cmd /c` with a string containing input; if a shell is unavoidable, input goes in positional parameters.
- [ ] Every untrusted argument is validated (allowlist) and placed after `--`.
- [ ] Program paths are absolute or resolved once at startup; `exec.ErrDot` is not suppressed.
- [ ] `Cmd.Env` is set explicitly from an allowlist.
- [ ] Children run with `CommandContext`, a deadline and bounded output.
- [ ] gosec G204 (subprocess launched with variable) findings are triaged, not silenced (chapter 41).

## References

- Package [`os/exec`](https://pkg.go.dev/os/exec) — package overview, "Executables in the current directory", [`Cmd.Env`](https://pkg.go.dev/os/exec#Cmd), [`ErrDot`](https://pkg.go.dev/os/exec#pkg-variables)
- Go Blog — [Command PATH security in Go](https://go.dev/blog/path-security) (2021); [Go 1.19 release notes](https://go.dev/doc/go1.19)
- POSIX — [Utility Syntax Guidelines](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap12.html), guideline 10 (`--`)
- [CVE-2017-1000117](https://nvd.nist.gov/vuln/detail/CVE-2017-1000117), [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439), [CVE-2021-3115](https://nvd.nist.gov/vuln/detail/CVE-2021-3115)
- OWASP — [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
