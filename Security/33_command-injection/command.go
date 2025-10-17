// Package cmdinject shows what os/exec does and does not protect against.
// exec.Command passes an argv vector straight to the kernel, so shell
// metacharacters in an argument are inert. The bugs that remain are the ones
// the program builds itself: a "sh -c" string assembled from input (CWE-78),
// an attacker-controlled argument that the child parses as an option (CWE-88),
// and an environment inherited wholesale from the parent.
package cmdinject

import (
	"errors"
	"net/url"
	"os/exec"
	"strings"
)

// ErrUnsafeArgument is returned when an argument would be parsed as an
// option by the child process or fails the allowlist.
var ErrUnsafeArgument = errors.New("cmdinject: unsafe argument")

// ShellEchoUnsafe builds a shell command line by concatenation. The input
// becomes shell source code: ";", "&&", "|", "$(...)" and backticks are all
// live. echo stands in for any real program (convert, ffmpeg, git, ...).
func ShellEchoUnsafe(shell, name string) *exec.Cmd {
	return exec.Command(shell, "-c", "echo hello "+name)
}

// ShellEchoSafe keeps the script constant and passes the input as a
// positional parameter. The shell expands "$1" as a single word after
// parsing, so the value is never parsed as code. "sh" fills $0.
//
// Prefer not to use a shell at all; this form exists for the cases where a
// pipeline or redirection genuinely needs one.
func ShellEchoSafe(shell, name string) *exec.Cmd {
	return exec.Command(shell, "-c", `echo hello "$1"`, "sh", name)
}

// CloneUnsafe passes a user-supplied repository URL straight into argv. No
// shell is involved, yet a "URL" such as "--upload-pack=..." is parsed by git
// as an option, which runs an arbitrary program (argument injection, CWE-88;
// compare CVE-2017-1000117 and CVE-2022-24439).
func CloneUnsafe(git, repoURL, dir string) *exec.Cmd {
	return exec.Command(git, "clone", repoURL, dir)
}

// CloneSafe validates both operands and places them after "--", the POSIX
// end-of-options marker, so that even a value which slipped past validation
// is treated as an operand. Validation is still required: "--" does not help
// with programs that ignore it, and a URL like "ext::sh -c ..." is an operand
// that git interprets as a transport.
func CloneSafe(git, repoURL, dir string) (*exec.Cmd, error) {
	if err := ValidateRepoURL(repoURL); err != nil {
		return nil, err
	}
	if err := ValidateOperand(dir); err != nil {
		return nil, err
	}
	return exec.Command(git, "clone", "--", repoURL, dir), nil
}

// ValidateOperand rejects values that a getopt-style parser would treat as an
// option, plus NUL (which the kernel cannot pass in argv) and empty strings.
func ValidateOperand(s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsRune(s, 0) {
		return ErrUnsafeArgument
	}
	return nil
}

// ValidateRepoURL accepts only absolute https URLs with a host and no
// userinfo. Anything else (ssh "-oProxyCommand" hosts, ext::, file://, local
// paths, option-looking strings) is rejected by construction.
func ValidateRepoURL(raw string) error {
	if err := ValidateOperand(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		strings.HasPrefix(u.Hostname(), "-") || u.Opaque != "" {
		return ErrUnsafeArgument
	}
	return nil
}

// FilterEnv returns the entries of environ whose key is in allow. Assign the
// result to exec.Cmd.Env: a nil Env means "inherit everything", including
// tokens and credentials that the parent was given (CWE-526 / CWE-214).
func FilterEnv(environ []string, allow ...string) []string {
	keep := make(map[string]bool, len(allow))
	for _, k := range allow {
		keep[k] = true
	}
	var out []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if ok && keep[k] {
			out = append(out, kv)
		}
	}
	return out
}
