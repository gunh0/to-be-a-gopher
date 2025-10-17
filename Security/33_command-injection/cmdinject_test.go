package cmdinject

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// helperEnv switches the test binary into "fake command" mode. Re-executing
// os.Args[0] gives the tests a child process that is harmless, portable and
// reports exactly what it received, instead of running real git or a shell
// payload.
const helperEnv = "CMDINJECT_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "argv":
		// Behave like a getopt-style program: everything before "--" that
		// starts with "-" is an option, the rest are operands.
		opts := true
		for _, a := range os.Args[1:] {
			switch {
			case opts && a == "--":
				opts = false
			case opts && strings.HasPrefix(a, "-"):
				fmt.Printf("option  %s\n", a)
			default:
				fmt.Printf("operand %s\n", a)
			}
		}
		os.Exit(0)
	case "env":
		fmt.Print(os.Getenv(os.Args[1]))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runFake runs cmd (whose program is the test binary) in helper mode and
// returns its output lines.
func runFake(t *testing.T, cmd *exec.Cmd, mode string) []string {
	t.Helper()
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	// atexit_sleep_ms=0: a -race child otherwise sleeps 1 s before exiting.
	cmd.Env = append(cmd.Env, helperEnv+"="+mode, "GORACE=atexit_sleep_ms=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

func needShell(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell available")
	}
	return sh
}

const shellPayload = "world; echo INJECTED"

func TestShellEchoUnsafeRunsInjectedCommand(t *testing.T) {
	out, err := ShellEchoUnsafe(needShell(t), shellPayload).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "hello world\nINJECTED\n" {
		t.Fatalf("output = %q, want a second, injected command", got)
	}
}

func TestShellEchoSafeKeepsInputAsData(t *testing.T) {
	out, err := ShellEchoSafe(needShell(t), shellPayload).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "hello "+shellPayload+"\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestExecCommandHasNoShell(t *testing.T) {
	// The same payload handed to exec.Command directly is one argv element.
	got := runFake(t, exec.Command(os.Args[0], shellPayload, "$(id)", "`id`"), "argv")
	want := []string{"operand " + shellPayload, "operand $(id)", "operand `id`"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

const optionPayload = "--upload-pack=touch /tmp/pwned"

func TestCloneUnsafeArgumentInjection(t *testing.T) {
	got := runFake(t, CloneUnsafe(os.Args[0], optionPayload, "dst"), "argv")
	if !slices.Contains(got, "option  "+optionPayload) {
		t.Fatalf("argv = %q, want the URL parsed as an option", got)
	}
}

func TestCloneSafeEndOfOptions(t *testing.T) {
	cmd, err := CloneSafe(os.Args[0], "https://example.com/org/repo.git", "dst")
	if err != nil {
		t.Fatal(err)
	}
	got := runFake(t, cmd, "argv")
	want := []string{"operand clone", "operand https://example.com/org/repo.git", "operand dst"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
}

func TestCloneSafeRejects(t *testing.T) {
	tests := []struct{ url, dir string }{
		{optionPayload, "dst"},
		{"-oProxyCommand=id", "dst"},
		{"ssh://-oProxyCommand=id/x", "dst"},
		{"ext::sh -c id", "dst"},
		{"file:///etc", "dst"},
		{"http://example.com/repo.git", "dst"},
		{"https://user:pw@example.com/repo.git", "dst"},
		{"https:///repo.git", "dst"},
		{"https://example.com/repo.git", "--template=/tmp/x"},
		{"https://example.com/repo.git", ""},
		{"https://example.com/repo.git", "a\x00b"},
	}
	for _, tt := range tests {
		if _, err := CloneSafe("git", tt.url, tt.dir); !errors.Is(err, ErrUnsafeArgument) {
			t.Errorf("CloneSafe(%q, %q) err = %v, want ErrUnsafeArgument", tt.url, tt.dir, err)
		}
	}
}

func TestLookPathRefusesCurrentDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH semantics differ on Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cmdinject-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".") // "." or an empty element in PATH: a planted binary

	if _, err := exec.LookPath("cmdinject-tool"); !errors.Is(err, exec.ErrDot) {
		t.Fatalf("LookPath err = %v, want exec.ErrDot", err)
	}
	if cmd := exec.Command("cmdinject-tool"); !errors.Is(cmd.Err, exec.ErrDot) {
		t.Fatalf("Command.Err = %v, want exec.ErrDot", cmd.Err)
	}
	// A name containing a separator never consults PATH: an explicit choice.
	if p, err := exec.LookPath("./cmdinject-tool"); err != nil || p != "./cmdinject-tool" {
		t.Fatalf("LookPath(./cmdinject-tool) = %q, %v", p, err)
	}
}

func TestNilEnvInheritsSecrets(t *testing.T) {
	t.Setenv("CMDINJECT_API_TOKEN", "tok_4f2c9a71")

	inherit := exec.Command(os.Args[0], "CMDINJECT_API_TOKEN") // Env == nil
	if got := runFake(t, inherit, "env"); got[0] != "tok_4f2c9a71" {
		t.Fatalf("child saw %q, want the inherited token", got)
	}

	scoped := exec.Command(os.Args[0], "CMDINJECT_API_TOKEN")
	scoped.Env = FilterEnv(os.Environ(), "PATH", "HOME")
	if got := runFake(t, scoped, "env"); got[0] != "" {
		t.Fatalf("child saw %q, want no token", got)
	}
}

func TestFilterEnv(t *testing.T) {
	env := []string{"PATH=/bin", "AWS_SECRET_ACCESS_KEY=x", "HOME=/home/u", "BROKEN", "PATHX=1"}
	got := FilterEnv(env, "PATH", "HOME")
	if want := []string{"PATH=/bin", "HOME=/home/u"}; !slices.Equal(got, want) {
		t.Fatalf("FilterEnv = %q, want %q", got, want)
	}
}

func ExampleCloneUnsafe() {
	cmd := CloneUnsafe("git", "--upload-pack=touch /tmp/pwned", "dst")
	fmt.Printf("%q\n", cmd.Args)
	cmd, err := CloneSafe("git", "--upload-pack=touch /tmp/pwned", "dst")
	fmt.Println(cmd == nil, err)
	// Output:
	// ["git" "clone" "--upload-pack=touch /tmp/pwned" "dst"]
	// true cmdinject: unsafe argument
}
