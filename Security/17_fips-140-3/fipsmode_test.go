package fipsmode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// report is what a child process observes about its own crypto behaviour.
type report struct {
	Status
	PolicyErr         string // Policy{RequireFIPS: true}.Check
	GCMCallerNonceErr string // cipher.NewGCM
	GCMRandomNonceErr string // cipher.NewGCMWithRandomNonce
	MD5Err            string // md5.New().Write
	SHA256Err         string
	XChaChaErr        string // golang.org/x/crypto, outside the module
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func observe() report {
	r := report{Status: Current()}
	r.PolicyErr = errString(Policy{RequireFIPS: true}.Check(r.Status))

	block, _ := aes.NewCipher(make([]byte, 32))
	_, err := cipher.NewGCM(block)
	r.GCMCallerNonceErr = errString(err)
	_, err = cipher.NewGCMWithRandomNonce(block)
	r.GCMRandomNonceErr = errString(err)
	_, err = md5.New().Write([]byte("x"))
	r.MD5Err = errString(err)
	_, err = sha256.New().Write([]byte("x"))
	r.SHA256Err = errString(err)
	_, err = chacha20poly1305.NewX(make([]byte, 32))
	r.XChaChaErr = errString(err)
	return r
}

const childEnv = "FIPSMODE_CHILD"

// TestMain lets the test binary double as the child process: when childEnv
// is set it prints a JSON report and exits without running tests.
func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		json.NewEncoder(os.Stdout).Encode(observe())
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// child re-executes os.Args[0] with the given GODEBUG. fips140 is fixed at
// process start, so a subprocess is the only way to observe each mode.
func child(t *testing.T, godebug string) report {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0])
	cmd.Env = append(os.Environ(), childEnv+"=1", "GODEBUG="+godebug)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child GODEBUG=%s: %v\n%s", godebug, err, out)
	}
	var r report
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("child output %q: %v", out, err)
	}
	return r
}

func TestModes(t *testing.T) {
	tests := []struct {
		godebug             string
		enabled, enforcing  bool
		policyOK            bool
		gcmCallerNonceFails bool
		md5Fails            bool
	}{
		{"fips140=off", false, false, false, false, false},
		{"fips140=on", true, false, true, false, false},
		{"fips140=only", true, true, true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.godebug, func(t *testing.T) {
			t.Parallel()
			r := child(t, tt.godebug)
			if r.Enabled != tt.enabled || r.Enforcing != tt.enforcing {
				t.Errorf("status = %+v, want enabled=%v enforcing=%v", r.Status, tt.enabled, tt.enforcing)
			}
			if (r.PolicyErr == "") != tt.policyOK {
				t.Errorf("policy error = %q, want ok=%v", r.PolicyErr, tt.policyOK)
			}
			if (r.GCMCallerNonceErr != "") != tt.gcmCallerNonceFails {
				t.Errorf("NewGCM error = %q", r.GCMCallerNonceErr)
			}
			if (r.MD5Err != "") != tt.md5Fails {
				t.Errorf("md5 error = %q", r.MD5Err)
			}
			// Approved algorithms work in every mode.
			if r.GCMRandomNonceErr != "" || r.SHA256Err != "" {
				t.Errorf("approved algorithm failed: %+v", r)
			}
			// x/crypto is outside the module boundary: fips140=only does not
			// stop it, so "only" is not a complete inventory of what runs.
			if r.XChaChaErr != "" {
				t.Errorf("x/crypto XChaCha20-Poly1305 error = %q", r.XChaChaErr)
			}
		})
	}
}

func TestSettingIsFixedAtStartup(t *testing.T) {
	before := Current()
	t.Setenv("GODEBUG", "fips140=on")
	if Current() != before {
		t.Fatal("changing GODEBUG at runtime must not change FIPS mode")
	}
}

func TestPolicyCheck(t *testing.T) {
	tests := []struct {
		policy Policy
		status Status
		ok     bool
	}{
		{Policy{}, Status{}, true},
		{Policy{RequireFIPS: true}, Status{}, false},
		{Policy{RequireFIPS: true}, Status{Enabled: true}, true},
		{Policy{RequireFIPS: true, RequireEnforce: true}, Status{Enabled: true}, false},
		{Policy{RequireFIPS: true, RequireEnforce: true}, Status{Enabled: true, Enforcing: true}, true},
	}
	for _, tt := range tests {
		err := tt.policy.Check(tt.status)
		if (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrFIPSRequired)) {
			t.Errorf("%+v.Check(%+v) = %v, want ok=%v", tt.policy, tt.status, err, tt.ok)
		}
	}
}

func TestCheckUnsafeOnlyWarns(t *testing.T) {
	var logged []string
	Policy{RequireFIPS: true}.CheckUnsafe(Status{}, func(f string, a ...any) {
		logged = append(logged, fmt.Sprintf(f, a...))
	})
	// The process keeps running: the only trace is one log line.
	if len(logged) != 1 || !strings.Contains(logged[0], "WARNING") {
		t.Fatalf("logged %q", logged)
	}
}

func ExamplePolicy_Check() {
	err := Policy{RequireFIPS: true}.Check(Status{Enabled: false})
	fmt.Println(err)
	// Output:
	// fipsmode: FIPS 140-3 mode required but not enabled: rebuild with GOFIPS140=v1.0.0 or run with GODEBUG=fips140=on
}
