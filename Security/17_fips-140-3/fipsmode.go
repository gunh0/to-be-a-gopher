// Package fipsmode is a startup policy gate for the Go Cryptographic Module's
// FIPS 140-3 mode (Go 1.24+): a service that must run in FIPS mode refuses to
// start when it is not, instead of logging a warning nobody reads.
package fipsmode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"errors"
	"fmt"
)

// Status describes the process's FIPS 140-3 state.
type Status struct {
	// Enabled is crypto/fips140.Enabled(): GODEBUG fips140=on or only, either
	// from the environment or from the binary's default (GOFIPS140 at build
	// time, a godebug line in go.mod, or //go:debug in package main).
	Enabled bool
	// Enforcing reports fips140=only, where non-approved algorithms fail.
	// Go 1.25 has no API for this, so it is probed: cipher.NewGCM (caller-
	// supplied nonces) is refused only in that mode.
	Enforcing bool
}

// Current reports the running process's status. The fips140 setting is read
// once at startup; changing GODEBUG afterwards has no effect.
func Current() Status {
	return Status{Enabled: fips140.Enabled(), Enforcing: probeEnforcing()}
}

func probeEnforcing() bool {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		return false
	}
	_, err = cipher.NewGCM(block)
	return err != nil
}

// ErrFIPSRequired is returned by Check when policy requires FIPS mode and the
// process is not in it.
var ErrFIPSRequired = errors.New("fipsmode: FIPS 140-3 mode required but not enabled")

// Policy is the deployment's compliance requirement, typically from config.
type Policy struct {
	RequireFIPS    bool // the module must be in FIPS mode (fips140=on or only)
	RequireEnforce bool // additionally fips140=only
}

// Check is the secure startup gate. Call it first in main and exit on error:
// a compliance requirement that only produces a log line is not enforced
// (CWE-1188: the insecure default wins whenever someone forgets a flag).
func (p Policy) Check(s Status) error {
	if p.RequireFIPS && !s.Enabled {
		return fmt.Errorf("%w: rebuild with GOFIPS140=v1.0.0 or run with GODEBUG=fips140=on", ErrFIPSRequired)
	}
	if p.RequireEnforce && !s.Enforcing {
		return fmt.Errorf("%w: GODEBUG=fips140=only expected", ErrFIPSRequired)
	}
	return nil
}

// CheckUnsafe is the common anti-pattern: notice the problem, warn, carry on.
// The service then runs with non-validated cryptography while every dashboard
// and audit document says it is FIPS compliant.
func (p Policy) CheckUnsafe(s Status, logf func(format string, args ...any)) {
	if p.RequireFIPS && !s.Enabled {
		logf("WARNING: FIPS mode is not enabled")
	}
}
