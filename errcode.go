package main

import (
	"errors"
	"fmt"
)

// Error codes (ROADMAP 4.8). Every error result ends with one machine-readable line,
// "[code: X]", so a client can branch on the kind of failure without parsing prose. The prose
// is unchanged and stays the thing a model reads: the denial text still prints the exact
// `allow` command. The set is small on purpose; a client that does not know a code treats it
// as FAILED.
const (
	codePolicyDenied    = "POLICY_DENIED"    // no grant covers the call, or the rate limit
	codeMFARequired     = "MFA_REQUIRED"     // granted, but a second factor is needed first
	codeRollbackPending = "ROLLBACK_PENDING" // an apply awaits uci_confirm or uci_rollback
	codeValidation      = "VALIDATION"       // the request itself is wrong; fix it and retry
	codeNotFound        = "NOT_FOUND"        // the config, package or id asked for is not there
	codeConflict        = "CONFLICT"         // the router changed under the caller; re-read first
	codeNotApplied      = "NOT_APPLIED"      // the router accepted a write, and a re-read does not show it
	codeTimeout         = "TIMEOUT"          // a command outlived its deadline
	codeFailed          = "FAILED"           // anything else
)

// codedError is an error that names its kind. The message is the wrapped error's, untouched,
// so wording that tests and operators already rely on does not move.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

func withCode(code string, err error) error { return &codedError{code: code, err: err} }

// The constructors take fmt.Errorf's arguments, so converting a call site is a rename.
func invalid(format string, a ...any) error {
	return withCode(codeValidation, fmt.Errorf(format, a...))
}
func notFound(format string, a ...any) error { return withCode(codeNotFound, fmt.Errorf(format, a...)) }
func conflict(format string, a ...any) error { return withCode(codeConflict, fmt.Errorf(format, a...)) }
func notApplied(format string, a ...any) error {
	return withCode(codeNotApplied, fmt.Errorf(format, a...))
}
func pending(format string, a ...any) error {
	return withCode(codeRollbackPending, fmt.Errorf(format, a...))
}

// errCode is the code of err, looking through wrapping and errors.Join. A lockout is a refusal,
// not a failure. Anything that never named a code is FAILED, so every error result has one.
func errCode(err error) string {
	var c *codedError
	if errors.As(err, &c) {
		return c.code
	}
	var lock *LockoutError
	if errors.As(err, &lock) {
		return codePolicyDenied
	}
	return codeFailed
}

// codeLine is the last line of an error result. Only a timeout carries advice: the other
// messages already say what to do next.
func codeLine(code string) string {
	if code == codeTimeout {
		return "[code: TIMEOUT; next: retry once, then narrow the request]"
	}
	return "[code: " + code + "]"
}
