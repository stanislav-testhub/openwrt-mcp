package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Error codes (ROADMAP 4.8). Every error result ends with one machine-readable line
// "[code: X]" so a client can branch on the kind of failure without parsing prose. The
// prose itself is unchanged: the denial text still prints the exact `allow` command.
//
// The expected strings are written out here, not taken from the constants under test.

func TestPolicyDenialEndsWithItsCode(t *testing.T) {
	s := testServer(t, "")
	cs := connectClient(t, s, "claude-code")
	out, isErr := callText(t, cs, "system_status", nil)
	if !isErr || !strings.HasSuffix(out, "\n[code: POLICY_DENIED]") {
		t.Errorf("want the denial to end with its code, got:\n%s", out)
	}
	if !strings.Contains(out, "openwrt-mcp allow claude-code system_status") {
		t.Errorf("the code line must not replace the actionable text:\n%s", out)
	}
}

func TestMFARefusalEndsWithItsCode(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, "\nconfig policy\n\toption client 'm'\n\tlist tools 'service_list'\n\tlist scopes '*'\n"+
		"\tlist mfa_tools 'service_list'\n")
	cs := connectClient(t, s, "m")
	out, isErr := callText(t, cs, "service_list", nil)
	if !isErr || !strings.HasSuffix(out, "\n[code: MFA_REQUIRED]") || !strings.Contains(out, "mfa_unlock") {
		t.Errorf("want an MFA refusal ending with its code and still naming mfa_unlock, got:\n%s", out)
	}
}

func TestBadArgumentEndsWithValidationCode(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, "\nconfig policy\n\toption client 'c'\n\tlist tools 'net_diag'\n\tlist scopes '*'\n")
	cs := connectClient(t, s, "c")
	out, isErr := callText(t, cs, "net_diag", map[string]any{"action": "ping", "target": "example.org", "iface": "bad iface!"})
	if !isErr || !strings.Contains(out, `bad iface "bad iface!"`) || !strings.HasSuffix(out, "\n[code: VALIDATION]") {
		t.Errorf("want the old message plus VALIDATION, got:\n%s", out)
	}
}

func TestHandlerErrorsCarryTheirCode(t *testing.T) {
	ctx := context.Background()
	staleRev := map[string]string{"dhcp": "000000000000"}
	cases := []struct {
		name string
		run  func(t *testing.T) error
		want string
	}{
		{"stale revision", func(t *testing.T) error {
			s, _, _ := applyFixture(t)
			_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: leaseChanges, ExpectedRevisions: staleRev})
			return err
		}, "CONFLICT"},
		{"second apply while one awaits confirmation", func(t *testing.T) error {
			s, _, _ := applyFixture(t)
			if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: leaseChanges, Timeout: 60}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.uciRollbackNow(ctx, firstToken(s)) })
			_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: leaseChanges, Timeout: 60})
			return err
		}, "ROLLBACK_PENDING"},
		{"config that does not exist", func(t *testing.T) error {
			s, _, _ := applyFixture(t)
			_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: []UCIChange{
				{Config: "nosuch", Section: "x", Option: "y", Value: "1"}}})
			return err
		}, "NOT_FOUND"},
		{"empty change list", func(t *testing.T) error {
			s, _, _ := applyFixture(t)
			_, _, err := s.uciApply(ctx, "c", uciApplyIn{})
			return err
		}, "VALIDATION"},
		{"bad option name", func(t *testing.T) error {
			s, _, _ := applyFixture(t)
			_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: []UCIChange{
				{Config: "dhcp", Section: "lan", Option: "bad name!", Value: "1"}}})
			return err
		}, "VALIDATION"},
		{"unknown pkg_query action", func(t *testing.T) error {
			newFakeRouter(t)
			_, _, err := pkgQuery(ctx, pkgQueryIn{Action: "frobnicate"})
			return err
		}, "VALIDATION"},
		{"expected revision of a config that does not exist", func(t *testing.T) error {
			applyFixture(t)
			return checkRevisions(map[string]string{"nosuch": "000000000000"})
		}, "NOT_FOUND"},
		{"command past its deadline", func(t *testing.T) error {
			t.Setenv("OPENWRT_MCP_HELPER", "sleep")
			_, err := run(ctx, 300*time.Millisecond, helperArgv()...)
			return err
		}, "TIMEOUT"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errCode(err); got != c.want {
				t.Errorf("errCode = %q, want %q (error: %v)", got, c.want, err)
			}
		})
	}
}

// A code survives wrapping, and anything that never named one reports FAILED, so a client can
// rely on every error result having a code.
func TestErrCodeSurvivesWrappingAndFallsBackToFailed(t *testing.T) {
	inner := fmt.Errorf("x")
	if got := errCode(fmt.Errorf("outer: %w", invalid("bad thing %d", 3))); got != "VALIDATION" {
		t.Errorf("wrapped code lost: %q", got)
	}
	if got := errCode(inner); got != "FAILED" {
		t.Errorf("an uncoded error reported %q, want FAILED", got)
	}
	if got := errCode(errors.Join(errors.New("a"), notFound("no %s", "b"))); got != "NOT_FOUND" {
		t.Errorf("joined code lost: %q", got)
	}
}

// Wording that existing callers and tests rely on is untouched by adding a code.
func TestCodedErrorsKeepTheirMessage(t *testing.T) {
	if got := invalid("bad iface %q", "x y").Error(); got != `bad iface "x y"` {
		t.Errorf("message changed: %q", got)
	}
	if got := conflict("CONFLICT: dhcp changed").Error(); got != "CONFLICT: dhcp changed" {
		t.Errorf("message changed: %q", got)
	}
}

// The code line is part of the bound, not an addition to it: a huge error text must still end
// with its code, and the result must stay within the cap plus the fixed truncation notice.
func TestCodeLineSurvivesTheResultCap(t *testing.T) {
	line := "[code: FAILED]"
	res := errResultCoded(strings.Repeat("x", 3*maxResultBytes), line)
	txt := res.Content[0].(*mcp.TextContent).Text
	if !res.IsError || !strings.HasSuffix(txt, "\n"+line) {
		t.Errorf("a capped error lost its code line; tail: %q", txt[len(txt)-80:])
	}
	if len(txt) > maxResultBytes+512 {
		t.Errorf("result is %d bytes, over the cap %d plus the truncation notice", len(txt), maxResultBytes)
	}
}
