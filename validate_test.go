package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	benignWarning = "[!] Section @rule[0] (Allow-SSH-WAN-limited) is disabled, ignoring section"
	bogusZone     = "[!] Section @zone[0] (lan) option 'input' specifies invalid value 'BOGUS'"
)

var bogusChange = UCIChange{Config: "firewall", Section: "@zone[0]", Option: "input", Value: "BOGUS"}

// firewallFixture is applyFixture plus a firewall config and a fw4 that behaves as measured on
// the router: it sees changes staged in uci, prints "[!]" lines for what it would ignore, and
// exits 0 even then. The baseline always prints one benign warning.
func firewallFixture(t *testing.T) (*Server, *fakeRouter) {
	t.Helper()
	s, f, root := applyFixture(t)
	writeFixture(t, root, "etc/config/firewall", "config zone\n\toption name 'lan'\n")
	staged := fakeUCI(t, f)
	f.onFn("fw4 check", func([]string, string) (string, error) {
		out := benignWarning
		for _, c := range staged["firewall"] {
			if strings.Contains(c, "BOGUS") {
				out += "\n" + bogusZone + "\n[!] Section @zone[0] (lan) skipped due to invalid options"
			}
		}
		return out, nil
	})
	return s, f
}

func TestDryRunReportsANewFirewallProblemAndLeavesNothingStaged(t *testing.T) {
	s, f := firewallFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: []UCIChange{bogusChange}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"validation", "firewall: 2 NEW problem(s)", bogusZone, "skipped due to invalid options"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run does not show %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, benignWarning) {
		t.Errorf("the pre-existing warning is listed as if new:\n%s", out)
	}
	if !f.ran("uci revert firewall") || f.ran("uci commit") {
		t.Errorf("a dry run must revert and never commit:\n%s", f.allCalls())
	}
}

func TestRealApplyIsRefusedOnANewProblemUnlessForced(t *testing.T) {
	s, f := firewallFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{bogusChange}})
	if err == nil || !strings.Contains(err.Error(), bogusZone) || !strings.Contains(err.Error(), "force=true") {
		t.Fatalf("want a refusal quoting the problem and naming force, got %v", err)
	}
	if f.ran("uci commit") || s.pendingSummary() != "" || !f.ran("uci revert firewall") {
		t.Errorf("a refused apply must revert, commit nothing and arm nothing:\n%s", f.allCalls())
	}

	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{bogusChange}, Force: true})
	if err != nil {
		t.Fatalf("force=true must apply: %v", err)
	}
	if !f.ran("uci commit firewall") || !strings.Contains(out, "ROLLBACK ARMED") || !strings.Contains(out, "NEW problem") {
		t.Errorf("a forced apply still commits with the rollback armed and says what it ignored:\n%s", out)
	}
}

func TestAProblemThatWasAlreadyThereDoesNotBlock(t *testing.T) {
	s, f := firewallFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{
		{Config: "firewall", Section: "@zone[0]", Option: "masq", Value: "1"}}})
	if err != nil {
		t.Fatalf("an unrelated change was blocked by an existing warning: %v", err)
	}
	if !f.ran("uci commit firewall") || !strings.Contains(out, "unchanged") || strings.Contains(out, "NEW problem") {
		t.Errorf("want OK with the existing warning counted as unchanged:\n%s", out)
	}
}

func TestBaselineIsCheckedBeforeAnythingIsStaged(t *testing.T) {
	s, f := firewallFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: []UCIChange{bogusChange}}); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, a := range f.argvList() {
		if k := strings.Join(a, " "); strings.HasPrefix(k, "fw4 check") || strings.HasPrefix(k, "uci set") {
			seq = append(seq, strings.Fields(k)[0]+" "+strings.Fields(k)[1])
		}
	}
	if got := strings.Join(seq, ","); got != "fw4 check,uci set,fw4 check" {
		t.Errorf("order = %s, want baseline check, staging, candidate check", got)
	}
}

func TestACheckerThatFailsToRunBlocksOnlyIfItWorkedBefore(t *testing.T) {
	for name, tc := range map[string]struct {
		failBaseline bool
		wantBlocked  bool
	}{"worked before": {false, true}, "already failing": {true, false}} {
		t.Run(name, func(t *testing.T) {
			s, f := firewallFixture(t)
			calls := 0
			f.onFn("fw4 check", func([]string, string) (string, error) {
				calls++
				if calls == 1 && !tc.failBaseline {
					return "", nil
				}
				return "syntax error near line 3", errors.New("exit status 1")
			})
			_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{
				{Config: "firewall", Section: "@zone[0]", Option: "masq", Value: "1"}}})
			if (err != nil) != tc.wantBlocked {
				t.Errorf("blocked = %v, want %v (%v)", err != nil, tc.wantBlocked, err)
			}
			if err != nil && !strings.Contains(err.Error(), "syntax error near line 3") {
				t.Errorf("the checker's own words are missing: %v", err)
			}
		})
	}
}

func TestConfigsWithoutACheckerAreSaidToBeUnchecked(t *testing.T) {
	s, f, _ := applyFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: leaseChanges})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not checked (no pre-reload checker exists): dhcp") || f.ran("fw4") {
		t.Errorf("dhcp has no checker that sees staged changes; say so and run nothing:\n%s\n%s", out, f.allCalls())
	}
}

// Section indexes shift when an earlier section is deleted, so a warning that merely moved is
// not new; a second copy of the same warning is.
func TestNewProblemsIgnoresIndexShiftsButCountsExtraCopies(t *testing.T) {
	for _, tc := range []struct {
		name       string
		base, cand []string
		want       string
	}{
		{"identical", []string{benignWarning}, []string{benignWarning}, ""},
		{"index moved", []string{"[!] Section @rule[3] (A) is disabled"}, []string{"[!] Section @rule[2] (A) is disabled"}, ""},
		{"one more copy", []string{"[!] Section @rule[0] (A) bad"}, []string{"[!] Section @rule[0] (A) bad", "[!] Section @rule[1] (A) bad"}, "[!] Section @rule[1] (A) bad"},
		{"different text", []string{"[!] Section @rule[0] (A) bad"}, []string{"[!] Section @rule[0] (A) worse"}, "[!] Section @rule[0] (A) worse"},
		{"fixed", []string{"[!] x"}, nil, ""},
	} {
		if got := strings.Join(newProblems(tc.base, tc.cand), "|"); got != tc.want {
			t.Errorf("%s: newProblems = %q, want %q", tc.name, got, tc.want)
		}
	}
}
