package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A router shaped like the real one: a bridged LAN carrying the SSH listener, a WAN, a
// firewall with a zone per side, an SSH rule and an unrelated DHCP rule.
const (
	mgmtNetwork = `network.lan=interface
network.lan.proto='static'
network.lan.device='br-lan'
network.lan.ipaddr='192.0.2.1/24'
network.lan.dns='192.0.2.53'
network.wan=interface
network.wan.proto='dhcp'
network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2'
`
	mgmtDropbear = `dropbear.@dropbear[0]=dropbear
dropbear.@dropbear[0].Port='2222'
dropbear.@dropbear[0].Interface='lan'
dropbear.@dropbear[0].PasswordAuth='off'
`
	mgmtFirewall = `firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan'
firewall.@zone[1].input='REJECT'
firewall.@rule[0]=rule
firewall.@rule[0].name='Allow-SSH-WAN'
firewall.@rule[0].src='wan'
firewall.@rule[0].dest_port='2222'
firewall.@rule[0].target='ACCEPT'
firewall.@rule[1]=rule
firewall.@rule[1].name='Allow-DHCP-Renew'
firewall.@rule[1].dest_port='68'
firewall.@rule[1].target='ACCEPT'
`
)

func mgmtFixture(t *testing.T) (*Server, *fakeRouter) {
	t.Helper()
	root := withFixtureRoot(t)
	for _, c := range []string{"network", "dropbear", "firewall", "dhcp"} {
		writeFixture(t, root, "etc/config/"+c, "config x '"+c+"'\n")
	}
	f := newFakeRouter(t)
	fakeUCI(t, f)
	f.on("uci -q show network", mgmtNetwork)
	f.on("uci -q show dropbear", mgmtDropbear)
	f.on("uci -q show firewall", mgmtFirewall)
	return testServer(t, ""), f
}

func chg(config, section, option, value string) UCIChange {
	return UCIChange{Config: config, Section: section, Option: option, Value: value}
}

// Each rule names a change that can cut the path the operator reached the router by. A change
// that restates the live value, or touches something else, is not one.
func TestManagementPathRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes []UCIChange
		want    string // substring of a reason, or "" for none
	}{
		{"LAN address", []UCIChange{chg("network", "lan", "ipaddr", "198.51.100.1/24")}, "network.lan"},
		{"LAN address restated", []UCIChange{chg("network", "lan", "ipaddr", "192.0.2.1/24")}, ""},
		{"LAN protocol", []UCIChange{chg("network", "lan", "proto", "dhcp")}, "network.lan"},
		{"LAN dns is not the path", []UCIChange{chg("network", "lan", "dns", "9.9.9.9")}, ""},
		{"WAN is not the path", []UCIChange{chg("network", "wan", "proto", "static")}, ""},
		{"LAN deleted", []UCIChange{{Config: "network", Section: "lan", Delete: true}}, "network.lan"},
		{"bridge ports", []UCIChange{{Op: "del_list", Config: "network", Section: "@device[0]", Option: "ports", Value: "lan1"}}, "br-lan"},
		{"bridge port not in the list", []UCIChange{{Op: "del_list", Config: "network", Section: "@device[0]", Option: "ports", Value: "lan9"}}, ""},
		{"bridge port already there", []UCIChange{{Op: "add_list", Config: "network", Section: "@device[0]", Option: "ports", Value: "lan1"}}, ""},
		{"SSH port", []UCIChange{chg("dropbear", "@dropbear[0]", "Port", "22")}, "SSH listener"},
		{"SSH interface", []UCIChange{chg("dropbear", "@dropbear[0]", "Interface", "wan")}, "SSH listener"},
		{"SSH password auth is not the path", []UCIChange{chg("dropbear", "@dropbear[0]", "PasswordAuth", "on")}, ""},
		{"LAN zone input", []UCIChange{chg("firewall", "@zone[0]", "input", "REJECT")}, "zone lan"},
		{"WAN zone input", []UCIChange{chg("firewall", "@zone[1]", "input", "ACCEPT")}, ""},
		{"SSH rule", []UCIChange{chg("firewall", "@rule[0]", "enabled", "0")}, "port 2222"},
		{"SSH rule deleted", []UCIChange{{Config: "firewall", Section: "@rule[0]", Delete: true}}, "port 2222"},
		{"unrelated rule", []UCIChange{chg("firewall", "@rule[1]", "enabled", "0")}, ""},
		{"another config", []UCIChange{chg("dhcp", "lan", "start", "100")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = mgmtFixture(t)
			got := strings.Join(mgmtReasons(context.Background(), tc.changes), "; ")
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("reasons = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestManagementPathReadsNothingForConfigsItDoesNotJudge(t *testing.T) {
	_, f := mgmtFixture(t)
	if r := mgmtReasons(context.Background(), []UCIChange{chg("dhcp", "lan", "start", "100")}); len(r) != 0 {
		t.Fatal(r)
	}
	f.noCalls(t, "a change to dhcp")
}

func TestAManagementPathChangeNeedsAProbeOrForce(t *testing.T) {
	s, f := mgmtFixture(t)
	ctx := context.Background()
	lan := []UCIChange{chg("network", "lan", "ipaddr", "198.51.100.1/24")}

	_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: lan})
	if err == nil || !strings.Contains(err.Error(), "management path") || !strings.Contains(err.Error(), "probe") ||
		!strings.Contains(err.Error(), "force") {
		t.Fatalf("want a refusal naming the management path, probe and force: %v", err)
	}
	if f.ran("uci commit") || s.pendingSummary() != "" || !f.ran("uci revert") && f.ran("uci set") {
		t.Errorf("a refused apply must commit and arm nothing and leave nothing staged:\n%s", f.allCalls())
	}

	dry, _, err := s.uciApply(ctx, "c", uciApplyIn{DryRun: true, Changes: lan})
	if err != nil || !strings.Contains(dry, "management path") || !strings.Contains(dry, "network.lan") {
		t.Errorf("a dry run says so without refusing (%v):\n%s", err, dry)
	}

	if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: lan, Force: true}); err != nil {
		t.Errorf("force=true must go ahead: %v", err)
	}
}

func TestAManagementPathChangeWithProbesGetsALongerWindow(t *testing.T) {
	probeEvery, probeWaitUnit = 0, time.Millisecond
	t.Cleanup(func() { probeEvery, probeWaitUnit = time.Second, time.Second })
	for name, tc := range map[string]struct {
		timeout int
		want    time.Duration
	}{"default": {0, 180 * time.Second}, "explicit is honoured": {60, 60 * time.Second}} {
		t.Run(name, func(t *testing.T) {
			s, f := mgmtFixture(t)
			f.on("ping", "")
			_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{
				Changes: []UCIChange{chg("network", "lan", "ipaddr", "198.51.100.1/24")}, Timeout: tc.timeout,
				Probe: []probeSpec{{Kind: "ping", Target: "198.51.100.254"}}})
			if err != nil {
				t.Fatal(err)
			}
			s.mu.RLock()
			defer s.mu.RUnlock()
			for _, p := range s.pending {
				if left := time.Until(p.Deadline); left > tc.want || left < tc.want-5*time.Second {
					t.Errorf("rollback window = %v, want about %v", left, tc.want)
				}
			}
		})
	}
}

func fastProbes(t *testing.T) {
	t.Helper()
	probeEvery, probeWaitUnit = 0, time.Millisecond
	t.Cleanup(func() { probeEvery, probeWaitUnit = time.Second, time.Second })
}

func TestProbesRunAfterTheReloadAndRetryUntilTheyPass(t *testing.T) {
	fastProbes(t)
	s, f, _ := applyFixture(t)
	attempts := 0
	f.onFn("ping", func(argv []string, _ string) (string, error) {
		attempts++
		if attempts < 3 {
			return "", errors.New("exit status 1")
		}
		return "1 packets received", nil
	})
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges,
		Probe: []probeSpec{{Kind: "ping", Target: "192.0.2.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || !strings.Contains(out, "ping 192.0.2.1: OK") || strings.Contains(out, "PROBE FAILED") {
		t.Errorf("attempts=%d, want 3 and an OK:\n%s", attempts, out)
	}
	calls := f.allCalls()
	if strings.Index(calls, "/sbin/reload_config") > strings.Index(calls, "ping") {
		t.Errorf("a probe ran before the reload:\n%s", calls)
	}
	if got := strings.Join(f.argvList()[len(f.argvList())-1], " "); got != "ping -c 1 -W 2 192.0.2.1" {
		t.Errorf("last probe command = %q", got)
	}
}

// A probe that never passes is reported, and the change stays armed: the timer is what rolls
// it back, exactly as for an agent that lost its connection.
func TestAFailingProbeIsReportedAndTheRollbackStillFires(t *testing.T) {
	fastProbes(t)
	s, f, _ := applyFixture(t)
	f.fail("ping", "100% packet loss")
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, ProbeWait: 2,
		Probe: []probeSpec{{Kind: "ping", Target: "192.0.2.1"}}})
	if err != nil {
		t.Fatalf("the change is applied; a failed probe is a result, not an error: %v", err)
	}
	if !strings.Contains(out, "ping 192.0.2.1: FAILED") || !strings.Contains(out, "PROBE FAILED") ||
		!strings.Contains(out, "uci_rollback") || !strings.Contains(out, "ROLLBACK ARMED") {
		t.Errorf("a failed probe must say so and keep the rollback armed:\n%s", out)
	}
	s.rollback(firstToken(s), "timeout")
	if readConf(t, "dhcp") != origDHCP {
		t.Error("the timer did not restore the config after the failed probe")
	}
}

func TestResolveProbe(t *testing.T) {
	fastProbes(t)
	for name, tc := range map[string]struct {
		out  string
		err  error
		want string
	}{
		"answers":         {"Name:\texample.com\nAddress: 192.0.2.7\n", nil, "resolve example.com: OK"},
		"nxdomain exit 0": {"** server can't find example.com: NXDOMAIN\n", nil, "resolve example.com: FAILED"},
		"cannot resolve":  {"nslookup: can't resolve 'example.com'\n", nil, "resolve example.com: FAILED"},
		"command failed":  {"", errors.New("exit status 1"), "resolve example.com: FAILED"},
	} {
		t.Run(name, func(t *testing.T) {
			s, f, _ := applyFixture(t)
			f.onFn("nslookup", func([]string, string) (string, error) { return tc.out, tc.err })
			out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, ProbeWait: 1,
				Probe: []probeSpec{{Kind: "resolve", Target: "example.com", Server: "192.0.2.53"}}})
			if err != nil || !strings.Contains(out, tc.want) {
				t.Errorf("(%v) want %q:\n%s", err, tc.want, out)
			}
			if !f.ran("nslookup example.com 192.0.2.53") {
				t.Errorf("did not ask the given server:\n%s", f.allCalls())
			}
		})
	}
}

func TestProbeInputIsValidatedBeforeAnythingIsStaged(t *testing.T) {
	s, f, _ := applyFixture(t)
	many := make([]probeSpec, 6)
	for i := range many {
		many[i] = probeSpec{Kind: "ping", Target: "192.0.2.1"}
	}
	for name, probes := range map[string][]probeSpec{
		"six probes":        many,
		"unknown kind":      {{Kind: "tcp", Target: "192.0.2.1"}},
		"no target":         {{Kind: "ping"}},
		"option as target":  {{Kind: "ping", Target: "-f"}},
		"space in target":   {{Kind: "ping", Target: "a b"}},
		"newline in target": {{Kind: "ping", Target: "a\nb"}},
		"option as server":  {{Kind: "resolve", Target: "example.com", Server: "-x"}},
		"server on a ping":  {{Kind: "ping", Target: "192.0.2.1", Server: "192.0.2.53"}},
	} {
		if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Probe: probes}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if f.ran("uci set") || f.ran("ping") {
		t.Error("a rejected probe list must not stage or probe")
	}
}

func TestProbesDoNotRunOnADryRunAndDoNotHoldTheApplyLock(t *testing.T) {
	fastProbes(t)
	s, f, _ := applyFixture(t)
	probes := []probeSpec{{Kind: "ping", Target: "192.0.2.1"}}
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: leaseChanges, Probe: probes}); err != nil {
		t.Fatal(err)
	}
	if f.ran("ping") {
		t.Fatal("a dry run probed the network")
	}
	free := false
	f.onFn("ping", func([]string, string) (string, error) {
		if free = s.applyMu.TryLock(); free {
			s.applyMu.Unlock()
		}
		return "", nil
	})
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Probe: probes}); err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Error("probes waited on the network while holding the staging lock")
	}
}

// A probe makes the router ping and resolve names on the caller's behalf, which a grant on
// uci_apply never allowed before, so each target is its own scope.
func TestProbeTargetsAreScopes(t *testing.T) {
	in := uciApplyIn{Changes: leaseChanges, Probe: []probeSpec{
		{Kind: "ping", Target: "192.0.2.1"}, {Kind: "resolve", Target: "example.com"}}}
	got := strings.Join(uciScopes(in), ",")
	if !strings.HasSuffix(got, "probe.ping.192.0.2.1,probe.resolve.example.com") {
		t.Fatalf("scopes = %s", got)
	}
	for _, tc := range []struct {
		grants  []string
		allowed bool
	}{
		{[]string{"dhcp.*"}, false},
		{[]string{"dhcp.*", "probe.ping.*"}, false},
		{[]string{"dhcp.*", "probe.*"}, true},
		{[]string{"dhcp.*", "probe.ping.192.0.2.1", "probe.resolve.example.com"}, true},
		{[]string{"*"}, true},
	} {
		s := testServer(t, policyFor("c", []string{"uci_apply"}, tc.grants...))
		cs := connectClient(t, s, "c")
		out, isErr := callText(t, cs, "uci_apply", map[string]any{"dry_run": true,
			"changes": []map[string]any{{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.0.2.5"}},
			"probe":   []map[string]any{{"kind": "ping", "target": "192.0.2.1"}, {"kind": "resolve", "target": "example.com"}}})
		if denied := isErr && strings.Contains(out, "denied"); denied == tc.allowed {
			t.Errorf("grants %v: denied=%v, want allowed=%v (%s)", tc.grants, denied, tc.allowed, out)
		}
	}
}

// A restore replaces a whole config, so restoring one of the configs the management path lives
// in is held to the same rule as a change to it.
func TestRestoringAManagementConfigNeedsAProbeOrForce(t *testing.T) {
	fastProbes(t)
	historyClock(t)
	s, f := mgmtFixture(t)
	f.on("ping", "")
	s.saveHistory("network", []byte("config x 'network'\n"), 0o644, "c", "test", "seed")
	id := s.historyEntries("network")[0].id()
	ctx := context.Background()

	if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: id}); err == nil || !strings.Contains(err.Error(), "management path") {
		t.Fatalf("restore of network without a probe: %v", err)
	}
	if s.pendingSummary() != "" {
		t.Fatal("a refused restore armed a rollback")
	}
	dry, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: id, DryRun: true})
	if err != nil || !strings.Contains(dry, "management path") {
		t.Errorf("a restore dry run says so without refusing (%v):\n%s", err, dry)
	}
	out, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: id, Probe: []probeSpec{{Kind: "ping", Target: "192.0.2.1"}}})
	if err != nil || !strings.Contains(out, "ping 192.0.2.1: OK") {
		t.Errorf("restore with a probe: %v\n%s", err, out)
	}
	s.mu.RLock()
	for _, p := range s.pending {
		if left := time.Until(p.Deadline); left < 170*time.Second {
			t.Errorf("window = %v, want about %ds", left, mgmtRollbackSec)
		}
	}
	s.mu.RUnlock()
}

// The probes may use only part of the rollback window: once the budget is spent each remaining
// probe gets a single attempt instead of waiting out its own retries.
func TestProbesStopRetryingOnceTheBudgetIsSpent(t *testing.T) {
	probeEvery, probeWaitUnit = time.Millisecond, time.Millisecond
	t.Cleanup(func() { probeEvery, probeWaitUnit = time.Second, time.Second })
	f := newFakeRouter(t)
	attempts := 0
	f.onFn("ping", func([]string, string) (string, error) { attempts++; return "", errors.New("exit status 1") })
	text, ok := runProbes(context.Background(), []probeSpec{{Kind: "ping", Target: "192.0.2.1"}}, 50*time.Millisecond, 0)
	if ok || attempts != 1 {
		t.Errorf("ok=%v attempts=%d, want one failed attempt and no retries:\n%s", ok, attempts, text)
	}
}

// With no Port set, dropbear listens on 22, so a firewall rule for 22 is the SSH rule.
func TestSSHPortDefaultsTo22(t *testing.T) {
	_, f := mgmtFixture(t)
	f.on("uci -q show dropbear", "dropbear.@dropbear[0]=dropbear\n")
	f.on("uci -q show firewall", "firewall.@rule[0]=rule\nfirewall.@rule[0].dest_port='22'\n")
	got := mgmtReasons(context.Background(), []UCIChange{chg("firewall", "@rule[0]", "enabled", "0")})
	if len(got) != 1 || !strings.Contains(got[0], "port 22") {
		t.Errorf("reasons = %v, want the rule for port 22", got)
	}
}

func TestPortListedUnderstandsRangesAndLists(t *testing.T) {
	for _, tc := range []struct {
		values []string
		port   string
		want   bool
	}{
		{[]string{"22"}, "22", true},
		{[]string{"2222"}, "22", false},
		{[]string{"20-30"}, "22", true},
		{[]string{"23-30"}, "22", false},
		{[]string{"80 22 443"}, "22", true},
		{[]string{"80,22"}, "22", true},
		{[]string{"80", "22"}, "22", true},
		{[]string{"x-y"}, "22", false},
		{nil, "22", false},
		{[]string{"22"}, "ssh", false},
	} {
		if got := portListed(tc.values, tc.port); got != tc.want {
			t.Errorf("portListed(%q, %q) = %v, want %v", tc.values, tc.port, got, tc.want)
		}
	}
}
