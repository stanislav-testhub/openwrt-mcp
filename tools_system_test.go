package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// callList returns every command the fake router saw, in order.
func (f *fakeRouter) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRouter) noCalls(t *testing.T, what string) {
	t.Helper()
	if c := f.callList(); len(c) != 0 {
		t.Errorf("%s still ran commands: %q", what, c)
	}
}

// ---------------------------------------------------------------- exec

func TestExecHandsArgvToTheRunnerUntouched(t *testing.T) {
	f := newFakeRouter(t)
	f.on("echo", "ok")
	argv := []string{"echo", "a;b", "$(reboot)", "`id`", "*", ">/etc/passwd", "x y", "--", "-rf"}
	out, summary, err := execTool(context.Background(), execIn{Argv: argv})
	if err != nil || out != "ok" {
		t.Fatalf("%v %q", err, out)
	}
	// One command, one argv: nothing was split, expanded or re-quoted on the way.
	want := strings.Join(argv, " ")
	if got := f.callList(); len(got) != 1 || got[0] != want {
		t.Errorf("runner saw %q, want %q", got, want)
	}
	if summary != want {
		t.Errorf("summary %q", summary)
	}
}

// The fake router bypasses execRunner, so "no shell" needs one test against the real thing.
// The test binary re-executes itself as the program being run.
func TestHelperArgs(t *testing.T) {
	mode := os.Getenv("OPENWRT_MCP_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "args":
		for i, a := range os.Args {
			if a == "--" {
				for _, x := range os.Args[i+1:] {
					fmt.Println(x)
				}
			}
		}
	case "stderr-exit3":
		fmt.Println("to-stdout")
		fmt.Fprintln(os.Stderr, "to-stderr")
		os.Exit(3)
	case "sleep":
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func helperArgv(extra ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestHelperArgs$", "--"}, extra...)
}

func TestRealRunnerPassesArgumentsVerbatimAndMergesStderr(t *testing.T) {
	t.Setenv("OPENWRT_MCP_HELPER", "args")
	hostile := []string{"a;b", "$HOME", "`id`", "*", ">out", "x y", "-rf", "'q'"}
	out, err := run(context.Background(), 20*time.Second, helperArgv(hostile...)...)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(strings.ReplaceAll(out, "x y", "x_y")); strings.Join(got, "|") != strings.Join(
		[]string{"a;b", "$HOME", "`id`", "*", ">out", "x_y", "-rf", "'q'"}, "|") {
		t.Errorf("arguments were interpreted on the way to the process:\n%s", out)
	}

	t.Setenv("OPENWRT_MCP_HELPER", "stderr-exit3")
	out, err = run(context.Background(), 20*time.Second, helperArgv()...)
	if err == nil {
		t.Error("exit status 3 was not reported")
	}
	if !strings.Contains(out, "to-stdout") || !strings.Contains(out, "to-stderr") {
		t.Errorf("output must carry stdout then stderr, got %q", out)
	}
}

func TestRealRunnerKillsAProcessThatOutlivesItsTimeout(t *testing.T) {
	t.Setenv("OPENWRT_MCP_HELPER", "sleep")
	start := time.Now()
	_, err := run(context.Background(), 300*time.Millisecond, helperArgv()...)
	if err == nil || !strings.Contains(err.Error(), "timed out after 300ms") {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("the process was not killed at its deadline")
	}
}

func TestExecTimeoutIsClampedToTheDocumentedBounds(t *testing.T) {
	for _, c := range []struct {
		in   int
		want time.Duration
	}{{0, 30 * time.Second}, {-5, 30 * time.Second}, {1, time.Second}, {299, 299 * time.Second},
		{300, 300 * time.Second}, {301, 300 * time.Second}, {1 << 30, 300 * time.Second}} {
		if got := clampSec(c.in, 30, 300); got != c.want {
			t.Errorf("clampSec(%d) = %s, want %s", c.in, got, c.want)
		}
	}
	// And execTool really uses it: read the deadline the runner is handed.
	old := cmdRunner
	t.Cleanup(func() { cmdRunner = old })
	var budget time.Duration
	cmdRunner = func(ctx context.Context, _ *string, _ []string) (string, string, error) {
		d, _ := ctx.Deadline()
		budget = time.Until(d)
		return "", "", nil
	}
	for in, want := range map[int]time.Duration{0: 30 * time.Second, 301: 300 * time.Second} {
		_, _, _ = execTool(context.Background(), execIn{Argv: []string{"x"}, Timeout: in})
		if budget > want || budget < want-5*time.Second {
			t.Errorf("timeout %d: the process was given %s, want about %s", in, budget, want)
		}
	}
}

func TestExecScopeIsTheLiteralProgramName(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ls", "files")
	f.on("cat", "secret")
	f.on("/bin/ls", "files")
	s := testServer(t, policyFor("c", []string{"exec"}, "ls"))
	cs := connectClient(t, s, "c")

	if out, isErr := callText(t, cs, "exec", map[string]any{"argv": []string{"ls", "/"}}); isErr || out != "files" {
		t.Errorf("granted program refused: %v %s", isErr, out)
	}
	for _, argv := range [][]string{{"cat", "/etc/shadow"}, {"/bin/ls"}, {"LS"}, {"ls;cat"}} {
		if out, isErr := callText(t, cs, "exec", map[string]any{"argv": argv}); !isErr || !strings.Contains(out, "denied") {
			t.Errorf("%v was not denied: %s", argv, out)
		}
	}
	if f.ran("cat") || f.ran("/bin/ls") {
		t.Errorf("a denied exec reached the runner:\n%s", f.allCalls())
	}

	f2 := newFakeRouter(t)
	out, isErr := callText(t, cs, "exec", map[string]any{"argv": []string{}})
	if !isErr || !strings.Contains(out, "argv must not be empty") {
		t.Errorf("empty argv: %v %s", isErr, out)
	}
	f2.noCalls(t, "an empty argv")
}

// ---------------------------------------------------------------- service_list / service_control

const rcFixture = `{
  "dropbear": {"enabled": true,  "running": true,  "start": 20, "stop": 89},
  "firewall": {"enabled": true,  "running": false, "start": 19, "stop": 89},
  "zz-oneshot": {"enabled": false, "running": false, "start": 99, "stop": 1},
  "network": {"enabled": true, "running": true, "start": 20, "stop": 90},
  "rpcd": {"enabled": true, "running": true, "start": 12, "stop": 89},
  "openwrt-mcp": {"enabled": true, "running": true, "start": 99, "stop": 10},
  "dnsmasq": {"enabled": true, "running": true, "start": 19, "stop": 89},
  "dnsmasq-extra": {"enabled": false, "running": false, "start": 50, "stop": 50}
}`

func TestServiceListReportsBootStateRunningStateAndOrderSorted(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", rcFixture)
	out, _, err := serviceList(context.Background(), serviceListIn{})
	if err != nil {
		t.Fatal(err)
	}
	row := func(name string) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, name+" ") {
				return strings.Join(strings.Fields(l), " ")
			}
		}
		t.Fatalf("no row for %s:\n%s", name, out)
		return ""
	}
	for name, want := range map[string]string{
		"dropbear":   "dropbear enabled running 20/89",
		"firewall":   "firewall enabled stopped 19/89",
		"zz-oneshot": "zz-oneshot disabled stopped 99/1",
	} {
		if got := row(name); got != want {
			t.Errorf("row %s = %q, want %q", name, got, want)
		}
	}
	if strings.Index(out, "dnsmasq ") > strings.Index(out, "dropbear ") || strings.Index(out, "dropbear ") > strings.Index(out, "zz-oneshot ") {
		t.Errorf("services are not sorted by name:\n%s", out)
	}
	if !strings.Contains(out, "one-shot") {
		t.Error("the caveat about one-shot scripts reporting 'stopped' is missing")
	}

	out, _, _ = serviceList(context.Background(), serviceListIn{Filter: "dnsmasq"})
	if !strings.Contains(out, "dnsmasq-extra") || strings.Contains(out, "dropbear") || strings.Contains(out, "firewall") {
		t.Errorf("filter wrong:\n%s", out)
	}
	out, _, _ = serviceList(context.Background(), serviceListIn{Filter: "no-such-service"})
	if strings.Count(out, "\n") > 3 || strings.Contains(out, "dropbear") {
		t.Errorf("a filter matching nothing should list nothing:\n%s", out)
	}

	f.fail("ubus call rc list", "Command failed: Not found")
	if _, _, err := serviceList(context.Background(), serviceListIn{}); err == nil {
		t.Error("a failing rc list was reported as an empty service list")
	}
}

func TestServiceControlNeverStopsOrDisablesALifelineWhateverTheService(t *testing.T) {
	serviceSettle = 0
	t.Cleanup(func() { serviceSettle = time.Second })
	f := newFakeRouter(t)
	f.on("ubus call rc list", rcFixture)
	f.on("ubus call rc init", "")
	ctx := context.Background()

	for _, svc := range []string{"dropbear", "network", "rpcd", "openwrt-mcp"} {
		for _, action := range []string{"start", "stop", "restart", "reload", "enable", "disable"} {
			before := len(f.callList())
			_, _, err := serviceControl(ctx, serviceControlIn{Name: svc, Action: action})
			cut := action == "stop" || action == "disable"
			switch {
			case cut && (err == nil || !strings.Contains(err.Error(), "refusing")):
				t.Errorf("%s %s was allowed: %v", action, svc, err)
			case cut && len(f.callList()) != before:
				t.Errorf("%s %s was refused but still ran: %q", action, svc, f.callList()[before:])
			case !cut && err != nil:
				t.Errorf("%s %s is harmless (the service comes back) but was refused: %v", action, svc, err)
			}
		}
	}
	// A non-lifeline service can be stopped: the guard is a list, not a blanket ban.
	if _, _, err := serviceControl(ctx, serviceControlIn{Name: "firewall", Action: "stop"}); err != nil {
		t.Errorf("stopping an ordinary service: %v", err)
	}
}

func TestServiceControlRejectsMalformedRequestsBeforeTouchingTheRouter(t *testing.T) {
	f := newFakeRouter(t)
	for _, in := range []serviceControlIn{
		{"", "restart"}, {"a b", "restart"}, {"../x", "restart"}, {"x;reboot", "restart"}, {"$(id)", "restart"},
		{"a\nb", "restart"}, {"dnsmasq", ""}, {"dnsmasq", "STOP"}, {"dnsmasq", "stop "}, {"dnsmasq", "kill"},
		{"dnsmasq", "status"}, {"dnsmasq", "restart;reboot"},
	} {
		if _, _, err := serviceControl(context.Background(), in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	f.noCalls(t, "a malformed request")
}

func TestServiceControlSendsExactlyOneRcInitAndReportsTheStateItFound(t *testing.T) {
	serviceSettle = 0
	t.Cleanup(func() { serviceSettle = time.Second })
	f := newFakeRouter(t)
	lists := 0
	f.onFn("ubus call rc list", func([]string, string) (string, error) {
		lists++
		if lists == 1 { // before: stopped
			return `{"dnsmasq":{"enabled":false,"running":false}}`, nil
		}
		return `{"dnsmasq":{"enabled":true,"running":true}}`, nil // after
	})
	f.on("ubus call rc init", "")

	out, summary, err := serviceControl(context.Background(), serviceControlIn{Name: "dnsmasq", Action: "start"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "start dnsmasq: done. Now enabled=true running=true.") || summary != "start dnsmasq" {
		t.Errorf("out=%q summary=%q", out, summary)
	}
	inits := 0
	for _, c := range f.callList() {
		if strings.HasPrefix(c, "ubus call rc init") {
			inits++
			if c != `ubus call rc init {"name":"dnsmasq","action":"start"}` {
				t.Errorf("rc init argument = %s", c)
			}
		}
	}
	if inits != 1 {
		t.Errorf("%d rc init calls, want 1", inits)
	}

	f.fail("ubus call rc init", "Command failed: Invalid argument")
	_, _, err = serviceControl(context.Background(), serviceControlIn{Name: "dnsmasq", Action: "restart"})
	if err == nil || !strings.Contains(err.Error(), "restart dnsmasq") {
		t.Errorf("a failing rc init: %v", err)
	}
}

func TestServiceControlPolicyScopeIsServiceDotAction(t *testing.T) {
	serviceSettle = 0
	t.Cleanup(func() { serviceSettle = time.Second })
	f := newFakeRouter(t)
	f.on("ubus call rc list", rcFixture)
	f.on("ubus call rc init", "")
	s := testServer(t, policyFor("c", []string{"service_control"}, "dnsmasq.restart"))
	cs := connectClient(t, s, "c")

	if out, isErr := callText(t, cs, "service_control", map[string]any{"name": "dnsmasq", "action": "restart"}); isErr {
		t.Errorf("granted restart refused: %s", out)
	}
	for _, in := range []map[string]any{
		{"name": "dnsmasq", "action": "stop"},
		{"name": "dnsmasq", "action": "disable"},
		{"name": "dnsmasq-extra", "action": "restart"}, // a longer name is not a prefix match
		{"name": "firewall", "action": "restart"},
	} {
		if out, isErr := callText(t, cs, "service_control", in); !isErr || !strings.Contains(out, "denied") {
			t.Errorf("%v not denied: %s", in, out)
		}
	}
}

// ---------------------------------------------------------------- sysupgrade

func TestSysupgradeListAndTestRunTheValidationFormsOnly(t *testing.T) {
	f := newFakeRouter(t)
	f.on("sysupgrade -l", "/etc/config/network\n/etc/dropbear/dropbear_ed25519_host_key")
	f.on("sysupgrade -T", "")

	out, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "list"})
	if err != nil || !strings.Contains(out, "/etc/config/network") {
		t.Errorf("list: %v %q", err, out)
	}
	out, _, err = sysupgradeTool(context.Background(), sysupgradeIn{Action: "test", Image: "/tmp//up/./fw.bin"})
	if err != nil || !strings.Contains(out, "nothing was flashed") {
		t.Errorf("test: %v %q", err, out)
	}
	if got := f.callList(); got[len(got)-1] != "sysupgrade -T /tmp/up/fw.bin" {
		t.Errorf("image path not cleaned before use: %q", got)
	}

	f.fail("sysupgrade -T", "Image check failed")
	out, summary, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "test", Image: "/tmp/bad.bin"})
	if err == nil || !strings.Contains(err.Error(), "FAILED validation") || !strings.Contains(out, "Image check failed") ||
		summary != "image test failed" {
		t.Errorf("failed validation: err=%v out=%q summary=%q", err, out, summary)
	}
}

func TestSysupgradeTestRefusesEverythingOutsideTmp(t *testing.T) {
	f := newFakeRouter(t)
	for _, img := range []string{"", "/", "/tmp", "/tmp/", "/tmp/..", "/tmp/../etc/passwd", "/tmp/a/../../etc/x", "/etc/passwd",
		"relative.bin", "tmp/x", "/tmpx/y", "-T", "/tmp/a/../..", "//etc/x"} {
		if _, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "test", Image: img}); err == nil {
			t.Errorf("image %q accepted", img)
		}
	}
	f.noCalls(t, "a refused image path")
}

func TestSysupgradeCheckNeedsOwut(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("owut check", "Version 25.12.6 is available")
	_, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "check"})
	if err == nil || !strings.Contains(err.Error(), "pkg_change add owut") {
		t.Errorf("owut missing: %v", err)
	}
	f.noCalls(t, "a check without owut")

	writeFixture(t, root, "usr/bin/owut", "#!/bin/sh\n")
	out, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "check"})
	if err != nil || !strings.Contains(out, "25.12.6") {
		t.Errorf("check with owut: %v %q", err, out)
	}
}

func TestSysupgradeBackupNamesAFileUnderTmpAndReportsItsDigest(t *testing.T) {
	root := withFixtureRoot(t)
	name := regexp.MustCompile(`^/tmp/backup-[A-Za-z0-9_-]+-\d{8}-\d{6}\.tar\.gz$`)

	for _, c := range []struct{ host, wantPrefix string }{
		{"OpenWrt\n", "/tmp/backup-OpenWrt-"},
		{"../../etc/x y;z", "/tmp/backup-etcxyz-"}, // a hostile hostname must not steer the path
		{"", "/tmp/backup-openwrt-"},
		{"!!!", "/tmp/backup-openwrt-"},
	} {
		f := newFakeRouter(t)
		f.on("uci -q get system.@system[0].hostname", c.host)
		var written string
		f.onFn("sysupgrade -k -b", func(argv []string, _ string) (string, error) {
			written = argv[3]
			writeFixture(t, root, strings.TrimPrefix(written, "/"), "hello")
			return "", nil
		})
		out, summary, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "backup"})
		if err != nil {
			t.Fatalf("host %q: %v", c.host, err)
		}
		if !name.MatchString(written) || !strings.HasPrefix(written, c.wantPrefix) {
			t.Errorf("host %q: archive named %q, want %s...", c.host, written, c.wantPrefix)
		}
		// sha256("hello"), from the standard test vector, not from the code under test.
		if !strings.Contains(out, "5 bytes") || !strings.Contains(out, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") {
			t.Errorf("digest or size missing:\n%s", out)
		}
		if !strings.Contains(out, "secrets") || !strings.Contains(summary, written) {
			t.Errorf("no warning about the archive holding secrets, or summary: %q / %q", out, summary)
		}
	}
}

func TestSysupgradeBackupFailsLoudly(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("uci -q get system.@system[0].hostname", "r")
	f.fail("sysupgrade -k -b", "no space left")
	if _, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "backup"}); err == nil || !strings.Contains(err.Error(), "backup failed") {
		t.Errorf("failed backup: %v", err)
	}
	f.on("sysupgrade -k -b", "") // claims success but wrote nothing
	if _, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "backup"}); err == nil {
		t.Error("a backup that left no file was reported as written")
	}
}

// ---------------------------------------------------------------- net_diag

func netDiagLine(t *testing.T, in netDiagIn) (string, error) {
	t.Helper()
	f := newFakeRouter(t)
	for _, p := range []string{"ping", "traceroute", "nslookup", "ip"} {
		f.on(p, "out")
	}
	_, _, err := netDiag(context.Background(), in)
	calls := f.callList()
	if err != nil {
		if len(calls) != 0 {
			t.Errorf("%+v was refused but still ran %q", in, calls)
		}
		return "", err
	}
	if len(calls) != 1 {
		t.Fatalf("%+v ran %d commands: %q", in, len(calls), calls)
	}
	return calls[0], nil
}

func TestNetDiagBuildsTheDocumentedCommandLines(t *testing.T) {
	for _, c := range []struct {
		in   netDiagIn
		want string
	}{
		{netDiagIn{Action: "ping", Target: "192.0.2.1"}, "ping -c 4 -W 2 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "192.0.2.1", Count: 1}, "ping -c 1 -W 2 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "192.0.2.1", Count: 10}, "ping -c 10 -W 2 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "192.0.2.1", Count: 11}, "ping -c 10 -W 2 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "192.0.2.1", Count: -3}, "ping -c 1 -W 2 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "2001:db8::1"}, "ping -c 4 -W 2 -6 2001:db8::1"},
		{netDiagIn{Action: "ping", Target: "192.0.2.1", Iface: "wg0"}, "ping -c 4 -W 2 -I wg0 192.0.2.1"},
		{netDiagIn{Action: "ping", Target: "2001:db8::1", Iface: "br-WAN"}, "ping -c 4 -W 2 -6 -I br-WAN 2001:db8::1"},
		{netDiagIn{Action: "traceroute", Target: "example.com"}, "traceroute -n -q 1 -w 2 -m 20 example.com"},
		{netDiagIn{Action: "traceroute", Target: "2001:db8::1", Iface: "wg0"}, "traceroute -n -q 1 -w 2 -m 20 -6 -i wg0 2001:db8::1"},
		{netDiagIn{Action: "nslookup", Target: "example.com"}, "nslookup example.com"},
		{netDiagIn{Action: "nslookup", Target: "example.com", Server: "9.9.9.9"}, "nslookup example.com 9.9.9.9"},
		{netDiagIn{Action: "route"}, "ip -4 route show table main"},
		{netDiagIn{Action: "route", Table: "all"}, "ip -4 route show table all"},
		{netDiagIn{Action: "route", Table: "100", IPv6: true}, "ip -6 route show table 100"},
		{netDiagIn{Action: "rule"}, "ip -4 rule show"},
		{netDiagIn{Action: "rule", IPv6: true}, "ip -6 rule show"},
		{netDiagIn{Action: "neigh"}, "ip -4 neigh show"},
		{netDiagIn{Action: "neigh", IPv6: true}, "ip -6 neigh show"},
	} {
		got, err := netDiagLine(t, c.in)
		if err != nil {
			t.Errorf("%+v: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%+v\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestNetDiagRefusesMalformedInputBeforeRunningAnything(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	bad := []netDiagIn{
		{Action: ""},
		{Action: "reboot"},
		{Action: "PING", Target: "x"},
		{Action: "ping"},
		{Action: "ping", Target: "-f"},
		{Action: "ping", Target: "x y"},
		{Action: "ping", Target: "1.1.1.1;reboot"},
		{Action: "ping", Target: "$(id)"},
		{Action: "ping", Target: "a\nb"},
		{Action: "ping", Target: long(254)}, // one over the 253-byte host name limit
		{Action: "ping", Target: "1.1.1.1", Iface: "-x"},
		{Action: "ping", Target: "1.1.1.1", Iface: "a b"},
		{Action: "ping", Target: "1.1.1.1", Iface: long(33)},
		{Action: "traceroute", Target: "--help"},
		{Action: "nslookup", Target: "x", Server: "-x"},
		{Action: "nslookup", Target: "x", Server: "a b"},
		{Action: "route", Table: "-x"},
		{Action: "route", Table: "a b"},
		{Action: "route", Table: long(33)},
	}
	for _, in := range bad {
		if _, err := netDiagLine(t, in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	// The boundaries themselves are fine.
	for _, in := range []netDiagIn{
		{Action: "ping", Target: long(253)},
		{Action: "ping", Target: "1.1.1.1", Iface: long(32)},
		{Action: "route", Table: long(32)},
		{Action: "ping", Target: "_srv.example.com"},
	} {
		if _, err := netDiagLine(t, in); err != nil {
			t.Errorf("%+v refused: %v", in, err)
		}
	}
}

func TestNetDiagOnlyPingAndTracerouteTreatNonZeroExitAsAnAnswer(t *testing.T) {
	f := newFakeRouter(t)
	f.fail("ping", "1 packets transmitted, 0 received")
	f.fail("traceroute", "* * *")
	f.fail("nslookup", "** server can't find x: NXDOMAIN")
	f.fail("ip", "RTNETLINK answers: Invalid argument")
	ctx := context.Background()

	for _, in := range []netDiagIn{{Action: "ping", Target: "x"}, {Action: "traceroute", Target: "x"}} {
		if out, _, err := netDiag(ctx, in); err != nil || out == "" {
			t.Errorf("%s with loss and output must be an answer: %v %q", in.Action, err, out)
		}
	}
	for _, in := range []netDiagIn{{Action: "nslookup", Target: "x"}, {Action: "route"}} {
		if _, _, err := netDiag(ctx, in); err == nil {
			t.Errorf("a failing %s was reported as success", in.Action)
		}
	}
	// With nothing printed there is no answer to hand back, so ping failing is an error.
	f.fail("ping", "")
	if _, _, err := netDiag(ctx, netDiagIn{Action: "ping", Target: "x"}); err == nil {
		t.Error("ping failing with no output was reported as success")
	}
}

func TestNetDiagScopeNamesTheTargetWhenThereIsOne(t *testing.T) {
	for in, want := range map[netDiagIn]string{
		{Action: "ping", Target: "1.1.1.1"}: "ping.1.1.1.1",
		{Action: "route"}:                   "route",
		{Action: "nslookup", Target: "x"}:   "nslookup.x",
		{Action: "ping"}:                    "ping",
	} {
		if got := netDiagScope(in); len(got) != 1 || got[0] != want {
			t.Errorf("scope of %+v = %v, want [%s]", in, got, want)
		}
	}
	f := newFakeRouter(t)
	f.on("ping", "ok")
	f.on("traceroute", "ok")
	cs := connectClient(t, testServer(t, policyFor("c", []string{"net_diag"}, "ping.1.1.1.1")), "c")
	if _, isErr := callText(t, cs, "net_diag", map[string]any{"action": "ping", "target": "1.1.1.1"}); isErr {
		t.Error("granted ping target refused")
	}
	for _, in := range []map[string]any{{"action": "ping", "target": "8.8.8.8"}, {"action": "traceroute", "target": "1.1.1.1"}} {
		if out, isErr := callText(t, cs, "net_diag", in); !isErr || !strings.Contains(out, "denied") {
			t.Errorf("%v not denied: %s", in, out)
		}
	}
}

// ---------------------------------------------------------------- pkg_query

func TestPkgQueryBuildsTheDocumentedApkCommands(t *testing.T) {
	withFixtureRoot(t)
	for _, c := range []struct {
		in   pkgQueryIn
		want string
	}{
		{pkgQueryIn{Action: "installed"}, "apk list --installed"},
		{pkgQueryIn{Action: "installed", Package: "luci-app-*"}, "apk list --installed luci-app-*"},
		{pkgQueryIn{Action: "upgradable"}, "apk list --upgradable"},
		{pkgQueryIn{Action: "search", Package: "tcp*"}, "apk search tcp*"},
		{pkgQueryIn{Action: "info", Package: "dnsmasq-full"}, "apk info -a dnsmasq-full"},
		{pkgQueryIn{Action: "files", Package: "libstdcpp6"}, "apk info -L libstdcpp6"},
		{pkgQueryIn{Action: "owner", Path: "/usr/sbin/nft"}, "apk info --who-owns /usr/sbin/nft"},
		{pkgQueryIn{Action: "owner", Path: "/usr//sbin/../sbin/nft"}, "apk info --who-owns /usr/sbin/nft"},
		{pkgQueryIn{Action: "policy", Package: "owut"}, "apk policy owut"},
		{pkgQueryIn{Action: "audit"}, "apk audit"},
	} {
		f := newFakeRouter(t)
		f.on("apk", "x")
		if _, _, err := pkgQuery(context.Background(), c.in); err != nil {
			t.Errorf("%+v: %v", c.in, err)
			continue
		}
		if got := f.callList(); len(got) != 1 || got[0] != c.want {
			t.Errorf("%+v\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestPkgQueryRefusesMalformedInputBeforeRunningAnything(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk", "x")
	name := func(n int) string { return "a" + strings.Repeat("b", n-1) }
	bad := []pkgQueryIn{
		{Action: ""}, {Action: "add", Package: "x"}, {Action: "INSTALLED"},
		{Action: "installed", Package: "-a"}, {Action: "installed", Package: "a b"},
		{Action: "search"}, {Action: "search", Package: "-v"}, {Action: "search", Package: "a;b"},
		{Action: "info"}, {Action: "info", Package: "dns*"}, {Action: "info", Package: "-a"}, {Action: "info", Package: "a b"},
		{Action: "files", Package: "$(id)"}, {Action: "policy", Package: "a\nb"},
		{Action: "info", Package: name(129)}, // one over the 128-character limit
		{Action: "owner"}, {Action: "owner", Path: "usr/sbin/nft"}, {Action: "owner", Path: "-rf"},
		{Action: "owner", Path: "/-rf"}, {Action: "owner", Path: "/etc/../-rf"},
	}
	for _, in := range bad {
		if _, _, err := pkgQuery(context.Background(), in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	f.noCalls(t, "a malformed query")
	if _, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "info", Package: name(128)}); err != nil {
		t.Errorf("a 128-character name is within the limit: %v", err)
	}
}

func TestPkgQueryRefreshWorldAndEmptyResults(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk update", "fetch https://downloads.example/packages.adb\nOK: 12345 distinct packages available")
	f.on("apk list --upgradable", "luci-2 noarch {x} (MIT) [upgradable from: luci-1]\n")
	out, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "upgradable", Refresh: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.callList(); got[0] != "apk update" || got[1] != "apk list --upgradable" {
		t.Errorf("refresh must update first: %q", got)
	}
	if !strings.HasPrefix(out, "OK: 12345 distinct packages available\n") || !strings.Contains(out, "luci-2 [upgradable from: luci-1]") {
		t.Errorf("update summary or list missing:\n%s", out)
	}

	f.fail("apk update", "network unreachable")
	if _, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "upgradable", Refresh: true}); err == nil ||
		!strings.Contains(err.Error(), "apk update") {
		t.Errorf("a failing refresh must stop the query: %v", err)
	}

	f.on("apk audit", "")
	if out, _, _ := pkgQuery(context.Background(), pkgQueryIn{Action: "audit"}); out != "(nothing)" {
		t.Errorf("an empty answer should say so, got %q", out)
	}

	if _, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "world"}); err == nil {
		t.Error("world with no /etc/apk/world should be an error")
	}
	writeFixture(t, root, "etc/apk/world", "base-files\ndnsmasq-full\n")
	if out, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "world"}); err != nil || out != "base-files\ndnsmasq-full\n" {
		t.Errorf("world: %v %q", err, out)
	}
}

// ---------------------------------------------------------------- pkg_change / pkg_config_resolve

func TestPkgChangeValidationAndCommandShapes(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk", "ok")
	ctx := context.Background()

	for _, in := range []pkgChangeIn{
		{Action: ""}, {Action: "remove", Packages: []string{"x"}}, {Action: "add"}, {Action: "del"},
		{Action: "add", Packages: []string{"ok", "--allow-untrusted"}}, {Action: "add", Packages: []string{"a b"}},
		{Action: "add", Packages: []string{""}}, {Action: "add", Packages: []string{"a;b"}},
	} {
		if _, _, err := pkgChange(ctx, in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	f.noCalls(t, "a refused change")

	cases := []struct {
		in   pkgChangeIn
		want []string
	}{
		{pkgChangeIn{Action: "add", Packages: []string{"a", "b"}}, []string{"apk update", "apk --simulate add a b"}},
		{pkgChangeIn{Action: "add", Packages: []string{"a"}, Commit: true}, []string{"apk update", "apk add a"}},
		{pkgChangeIn{Action: "del", Packages: []string{"a"}}, []string{"apk --simulate del a"}}, // no index refresh to remove
		{pkgChangeIn{Action: "del", Packages: []string{"a"}, Commit: true}, []string{"apk del a"}},
		{pkgChangeIn{Action: "upgrade"}, []string{"apk update", "apk --simulate upgrade"}},
		{pkgChangeIn{Action: "upgrade", Packages: []string{"a"}, Commit: true}, []string{"apk update", "apk upgrade a"}},
	}
	for _, c := range cases {
		f2 := newFakeRouter(t)
		f2.on("apk", "ok")
		if _, _, err := pkgChange(ctx, c.in); err != nil {
			t.Errorf("%+v: %v", c.in, err)
			continue
		}
		if got := f2.callList(); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%+v\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestPkgChangeStopsAtTheFirstFailureAndSaysWhich(t *testing.T) {
	withFixtureRoot(t)
	ctx := context.Background()

	f := newFakeRouter(t)
	f.fail("apk update", "network unreachable")
	f.on("apk", "x")
	_, _, err := pkgChange(ctx, pkgChangeIn{Action: "add", Packages: []string{"a"}, Commit: true})
	if err == nil || !strings.Contains(err.Error(), "apk update") || f.ran("apk add") {
		t.Errorf("a failed index refresh must stop before installing: %v / %q", err, f.callList())
	}

	f = newFakeRouter(t)
	f.on("apk update", "OK")
	f.fail("apk --simulate add", "ERROR: unable to select packages")
	if out, _, err := pkgChange(ctx, pkgChangeIn{Action: "add", Packages: []string{"a"}}); err == nil || !strings.Contains(err.Error(), "simulation failed") ||
		!strings.Contains(out, "unable to select") {
		t.Errorf("failed simulation: %v %q", err, out)
	}

	f = newFakeRouter(t)
	f.on("apk update", "OK")
	f.fail("apk add", "ERROR: disk full")
	if out, _, err := pkgChange(ctx, pkgChangeIn{Action: "add", Packages: []string{"a"}, Commit: true}); err == nil || !strings.Contains(err.Error(), "apk add failed") ||
		!strings.Contains(out, "disk full") {
		t.Errorf("failed commit: %v %q", err, out)
	}

	f = newFakeRouter(t)
	f.on("apk", "x")
	out, _, _ := pkgChange(ctx, pkgChangeIn{Action: "upgrade"})
	if !strings.Contains(out, "discouraged") {
		t.Errorf("a full-system upgrade simulation must carry the warning:\n%s", out)
	}
	out, _, _ = pkgChange(ctx, pkgChangeIn{Action: "upgrade", Packages: []string{"a"}})
	if strings.Contains(out, "discouraged") {
		t.Errorf("upgrading one package needs no warning:\n%s", out)
	}
}

func TestPkgConfigResolveScopeAndGuards(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/config/dhcp":             "/etc/config/dhcp",
		"/etc/config/dhcp.apk-new":     "/etc/config/dhcp",
		"/etc/../etc/config/dhcp":      "/etc/config/dhcp",
		"/etc/config//dhcp.apk-new":    "/etc/config/dhcp",
		"/etc/config/../../etc/shadow": "/etc/shadow", // cleaned, so a grant on /etc/config/* does not cover it
	} {
		got := pkgResolveScope(pkgConfigResolveIn{Path: in})
		if len(got) != 1 || got[0] != want {
			t.Errorf("scope(%q) = %v, want [%s]", in, got, want)
		}
	}
	if matchAny([]string{"/etc/config/*"}, pkgResolveScope(pkgConfigResolveIn{Path: "/etc/config/../../etc/shadow"})[0]) {
		t.Error("a traversal path was covered by a /etc/config/* grant")
	}

	root := withFixtureRoot(t)
	s := testServer(t, "")
	ctx := context.Background()
	for _, p := range []string{"/tmp/x", "/usr/bin/x", "etc/x", "/etcetera/x"} {
		writeFixture(t, root, strings.TrimPrefix(p, "/")+".apk-new", "x")
		if _, _, err := s.pkgConfigResolve(ctx, "c", pkgConfigResolveIn{Path: p, Action: "keep_current"}); err == nil {
			t.Errorf("resolve accepted a path outside /etc: %s", p)
		}
	}

	// The policy file may be left as it is but never replaced: that would be self-escalation.
	writeFixture(t, root, "etc/config/openwrt-mcp", "config server\n")
	writeFixture(t, root, "etc/config/openwrt-mcp.apk-new", "config policy\n\tlist tools 'exec'\n")
	if _, _, err := s.pkgConfigResolve(ctx, "c", pkgConfigResolveIn{Path: "/etc/config/openwrt-mcp", Action: "use_new"}); err != errPolicyFile {
		t.Errorf("use_new on the policy file: %v", err)
	}
	if b, _ := os.ReadFile(root + "/etc/config/openwrt-mcp"); string(b) != "config server\n" {
		t.Errorf("the policy file was changed: %q", b)
	}
	if _, _, err := s.pkgConfigResolve(ctx, "c", pkgConfigResolveIn{Path: "/etc/config/openwrt-mcp", Action: "bogus"}); err == nil {
		t.Error("unknown action accepted")
	}
}

// ---------------------------------------------------------------- system_status

const ifaceDump = `{"interface":[
 {"interface":"WAN","up":true,"proto":"dhcp","l3_device":"eth1","uptime":3600,"metric":10,
  "ipv4-address":[{"address":"100.64.1.2","mask":24}],
  "route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.1.1"},{"target":"100.64.1.0","mask":24,"nexthop":"0.0.0.0"}]},
 {"interface":"WAN6","up":true,"proto":"dhcpv6","l3_device":"eth1","uptime":5,"metric":20,
  "ipv6-address":[{"address":"2001:db8::2","mask":64}],
  "route":[{"target":"::","mask":0,"nexthop":"fe80::1"}]},
 {"interface":"lan","up":true,"proto":"static","l3_device":"br-lan","uptime":7200,
  "ipv4-address":[{"address":"192.168.1.1","mask":24}],"ipv6-address":[{"address":"fd00::1","mask":60}]},
 {"interface":"wwan","up":false,"proto":"dhcp","errors":[{"code":"NO_DEVICE"}]}
]}`

const wirelessStatus = `{
 "radio0":{"up":true,"disabled":false,"interfaces":[{"ifname":"phy0-ap0","config":{"ssid":"Home","mode":"ap"}}]},
 "radio1":{"up":false,"disabled":true,"interfaces":[]},
 "radio2":{"up":false,"disabled":false,"interfaces":[]}}`

func TestSystemStatusReportsEverySectionFromTheRawData(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_count", "1234\n")
	writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_max", "65536\n")
	writeFixture(t, root, "sys/class/thermal/thermal_zone0/type", "cpu-thermal\n") // no hwmon: the fallback
	writeFixture(t, root, "sys/class/thermal/thermal_zone0/temp", "41000\n")
	writeFixture(t, root, "etc/config/dhcp.apk-new", "x")

	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"Test Board","board_name":"vendor,test","kernel":"6.12.1","hostname":"rtr","release":{"description":"OpenWrt 25.12.5"}}`)
	f.on("ubus call system info", `{"uptime":3661,"load":[65536,32768,0],
		"memory":{"total":536870912,"free":1,"available":268435456},
		"root":{"total":102400,"used":1,"avail":51200},"tmp":{"total":262144,"avail":131072}}`)
	f.on("ubus call network.interface dump", ifaceDump)
	f.on("ubus call network.wireless status", wirelessStatus)
	f.on("uci changes", "dhcp.pi=host")
	s := testServer(t, "")
	s.pending["tok123"] = &pendingApply{Token: "tok123", Configs: []string{"network"}, Client: "c", Deadline: time.Now().Add(time.Minute)}

	out, summary, err := s.systemStatus(context.Background(), systemStatusIn{})
	if err != nil || summary != "system status" {
		t.Fatalf("%v %q", err, summary)
	}
	for _, want := range []string{
		"Test Board (vendor,test) -- OpenWrt 25.12.5, kernel 6.12.1, host rtr",
		"uptime 1h1m1s, load 1.00 0.50 0.00", // 65536 is 1.0 in ubus fixed-point
		"memory 256/512 MiB available; overlay 50/100 MiB free; /tmp 128/256 MiB free",
		"temperatures: cpu-thermal 41.0C",
		"conntrack 1234/65536",
		"up 1h0m0s 100.64.1.2/24 default via 100.64.1.1 metric 10",
		"up 5s 2001:db8::2/64 default via fe80::1 metric 20",
		"192.168.1.1/24 fd00::1/60",
		"DOWN",
		"ERROR:NO_DEVICE",
		`radio0 up phy0-ap0="Home"(ap)`,
		"radio1 disabled",
		"radio2 DOWN",
		"uncommitted uci changes (not ours):",
		"dhcp.pi=host",
		"uci_apply awaiting confirmation: tok123",
		"1 .apk-new config file(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "nothing\n") {
		t.Error("said nothing was outstanding while listing three things")
	}
}

func TestSystemStatusSaysNothingIsOutstandingOnAQuietRouter(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call system board", `{}`)
	f.on("uci changes", "")
	out, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{})
	if err != nil || !strings.Contains(out, "outstanding:\n  nothing\n") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestSystemStatusSurvivesEveryUbusCallFailing(t *testing.T) {
	withFixtureRoot(t)
	newFakeRouter(t) // no handlers: every command fails like a missing binary
	out, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{})
	if err != nil {
		t.Fatalf("a dead ubus made the whole status fail: %v", err)
	}
	for _, want := range []string{"board:", "interfaces:", "outstanding:"} {
		if !strings.Contains(out, want) {
			t.Errorf("section %q missing from a degraded status:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------- firewall_show, logread, ubus_*

func TestFirewallShowViews(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		in   firewallShowIn
		want string
	}{
		{firewallShowIn{}, "nft list ruleset"},
		{firewallShowIn{View: "ruleset"}, "nft list ruleset"},
		{firewallShowIn{View: "rendered"}, "fw4 -q print"},
		{firewallShowIn{View: "check"}, "fw4 check"},
		{firewallShowIn{View: "table"}, "nft list table inet fw4"},
		{firewallShowIn{View: "table", Family: "ip", Table: "nat"}, "nft list table ip nat"},
		{firewallShowIn{View: "chain", Chain: "forward_lan"}, "nft list chain inet fw4 forward_lan"},
		{firewallShowIn{View: "chain", Family: "ip", Table: "t", Chain: "c-1_x"}, "nft list chain ip t c-1_x"},
	} {
		f := newFakeRouter(t)
		f.on("nft", "x")
		f.on("fw4", "x")
		if _, _, err := firewallShow(ctx, c.in); err != nil {
			t.Errorf("%+v: %v", c.in, err)
		} else if got := f.callList(); len(got) != 1 || got[0] != c.want {
			t.Errorf("%+v ran %q, want %q", c.in, got, c.want)
		}
	}

	f := newFakeRouter(t)
	f.on("nft", "x")
	n := func(k int) string { return strings.Repeat("a", k) }
	for _, in := range []firewallShowIn{
		{View: "bogus"}, {View: "chain"}, {View: "chain", Chain: "x y"}, {View: "chain", Chain: "x;y"},
		{View: "chain", Chain: n(65)}, {View: "table", Table: "a b"}, {View: "table", Family: "inet; flush ruleset"},
		{View: "chain", Family: "-x", Chain: "c"},
	} {
		if _, _, err := firewallShow(ctx, in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	f.noCalls(t, "a refused firewall view")
	if _, _, err := firewallShow(ctx, firewallShowIn{View: "chain", Chain: n(64)}); err != nil {
		t.Errorf("a 64-character chain is within the limit: %v", err)
	}

	f = newFakeRouter(t)
	f.on("fw4 check", "")
	if out, _, _ := firewallShow(ctx, firewallShowIn{View: "check"}); out != "firewall configuration is valid" {
		t.Errorf("silent success of check should say so, got %q", out)
	}
	f.fail("fw4 check", "Section @rule[3] is missing a src")
	if out, _, err := firewallShow(ctx, firewallShowIn{View: "check"}); err == nil || !strings.Contains(out, "@rule[3]") {
		t.Errorf("a failing check must surface its complaint: %v %q", err, out)
	}
}

func TestLogreadLimitsAndEmptyResults(t *testing.T) {
	f := newFakeRouter(t)
	var lines []string
	for i := 0; i < 2100; i++ {
		lines = append(lines, fmt.Sprintf("Tue Sep 30 12:00:00 2026 daemon.info x[1]: line-%04d", i))
	}
	f.on("logread", strings.Join(lines, "\n"))
	ctx := context.Background()

	count := func(in logreadIn) int {
		out, _, err := logread(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(out, "line-")
	}
	for in, want := range map[int]int{0: 100, 1: 1, -7: 1, 2000: 2000, 2001: 2000, 1 << 30: 2000} {
		if got := count(logreadIn{Lines: in}); got != want {
			t.Errorf("Lines=%d returned %d lines, want %d", in, got, want)
		}
	}
	// It is the NEWEST matching lines that survive.
	out, _, _ := logread(ctx, logreadIn{Lines: 2})
	if !strings.Contains(out, "line-2099") || !strings.Contains(out, "line-2098") || strings.Contains(out, "line-2097") {
		t.Errorf("not the most recent lines:\n%s", out)
	}
	if out, _, _ := logread(ctx, logreadIn{Pattern: "no-such-text"}); out != "(no matching log lines)" {
		t.Errorf("empty result: %q", out)
	}
	f.fail("logread", "logd not running")
	if _, _, err := logread(ctx, logreadIn{}); err == nil {
		t.Error("a failing logread was reported as an empty log")
	}
}

func TestUbusListAndCallArgumentHandling(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus", "ok")
	srv := testServer(t, policyFor("c", []string{"ubus_call"}, "*"))
	cs := connectClient(t, srv, "c")

	if _, isErr := callText(t, cs, "ubus_list", map[string]any{}); isErr {
		t.Fatal("ubus_list refused")
	}
	if _, isErr := callText(t, cs, "ubus_list", map[string]any{"filter": "network.interface.lan"}); isErr {
		t.Fatal("ubus_list with filter refused")
	}
	// Arguments reach ubus as ONE JSON argv element, keys sorted, shell characters inert.
	if _, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "file", "method": "read",
		"args": map[string]any{"path": "/etc/x; reboot", "b": 2, "a": []int{1}}}); isErr {
		t.Fatal("ubus_call refused")
	}
	if _, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "system", "method": "board", "args": map[string]any{}}); isErr {
		t.Fatal("ubus_call refused")
	}
	want := []string{
		"ubus -v list",
		"ubus -v list network.interface.lan",
		`ubus call file read {"a":[1],"b":2,"path":"/etc/x; reboot"}`,
		"ubus call system board", // an empty args object adds no argument
	}
	if got := f.callList(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	f.fail("ubus call", "Command failed: Not found")
	out, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "nosuch", "method": "x"})
	if !isErr || !strings.Contains(out, "Not found") {
		t.Errorf("ubus failure must come back as an error carrying its output: %v %q", isErr, out)
	}
}
