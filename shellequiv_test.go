package main

import (
	"sort"
	"strings"
	"testing"
)

// ROADMAP 3.7. The names below are the spec, written out here and not read from the table in
// shellequiv.go: the roadmap's list (sh, ash, busybox, env, nice, flock, find, awk, sed, xargs,
// tar, ssh, lua, ucode, apk, opkg, ubus) plus the BusyBox wrappers and shells of the same class.
var specShellEquivalent = []string{
	"sh", "ash", "bash", "dash", "busybox", "env", "nice", "flock", "timeout", "nohup", "setsid",
	"chroot", "su", "watch", "time", "start-stop-daemon", "taskset", "ionice", "chrt",
	"find", "awk", "sed", "xargs", "tar", "ssh", "dbclient",
	"lua", "ucode", "apk", "opkg", "ubus",
}

func execHits(scope string) []string { return shellEquivalentNames([]string{"exec"}, []string{scope}) }

func TestShellEquivalentProgramsArePinned(t *testing.T) {
	got := append([]string(nil), shellEquivalentPrograms...)
	want := append([]string(nil), specShellEquivalent...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the table and the spec differ (adding a program is a decision: update both)\n table %v\n spec  %v", got, want)
	}
}

// Every name is caught however it is written: bare, by absolute path, through a ".." path, or
// as a glob that can only mean that program.
func TestEveryShellEquivalentProgramIsCaughtInEveryForm(t *testing.T) {
	for _, n := range specShellEquivalent {
		for _, form := range []string{
			n, "/bin/" + n, "/usr/bin/" + n, "/sbin/" + n, "/usr/sbin/" + n, "/usr/bin/../bin/" + n, "./" + n, "/opt/tools/" + n,
			n + "*", "/bin/" + n + "*",
		} {
			if hit := execHits(form); !contains(hit, n) {
				t.Errorf("exec scope %q is a grant for %s but was reported as %v", form, n, hit)
			}
		}
	}
}

func TestOrdinaryProgramsAreNotShellEquivalent(t *testing.T) {
	for _, scope := range []string{
		"ping", "/bin/ping", "/usr/bin/ping", "ping6", "ls", "cat", "logger", "uci", "wg", "ip", "nft", "ifstatus", "df",
		"/usr/sbin/iwinfo", "traceroute", "nslookup", "ubusd", "shell", "bashful", "awkward", "sedan", "/usr/bin/findutils",
		"timeouts", "ssh-keygen", "apkg", "", "file.exec",
	} {
		if hit := execHits(scope); len(hit) != 0 {
			t.Errorf("exec scope %q was reported as shell-equivalent (%v)", scope, hit)
		}
	}
}

// A glob counts when it can match a listed program, because the policy engine would let it.
func TestGlobsThatCanReachAShellAreCaught(t *testing.T) {
	for scope, wantName := range map[string]string{
		"*":       "sh",
		"s*":      "sh",
		"?sh":     "ash",
		"b*":      "bash",
		"*sh":     "dash",
		"/bin/*":  "sh",
		"*/sh":    "sh",
		"/*/*/sh": "sh",
		"busy*":   "busybox",
		"/usr/*":  "find",
	} {
		if hit := execHits(scope); !contains(hit, wantName) {
			t.Errorf("exec scope %q can run %s but was reported as %v", scope, wantName, hit)
		}
	}
	for _, scope := range []string{"ping*", "/usr/bin/ping", "net*", "i[pf]", "z*"} {
		if hit := execHits(scope); len(hit) != 0 {
			t.Errorf("exec scope %q cannot reach a listed program but was reported as %v", scope, hit)
		}
	}
}

// Policy engine and check must agree: whatever the check calls safe, the engine must not let
// through as a listed program. Walks every listed name against every glob in the spec above.
func TestTheCheckAgreesWithThePolicyEngine(t *testing.T) {
	globs := []string{"*", "s*", "/bin/*", "ping", "/bin/sh", "b*", "*sh", "?sh", "/usr/bin/awk", "ping*", "x*"}
	for _, g := range globs {
		hit := execHits(g)
		for _, n := range specShellEquivalent {
			// What the engine would run for argv[0] n or /bin/n: both are the same program.
			engineAllows := matchAny([]string{g}, n) || matchAny([]string{g}, "/bin/"+n)
			if engineAllows && !contains(hit, n) {
				t.Errorf("glob %q lets argv[0] %s through the policy engine, but the check did not report it", g, n)
			}
		}
	}
}

// Only the tools that can run a program count: the same scope text on another tool is harmless.
func TestShellEquivalenceDependsOnTheToolGranted(t *testing.T) {
	if hit := shellEquivalentNames([]string{"net_diag", "logread", "service_control"}, []string{"sh", "*", "find"}); len(hit) != 0 {
		t.Errorf("tools that cannot run a program were reported: %v", hit)
	}
	for scope, want := range map[string]bool{
		"file.exec": true, "file.*": true, "*": true, "f*.e*": true, "fi?e.exec": true,
		"file.read": false, "network.interface.*": false, "system.board": false, "iwinfo.info": false, "uci.get": false,
	} {
		hit := shellEquivalentNames([]string{"ubus_call"}, []string{scope})
		if (len(hit) > 0) != want {
			t.Errorf("ubus_call on %q: reported %v, want shell-equivalent=%v", scope, hit, want)
		}
	}
	// A block that grants exec and ubus_call shares its scopes; both checks apply.
	hit := shellEquivalentNames([]string{"exec", "ubus_call"}, []string{"ping", "file.exec"})
	if len(hit) != 1 || hit[0] != "file.exec" {
		t.Errorf("exec+ubus_call on ping, file.exec: %v", hit)
	}
	// "*" in a hand-edited policy grants every tool.
	if hit := shellEquivalentNames([]string{"*"}, []string{"sh"}); !contains(hit, "sh") {
		t.Errorf("a wildcard tool list with scope sh: %v", hit)
	}
}

func TestDescribeShellEquivalentStaysShortForAWildcard(t *testing.T) {
	d := describeShellEquivalent(execHits("*"))
	if strings.Count(d, ",") > 6 || !strings.Contains(d, "more") {
		t.Errorf("a wildcard grant is described as %q: it should be cut to a few names and a count", d)
	}
	if d := describeShellEquivalent([]string{"sh", "find"}); d != "sh, find" {
		t.Errorf("two names: %q", d)
	}
}

func TestTakeFlagRemovesEveryCopyAndKeepsTheOrder(t *testing.T) {
	rest, found := takeFlag([]string{"allow", "--shell-equivalent", "c", "exec", "sh", "--shell-equivalent", "1h"}, "--shell-equivalent")
	if !found || strings.Join(rest, " ") != "allow c exec sh 1h" {
		t.Errorf("rest %v found %v", rest, found)
	}
	if rest, found := takeFlag([]string{"allow", "c"}, "--shell-equivalent"); found || len(rest) != 2 {
		t.Errorf("no flag present: %v %v", rest, found)
	}
}
