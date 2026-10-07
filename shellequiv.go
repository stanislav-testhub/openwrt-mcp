package main

import (
	"fmt"
	"path"
	"strings"
)

// The exec scope is argv[0] taken literally, so a grant for `find` or `awk` looks harmless
// and is a root shell: both run other programs. These are the programs for which that holds.
// Judging them by base name catches `/usr/bin/../bin/sh` and a glob such as `/bin/*` too
// (CVE-2025-11490: a blocklist of command names was bypassed by an absolute path).
//
// The list is pinned by TestShellEquivalentProgramsArePinned; adding a name is a decision
// that test makes you write down. Grants that write files (wget, cp, dd) are the same class
// of risk by a different route and are not covered here.
var shellEquivalentPrograms = []string{
	// shells and wrappers that run another program
	"sh", "ash", "bash", "dash", "busybox", "env", "nice", "flock", "timeout", "nohup", "setsid",
	"chroot", "su", "watch", "time", "start-stop-daemon", "taskset", "ionice", "chrt",
	// commands that run commands
	"find", "awk", "sed", "xargs", "tar", "ssh", "dbclient",
	// interpreters
	"lua", "ucode",
	// package managers run package scripts as root
	"apk", "opkg",
	// `ubus call file exec` runs a program wherever the ACL allows it
	"ubus",
}

// ubusExecScope is the ubus_call scope that runs a program.
const ubusExecScope = "file.exec"

// shellEquivalentNames reports what a policy block that grants tools on scopes lets its client
// run that amounts to a root shell: table entries for exec, and file.exec for ubus_call. A scope
// is a glob over argv[0] (exec) or object.method (ubus_call); a glob that can match a listed
// name counts, so `*`, `s*` and `/bin/*` are caught along with `sh`.
func shellEquivalentNames(tools, scopes []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	grants := func(tool string) bool { return contains(tools, tool) || contains(tools, "*") }
	if grants("exec") {
		for _, g := range scopes {
			base := path.Base(g)
			for _, n := range shellEquivalentPrograms {
				if matchAny([]string{base}, n) {
					add(n)
				}
			}
		}
	}
	if grants("ubus_call") {
		for _, g := range scopes {
			if matchAny([]string{g}, ubusExecScope) {
				add(ubusExecScope)
			}
		}
	}
	return out
}

// describeShellEquivalent is names for a message: a grant on `*` matches every table entry.
func describeShellEquivalent(names []string) string {
	if len(names) > 6 {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:6], ", "), len(names)-6)
	}
	return strings.Join(names, ", ")
}

// shellEquivalent lists what this policy lets its client run that amounts to a root shell.
func (p *Policy) shellEquivalent() []string { return shellEquivalentNames(p.Tools, p.Scopes) }

// takeFlag removes every occurrence of flag from args and reports whether there was one.
func takeFlag(args []string, flag string) ([]string, bool) {
	var rest []string
	found := false
	for _, a := range args {
		if a == flag {
			found = true
			continue
		}
		rest = append(rest, a)
	}
	return rest, found
}
