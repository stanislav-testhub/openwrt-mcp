package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Post-apply probes and management-path detection (ROADMAP 2.3).
//
// The rollback timer undoes a change nobody confirms, but deciding whether the change worked
// is left to the caller, and a change can cut off the very session that would confirm it. So
// uci_apply can run probes once the reload is done, and a change that touches the management
// path is refused unless the caller names a probe that proves the router is still reachable
// (or forces it).

type probeSpec struct {
	Kind   string `json:"kind" jsonschema:"ping | resolve"`
	Target string `json:"target" jsonschema:"host name or IP to ping, or the name to resolve"`
	Server string `json:"server,omitempty" jsonschema:"resolve only: the DNS server to ask (default: the router's resolver)"`
}

const (
	maxProbes        = 5
	defaultProbeWait = 15
	maxProbeWait     = 60
	// a change that touches the management path gets this window unless the caller chose one
	mgmtRollbackSec = 180
)

// Variables so tests need not wait for real.
var (
	probeEvery    = time.Second
	probeWaitUnit = time.Second
)

func validateProbes(ps []probeSpec) error {
	if len(ps) > maxProbes {
		return fmt.Errorf("at most %d probes", maxProbes)
	}
	for _, p := range ps {
		if p.Kind != "ping" && p.Kind != "resolve" {
			return fmt.Errorf("probe kind must be ping or resolve, not %q", p.Kind)
		}
		// A target is an argv element, never a shell word, but it must not read as an option.
		if !reNetTarget.MatchString(p.Target) {
			return fmt.Errorf("bad probe target %q", p.Target)
		}
		if p.Server != "" && (p.Kind != "resolve" || !reNetTarget.MatchString(p.Server)) {
			return fmt.Errorf("bad probe server %q: only a resolve probe takes one, a host or IP", p.Server)
		}
	}
	return nil
}

// probeScopes makes each probe target a policy scope of its own: a probe has the router ping
// and resolve names for the caller, which a grant on uci_apply alone never allowed.
func probeScopes(ps []probeSpec) []string {
	var out []string
	for _, p := range ps {
		out = append(out, "probe."+p.Kind+"."+p.Target)
	}
	return out
}

func probeArgv(p probeSpec) []string {
	if p.Kind == "ping" {
		argv := []string{"ping", "-c", "1", "-W", "2"}
		if strings.Contains(p.Target, ":") {
			argv = append(argv, "-6")
		}
		return append(argv, p.Target)
	}
	argv := []string{"nslookup", p.Target}
	if p.Server != "" {
		argv = append(argv, p.Server)
	}
	return argv
}

// probeOnce runs one attempt. nslookup (BusyBox) can print a failure and still exit 0, so the
// words it uses for one count too.
func probeOnce(ctx context.Context, p probeSpec) (bool, string) {
	out, err := run(ctx, 10*time.Second, probeArgv(p)...)
	if err != nil {
		return false, firstLine(strings.TrimSpace(err.Error() + " " + out))
	}
	if p.Kind == "resolve" {
		low := strings.ToLower(out)
		for _, bad := range []string{"can't find", "can't resolve", "nxdomain", "servfail", "refused"} {
			if strings.Contains(low, bad) {
				return false, firstLine(strings.TrimSpace(out))
			}
		}
	}
	return true, ""
}

// runProbes runs each probe, retrying until it passes or wait runs out, and stops spending
// time once budget (the part of the rollback window it may use) is gone. It reports whether
// every probe passed.
func runProbes(ctx context.Context, ps []probeSpec, wait, budget time.Duration) (string, bool) {
	lines := []string{"probes (run after the reload, each retried for up to " + wait.String() + "):"}
	allOK := true
	var used time.Duration
	for _, p := range ps {
		w := min(wait, max(budget-used, 0))
		start := time.Now()
		ok, why := probeOnce(ctx, p)
		for !ok && time.Since(start) < w && ctx.Err() == nil {
			time.Sleep(probeEvery)
			ok, why = probeOnce(ctx, p)
		}
		took := time.Since(start)
		used += took
		if ok {
			lines = append(lines, fmt.Sprintf("  %s %s: OK after %s", p.Kind, p.Target, took.Round(100*time.Millisecond)))
			continue
		}
		allOK = false
		lines = append(lines, fmt.Sprintf("  %s %s: FAILED after %s (%s)", p.Kind, p.Target, took.Round(100*time.Millisecond), why))
	}
	if !allOK {
		lines = append(lines, "PROBE FAILED -- the change may have broken something. Call uci_rollback now, or let the "+
			"rollback timer expire; do not confirm.")
	}
	return strings.Join(lines, "\n"), allOK
}

func probeWait(sec int) time.Duration {
	return time.Duration(clampInt(sec, defaultProbeWait, 1, maxProbeWait)) * probeWaitUnit
}

// ---------------------------------------------------------------- management path

// mgmtConfigs are the configs the management path lives in.
var mgmtConfigs = map[string]bool{"network": true, "dropbear": true, "firewall": true}

// The options that decide whether the path survives. A change to anything else on the same
// section (a DNS server, a rule's comment) is not flagged.
var (
	mgmtNetOpts  = map[string]bool{"ipaddr": true, "netmask": true, "proto": true, "device": true, "ports": true, "name": true, "type": true, "disabled": true, "auto": true, "gateway": true}
	mgmtSSHOpts  = map[string]bool{"Port": true, "Interface": true, "enable": true, "disabled": true}
	mgmtZoneOpts = map[string]bool{"input": true, "network": true, "name": true}
)

// mgmtView is the live configuration the rules read.
type mgmtView struct {
	net, ssh, fw *uciTree
	nets         map[string]bool // networks the management path rides on
	devices      map[string]bool // device names those networks use (the bridge)
	ports        []string        // SSH listening ports
}

func loadMgmtView(ctx context.Context) *mgmtView {
	load := func(name string) *uciTree {
		if t, err := uciShow(ctx, name, false); err == nil {
			return t
		}
		return parseUCIShow("")
	}
	v := &mgmtView{net: load("network"), ssh: load("dropbear"), fw: load("firewall"),
		nets: map[string]bool{"lan": true}, devices: map[string]bool{}}
	for _, sec := range v.ssh.sectionsOfType("dropbear") {
		if i := v.ssh.get(sec, "Interface"); i != "" {
			v.nets[i] = true
		}
		v.ports = append(v.ports, orDefault(v.ssh.get(sec, "Port"), "22"))
	}
	if len(v.ports) == 0 {
		v.ports = []string{"22"}
	}
	for n := range v.nets {
		if d := v.net.get(n, "device"); d != "" {
			v.devices[d] = true
		}
	}
	return v
}

// differs says whether applying c to the live option would change it. A create never does here.
func differs(c UCIChange, t *uciTree) bool {
	cur := t.list(c.Section, c.Option)
	switch c.op() {
	case opSet:
		return !(len(cur) == 1 && cur[0] == c.Value)
	case opSetList:
		return strings.Join(cur, "\x00") != strings.Join(c.Values, "\x00")
	case opAddList:
		return !contains(cur, c.Value)
	case opDelList:
		return contains(cur, c.Value)
	case opDelete:
		return c.Option == "" || len(cur) > 0
	}
	return false
}

func (v *mgmtView) reason(c UCIChange) string {
	if c.op() == opCreate {
		return ""
	}
	switch c.Config {
	case "network":
		typ := v.net.typ[c.Section]
		switch {
		case typ == "interface" && v.nets[c.Section]:
			if (mgmtNetOpts[c.Option] || c.Option == "") && differs(c, v.net) {
				return fmt.Sprintf("network.%s is the interface the management path rides on", c.Section)
			}
		case typ == "device" && v.devices[v.net.get(c.Section, "name")]:
			if (mgmtNetOpts[c.Option] || c.Option == "") && differs(c, v.net) {
				return fmt.Sprintf("network.%s is the device %s that carries the management network", c.Section, v.net.get(c.Section, "name"))
			}
		}
	case "dropbear":
		if v.ssh.typ[c.Section] == "dropbear" && (mgmtSSHOpts[c.Option] || c.Option == "") && differs(c, v.ssh) {
			return fmt.Sprintf("dropbear.%s changes the SSH listener", c.Section)
		}
	case "firewall":
		switch v.fw.typ[c.Section] {
		case "zone":
			for _, n := range v.fw.list(c.Section, "network") {
				if v.nets[n] && (mgmtZoneOpts[c.Option] || c.Option == "") && differs(c, v.fw) {
					return fmt.Sprintf("firewall.%s is zone %s, which carries the management network", c.Section, v.fw.get(c.Section, "name"))
				}
			}
		case "rule":
			for _, p := range v.ports {
				if portListed(v.fw.list(c.Section, "dest_port"), p) && c.Option != "name" && differs(c, v.fw) {
					return fmt.Sprintf("firewall.%s is a rule for the SSH port %s", c.Section, p)
				}
			}
		}
	}
	return ""
}

// portListed reports whether port is one of the dest_port values (single ports, ranges "a-b",
// or several in one value).
func portListed(values []string, port string) bool {
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, v := range values {
		for _, f := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' }) {
			lo, hi, isRange := strings.Cut(f, "-")
			a, errA := strconv.Atoi(lo)
			b, errB := strconv.Atoi(orDefault(hi, lo))
			if errA == nil && errB == nil && (isRange && a <= n && n <= b || a == n) {
				return true
			}
		}
	}
	return false
}

// mgmtReasons says why a change list touches the path the operator reaches the router by: the
// LAN interface or its bridge, the SSH listener, the firewall zone and the rule that let SSH in.
// The live configuration is read only when a change is in a config that can matter.
func mgmtReasons(ctx context.Context, changes []UCIChange) []string {
	relevant := false
	for _, c := range changes {
		relevant = relevant || mgmtConfigs[c.Config]
	}
	if !relevant {
		return nil
	}
	v := loadMgmtView(ctx)
	var out []string
	for _, c := range changes {
		if r := v.reason(c); r != "" && !contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}
