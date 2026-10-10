package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Advisory warnings for a uci_apply dry run (ROADMAP 5.9). A warning is a finding the change
// would add: the security audit's configuration checks run on the live configuration and again on
// the staged one, and what only the second run reports is the change's doing. Two checks are
// added that no audit has a reason to make: a name the change leaves with nothing behind it, and
// the radio this session is connected through. Nothing here blocks anything (Principle 3); the
// management-path refusal is a separate rule (probe.go), and blocking policy is 6.2.

var warnChecks = []check{
	{"firewall", checkFirewall}, {"ssh", checkSSH}, {"luci", checkLuci}, {"upnp", checkUPnP}, {"wifi", checkWifi},
}

// warnConfigs are the configs those checks and the reference check read. A change to any other
// config cannot raise a warning, so it pays for none.
var warnConfigs = []string{"firewall", "dropbear", "uhttpd", "upnpd", "wireless", "network", "dhcp", "sqm", "mwan3"}

func warnsOn(changes []UCIChange) bool {
	for _, c := range changes {
		if contains(warnConfigs, c.Config) {
			return true
		}
	}
	return false
}

// advice is the configuration as the checks see it at one moment.
type advice struct {
	sn  *snapshot
	run *findingsRun
}

// takeAdvice reads everything now, including the configs the reference check needs: a snapshot
// that read them later would read the staged state and call it the live one.
func takeAdvice(ctx context.Context) *advice {
	sn := newSnapshot(ctx)
	sn.ids = true // an unnamed section keeps its name across the two readings
	a := &advice{sn: sn, run: runChecksOn(sn, "warnings from this change", warnChecks)}
	for _, c := range refConfigs() {
		if installed(c) {
			_, _ = sn.getUCI(c)
		}
	}
	return a
}

func installed(config string) bool {
	_, err := os.Stat(filepath.Join(uciConfDir, config))
	return err == nil
}

func (f finding) key() string { return f.id + "\x00" + f.evidence }

// report is the warnings paragraph, with its trailing blank line: what the staged state shows
// that this one (the live state) did not. It must run while the change is still staged.
func (before *advice) report(ctx context.Context) string {
	if before == nil {
		return ""
	}
	after := takeAdvice(ctx)
	seen := map[string]bool{}
	for _, f := range before.run.findings {
		seen[f.key()] = true
	}
	r := &findingsRun{title: after.run.title, checked: after.run.checked, skipped: after.run.skipped}
	for _, f := range after.run.findings {
		if !seen[f.key()] {
			r.findings = append(r.findings, f)
		}
	}
	tb, ta, unread := adviceTrees(before.sn, after.sn)
	r.findings = append(r.findings, refFindings(tb, ta)...)
	r.checked = append(r.checked, "references")
	for _, c := range unread {
		r.skipped = append(r.skipped, "references ("+c+" would not print)")
	}
	r.findings = append(r.findings, radioFindings(ctx, before.sn, after.sn)...)
	return r.render() + "\n\n"
}

// adviceTrees are the reference configs as both snapshots read them. A config that is not
// installed is left out; one that is installed and would not print in either reading is left out
// of both and named, because comparing a config with nothing would make all of it look new.
func adviceTrees(before, after *snapshot) (tb, ta map[string]*uciTree, unread []string) {
	tb, ta = map[string]*uciTree{}, map[string]*uciTree{}
	for _, c := range refConfigs() {
		if !installed(c) {
			continue
		}
		b, errB := before.getUCI(c)
		a, errA := after.getUCI(c)
		if errB != nil || errA != nil {
			unread = append(unread, c)
			continue
		}
		tb[c], ta[c] = b, a
	}
	return tb, ta, unread
}

// ---------------------------------------------------------------- dangling names

// refName is one name a field holds, and what it is meant to be.
type refName struct{ name, target string }

// named lists the names a reference field holds. A value that names a device is not judged: any
// kernel device may be written there without a section behind it, except the "@name" alias form.
func (u refSpec) named(t *uciTree, sec string) []refName {
	if u.option == "" {
		return []refName{{sec, u.target}}
	}
	var out []refName
	for _, v := range t.list(sec, u.option) {
		for _, w := range strings.Fields(v) {
			switch {
			case u.alias && strings.HasPrefix(w, "@"):
				out = append(out, refName{w[1:], "interface"})
			case u.target != "device" && w != "*":
				out = append(out, refName{w, u.target})
			}
		}
	}
	return out
}

// refDefined is every name something defines, per kind: "zone\x00lan".
func refDefined(trees map[string]*uciTree) map[string]bool {
	out := map[string]bool{}
	for c, t := range trees {
		for _, sec := range t.order {
			for _, d := range refDefs {
				if d.config != c || d.typ != t.typ[sec] {
					continue
				}
				name := sec
				if d.option != "" {
					name = t.get(sec, d.option)
				}
				if name != "" {
					out[d.target+"\x00"+name] = true
				}
			}
		}
	}
	return out
}

// A refGap is a field that names something nothing defines.
type refGap struct {
	name, target string
	at           string // where, as refs prints it: firewall.cfg0392bd.network (zone "guest")
	key          string
}

func refGaps(trees map[string]*uciTree) []refGap {
	defined := refDefined(trees)
	var out []refGap
	for _, c := range refConfigs() {
		t := trees[c]
		if t == nil {
			continue
		}
		for _, sec := range t.order {
			for _, u := range refUses {
				// dnsmasq lists interfaces, and may take a device name there (not verified), so a
				// name it does not know proves nothing.
				if u.config != c || u.typ != t.typ[sec] || u.typ == "dnsmasq" {
					continue
				}
				for _, n := range u.named(t, sec) {
					if defined[n.target+"\x00"+n.name] {
						continue
					}
					at := fmt.Sprintf("%s.%s", c, sec)
					if u.option != "" {
						at += "." + u.option
						what := u.typ
						if l := t.get(sec, "name"); l != "" {
							what += fmt.Sprintf(" %q", trunc(l, 40))
						}
						at += " (" + what + ")"
					}
					out = append(out, refGap{n.name, n.target, at, c + "." + sec + "." + u.option + "\x00" + n.name})
				}
			}
		}
	}
	return out
}

// refFindings reports the names the change leaves with nothing behind them: a section deleted or
// renamed while others still use its name (ref-removed), and a field that now names something
// that never existed, often the same name in another case (ref-unknown). A name that dangled
// before the change is not the change's doing and is not reported.
func refFindings(before, after map[string]*uciTree) []finding {
	was := map[string]bool{}
	for _, g := range refGaps(before) {
		was[g.key] = true
	}
	wasDefined, nowDefined := refDefined(before), refDefined(after)
	groups := map[string][]refGap{}
	for _, g := range refGaps(after) {
		if !was[g.key] {
			k := g.target + "\x00" + g.name
			groups[k] = append(groups[k], g)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []finding
	for _, k := range keys {
		g := groups[k]
		id, msg := "ref-unknown", fmt.Sprintf("%s %q is used but nothing defines it", g[0].target, trunc(g[0].name, 64))
		if wasDefined[k] {
			id, msg = "ref-removed", fmt.Sprintf("%s %q is no longer defined, but fields still use it", g[0].target, trunc(g[0].name, 64))
		} else if near := nearName(nowDefined, g[0].target, g[0].name); near != "" {
			msg += fmt.Sprintf("; did you mean %q?", near)
		}
		var at []string
		for _, x := range g {
			at = append(at, x.at)
		}
		ev := strings.Join(at[:min(len(at), 3)], ", ")
		if len(at) > 3 {
			ev += fmt.Sprintf(" (+%d more)", len(at)-3)
		}
		f := newFinding(id, sevMedium, msg, ev)
		if reRefName.MatchString(g[0].name) {
			f.next = strings.ReplaceAll(f.next, "NAME", g[0].name) // a call that can be pasted
		}
		switch g[0].target {
		case "zone":
			f.doc = docFirewall
		case "radio":
			f.doc = docWifi
		}
		out = append(out, f)
	}
	return out
}

// nearName finds a defined name of this kind that differs from name only in case.
func nearName(defined map[string]bool, target, name string) string {
	var near []string
	for k := range defined {
		if t, n, _ := strings.Cut(k, "\x00"); t == target && n != name && strings.EqualFold(n, name) {
			near = append(near, n)
		}
	}
	sort.Strings(near)
	if len(near) == 0 {
		return ""
	}
	return near[0]
}

// ---------------------------------------------------------------- the radio the session is on

func wifiUp(t *uciTree, sec string) bool {
	if t.typ[sec] != "wifi-iface" || uciOn(t.get(sec, "disabled")) {
		return false
	}
	radio := t.get(sec, "device")
	return t.typ[radio] == "wifi-device" && !uciOn(t.get(radio, "disabled"))
}

// radioFindings warns when the change takes down the Wi-Fi network this session is connected
// through: its section, or its radio, disabled or deleted. The session is found only when a change
// does take something down, because it costs four commands.
func radioFindings(ctx context.Context, before, after *snapshot) []finding {
	peer := profileFrom(ctx).Peer
	if !peer.IsValid() {
		return nil
	}
	tb, errB := before.getUCI("wireless")
	ta, errA := after.getUCI("wireless")
	if errB != nil || errA != nil {
		return nil
	}
	down := map[string]bool{}
	for _, sec := range tb.sectionsOfType("wifi-iface") {
		if wifiUp(tb, sec) && !wifiUp(ta, sec) {
			down[sec] = true
		}
	}
	if len(down) == 0 {
		return nil
	}
	sec := sessionWiFi(ctx, peer.String())
	if !down[sec] {
		return nil
	}
	return []finding{newFinding("radio-in-use", sevHigh,
		"this change turns off the Wi-Fi network this session is connected through",
		fmt.Sprintf("wireless.%s (ssid %q) on %s; the session's device %s is associated to it", sec,
			trunc(tb.get(sec, "ssid"), 32), tb.get(sec, "device"), peer))}
}

// sessionWiFi names the wifi-iface section the device at addr is associated to ("" if it is not on
// Wi-Fi or cannot be told): its MAC from the neighbour table, then every AP interface's association
// list, which is how network_clients tells a Wi-Fi client from a wired one.
func sessionWiFi(ctx context.Context, addr string) string {
	out, err := run(ctx, defaultCmdTimeout, "ip", "neigh", "show")
	if err != nil {
		return ""
	}
	mac := ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != addr {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" && isMAC(f[i+1]) {
				mac = strings.ToLower(f[i+1])
			}
		}
	}
	if mac == "" {
		return ""
	}
	var status map[string]struct {
		Interfaces []struct {
			Section string `json:"section"`
			Ifname  string `json:"ifname"`
		} `json:"interfaces"`
	}
	if runJSON(ctx, &status, "ubus", "call", "network.wireless", "status") != nil {
		return ""
	}
	for _, radio := range sortedKeys(status) {
		for _, i := range status[radio].Interfaces {
			var assoc struct {
				Results []struct {
					MAC string `json:"mac"`
				} `json:"results"`
			}
			if runJSON(ctx, &assoc, "ubus", "call", "iwinfo", "assoclist", fmt.Sprintf(`{"device":%q}`, i.Ifname)) != nil {
				continue
			}
			for _, r := range assoc.Results {
				if strings.EqualFold(r.MAC, mac) {
					return i.Section
				}
			}
		}
	}
	return ""
}
