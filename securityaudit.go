package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The security audit (ROADMAP 4.3): configuration that looks fine and is quietly insecure. It is a
// separate list from the doctor on purpose -- one asks "is it working", the other "is it safe".
// Everything here reads configuration; the only file it opens that holds a secret is
// /etc/shadow, for one fact (is root's password field empty), and that fact is all it keeps.

func auditFindings(ctx context.Context) *findingsRun {
	return runChecks(ctx, "audit", []check{
		{"firewall", checkFirewall},
		{"ssh", checkSSH},
		{"luci", checkLuci},
		{"upnp", checkUPnP},
		{"wifi", checkWifi},
		{"root-password", checkRootPassword},
		{"packages", checkPackagesAudit},
		{"wireguard", checkWireGuard},
	})
}

// uciOff reports whether a UCI boolean option is switched off.
func uciOff(v string) bool {
	switch strings.ToLower(v) {
	case "0", "off", "no", "false", "disabled":
		return true
	}
	return false
}

func uciOn(v string) bool {
	switch strings.ToLower(v) {
	case "1", "on", "yes", "true", "enabled":
		return true
	}
	return false
}

// portCovers reports whether one dest_port token ("443", "8000-8100", "8000:8100") includes port.
func portCovers(tok string, port int) bool {
	tok = strings.TrimSpace(tok)
	for _, sep := range []string{"-", ":"} {
		if lo, hi, ok := strings.Cut(tok, sep); ok {
			l, e1 := strconv.Atoi(lo)
			h, e2 := strconv.Atoi(hi)
			return e1 == nil && e2 == nil && l <= port && port <= h
		}
	}
	n, err := strconv.Atoi(tok)
	return err == nil && n == port
}

func anyPortCovered(specs []string, ports []int) (int, bool) {
	for _, s := range specs {
		for _, p := range ports {
			if portCovers(s, p) {
				return p, true
			}
		}
	}
	return 0, false
}

// wanZoneSet names the zones that face the internet: those called wan*, and those that hold an
// interface carrying a default route.
func wanZoneSet(sn *snapshot, fw *uciTree) map[string]bool {
	viaDefault := map[string]bool{}
	if ifs, err := sn.getIfaces(); err == nil {
		for _, i := range ifs {
			for _, r := range i.Route {
				if r.Mask == 0 && (r.Target == "0.0.0.0" || r.Target == "::") {
					viaDefault[i.Interface] = true
				}
			}
		}
	}
	wan := map[string]bool{}
	for _, sec := range fw.sectionsOfType("zone") {
		name := fw.get(sec, "name")
		if strings.HasPrefix(strings.ToLower(name), "wan") {
			wan[name] = true
		}
		for _, n := range splitAll(fw.list(sec, "network")) {
			if viaDefault[n] {
				wan[name] = true
			}
		}
	}
	return wan
}

// dropbearPorts are the ports dropbear listens on at every address (an Interface option binds it
// to one, which the WAN cannot reach).
func dropbearPorts(t *uciTree) []int {
	var out []int
	for _, sec := range t.sectionsOfType("dropbear") {
		if t.get(sec, "Interface") != "" {
			continue
		}
		p, err := strconv.Atoi(orDefault(t.get(sec, "Port"), "22"))
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

// allAddressListens returns the uhttpd listen entries that bind every address: "0.0.0.0:80",
// "[::]:443", or a bare port.
func allAddressListens(t *uciTree, sec string) []string {
	var out []string
	for _, opt := range []string{"listen_http", "listen_https"} {
		for _, l := range splitAll(t.list(sec, opt)) {
			host := ""
			if i := strings.LastIndex(l, ":"); i >= 0 {
				host = l[:i]
			}
			if host == "" || host == "0.0.0.0" || host == "[::]" || host == "::" {
				out = append(out, l)
			}
		}
	}
	return out
}

func listenPort(l string) int {
	p := l
	if i := strings.LastIndex(l, ":"); i >= 0 {
		p = l[i+1:]
	}
	n, _ := strconv.Atoi(p)
	return n
}

func checkFirewall(sn *snapshot) ([]finding, error) {
	fw, err := sn.getUCI("firewall")
	if err != nil {
		return nil, err
	}
	var sshPorts, luciPorts []int
	if db, err := sn.getUCI("dropbear"); err == nil {
		sshPorts = dropbearPorts(db)
	}
	if uh, err := sn.getUCI("uhttpd"); err == nil {
		for _, sec := range uh.sectionsOfType("uhttpd") {
			for _, l := range allAddressListens(uh, sec) {
				if p := listenPort(l); p > 0 {
					luciPorts = append(luciPorts, p)
				}
			}
		}
	}
	wan := wanZoneSet(sn, fw)
	var out []finding

	defaults := ""
	if ds := fw.sectionsOfType("defaults"); len(ds) > 0 {
		defaults = ds[0]
	}
	for _, sec := range fw.sectionsOfType("zone") {
		name := fw.get(sec, "name")
		if !wan[name] {
			continue
		}
		for _, p := range []struct{ opt, id string }{{"input", "wan-zone-input-accept"}, {"forward", "wan-zone-forward-accept"}} {
			v := fw.get(sec, p.opt)
			if v == "" && defaults != "" {
				v = fw.get(defaults, p.opt)
			}
			if strings.EqualFold(v, "ACCEPT") {
				what := "traffic from the internet to the router"
				if p.opt == "forward" {
					what = "traffic from the internet through the router"
				}
				out = append(out, newFinding(p.id, sevHigh, fmt.Sprintf("the %s zone accepts %s by default", name, what),
					fmt.Sprintf("firewall zone %s: %s=ACCEPT", name, p.opt)))
			}
		}
	}

	fromWan := func(sec string) bool {
		for _, s := range splitAll(fw.list(sec, "src")) {
			if s == "*" || wan[s] {
				return true
			}
		}
		return false
	}
	for _, sec := range fw.sectionsOfType("rule") {
		if uciOff(fw.get(sec, "enabled")) || !strings.EqualFold(fw.get(sec, "target"), "ACCEPT") || !fromWan(sec) {
			continue
		}
		protos := splitAll(fw.list(sec, "proto"))
		var rel []string
		for _, p := range protos {
			switch strings.ToLower(p) {
			case "tcp", "udp", "all", "tcpudp":
				rel = append(rel, strings.ToLower(p))
			}
		}
		if len(protos) > 0 && len(rel) == 0 {
			continue // icmp, igmp, esp and the like: the stock rules
		}
		if len(protos) == 0 {
			rel = []string{"tcp", "udp"}
		}
		ports := splitAll(fw.list(sec, "dest_port"))
		name := orDefault(fw.get(sec, "name"), sec)
		proto := strings.Join(rel, "+")
		restr := orDefault(fw.get(sec, "src_ip"), fw.get(sec, "src_mac"))
		sev := sevMedium
		if restr != "" {
			sev = sevLow
		}
		label := proto + "/all ports"
		if len(ports) > 0 {
			label = proto + "/" + strings.Join(ports, ",")
		}
		ev := fmt.Sprintf("rule %q: %s from the internet", trunc(name, 40), label)
		if restr != "" {
			ev += ", only from " + trunc(restr, 40)
		}

		if dest := fw.get(sec, "dest"); dest != "" {
			out = append(out, newFinding("wan-forward-open", sev,
				fmt.Sprintf("a rule lets traffic from the internet into %s", dest), ev+" to "+dest))
			continue
		}
		// An explicit port that is SSH or the web interface is its own, louder finding.
		tcp := contains(rel, "tcp") || contains(rel, "all") || contains(rel, "tcpudp")
		if p, ok := anyPortCovered(ports, sshPorts); ok && tcp {
			out = append(out, newFinding("ssh-wan", sevHigh, "SSH is reachable from the internet",
				fmt.Sprintf("%s; dropbear listens on every address, port %d", ev, p)))
			continue
		}
		if p, ok := anyPortCovered(ports, luciPorts); ok && tcp {
			out = append(out, newFinding("luci-wan", sevHigh, "the web interface (LuCI) is reachable from the internet",
				fmt.Sprintf("%s; uhttpd listens on every address, port %d", ev, p)))
			continue
		}
		if len(ports) == 0 {
			if restr == "" {
				sev = sevHigh
			}
			out = append(out, newFinding("wan-port-open", sev, "the firewall accepts every port from the internet", ev))
			continue
		}
		if proto == "udp" && (ports[0] == "68" || ports[0] == "546") && len(ports) == 1 {
			continue // DHCP and DHCPv6 client replies, in the stock rules
		}
		out = append(out, newFinding("wan-port-open", sev, "the firewall accepts a port from the internet", ev))
	}

	for _, sec := range fw.sectionsOfType("redirect") {
		if uciOff(fw.get(sec, "enabled")) || !fromWan(sec) {
			continue
		}
		if t := fw.get(sec, "target"); t != "" && !strings.EqualFold(t, "DNAT") {
			continue
		}
		dport := orDefault(fw.get(sec, "dest_port"), fw.get(sec, "src_dport"))
		to := orDefault(fw.get(sec, "dest_ip"), "the router")
		out = append(out, newFinding("wan-redirect", sevMedium, "a port forward exposes a device to the internet",
			fmt.Sprintf("redirect %q: %s %s -> %s:%s", trunc(orDefault(fw.get(sec, "name"), sec), 40),
				orDefault(fw.get(sec, "proto"), "tcp+udp"), fw.get(sec, "src_dport"), to, dport)))
	}
	return out, nil
}

func checkSSH(sn *snapshot) ([]finding, error) {
	db, err := sn.getUCI("dropbear")
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, sec := range db.sectionsOfType("dropbear") {
		pa := db.get(sec, "PasswordAuth")
		if uciOff(pa) {
			continue
		}
		ev := "dropbear." + sec + ".PasswordAuth=" + pa
		if pa == "" {
			ev = "dropbear." + sec + ".PasswordAuth=on (the default)"
		}
		if ra := db.get(sec, "RootPasswordAuth"); !uciOff(ra) {
			ev += ", RootPasswordAuth=" + orDefault(ra, "on (the default)")
		}
		out = append(out, newFinding("ssh-password-auth", sevMedium, "SSH accepts password logins", ev))
	}
	return out, nil
}

func checkLuci(sn *snapshot) ([]finding, error) {
	uh, err := sn.getUCI("uhttpd")
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, sec := range uh.sectionsOfType("uhttpd") {
		if all := allAddressListens(uh, sec); len(all) > 0 {
			out = append(out, newFinding("luci-all-addresses", sevLow,
				"the web server listens on every address, so only the firewall keeps it off the internet",
				"uhttpd."+sec+" listens on "+strings.Join(all, " ")))
		}
	}
	return out, nil
}

func checkUPnP(sn *snapshot) ([]finding, error) {
	if _, err := os.Stat(sysPath("/etc/config/upnpd")); err != nil {
		return nil, nil // not installed
	}
	t, err := sn.getUCI("upnpd")
	if err != nil {
		return nil, err
	}
	for _, sec := range t.sectionsOfType("upnpd") {
		if uciOn(t.get(sec, "enabled")) {
			return []finding{newFinding("upnp-on", sevMedium, "UPnP is enabled: any device on the network can open ports to the internet",
				"upnpd."+sec+".enabled=1")}, nil
		}
	}
	return nil, nil
}

func checkWifi(sn *snapshot) ([]finding, error) {
	t, err := sn.getUCI("wireless")
	if err != nil {
		return nil, err
	}
	radioOff := map[string]bool{}
	for _, sec := range t.sectionsOfType("wifi-device") {
		if uciOn(t.get(sec, "disabled")) {
			radioOff[sec] = true
		}
	}
	var out []finding
	for _, sec := range t.sectionsOfType("wifi-iface") {
		if uciOn(t.get(sec, "disabled")) || radioOff[t.get(sec, "device")] {
			continue
		}
		if mode := t.get(sec, "mode"); mode != "" && mode != "ap" {
			continue
		}
		ssid := trunc(t.get(sec, "ssid"), 32)
		nets := splitAll(t.list(sec, "network"))
		enc := strings.ToLower(t.get(sec, "encryption"))
		desc := fmt.Sprintf("%s: ssid %q on %s, encryption %s", sec, ssid, orDefault(strings.Join(nets, ","), "?"), orDefault(enc, "none"))

		switch {
		case enc == "" || enc == "none":
			sev := sevMedium
			if contains(nets, "lan") {
				sev = sevHigh
			}
			out = append(out, newFinding("ssid-open", sev, "a Wi-Fi network has no encryption: anyone in range can join and read its traffic", desc))
		case strings.HasPrefix(enc, "wep"):
			out = append(out, newFinding("ssid-wep", sevHigh, "a Wi-Fi network uses WEP, which can be broken in minutes", desc))
		case strings.Contains(enc, "tkip"):
			out = append(out, newFinding("ssid-weak-cipher", sevMedium, "a Wi-Fi network still allows the TKIP cipher", desc))
		case enc == "psk" || enc == "wpa":
			out = append(out, newFinding("ssid-wpa1", sevMedium, "a Wi-Fi network uses WPA1 only", desc))
		case enc == "psk-mixed" || enc == "wpa-mixed":
			out = append(out, newFinding("ssid-wpa1", sevLow, "a Wi-Fi network accepts WPA1 clients alongside WPA2", desc))
		}
		if t.get(sec, "wps_pushbutton") == "1" {
			out = append(out, newFinding("wps-on", sevMedium, "WPS push-button pairing is on for a Wi-Fi network", desc))
		}
	}
	return out, nil
}

// checkRootPassword reads /etc/shadow for one fact. The hash is never stored or shown, and an
// error says what failed, never what the file held.
func checkRootPassword(sn *snapshot) ([]finding, error) {
	b, err := readSys("/etc/shadow")
	if err != nil {
		return nil, fmt.Errorf("cannot read /etc/shadow")
	}
	for _, line := range strings.Split(b, "\n") {
		if !strings.HasPrefix(line, "root:") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 2 {
			break
		}
		if f[1] == "" {
			return []finding{newFinding("root-no-password", sevHigh, "the root account has no password",
				"/etc/shadow: the password field of root is empty")}, nil
		}
		return nil, nil
	}
	return nil, fmt.Errorf("no root entry in /etc/shadow")
}

var reApkAudit = regexp.MustCompile(`^([AUD]) (\S.*)$`)

// Changes under these are configuration and state, not the packages' own files.
var apkAuditBenign = []string{"etc/", "tmp/", "var/", "overlay/", "root/", "mnt/"}

func checkPackagesAudit(sn *snapshot) ([]finding, error) {
	out, err := run(sn.ctx, 2*time.Minute, "apk", "audit")
	if err != nil {
		return nil, fmt.Errorf("apk audit: %w", err)
	}
	var changed []string
lines:
	for _, line := range strings.Split(out, "\n") {
		m := reApkAudit.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] == "A" {
			continue
		}
		for _, pre := range apkAuditBenign {
			if strings.HasPrefix(m[2], pre) {
				continue lines
			}
		}
		changed = append(changed, m[2])
	}
	if len(changed) == 0 {
		return nil, nil
	}
	shown := changed
	if len(shown) > 3 {
		shown = shown[:3]
	}
	ev := strings.Join(shown, ", ")
	if len(changed) > len(shown) {
		ev += fmt.Sprintf(" (+%d more)", len(changed)-len(shown))
	}
	return []finding{newFinding("apk-audit-modified", sevMedium,
		fmt.Sprintf("%d file(s) that belong to a package were changed or removed since it was installed", len(changed)), ev)}, nil
}

const wgStale = 30 * 24 * time.Hour

func checkWireGuard(sn *snapshot) ([]finding, error) {
	t, err := sn.getUCI("network")
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, iface := range wgIfaces(t) {
		_, _, peers, err := loadWG(sn.ctx, iface)
		if err != nil {
			return nil, err
		}
		for _, p := range peers {
			if !p.InKernel {
				continue // the interface is not up, so there is nothing to judge
			}
			who := p.Name
			if who == "" {
				who = trunc(p.PubKey, 12)
			}
			switch {
			case p.Handshake == 0:
				out = append(out, newFinding("wg-stale-peer", sevInfo, "a WireGuard peer has never connected",
					fmt.Sprintf("%s peer %q: no handshake", iface, trunc(who, 32))))
			case time.Since(time.Unix(p.Handshake, 0)) > wgStale:
				out = append(out, newFinding("wg-stale-peer", sevLow, "a WireGuard peer has not connected for over 30 days",
					fmt.Sprintf("%s peer %q: last handshake %s", iface, trunc(who, 32), time.Unix(p.Handshake, 0).UTC().Format("2006-01-02"))))
			}
		}
	}
	return out, nil
}
