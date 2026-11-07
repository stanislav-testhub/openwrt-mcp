package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Wave 2 add-ons that are read from their UCI config plus a process check: watchcat, openvpn,
// nextdns, qosify and travelmate; zerotier and netbird add one fixed CLI read each. Secrets
// (keys, setup keys, profile ids, auth files) are never read: only whether they are set.

func running(ctx context.Context, proc string) string {
	if out, err := run(ctx, defaultCmdTimeout, "pidof", proc); err == nil && pidText(out) != "" {
		return proc + ": running, " + pidText(out)
	}
	return proc + ": not running"
}

const maxShown = 12

// ---------------------------------------------------------------- watchcat

func readWatchcat(ctx context.Context) string {
	lines := []string{running(ctx, "watchcat.sh")}
	tree, err := uciShow(ctx, "watchcat", false)
	if err != nil {
		return strings.Join(append(lines, "watchcat config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	secs := tree.sectionsOfType("watchcat")
	lines = append(lines, fmt.Sprintf("rules (%d):", len(secs)))
	for i, s := range secs {
		if i == maxShown {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(secs)-maxShown))
			break
		}
		mode := clip(tree.get(s, "mode"), 20)
		parts := []string{pick(mode != "", mode, "mode not set")}
		if v := tree.get(s, "period"); v != "" {
			parts = append(parts, "period "+clip(v, 10))
		}
		if v := tree.get(s, "pinghosts"); v != "" {
			parts = append(parts, "ping "+clip(v, 60))
		}
		if v := tree.get(s, "interface"); v != "" {
			parts = append(parts, "interface "+clip(v, 20))
		}
		if v := tree.get(s, "script"); v != "" {
			parts = append(parts, "runs a script")
		}
		lines = append(lines, "  "+strings.Join(parts, ", "))
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- openvpn

func readOpenVPN(ctx context.Context) string {
	found, anyRunning, _ := procdData(ctx, "openvpn")
	lines := []string{"openvpn: " + pick(anyRunning, "an instance is running", pick(found, "registered, no running instance", "not running"))}
	tree, err := uciShow(ctx, "openvpn", false)
	if err != nil {
		return strings.Join(append(lines, "openvpn config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	secs := tree.sectionsOfType("openvpn")
	lines = append(lines, fmt.Sprintf("instances (%d):", len(secs)))
	for i, s := range secs {
		if i == maxShown {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(secs)-maxShown))
			break
		}
		role := "server"
		remote := tree.list(s, "remote")
		if uciFlag(tree.get(s, "client"), false) || len(remote) > 0 {
			role = "client"
		}
		parts := []string{clip(s, 40), pick(uciFlag(tree.get(s, "enabled"), false), "enabled", "disabled"), role}
		if v := tree.get(s, "proto"); v != "" {
			parts = append(parts, clip(v, 8))
		}
		if v := tree.get(s, "dev"); v != "" {
			parts = append(parts, "dev "+clip(v, 15))
		}
		if len(remote) > 0 {
			parts = append(parts, "remote "+hostOnly(remote[0]))
		}
		if tree.get(s, "redirect_gateway") != "" || tree.get(s, "redirect-gateway") != "" {
			parts = append(parts, "redirects the default route")
		}
		if tree.get(s, "config") != "" {
			parts = append(parts, "uses an .ovpn file")
		}
		lines = append(lines, "  "+strings.Join(parts, ", "))
		if uciFlag(tree.get(s, "enabled"), false) && uciName.MatchString(s) {
			lines = append(lines, openVPNStatus(s)...)
		}
	}
	return strings.Join(lines, "\n")
}

const openVPNMaxClients = 15

// openVPNStatus reads /var/run/openvpn.<section>.status, which OpenWrt's init script asks every
// instance to write (version 1, comma separated, refreshed about once a minute). A server lists
// each client's name, virtual address and traffic; a client has only its tunnel counters. The
// client's public address is left out, and its name is chosen by whoever holds the certificate.
func openVPNStatus(section string) []string {
	text, err := readSys("/var/run/openvpn." + section + ".status")
	if err != nil {
		return []string{"    status file not written yet (about once a minute after start)"}
	}
	var clients []string
	virt := map[string]string{}
	stats := map[string]int64{}
	updated, mode := "", ""
	for _, l := range strings.Split(text, "\n") {
		f := strings.Split(strings.TrimRight(l, "\r"), ",")
		switch {
		case l == "OpenVPN CLIENT LIST" || l == "ROUTING TABLE" || l == "OpenVPN STATISTICS":
			mode = l
		case l == "GLOBAL STATS" || l == "END":
			mode = ""
		case f[0] == "Updated" && len(f) > 1 && updated == "":
			updated = clip(f[1], 24)
		case mode == "OpenVPN CLIENT LIST" && len(f) >= 5 && f[0] != "Common Name":
			rx, e1 := strconv.ParseInt(f[2], 10, 64)
			tx, e2 := strconv.ParseInt(f[3], 10, 64)
			if e1 == nil && e2 == nil {
				clients = append(clients, fmt.Sprintf("%s (in %s, out %s, since %s)", fmt.Sprintf("%q", clip(f[0], 32)), humanBytes(rx), humanBytes(tx), clip(f[4], 24)))
			}
		case mode == "ROUTING TABLE" && len(f) >= 4 && f[0] != "Virtual Address" && validIP(f[0]):
			virt[f[1]] = f[0]
		case mode == "OpenVPN STATISTICS" && len(f) == 2:
			if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				stats[f[0]] = n
			}
		}
	}
	asOf := pick(updated != "", " (as of "+updated+")", "")
	switch {
	case len(stats) > 0:
		return []string{fmt.Sprintf("    tunnel: carried %s in, %s out on the wire%s", humanBytes(stats["TCP/UDP read bytes"]), humanBytes(stats["TCP/UDP write bytes"]), asOf)}
	case strings.Contains(text, "OpenVPN CLIENT LIST"):
		if len(clients) == 0 {
			return []string{"    connected clients: none" + asOf}
		}
		out := []string{fmt.Sprintf("    connected clients (%d)%s:", len(clients), asOf)}
		for i, c := range clients {
			if i == openVPNMaxClients {
				out = append(out, fmt.Sprintf("      ... %d more", len(clients)-openVPNMaxClients))
				break
			}
			if name, rest, ok := strings.Cut(c, " ("); ok {
				if v := virt[strings.Trim(name, `"`)]; v != "" {
					c = name + " at " + v + " (" + rest
				}
			}
			out = append(out, "      "+c)
		}
		return out
	}
	return []string{"    status file not recognised"}
}

// ---------------------------------------------------------------- nextdns

func readNextDNS(ctx context.Context) string {
	lines := []string{running(ctx, "nextdns")}
	tree, err := uciShow(ctx, "nextdns", false)
	if err != nil {
		return strings.Join(append(lines, "nextdns config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines,
		"enabled in config: "+pick(uciFlag(tree.get("main", "enabled"), false), "yes", "no"),
		"profile: "+pick(tree.get("main", "config") != "", "set (id not shown)", "not set"),
		"listen: "+pick(tree.get("main", "listen") != "", clip(tree.get("main", "listen"), 40), "default"),
		"report client info: "+pick(uciFlag(tree.get("main", "report_client_info"), false), "yes", "no"))
	return strings.Join(append(lines, dnsPathLine(dnsmasqServers(ctx), portOf(tree.get("main", "listen")))), "\n")
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i+1:]
	}
	return ""
}

// ---------------------------------------------------------------- qosify

func readQosify(ctx context.Context) string {
	lines := []string{running(ctx, "qosify")}
	tree, err := uciShow(ctx, "qosify", false)
	if err != nil {
		return strings.Join(append(lines, "qosify config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	ifs := tree.sectionsOfType("interface")
	lines = append(lines, fmt.Sprintf("interfaces (%d):", len(ifs)))
	for i, s := range ifs {
		if i == maxShown {
			break
		}
		lines = append(lines, fmt.Sprintf("  %s: %s, up %s, down %s, mode %s", clip(pick(tree.get(s, "name") != "", tree.get(s, "name"), s), 20),
			pick(uciFlag(tree.get(s, "disabled"), false), "disabled", "enabled"), pick(tree.get(s, "bandwidth_up") != "", clip(tree.get(s, "bandwidth_up"), 12), "?"),
			pick(tree.get(s, "bandwidth_down") != "", clip(tree.get(s, "bandwidth_down"), 12), "?"), pick(tree.get(s, "mode") != "", clip(tree.get(s, "mode"), 12), "default")))
	}
	lines = append(lines, fmt.Sprintf("classes: %d", len(tree.sectionsOfType("class"))))
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- travelmate

func readTravelmate(ctx context.Context) string {
	lines := []string{running(ctx, "travelmate.sh")}
	tree, err := uciShow(ctx, "travelmate", false)
	if err != nil {
		return strings.Join(append(lines, "travelmate config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines,
		"enabled in config: "+pick(uciFlag(tree.get("global", "trm_enabled"), false), "yes", "no"),
		"captive portal check: "+pick(uciFlag(tree.get("global", "trm_captive"), true), "on", "off"),
		fmt.Sprintf("configured uplinks: %d", len(tree.sectionsOfType("uplink"))))
	return strings.Join(append(lines, travelmateRuntime()...), "\n")
}

// travelmateRuntimeFiles: 2.2.1 on 24.10 writes /tmp/trm_runtime.json, 2.4.9 on 25.12 writes
// /var/run/travelmate/travelmate.runtime.json and calls its version backend_ver. Both are {"data": {...}}.
var travelmateRuntimeFiles = []string{"/var/run/travelmate/travelmate.runtime.json", "/tmp/trm_runtime.json"}

// travelmateRuntime reads what travelmate itself reports: its status, the uplink it is on and that
// uplink's subnet. The SSID in the uplink is chosen by whoever runs the access point, so the entry
// marks it untrusted.
func travelmateRuntime() []string {
	var text string
	for _, f := range travelmateRuntimeFiles {
		if t, err := readSys(f); err == nil {
			text = t
			break
		}
	}
	if text == "" {
		return nil
	}
	var doc struct {
		Data map[string]string `json:"data"`
	}
	if json.Unmarshal([]byte(text), &doc) != nil || len(doc.Data) == 0 {
		return []string{"runtime file not recognised"}
	}
	d := doc.Data
	var out []string
	if v := d["travelmate_status"]; v != "" {
		ver := d["travelmate_version"]
		if ver == "" {
			ver = d["backend_ver"]
		}
		out = append(out, "status: "+clip(v, 60)+pick(ver != "", ", travelmate "+clip(ver, 20), ""))
		if strings.Contains(v, "net nok") {
			out = append(out, "WARNING: associated, but travelmate's internet check fails: the uplink gives no internet")
		}
	}
	if id := strings.Split(d["station_id"], "/"); len(id) >= 2 && id[1] != "-" {
		out = append(out, "uplink: radio "+clip(id[0], 20)+", SSID "+clip(id[1], 32)+", interface "+clip(strings.TrimSuffix(strings.Split(d["station_interfaces"], ",")[0], " "), 20))
	}
	if sub, lan, ok := strings.Cut(d["station_subnet"], " (lan: "); ok {
		lan = strings.TrimSuffix(lan, ")")
		if sub != "-" && sub == lan {
			out = append(out, "WARNING: the uplink's subnet "+clip(sub, 20)+" is the LAN's subnet: traffic cannot be routed through it, change the LAN subnet")
		}
	}
	if v := d["last_run"]; v != "" {
		out = append(out, "last run: "+clip(v, 30))
	}
	return out
}

// ---------------------------------------------------------------- zerotier

func readZeroTier(ctx context.Context) string {
	lines := []string{running(ctx, "zerotier-one")}
	out, err := run(ctx, defaultCmdTimeout, "zerotier-cli", "listnetworks")
	if err != nil {
		return strings.Join(append(lines, "zerotier-cli does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 120)), "\n")
	}
	var nets []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		// 200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ips>; the name is free text
		// from the network's owner and is not printed.
		if len(f) < 8 || f[0] != "200" || f[1] != "listnetworks" || strings.HasPrefix(f[2], "<") { // the header row is literal
			continue
		}
		n := len(f)
		nets = append(nets, fmt.Sprintf("  %s: %s, %s, dev %s, addresses %s", clip(f[2], 16), clip(f[n-4], 20), clip(f[n-3], 10), clip(f[n-2], 15), clip(f[n-1], 80)))
	}
	lines = append(lines, fmt.Sprintf("networks (%d):", len(nets)))
	if len(nets) > maxShown {
		nets = append(nets[:maxShown], "  ...")
	}
	return strings.Join(append(lines, nets...), "\n")
}

// ---------------------------------------------------------------- netbird

// netbirdSocketMark is the fwmark NetBird puts on its own control-plane sockets (ControlPlaneMark in
// the client). A routing rule that matches it and discards the packet makes every connect fail with
// EINVAL; mwan3's default "fwmark 0x3d00/0x3f00 blackhole" does (seen on 24.10.8, netbird 0.59.13).
const netbirdSocketMark = 0x1bd00

var discardingMarkRule = lazyRegexp(`fwmark (0x[0-9a-fA-F]+)(?:/(0x[0-9a-fA-F]+))?\s+(blackhole|unreachable|prohibit)`)

func netbirdMarkWarnings(rules string) []string {
	var out []string
	for _, l := range strings.Split(rules, "\n") {
		m := discardingMarkRule.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		mark, err := strconv.ParseUint(m[1], 0, 32)
		mask := uint64(0xffffffff)
		if m[2] != "" {
			mask, _ = strconv.ParseUint(m[2], 0, 32)
		}
		if err == nil && netbirdSocketMark&mask == mark {
			out = append(out, "WARNING: the routing rule \"fwmark "+m[1]+pick(m[2] != "", "/"+m[2], "")+" "+m[3]+"\" catches NetBird's own socket mark 0x1bd00, so it cannot reach its management server (connect fails with EINVAL); this is the default of mwan3: change mwan3's mmx_mask or stop mwan3")
		}
	}
	return out
}

func readNetBird(ctx context.Context) string {
	lines := []string{running(ctx, "netbird")}
	rules, _ := run(ctx, defaultCmdTimeout, "ip", "-4", "rule", "show")
	warn := netbirdMarkWarnings(rules)
	out, err := run(ctx, 15*time.Second, "netbird", "status")
	if err != nil {
		return strings.Join(append(append(lines, "netbird does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 120)), warn...), "\n")
	}
	want := []string{"Management:", "Signal:", "Peers count:", "NetBird IP:", "Daemon version:"}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		for _, w := range want {
			if strings.HasPrefix(l, w) {
				lines = append(lines, clip(l, 80))
			}
		}
	}
	return strings.Join(append(lines, warn...), "\n")
}
