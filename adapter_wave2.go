package main

import (
	"context"
	"fmt"
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
	}
	return strings.Join(lines, "\n")
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
	return strings.Join(lines, "\n")
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

func readNetBird(ctx context.Context) string {
	lines := []string{running(ctx, "netbird")}
	out, err := run(ctx, 15*time.Second, "netbird", "status")
	if err != nil {
		return strings.Join(append(lines, "netbird does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 120)), "\n")
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
	return strings.Join(lines, "\n")
}
