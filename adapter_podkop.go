package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// podkop routes chosen domains through a VPN interface or a sing-box proxy. Its init script is a
// one-shot that starts sing-box, so procd lists "podkop" as stopped even when it works: the
// state worth reporting is sing-box, the nft table and where dnsmasq forwards DNS. podkop's UCI
// config also holds the proxy credentials (proxy_string, selector and urltest links,
// outbound_json) and the user's domain lists; only the fixed fields below are printed.

const (
	podkopConstants   = "/usr/lib/podkop/constants.sh"
	podkopNftTable    = "PodkopTable"
	podkopMaxSections = 20
	podkopDNS         = "127.0.0.42"
)

var (
	reVersion       = regexp.MustCompile(`^[0-9A-Za-z._+-]{1,32}$`)
	rePodkopVersion = regexp.MustCompile(`(?m)^\s*(?:export\s+)?PODKOP_VERSION=["']?([^"'\s]*)["']?\s*$`)
)

func readPodkop(ctx context.Context) string {
	version := "(version unknown)"
	if text, err := readSys(podkopConstants); err == nil {
		if m := rePodkopVersion.FindStringSubmatch(text); m != nil && reVersion.MatchString(m[1]) {
			version = m[1]
		}
	}
	head := "podkop " + version
	if out, err := run(ctx, defaultCmdTimeout, "sing-box", "version"); err == nil {
		if f := strings.Fields(firstLine(strings.TrimSpace(out))); len(f) >= 3 && f[0] == "sing-box" && f[1] == "version" && reVersion.MatchString(f[2]) {
			head += ", sing-box " + f[2]
		}
	}
	lines := []string{head}

	if out, err := run(ctx, defaultCmdTimeout, "pidof", "sing-box"); err == nil && pidText(out) != "" {
		lines = append(lines, "sing-box: running, "+pidText(out))
	} else {
		lines = append(lines, "sing-box: not running")
	}

	if out, err := run(ctx, defaultCmdTimeout, "nft", "list", "table", "inet", podkopNftTable); err != nil {
		lines = append(lines, "nft: table "+podkopNftTable+" not loaded")
	} else {
		var chains, sets int
		for _, l := range strings.Split(out, "\n") {
			switch f := strings.Fields(l); {
			case len(f) > 0 && f[0] == "chain":
				chains++
			case len(f) > 0 && f[0] == "set":
				sets++
			}
		}
		lines = append(lines, fmt.Sprintf("nft: table %s loaded, %s, %s", podkopNftTable, plural(chains, "chain"), plural(sets, "set")))
	}

	tree, err := uciShow(ctx, "podkop", false)
	dontTouch := ""
	if err == nil {
		dontTouch = tree.get("settings", "dont_touch_dhcp")
	}
	lines = append(lines, podkopDnsmasqLine(dnsmasqServers(ctx), dontTouch, err == nil))
	if err != nil {
		lines = append(lines, "podkop config unreadable: "+clip(err.Error(), 160))
		return strings.Join(lines, "\n")
	}
	return strings.Join(append(lines, podkopConfigLines(tree)...), "\n")
}

// podkopDnsmasqLine says where dnsmasq forwards DNS and whether that puts podkop in the path.
// With dont_touch_dhcp set podkop leaves dnsmasq alone on purpose, so another server there is
// the operator's chain, not a fault.
func podkopDnsmasqLine(servers []string, dontTouch string, haveConfig bool) string {
	line := "dnsmasq upstream servers: (none set)"
	inPath := false
	if len(servers) > 0 {
		line = "dnsmasq upstream servers: " + strings.Join(servers, ", ")
		for _, s := range servers {
			if s == podkopDNS || strings.HasPrefix(s, podkopDNS+"#") {
				inPath = true
			}
		}
	}
	switch {
	case inPath:
		line += "; podkop is in the DNS path"
	case !haveConfig:
	case dontTouch == "1":
		line += "; podkop leaves dnsmasq alone (dont_touch_dhcp 1)"
	default:
		line += "; podkop expects " + podkopDNS + ", so DNS bypasses it"
	}
	return line
}

// podkopConfigLines renders the settings and sections of `uci show podkop`.
func podkopConfigLines(t *uciTree) []string {
	var parts []string
	add := func(label, v string) {
		if v = clip(v, 60); v != "" {
			parts = append(parts, strings.TrimSpace(label+" "+v))
		}
	}
	if dns := strings.TrimSpace(clip(t.get("settings", "dns_type"), 20) + " " + clip(t.get("settings", "dns_server"), 60)); dns != "" {
		parts = append(parts, "dns "+dns)
	}
	add("bootstrap", t.get("settings", "bootstrap_dns_server"))
	add("sources", strings.Join(t.list("settings", "source_network_interfaces"), " "))
	add("log", t.get("settings", "log_level"))
	add("list update", t.get("settings", "update_interval"))
	quic, yacd := "quic allowed", "yacd off"
	if t.get("settings", "disable_quic") == "1" {
		quic = "quic blocked"
	}
	if t.get("settings", "enable_yacd") == "1" {
		yacd = "yacd on"
	}
	lines := []string{"settings: " + strings.Join(append(parts, quic, yacd), ", ")}

	secs := t.sectionsOfType("section")
	if len(secs) == 0 {
		return append(lines, "sections (0)")
	}
	lines = append(lines, fmt.Sprintf("sections (%d):", len(secs)))
	for i, s := range secs {
		if i == podkopMaxSections {
			lines = append(lines, fmt.Sprintf("... %d more sections not shown", len(secs)-podkopMaxSections))
			break
		}
		lines = append(lines, podkopSection(t, s))
	}
	return lines
}

func podkopSection(t *uciTree, s string) string {
	kind := clip(t.get(s, "connection_type"), 20)
	switch kind {
	case "vpn":
		if iface := clip(t.get(s, "interface"), 40); iface != "" {
			kind = "vpn via " + iface
		}
	case "proxy":
		if how := clip(t.get(s, "proxy_config_type"), 20); how != "" {
			kind = "proxy (" + how + " config)"
		}
	case "":
		kind = "(connection_type not set)"
	}
	line := clip(s, 40) + ": " + kind
	if lists := t.list(s, "community_lists"); len(lists) > 0 {
		for i := range lists {
			lists[i] = clip(lists[i], 40)
		}
		line += "; community lists: " + strings.Join(lists, ", ")
	}
	line += podkopUserList(t, s, "domains", "user_domain_list_type", "user_domains")
	line += podkopUserList(t, s, "subnets", "user_subnet_list_type", "user_subnets")
	return line
}

// podkopUserList says how a section takes its own domains or subnets, and for the dynamic list
// how many, but never what they are.
func podkopUserList(t *uciTree, s, label, typeOpt, listOpt string) string {
	switch kind := t.get(s, typeOpt); kind {
	case "dynamic":
		return fmt.Sprintf("; %s: dynamic list (%d)", label, len(t.list(s, listOpt)))
	case "text":
		return "; " + label + ": text list"
	case "disabled":
		return "; " + label + ": disabled"
	}
	return ""
}
