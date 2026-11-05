package main

import (
	"strconv"
	"strings"
)

// Doctor findings for the wave 2 add-ons (ROADMAP 9.4): an encrypted resolver that nothing
// uses, and a watchdog that reboots on the first short outage.

func init() {
	for id, h := range map[string]findingHint{
		"dns-resolver-bypassed": {"net_diag action=dns_path shows what dnsmasq forwards to; point dnsmasq at the resolver's local port with uci_apply (dhcp.@dnsmasq[0].server, dry_run first) or turn the resolver off", ""},
		"watchcat-short-reboot": {"service_list detail=watchcat shows each rule; lengthen the period with uci_apply (dry_run first) so a short upstream outage does not reboot the router", ""},
	} {
		findingHints[id] = h
	}
}

// resolverPorts returns the loopback ports a local encrypted resolver listens on, or nil when it
// is not installed, not enabled, or is the front resolver on port 53 (then nothing forwards to it).
func resolverPorts(sn *snapshot, name string) map[string]bool {
	if !addonInstalled(name) || !enabledAtBoot(sn, name) {
		return nil
	}
	t, err := sn.getUCI(name)
	if err != nil {
		return nil
	}
	ports := map[string]bool{}
	switch name {
	case "stubby":
		for _, l := range t.list("global", "listen_address") {
			if _, p, ok := strings.Cut(l, "@"); ok {
				ports[p] = true
			}
		}
		if len(ports) == 0 {
			ports["5453"] = true
		}
	case "smartdns":
		if !uciFlag(t.get("@smartdns[0]", "enabled"), true) {
			return nil
		}
		if r := t.get("@smartdns[0]", "redirect"); r != "" && r != "none" && r != "dnsmasq-upstream" {
			return nil // smartdns takes port 53 traffic itself
		}
		ports[pick(t.get("@smartdns[0]", "port") != "", t.get("@smartdns[0]", "port"), "6053")] = true
	}
	if ports["53"] {
		return nil
	}
	return ports
}

func checkResolverBypassed(sn *snapshot) ([]finding, error) {
	if enabledAtBoot(sn, "unbound") {
		return nil, nil // unbound fronts the path; dns_path shows it
	}
	var out []finding
	servers := dnsmasqServers(sn.ctx)
	for _, name := range []string{"stubby", "smartdns"} {
		ports := resolverPorts(sn, name)
		if len(ports) == 0 {
			continue
		}
		used := false
		for _, s := range servers {
			if host, p, ok := strings.Cut(s, "#"); ok && (host == "127.0.0.1" || host == "::1") && ports[p] {
				used = true
			}
		}
		if !used {
			out = append(out, newFinding("dns-resolver-bypassed", sevMedium,
				name+" is enabled but dnsmasq does not forward to it: DNS does not use it",
				name+" ports "+strings.Join(sortedKeys(ports), ", ")+"; dnsmasq servers: "+clip(pick(len(servers) > 0, strings.Join(servers, " "), "none set (WAN lease resolvers)"), 120)))
		}
	}
	return out, nil
}

// watchSeconds reads a watchcat period such as 30, 90s, 5m, 6h or 1d.
func watchSeconds(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	mul := 1
	switch v[len(v)-1] {
	case 's':
		v = v[:len(v)-1]
	case 'm':
		mul, v = 60, v[:len(v)-1]
	case 'h':
		mul, v = 3600, v[:len(v)-1]
	case 'd':
		mul, v = 86400, v[:len(v)-1]
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 1<<20 {
		return 0, false
	}
	return n * mul, true
}

func checkWatchcatShortReboot(sn *snapshot) ([]finding, error) {
	if !addonInstalled("watchcat") || !enabledAtBoot(sn, "watchcat") {
		return nil, nil
	}
	t, err := sn.getUCI("watchcat")
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, s := range t.sectionsOfType("watchcat") {
		if t.get(s, "mode") != "ping_reboot" {
			continue
		}
		if sec, ok := watchSeconds(t.get(s, "period")); ok && sec < 300 {
			out = append(out, newFinding("watchcat-short-reboot", sevLow,
				"watchcat reboots the router after a failed ping lasting only "+strconv.Itoa(sec)+" s",
				"watchcat."+s+".period="+clip(t.get(s, "period"), 10)))
		}
	}
	return out, nil
}
