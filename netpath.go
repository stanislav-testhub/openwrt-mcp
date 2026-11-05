package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// net_diag action=dns_path and action=path: the two questions the add-on adapters answer one
// package at a time, answered across packages. Both are built from reads only.

// ---------------------------------------------------------------- dns_path

// dnsOwners maps a loopback port to the add-on that listens on it, from each add-on's own config.
func dnsOwners(ctx context.Context, rc map[string]rcEntry) map[string]string {
	owners := map[string]string{}
	has := func(n string) bool { _, ok := rc[n]; return ok }
	if has("https-dns-proxy") {
		if t, err := uciShow(ctx, "https-dns-proxy", false); err == nil {
			next := 5053
			for _, s := range t.sectionsOfType("https-dns-proxy") {
				p := t.get(s, "listen_port")
				if p == "" {
					p = strconv.Itoa(next)
				}
				next++
				owners[p] = "https-dns-proxy (" + resolverHost(t.get(s, "resolver_url")) + ")"
			}
		}
	}
	if has("stubby") {
		if t, err := uciShow(ctx, "stubby", false); err == nil {
			for _, l := range t.list("global", "listen_address") {
				if _, p, ok := strings.Cut(l, "@"); ok {
					owners[p] = "stubby"
				}
			}
		}
	}
	if has("smartdns") {
		if t, err := uciShow(ctx, "smartdns", false); err == nil {
			p := t.get("@smartdns[0]", "port")
			owners[pick(p != "", p, "6053")] = "smartdns"
		}
	}
	if has("unbound") {
		if t, err := uciShow(ctx, "unbound", false); err == nil {
			p := t.get("ub_main", "listen_port")
			owners[pick(p != "", p, "53")] = "unbound"
		}
	}
	return owners
}

func dnsPath(ctx context.Context) (string, string, error) {
	rc, err := rcList(ctx)
	if err != nil {
		return "", "", err
	}
	var lines []string
	owners := dnsOwners(ctx, rc)
	front := "dnsmasq"
	if o, ok := owners["53"]; ok {
		front = o
		lines = append(lines, "clients ask "+o+" on port 53 (dnsmasq is moved aside)")
	} else {
		lines = append(lines, "clients ask dnsmasq on port 53")
	}
	var blockers []string
	for _, b := range []string{"adblock", "adblock-fast", "adguardhome", "simple-adblock"} {
		if e, ok := rc[b]; ok && e.Enabled {
			blockers = append(blockers, b)
		}
	}
	servers := dnsmasqServers(ctx)
	if len(servers) == 0 {
		lines = append(lines, "dnsmasq upstream: the ISP resolvers from the WAN lease (no server option set)")
	}
	for _, s := range servers {
		host, port, ok := strings.Cut(s, "#")
		switch {
		case ok && (host == "127.0.0.1" || host == "::1") && owners[port] != "":
			lines = append(lines, "dnsmasq -> "+s+" -> "+owners[port])
		case ok && (host == "127.0.0.1" || host == "::1"):
			who := "a local listener this tool does not know"
			if o := localPortOwner(port); o != "" {
				who = "process " + o + ", no add-on config claims this port"
			}
			lines = append(lines, "dnsmasq -> "+s+" -> ("+who+")")
		default:
			lines = append(lines, "dnsmasq -> "+s+" (plain DNS, not encrypted)")
		}
	}
	if len(blockers) == 0 {
		lines = append(lines, "blockers: none enabled")
	} else {
		lines = append(lines, "blockers enabled: "+strings.Join(blockers, ", "))
	}
	if len(blockers) > 1 {
		lines = append(lines, "WARNING: more than one blocker is enabled; they filter the same queries twice and one hides the other's counters")
	}
	if front != "dnsmasq" && rc["adguardhome"].Enabled {
		lines = append(lines, "WARNING: "+front+" and adguardhome both want port 53")
	}
	return strings.Join(lines, "\n"), "dns path", nil
}

// ---------------------------------------------------------------- path

var reFwmarkRule = regexp.MustCompile(`^(\d+):\s+.*fwmark (0x[0-9a-fA-F]+)(?:/(0x[0-9a-fA-F]+))?\s+(?:lookup|.*lookup)\s+(\S+)`)

type markEntry struct {
	prio, mark, mask, table string
	m, k                    uint64
}

// markMap lists the fwmark rules of `ip rule show` with their masks, and the pairs whose mask
// bits overlap: two routing add-ons that share bits break each other without an error.
func markMap(rules string) ([]markEntry, []string) {
	var ms []markEntry
	for _, l := range strings.Split(rules, "\n") {
		g := reFwmarkRule.FindStringSubmatch(strings.TrimSpace(l))
		if g == nil {
			continue
		}
		mask := g[3]
		if mask == "" {
			mask = "0xffffffff"
		}
		m, e1 := strconv.ParseUint(strings.TrimPrefix(g[2], "0x"), 16, 32)
		k, e2 := strconv.ParseUint(strings.TrimPrefix(mask, "0x"), 16, 32)
		if e1 != nil || e2 != nil {
			continue
		}
		ms = append(ms, markEntry{g[1], g[2], mask, clip(g[4], 20), m, k})
	}
	var overlaps []string
	for i := range ms {
		for j := i + 1; j < len(ms); j++ {
			if ms[i].k&ms[j].k != 0 && ms[i].k != ms[j].k {
				overlaps = append(overlaps, fmt.Sprintf("%s/%s (table %s) and %s/%s (table %s)", ms[i].mark, ms[i].mask, ms[i].table, ms[j].mark, ms[j].mask, ms[j].table))
			}
		}
	}
	return ms, overlaps
}

// clientAddr turns a MAC into the IPv4 neighbour entry it has, or validates an IP.
func clientAddr(ctx context.Context, src string) (ip, dev string, err error) {
	neigh, _ := run(ctx, defaultCmdTimeout, "ip", "-4", "neigh", "show")
	mac := strings.ToLower(src)
	for _, l := range strings.Split(neigh, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		var d, lladdr string
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				d = f[i+1]
			case "lladdr":
				lladdr = strings.ToLower(f[i+1])
			}
		}
		if (net.ParseIP(src) != nil && f[0] == src) || (lladdr != "" && lladdr == mac) {
			return f[0], d, nil
		}
	}
	return "", "", fmt.Errorf("no neighbour entry for %q: the client has not been seen recently (use an IP or MAC from network_clients)", src)
}

func pathDiag(ctx context.Context, in netDiagIn) (string, string, error) {
	if in.Src == "" || net.ParseIP(in.Target) == nil || strings.Contains(in.Target, ":") {
		return "", "", invalid("path needs src (client IP or MAC) and target (an IPv4 address; resolve names with nslookup first)")
	}
	ip, dev, err := clientAddr(ctx, in.Src)
	if err != nil {
		return "", "", err
	}
	if !ifaceName.MatchString(dev) {
		return "", "", fmt.Errorf("client device %q not usable", dev)
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("client %s on %s -> %s", ip, dev, in.Target))
	route := func(extra ...string) string {
		argv := append([]string{"ip", "-4", "route", "get", in.Target, "from", ip, "iif", dev}, extra...)
		out, err := run(ctx, defaultCmdTimeout, argv...)
		if err != nil {
			return "(no route: " + clip(strings.TrimSpace(out+" "+err.Error()), 120) + ")"
		}
		return clip(strings.Join(strings.Fields(strings.SplitN(out, "\n", 2)[0]), " "), 200)
	}
	lines = append(lines, "unmarked traffic: "+route())
	rules, _ := run(ctx, defaultCmdTimeout, "ip", "-4", "rule", "show")
	ms, overlaps := markMap(rules)
	nftOut, _ := run(ctx, defaultCmdTimeout, "nft", "-t", "list", "ruleset")
	owners := parseMarkOwners(nftOut)
	if len(ms) == 0 {
		lines = append(lines, "no fwmark routing rules: every packet takes the route above")
	} else {
		lines = append(lines, fmt.Sprintf("mark map (%d fwmark rules):", len(ms)))
		for _, m := range ms {
			who := ruleOwners(m, owners)
			lines = append(lines, fmt.Sprintf("  prio %s: mark %s/%s -> table %s%s", m.prio, m.mark, m.mask, m.table, pick(who != "", " ("+who+")", "")))
		}
		for _, u := range owners {
			lines = append(lines, "  nftables "+u.describe())
		}
		for _, c := range markConflicts(owners) {
			lines = append(lines, "WARNING: "+c)
		}
		for _, o := range overlaps {
			lines = append(lines, "WARNING: overlapping mask bits: "+o)
		}
		lines = append(lines, "which mark a packet gets is decided by nftables (pbr, mwan3, tailscale, podkop); the owners above come from the chain each rule sits in, and the view does not say which rule matches this client except for pbr policies")
	}
	if tree, err := uciShow(ctx, "pbr", false); err == nil {
		for _, s := range tree.sectionsOfType("policy") {
			if !uciFlag(tree.get(s, "enabled"), true) || !strings.Contains(" "+strings.ReplaceAll(tree.get(s, "src_addr"), ",", " ")+" ", " "+ip+" ") {
				continue
			}
			lines = append(lines, fmt.Sprintf("pbr policy %q sends this client out of %s", clip(tree.get(s, "name"), 40), clip(tree.get(s, "interface"), 20)))
		}
	}
	return strings.Join(lines, "\n"), "path " + ip + " -> " + in.Target, nil
}
