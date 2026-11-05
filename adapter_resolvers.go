package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Local resolvers that sit between dnsmasq and the internet: unbound, stubby and smartdns. Each
// adapter prints the listen port, the upstream hosts (never URLs, which can carry a
// configuration id or token) and whether dnsmasq actually forwards to it.

// dnsmasqForwardsTo says whether one of dnsmasq's upstream servers is a loopback address on port.
func dnsmasqForwardsTo(servers []string, port string) bool {
	for _, s := range servers {
		host, p, ok := strings.Cut(s, "#")
		if ok && p == port && (host == "127.0.0.1" || host == "::1") {
			return true
		}
	}
	return false
}

func dnsPathLine(servers []string, ports ...string) string {
	for _, p := range ports {
		if p != "" && dnsmasqForwardsTo(servers, p) {
			return "dnsmasq forwards to it: yes"
		}
	}
	return "dnsmasq forwards to it: no (dnsmasq upstream servers: " + pick(len(servers) > 0, strings.Join(servers, ", "), "none set") + ")"
}

// hostOnly reduces a server address, URL or host@port to a host name or IP.
func hostOnly(v string) string {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
			return clip(u.Hostname(), 60)
		}
		return "(unreadable)"
	}
	if i := strings.IndexAny(v, "@#/ "); i >= 0 {
		v = v[:i]
	}
	return clip(v, 60)
}

// ---------------------------------------------------------------- unbound

func readUnbound(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "unbound"); err == nil && pidText(out) != "" {
		lines = append(lines, "unbound: running, "+pidText(out))
	} else {
		lines = append(lines, "unbound: not running")
	}
	tree, err := uciShow(ctx, "unbound", false)
	if err != nil {
		return strings.Join(append(lines, "unbound config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	port := tree.get("ub_main", "listen_port")
	if port == "" {
		port = "53"
	}
	link := tree.get("ub_main", "dhcp_link")
	lines = append(lines, "listen port: "+clip(port, 6), "dhcp link: "+pick(link != "", clip(link, 20), "none"),
		"DNSSEC validator: "+pick(uciFlag(tree.get("ub_main", "validator"), false), "on", "off"),
		"forwarding to upstream resolvers: "+pick(uciFlag(tree.get("ub_main", "forward_upstream"), false), "yes", "no (recursive)"))
	servers := dnsmasqServers(ctx)
	if port == "53" {
		lines = append(lines, "unbound answers on 53; dnsmasq is expected on another port (dhcp link "+pick(link == "dnsmasq", "dnsmasq", "not set")+")")
	} else {
		lines = append(lines, dnsPathLine(servers, port))
	}
	if out, err := run(ctx, defaultCmdTimeout, "unbound-control", "stats_noreset"); err == nil {
		lines = append(lines, unboundStats(out))
	} else {
		lines = append(lines, "cache stats: unbound-control not available")
	}
	return strings.Join(lines, "\n")
}

func unboundStats(out string) string {
	vals := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if ok {
			vals[k] = v
		}
	}
	var q, hit, miss int
	if _, err := fmt.Sscan(vals["total.num.queries"], &q); err != nil {
		return "cache stats: not recognised"
	}
	fmt.Sscan(vals["total.num.cachehits"], &hit)
	fmt.Sscan(vals["total.num.cachemiss"], &miss)
	return fmt.Sprintf("queries %d, cache hits %d, misses %d", q, hit, miss)
}

// ---------------------------------------------------------------- stubby

func readStubby(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "stubby"); err == nil && pidText(out) != "" {
		lines = append(lines, "stubby: running, "+pidText(out))
	} else {
		lines = append(lines, "stubby: not running")
	}
	tree, err := uciShow(ctx, "stubby", false)
	if err != nil {
		return strings.Join(append(lines, "stubby config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	var ports []string
	var listen []string
	for _, l := range tree.list("global", "listen_address") {
		listen = append(listen, clip(l, 50))
		if _, p, ok := strings.Cut(l, "@"); ok {
			ports = append(ports, p)
		}
	}
	lines = append(lines, "listens on: "+pick(len(listen) > 0, strings.Join(listen, ", "), "(default)"))
	secs := tree.sectionsOfType("resolver")
	lines = append(lines, fmt.Sprintf("upstream resolvers (%d):", len(secs)))
	for i, s := range secs {
		if i == 8 {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(secs)-8))
			break
		}
		name := tree.get(s, "tls_auth_name")
		lines = append(lines, fmt.Sprintf("  %s, TLS name %s", hostOnly(tree.get(s, "address")), pick(name != "", clip(name, 60), "not set (no authentication)")))
	}
	return strings.Join(append(lines, dnsPathLine(dnsmasqServers(ctx), ports...)), "\n")
}

// ---------------------------------------------------------------- smartdns

func readSmartDNS(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "smartdns"); err == nil && pidText(out) != "" {
		lines = append(lines, "smartdns: running, "+pidText(out))
	} else {
		lines = append(lines, "smartdns: not running")
	}
	tree, err := uciShow(ctx, "smartdns", false)
	if err != nil {
		return strings.Join(append(lines, "smartdns config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	port := tree.get("@smartdns[0]", "port")
	if port == "" {
		port = "6053"
	}
	redirect := tree.get("@smartdns[0]", "redirect")
	lines = append(lines, "listen port: "+clip(port, 6), "redirect: "+pick(redirect != "", clip(redirect, 30), "none"))
	servers := tree.sectionsOfType("server")
	lines = append(lines, fmt.Sprintf("upstream servers (%d):", len(servers)))
	for i, s := range servers {
		if i == 8 {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(servers)-8))
			break
		}
		typ := clip(tree.get(s, "type"), 8)
		host := hostOnly(tree.get(s, "ip"))
		if net.ParseIP(host) == nil && typ == "" {
			typ = "?"
		}
		lines = append(lines, fmt.Sprintf("  %s %s, %s", pick(typ != "", typ, "udp"), host, pick(uciFlag(tree.get(s, "enabled"), true), "enabled", "disabled")))
	}
	in := redirect == "dnsmasq-upstream" || dnsmasqForwardsTo(dnsmasqServers(ctx), port)
	if in {
		lines = append(lines, "dnsmasq forwards to it: yes")
	} else {
		lines = append(lines, dnsPathLine(dnsmasqServers(ctx), port))
	}
	return strings.Join(lines, "\n")
}
