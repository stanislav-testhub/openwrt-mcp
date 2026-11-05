package main

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// https-dns-proxy runs one DoH client per provider section, each listening on a local port that
// dnsmasq forwards to. The resolver URL is printed as its host only: some providers (NextDNS)
// put a configuration id in the path.

func readHTTPSDNSProxy(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "https-dns-proxy"); err == nil && pidText(out) != "" {
		lines = append(lines, "https-dns-proxy: running, "+pidText(out))
	} else {
		lines = append(lines, "https-dns-proxy: not running")
	}
	tree, err := uciShow(ctx, "https-dns-proxy", false)
	if err != nil {
		return strings.Join(append(lines, "https-dns-proxy config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	secs := tree.sectionsOfType("https-dns-proxy")
	ports := map[string]bool{}
	lines = append(lines, fmt.Sprintf("instances (%d):", len(secs)))
	for _, s := range secs {
		port := clip(tree.get(s, "listen_port"), 6)
		addr := clip(tree.get(s, "listen_addr"), 40)
		if addr == "" {
			addr = clip(tree.get("config", "listen_addr"), 40) // the package default lives in the config section
		}
		if addr == "" {
			addr = "127.0.0.1"
		}
		if port != "" {
			ports[port] = true
		}
		lines = append(lines, fmt.Sprintf("  %s: %s, listens on %s:%s, bootstrap DNS %s", clip(s, 40), resolverHost(tree.get(s, "resolver_url")), addr,
			pick(port != "", port, "(automatic)"), pick(tree.get(s, "bootstrap_dns") != "", "set", "not set")))
	}
	return strings.Join(append(lines, httpsDNSDnsmasq(dnsmasqServers(ctx), ports, len(secs))), "\n")
}

func resolverHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "(resolver URL not set)"
	}
	return clip(u.Hostname(), 60)
}

// httpsDNSDnsmasq says whether dnsmasq forwards to a local proxy port. Instances with no fixed
// port are given ports from 5053 up by the init script.
func httpsDNSDnsmasq(servers []string, ports map[string]bool, instances int) string {
	if len(servers) == 0 {
		if instances == 0 {
			return "dnsmasq upstream servers: (none set)"
		}
		return "dnsmasq upstream servers: (none set); DNS bypasses https-dns-proxy unless its init script manages dnsmasq (dnsmasq_config_update)"
	}
	line := "dnsmasq upstream servers: " + strings.Join(servers, ", ")
	for _, s := range servers {
		host, port, ok := strings.Cut(s, "#")
		if ok && (host == "127.0.0.1" || host == "::1") && (ports[port] || (len(port) == 4 && port >= "5053" && port < "5100")) {
			return line + "; https-dns-proxy is in the DNS path"
		}
	}
	return line + "; no forwarder points at a local https-dns-proxy port, so DNS bypasses it"
}
