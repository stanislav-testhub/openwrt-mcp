package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ddns-scripts keeps one set of files per section in its run directory: <section>.ip is the
// address DNS returns for lookup_host (empty when the lookup fails, even after a good update), <section>.update the router uptime of the last
// successful update. Together with the WAN address netifd reports they answer "did my dynamic
// DNS update". The section's username, password, token and update URL are never read.

const (
	ddnsRunDir      = "/var/run/ddns"
	ddnsMaxSections = 20
)

func readDDNS(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "dynamic_dns_updater.sh"); err == nil && pidText(out) != "" {
		lines = append(lines, "updaters running: "+pidText(out))
	} else {
		lines = append(lines, "updaters running: none")
	}
	tree, err := uciShow(ctx, "ddns", false)
	if err != nil {
		return strings.Join(append(lines, "ddns config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	dir := runtimePath(tree.get("global", "ddns_rundir"), ddnsRunDir)
	secs := tree.sectionsOfType("service")
	if len(secs) == 0 {
		return strings.Join(append(lines, "services (0)"), "\n")
	}
	lines = append(lines, fmt.Sprintf("services (%d):", len(secs)))
	up, haveUp := uptimeSeconds()
	for i, s := range secs {
		if i == ddnsMaxSections {
			lines = append(lines, fmt.Sprintf("... %d more services not shown", len(secs)-ddnsMaxSections))
			break
		}
		lines = append(lines, ddnsService(ctx, tree, s, dir, up, haveUp)...)
	}
	return strings.Join(lines, "\n")
}

func ddnsService(ctx context.Context, t *uciTree, s, dir string, uptime int, haveUptime bool) []string {
	enabled := uciFlag(t.get(s, "enabled"), false)
	provider := clip(t.get(s, "service_name"), 40)
	if provider == "" {
		provider = "custom update URL"
	}
	v6 := uciFlag(t.get(s, "use_ipv6"), false)
	head := fmt.Sprintf("%s: %s, %s, %s, IPv%s", clip(s, 40), pick(enabled, "enabled", "disabled"), clip(t.get(s, "domain"), 60), provider, pick(v6, "6", "4"))
	if !uciName.MatchString(s) {
		return []string{head + "; section name not usable for state files"}
	}
	registered := ""
	if text, err := readSys(dir + "/" + s + ".ip"); err == nil {
		if ip := strings.TrimSpace(text); validIP(ip) {
			registered = ip
		}
	}
	iface := t.get(s, "ip_network")
	if iface == "" {
		iface = t.get(s, "interface")
	}
	wan := wanAddress(ctx, iface, v6)
	parts := []string{"registered " + pick(registered != "", registered, "unknown")}
	if wan != "" {
		parts = append(parts, "WAN "+wan)
	}
	if haveUptime {
		if text, err := readSys(dir + "/" + s + ".update"); err == nil {
			if at, err := strconv.Atoi(strings.TrimSpace(text)); err == nil && at <= uptime {
				parts = append(parts, "last update "+ageText(uptime-at)+" ago")
			}
		} else {
			parts = append(parts, "no update recorded")
		}
	}
	out := []string{head, "  " + strings.Join(parts, ", ")}
	switch {
	case enabled && behindCGNAT(wan):
		out = append(out, "  WARNING: the WAN address is in 100.64.0.0/10 (carrier-grade NAT): the record cannot be reached from outside")
	case enabled && registered != "" && wan != "" && registered != wan:
		out = append(out, "  WARNING: the registered address differs from the WAN address, so the record is stale or the update failed")
	}
	return out
}
