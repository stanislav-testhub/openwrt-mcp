package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// miniupnpd answers UPnP IGD and NAT-PMP requests: any LAN host may ask it to open a port to the
// internet. The status lists the live mappings from its lease file (PROTO:eport:iaddr:iport:
// expiry:description, one per line), because "which ports did UPnP open, and for whom" is the
// whole point. A mapping's description is chosen by the client, so it is clipped and marked.

const (
	upnpLeaseFile = "/var/run/miniupnpd.leases"
	upnpMaxLeases = 30
)

func readUPnP(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "miniupnpd"); err == nil && pidText(out) != "" {
		lines = append(lines, "miniupnpd: running, "+pidText(out))
	} else {
		lines = append(lines, "miniupnpd: not running")
	}
	tree, err := uciShow(ctx, "upnpd", false)
	if err != nil {
		return strings.Join(append(lines, "upnpd config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines, upnpSettings(tree)...)
	lease := runtimePath(tree.get("config", "upnp_lease_file"), upnpLeaseFile)
	text, rerr := readSys(lease)
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			// miniupnpd creates the file with the first mapping, so on a quiet LAN there is none.
			return strings.Join(append(lines, "mappings: none (no lease file yet)"), "\n")
		}
		return strings.Join(append(lines, "mappings: lease file not readable"), "\n")
	}
	return strings.Join(append(lines, upnpLeases(text)...), "\n")
}

func upnpSettings(t *uciTree) []string {
	enabled := uciFlag(t.get("config", "enabled"), true)
	secure := uciFlag(t.get("config", "secure_mode"), true)
	proto := []string{}
	if uciFlag(t.get("config", "enable_upnp"), true) {
		proto = append(proto, "UPnP")
	}
	if uciFlag(t.get("config", "enable_natpmp"), true) {
		proto = append(proto, "NAT-PMP")
	}
	ext := clip(t.get("config", "external_iface"), 20)
	if ext == "" {
		ext = "found from ubus"
	}
	lines := []string{fmt.Sprintf("settings: %s, protocols %s, internal %s, external %s, secure mode %s",
		pick(enabled, "enabled", "disabled"), strings.Join(proto, "+"), clip(strings.Join(t.list("config", "internal_iface"), " "), 40),
		ext, pick(secure, "on", "off"))}
	if !secure {
		lines = append(lines, "WARNING: secure mode is off, so any LAN host may map ports to other hosts' addresses")
	}
	return lines
}

type upnpLease struct {
	proto        string
	eport, iport int
	ip, desc     string
}

// parseUPnPLeases reads the lease file; the description is the client's choice, so it is clipped.
func parseUPnPLeases(text string) []upnpLease {
	var out []upnpLease
	for _, l := range strings.Split(text, "\n") {
		f := strings.SplitN(strings.TrimSpace(l), ":", 6)
		if len(f) < 5 || (f[0] != "TCP" && f[0] != "UDP") {
			continue
		}
		eport, e1 := strconv.Atoi(f[1])
		iport, e2 := strconv.Atoi(f[3])
		if e1 != nil || e2 != nil || eport < 1 || eport > 65535 || iport < 1 || iport > 65535 || !validIP(f[2]) {
			continue
		}
		m := upnpLease{proto: f[0], eport: eport, iport: iport, ip: f[2]}
		if len(f) == 6 {
			m.desc = sanitizeText(clip(f[5], 40))
		}
		out = append(out, m)
	}
	return out
}

func upnpLeases(text string) []string {
	var maps []string
	all := parseUPnPLeases(text)
	total := len(all)
	for i, m := range all {
		if i == upnpMaxLeases {
			break
		}
		line := fmt.Sprintf("  %s %d -> %s:%d", m.proto, m.eport, m.ip, m.iport)
		if m.desc != "" {
			line += " (" + m.desc + ")"
		}
		maps = append(maps, line)
	}
	if total == 0 {
		return []string{"mappings (0)"}
	}
	out := append([]string{fmt.Sprintf("mappings (%d):", total)}, maps...)
	if total > len(maps) {
		out = append(out, fmt.Sprintf("  ... %d more not shown", total-len(maps)))
	}
	return out
}
