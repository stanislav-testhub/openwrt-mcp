package main

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------- network_clients

type networkClientsIn struct {
	Filter       string `json:"filter,omitempty" jsonschema:"only rows containing this text (host name, IP, MAC, SSID; case-insensitive)"`
	WirelessOnly bool   `json:"wireless_only,omitempty" jsonschema:"only clients associated to a Wi-Fi interface right now"`
}

type netClient struct {
	MAC      string
	IPs      []string
	Host     string
	Static   bool
	HasLease bool
	LeaseEnd int64 // unix; 0 = infinite
	Dev      string
	SSID     string
	Signal   int
	Conn     int64 // seconds connected (wifi)
	RxRate   int   // kbit/s
	TxRate   int
	Wireless bool
	Neigh    string // neighbour state
}

// networkClients answers "who is on my network, where, and how well connected" in one call:
// DHCP leases and static hosts (names), the kernel neighbour table (who is actually present),
// and every AP interface's association list (Wi-Fi signal, rates, time connected). Doing this
// by hand is four ubus calls, a file read and a join by MAC address.
func networkClients(ctx context.Context, in networkClientsIn) (string, string, error) {
	clients := map[string]*netClient{}
	get := func(mac string) *netClient {
		mac = strings.ToLower(mac)
		if c, ok := clients[mac]; ok {
			return c
		}
		c := &netClient{MAC: mac}
		clients[mac] = c
		return c
	}
	addIP := func(c *netClient, ip string) {
		if ip != "" && !contains(c.IPs, ip) {
			c.IPs = append(c.IPs, ip)
		}
	}
	var notes []string

	// dnsmasq leases: "<expiry> <mac> <ip> <hostname|*> <client-id|*>"
	if leases, err := readSys("/tmp/dhcp.leases"); err == nil {
		for _, line := range strings.Split(leases, "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || !isMAC(f[1]) {
				continue
			}
			c := get(f[1])
			// The file is dnsmasq's, but a leases file is just text: only a real address is
			// shown as one.
			if _, err := netip.ParseAddr(f[2]); err == nil {
				addIP(c, f[2])
			}
			if f[3] != "*" {
				c.Host = trunc(f[3], maxFieldBytes)
			}
			c.LeaseEnd, _ = strconv.ParseInt(f[0], 10, 64)
			c.HasLease = true
		}
	} else {
		notes = append(notes, "no /tmp/dhcp.leases (dnsmasq not the DHCP server?)")
	}

	// Static leases: names for hosts that may never have asked for a lease.
	if t, err := uciShow(ctx, "dhcp", false); err == nil {
		for _, sec := range t.sectionsOfType("host") {
			for _, mac := range t.list(sec, "mac") {
				for _, m := range strings.Fields(mac) {
					if !isMAC(m) {
						continue
					}
					c := get(m)
					c.Static = true
					if n := t.get(sec, "name"); n != "" && c.Host == "" {
						c.Host = trunc(n, maxFieldBytes)
					}
					addIP(c, t.get(sec, "ip"))
				}
			}
		}
	}

	var neigh []struct {
		Dst    string   `json:"dst"`
		Dev    string   `json:"dev"`
		LLAddr string   `json:"lladdr"`
		State  []string `json:"state"`
	}
	if err := runJSON(ctx, &neigh, "ip", "-j", "neigh", "show"); err == nil {
		for _, n := range neigh {
			if !isMAC(n.LLAddr) {
				continue
			}
			c := get(n.LLAddr)
			if a, err := netip.ParseAddr(n.Dst); err == nil && (a.Is4() || a.IsGlobalUnicast()) {
				addIP(c, n.Dst)
			}
			if c.Dev == "" {
				c.Dev = trunc(n.Dev, maxFieldBytes)
			}
			if len(n.State) > 0 && c.Neigh == "" {
				c.Neigh = trunc(strings.ToLower(n.State[0]), maxFieldBytes)
			}
		}
	} else {
		notes = append(notes, "neighbour table unavailable: "+err.Error())
	}

	var devs struct {
		Devices []string `json:"devices"`
	}
	if err := runJSON(ctx, &devs, "ubus", "call", "iwinfo", "devices"); err == nil {
		for _, dev := range devs.Devices {
			var info struct {
				SSID string `json:"ssid"`
				Mode string `json:"mode"`
			}
			arg := fmt.Sprintf(`{"device":%q}`, dev)
			if runJSON(ctx, &info, "ubus", "call", "iwinfo", "info", arg) != nil || info.Mode != "Master" {
				continue
			}
			var assoc struct {
				Results []struct {
					MAC       string `json:"mac"`
					Signal    int    `json:"signal"`
					Connected int64  `json:"connected_time"`
					Rx        struct {
						Rate int `json:"rate"`
					} `json:"rx"`
					Tx struct {
						Rate int `json:"rate"`
					} `json:"tx"`
				} `json:"results"`
			}
			if runJSON(ctx, &assoc, "ubus", "call", "iwinfo", "assoclist", arg) != nil {
				continue
			}
			for _, a := range assoc.Results {
				c := get(a.MAC)
				c.Wireless, c.Dev, c.SSID = true, trunc(dev, maxFieldBytes), trunc(info.SSID, maxFieldBytes)
				c.Signal, c.Conn = a.Signal, a.Connected
				c.RxRate, c.TxRate = a.Rx.Rate, a.Tx.Rate
			}
		}
	}

	now := time.Now().Unix()
	var rows []*netClient
	for _, c := range clients {
		if in.WirelessOnly && !c.Wireless {
			continue
		}
		// A static lease for a device that is not here is configuration, not a client.
		if !c.Wireless && c.Neigh == "" && !c.HasLease {
			continue
		}
		rows = append(rows, c)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Wireless != rows[j].Wireless {
			return rows[i].Wireless
		}
		if rows[i].SSID != rows[j].SSID {
			return rows[i].SSID < rows[j].SSID
		}
		return rows[i].Host < rows[j].Host
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %-16s %-17s %-28s %-7s %-9s %-11s %s\n",
		"HOST", "IP", "MAC", "VIA", "SIGNAL", "CONNECTED", "RATE rx/tx", "LEASE")
	filter := strings.ToLower(in.Filter)
	shown := 0
	for _, c := range rows {
		ip := "-"
		sort.Slice(c.IPs, func(i, j int) bool { return len(c.IPs[i]) < len(c.IPs[j]) }) // v4 first
		if len(c.IPs) > 0 {
			ip = c.IPs[0]
		}
		via, signal, conn, rate := orDefault(c.Dev, "-"), "-", "-", "-"
		if c.Wireless {
			via = fmt.Sprintf("%s(%s)", c.SSID, c.Dev)
			signal = fmt.Sprintf("%ddBm", c.Signal)
			conn = (time.Duration(c.Conn) * time.Second).String()
			rate = fmt.Sprintf("%d/%dM", c.RxRate/1000, c.TxRate/1000)
		} else if c.Neigh != "" {
			conn = c.Neigh
		}
		lease := "-"
		switch {
		case c.Static:
			lease = "static"
		case !c.HasLease:
			lease = "-"
		case c.LeaseEnd == 0:
			lease = "infinite"
		case c.LeaseEnd > now:
			lease = (time.Duration(c.LeaseEnd-now) * time.Second).Round(time.Minute).String()
		case c.LeaseEnd > 0:
			lease = "expired"
		}
		line := fmt.Sprintf("%-22s %-16s %-17s %-28s %-7s %-9s %-11s %s",
			trunc(orDefault(c.Host, "?"), 22), ip, c.MAC, trunc(via, 28), signal, conn, rate, lease)
		if len(c.IPs) > 1 {
			extra := c.IPs[1:]
			if len(extra) > maxExtraIPs {
				extra = append(extra[:maxExtraIPs:maxExtraIPs], fmt.Sprintf("(+%d)", len(c.IPs)-1-maxExtraIPs))
			}
			line += "  also " + strings.Join(extra, " ")
		}
		if filter != "" && !strings.Contains(strings.ToLower(line), filter) {
			continue
		}
		b.WriteString(line + "\n")
		shown++
	}
	fmt.Fprintf(&b, "\n%d client(s)", shown)
	if len(notes) > 0 {
		b.WriteString("\nnotes: " + strings.Join(notes, "; "))
	}
	return b.String(), fmt.Sprintf("%d clients", shown), nil
}

var reMAC = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

func isMAC(s string) bool { return reMAC.MatchString(s) }

// maxFieldBytes bounds any one field a network client can influence (host name, SSID,
// interface name, neighbour state); maxExtraIPs bounds the addresses listed after the first.
const (
	maxFieldBytes = 64
	maxExtraIPs   = 4
)

// trunc cuts s to at most n bytes, on a character boundary, ending in "~" when it cut.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - 1
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "~"
}

// ---------------------------------------------------------------- firewall_show

type firewallShowIn struct {
	View   string `json:"view,omitempty" jsonschema:"ruleset (default; live nftables ruleset) | rendered (what fw4 would load from /etc/config/firewall) | check (validate the firewall config without applying) | chain (one chain) | table (one table)"`
	Family string `json:"family,omitempty" jsonschema:"for chain/table: nft family (default inet)"`
	Table  string `json:"table,omitempty" jsonschema:"for chain/table: table name (default fw4)"`
	Chain  string `json:"chain,omitempty" jsonschema:"for chain: chain name, e.g. 'forward_lan' or 'srcnat'"`
}

// A name is passed to nft as its own argument, so it must not begin with '-': nft would read
// it as an option wherever it sits on the command line.
var reNftName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)

// firewallShow reads the firewall. OpenWrt 22.03+ is fw4 on nftables: iptables is gone, and
// the rules an agent needs to reason about are fw4's rendered ruleset plus whatever other
// packages (docker, tailscale, banip, pbr, ...) have added as their own tables.
func firewallShow(ctx context.Context, in firewallShowIn) (string, string, error) {
	fam, table := orDefault(in.Family, "inet"), orDefault(in.Table, "fw4")
	var argv []string
	switch orDefault(in.View, "ruleset") {
	case "ruleset":
		argv = []string{"nft", "list", "ruleset"}
	case "rendered":
		argv = []string{"fw4", "-q", "print"}
	case "check":
		argv = []string{"fw4", "check"}
	case "table":
		if !reNftName.MatchString(fam) || !reNftName.MatchString(table) {
			return "", "", fmt.Errorf("bad family/table")
		}
		argv = []string{"nft", "list", "table", fam, table}
	case "chain":
		if !reNftName.MatchString(fam) || !reNftName.MatchString(table) || !reNftName.MatchString(in.Chain) {
			return "", "", fmt.Errorf("chain view needs a valid chain (and optionally family/table)")
		}
		argv = []string{"nft", "list", "chain", fam, table, in.Chain}
	default:
		return "", "", fmt.Errorf("unknown view %q", in.View)
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if in.View == "check" && err == nil && strings.TrimSpace(out) == "" {
		out = "firewall configuration is valid"
	}
	return out, strings.Join(argv, " "), err
}
