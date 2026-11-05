package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Add-on adapters: `service_list detail=<service>` returns a defined, read-only status for a
// popular add-on, so a model need not know that tailscale wants `tailscale status --json` or that
// AdGuard Home keeps its settings in a YAML file next to a login hash.
//
// An adapter is a fixed set of reads and a renderer. It applies when the add-on's init script
// exists (the rc listing already enumerates /etc/init.d, so no package manager is involved), and
// the tool list stays flat: there is one tool, and the plain listing names the adapters that
// apply on this router.
//
// Rules every adapter follows:
//   - It runs only read commands, with argv built by the code, never from the caller's input.
//   - It prints fixed fields extracted by name. It never echoes a config file or a command's
//     output, because those hold credentials (login hashes, proxy links, node keys, tokens in
//     upstream URLs) that no masker could be trusted to find in free text.
//   - Text that someone other than the operator chose (a tailnet peer's host name) is clipped,
//     sanitised, and the result is marked untrusted.
//   - It never fails the call: an add-on that does not answer is itself a status.
type adapter struct {
	service   string
	untrusted string // the third-party text the output carries ("" if it is all the operator's own)
	read      func(ctx context.Context) string
	query     *adapterQuery // optional: `service_list detail=<service> query=<value>`
}

// adapterQuery answers one bounded lookup ("is this domain blocked", "is this address banned").
// The value is validated by kind before the function sees it, so no argv or file path is built
// from unchecked caller text.
type adapterQuery struct {
	kind string // "domain" or "ip"
	fn   func(ctx context.Context, value string) string
}

var reQueryDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]{0,251}[a-z0-9_])?$`)

// cleanQuery validates and normalises a query value of the given kind.
func cleanQuery(kind, v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	switch kind {
	case "domain":
		v = strings.TrimSuffix(v, ".")
		if !reQueryDomain.MatchString(v) || strings.Contains(v, "..") || !strings.Contains(v, ".") {
			return "", fmt.Errorf("query must be a domain name such as example.com")
		}
	case "ip":
		ip := net.ParseIP(v)
		if ip == nil {
			return "", fmt.Errorf("query must be an IPv4 or IPv6 address")
		}
		v = ip.String()
	}
	return v, nil
}

// adapters is sorted by service name; the listing and the "available here" line follow it.
var adapters = []adapter{
	{service: "adblock", read: readAdblock},
	{service: "adblock-fast", read: readAdblockFast, query: &adapterQuery{"domain", queryAdblockFast}},
	{service: "adguardhome", read: readAdGuardHome},
	{service: "banip", read: readBanIP, query: &adapterQuery{"ip", queryBanIP}},
	{service: "cloudflared", read: readCloudflared},
	{service: "collectd", read: readStatistics},
	{service: "ddns", read: readDDNS},
	{service: "frpc", read: readFrpc},
	{service: "frps", read: readFrps},
	{service: "https-dns-proxy", read: readHTTPSDNSProxy},
	{service: "ipsec", read: readStrongSwan},
	{service: "miniupnpd", untrusted: "UPnP lease descriptions", read: readUPnP},
	{service: "mwan3", read: readMwan3},
	{service: "netbird", read: readNetBird},
	{service: "nextdns", read: readNextDNS},
	{service: "openvpn", read: readOpenVPN},
	{service: "pbr", read: readPBR},
	{service: "podkop", read: readPodkop},
	{service: "qosify", read: readQosify},
	{service: "smartdns", read: readSmartDNS},
	{service: "sqm", read: readSQM},
	{service: "stubby", read: readStubby},
	{service: "swanctl", read: readStrongSwan},
	{service: "tailscale", untrusted: "tailnet host names", read: readTailscale},
	{service: "travelmate", read: readTravelmate},
	{service: "ttyd", read: readTTYD},
	{service: "unbound", read: readUnbound},
	{service: "watchcat", read: readWatchcat},
	{service: "zerotier", read: readZeroTier},
}

func adapterFor(service string) (adapter, bool) {
	for _, a := range adapters {
		if a.service == service {
			return a, true
		}
	}
	return adapter{}, false
}

// adaptersHere are the adapters whose init script is on this router.
func adaptersHere(rc map[string]rcEntry) []string {
	var out []string
	for _, a := range adapters {
		if _, ok := rc[a.service]; ok {
			out = append(out, a.service)
		}
	}
	return out
}

func serviceHeader() string {
	return fmt.Sprintf("%-24s %-9s %-8s %s", "SERVICE", "BOOT", "STATE", "START/STOP")
}

func serviceRow(name string, e rcEntry) string {
	boot, state := "disabled", "stopped"
	if e.Enabled {
		boot = "enabled"
	}
	if e.Running {
		state = "running"
	}
	return fmt.Sprintf("%-24s %-9s %-8s %d/%d", name, boot, state, e.Start, e.Stop)
}

// serviceDetail is the result of service_list detail=name: the service's own row, then what the
// adapter says.
func serviceDetail(ctx context.Context, rc map[string]rcEntry, name, query string) (string, string, error) {
	e, ok := rc[name]
	if !ok {
		return "", "", fmt.Errorf("no init script %q (see service_list)", name)
	}
	var b strings.Builder
	b.WriteString(serviceHeader() + "\n" + serviceRow(name, e) + "\n\n")
	a, has := adapterFor(name)
	if !has {
		here := strings.Join(adaptersHere(rc), ", ")
		if here == "" {
			here = "none"
		}
		fmt.Fprintf(&b, "no add-on status for %s; available here: %s", name, here)
		return b.String(), "service " + name, nil
	}
	if query != "" {
		if a.query == nil {
			return "", "", fmt.Errorf("%s has no query; omit query for its status", name)
		}
		v, err := cleanQuery(a.query.kind, query)
		if err != nil {
			return "", "", err
		}
		b.WriteString(strings.TrimRight(a.query.fn(ctx, v), "\n"))
		return b.String(), "service query " + name, nil
	}
	b.WriteString(strings.TrimRight(a.read(ctx), "\n"))
	text := b.String()
	if a.untrusted != "" {
		text = untrustedMarker(a.untrusted) + "\n" + text
	}
	return text, "service detail " + name, nil
}

// ---------------------------------------------------------------- helpers shared by adapters

// clip makes a third-party or config string safe to print: no control or format characters, one
// line, at most n characters.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(sanitizeText(s)), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// pidText turns `pidof` output into "pid 8330" or "pids 12 34".
func pidText(out string) string {
	f := strings.Fields(out)
	if len(f) == 0 {
		return ""
	}
	if len(f) > 4 {
		f = f[:4]
	}
	if len(f) == 1 {
		return "pid " + clip(f[0], 10)
	}
	return "pids " + clip(strings.Join(f, " "), 40)
}

// dnsmasqServers reads dnsmasq's upstream servers (dhcp.@dnsmasq[0].server), the first thing to
// check when asking whether an add-on is in the DNS path. Empty when none is set.
func dnsmasqServers(ctx context.Context) []string {
	out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "dhcp.@dnsmasq[0].server")
	if err != nil {
		return nil
	}
	f := strings.Fields(out)
	if len(f) > 8 {
		f = f[:8]
	}
	for i := range f {
		f[i] = clip(f[i], 60)
	}
	return f
}

// uciName matches what UCI allows in a section name, the only thing built into a file path or an
// ubus object name from the config.
var uciName = regexp.MustCompile(`^[A-Za-z0-9_]{1,40}$`)

// ifaceName is a network interface or device name as the kernel and netifd allow it.
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,15}$`)

// runtimeDir accepts a directory or file path that an add-on's config names only when it is in
// RAM-backed storage, so a config option cannot point an adapter at /etc/shadow.
func runtimePath(p, fallback string) string {
	if (strings.HasPrefix(p, "/var/run/") || strings.HasPrefix(p, "/tmp/")) && !strings.Contains(p, "..") && len(p) <= 120 {
		return p
	}
	return fallback
}

// procdData is what a procd service registered under `ubus call service list`: whether any
// instance runs, and the data object (at service level, or on the first instance that has one).
func procdData(ctx context.Context, name string) (found, running bool, data map[string]json.RawMessage) {
	var all map[string]struct {
		Data      map[string]json.RawMessage `json:"data"`
		Instances map[string]struct {
			Running bool                       `json:"running"`
			Data    map[string]json.RawMessage `json:"data"`
		} `json:"instances"`
	}
	if err := runJSON(ctx, &all, "ubus", "call", "service", "list", `{"name":"`+name+`"}`); err != nil {
		return false, false, nil
	}
	svc, ok := all[name]
	if !ok {
		return false, false, nil
	}
	data = svc.Data
	keys := make([]string, 0, len(svc.Instances))
	for k := range svc.Instances {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		in := svc.Instances[k]
		running = running || in.Running
		if len(data) == 0 && len(in.Data) > 0 {
			data = in.Data
		}
	}
	return true, running, data
}

// dataString reads a string field of procd data.
func dataString(d map[string]json.RawMessage, key string) string {
	var s string
	if raw, ok := d[key]; ok && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// dataCodes lists the `code` of each entry of an errors/warnings array in procd data, in order.
// Only the codes are printed: the info text is whatever the add-on chose to say (list URLs).
func dataCodes(d map[string]json.RawMessage, key string) []string {
	var list []struct {
		Code string `json:"code"`
	}
	if raw, ok := d[key]; !ok || json.Unmarshal(raw, &list) != nil {
		return nil
	}
	var out []string
	for _, e := range list {
		if c := clip(e.Code, 40); c != "" {
			out = append(out, c)
		}
		if len(out) == 8 {
			break
		}
	}
	return out
}

// uptimeSeconds is the router's uptime, the clock add-ons such as ddns-scripts stamp files with.
func uptimeSeconds() (int, bool) {
	s, err := readSys("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return int(v), true
}

// ageText is a duration in seconds as "45s", "12m", "3h" or "2d".
func ageText(sec int) string {
	switch {
	case sec < 0:
		return "0s"
	case sec < 120:
		return fmt.Sprintf("%ds", sec)
	case sec < 2*3600:
		return fmt.Sprintf("%dm", sec/60)
	case sec < 2*86400:
		return fmt.Sprintf("%dh", sec/3600)
	}
	return fmt.Sprintf("%dd", sec/86400)
}

func pick(b bool, on, off string) string {
	if b {
		return on
	}
	return off
}

// uciFlag reads a UCI boolean the way procd scripts do.
func uciFlag(v string, def bool) bool {
	switch strings.ToLower(v) {
	case "1", "on", "yes", "true", "enabled":
		return true
	case "0", "off", "no", "false", "disabled":
		return false
	}
	return def
}

// wanAddress is the first address netifd reports on a logical interface ("" when it has none).
func wanAddress(ctx context.Context, iface string, v6 bool) string {
	if !uciName.MatchString(iface) {
		return ""
	}
	var st struct {
		V4 []struct {
			Address string `json:"address"`
		} `json:"ipv4-address"`
		V6 []struct {
			Address string `json:"address"`
		} `json:"ipv6-address"`
	}
	if runJSON(ctx, &st, "ubus", "call", "network.interface."+iface, "status") != nil {
		return ""
	}
	if v6 && len(st.V6) > 0 {
		return st.V6[0].Address
	}
	if !v6 && len(st.V4) > 0 {
		return st.V4[0].Address
	}
	return ""
}

var cgnatNet = func() *net.IPNet { _, n, _ := net.ParseCIDR("100.64.0.0/10"); return n }()

// behindCGNAT is true for an address in 100.64.0.0/10: a WAN address no one outside the
// provider can reach, so a port forward, UPnP mapping or dynamic DNS record for it cannot work.
func behindCGNAT(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && cgnatNet.Contains(ip)
}

func validIP(s string) bool { return net.ParseIP(s) != nil }
