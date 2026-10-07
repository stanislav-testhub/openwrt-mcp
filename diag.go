package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// `openwrt-mcp diag` prints what a maintainer needs to read a bug report (ROADMAP 3.9): the
// version, the board, the shape of the policy and the last few audit lines, with every address and
// name that identifies the sender replaced by a stable placeholder. The output is made to be pasted
// into a public issue, which is why it is built to leak too little rather than to be complete:
// audit arguments are never printed, and the free text of an entry (scope, summary, error) only
// with --detail, and masked like everything else.
//
// Masking has two parts. Patterns catch IPv4, IPv6 and MAC addresses wherever they appear. Names
// (host names, DHCP names, SSIDs, the domain, WireGuard peer names) are not recognisable by shape,
// so they are read from the router's own configuration and matched exactly. A name nobody told
// the masker about is not masked; the test for that is in diag_test.go.

var (
	reDiagMAC  = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	reDiagIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reDiagIPv6 = regexp.MustCompile(`[0-9A-Fa-f:]{2,}(?:%[A-Za-z0-9_.-]+)?`)
)

// genericClients are client names that say which program connected and nothing about who runs it.
var genericClients = append([]string{"stdio"}, connectClients...)

type masker struct {
	macs, ips, names, clients map[string]string
	nameRes                   []*regexp.Regexp
	namePlaceholders          []string
}

// newMasker takes the names to hide, each with the kind its placeholder is numbered under
// (host, ssid, peer, domain). Placeholders are numbered in sorted order of the names, so the same
// router masks the same way twice.
func newMasker(names map[string]string) *masker {
	m := &masker{macs: map[string]string{}, ips: map[string]string{}, names: map[string]string{}, clients: map[string]string{}}
	var values []string
	for v := range names {
		if len(v) >= 2 { // one character would turn every stray letter into a placeholder
			values = append(values, v)
		}
	}
	sort.Strings(values)
	count := map[string]int{}
	for _, v := range values {
		kind := names[v]
		count[kind]++
		m.names[v] = fmt.Sprintf("%s-%d", kind, count[kind])
	}
	// Longest first, so "Home WiFi 5G" goes before "Home WiFi".
	sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		m.nameRes = append(m.nameRes, regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_-])`+regexp.QuoteMeta(v)+`($|[^A-Za-z0-9_-])`))
		m.namePlaceholders = append(m.namePlaceholders, m.names[v])
	}
	return m
}

// canonIPv4 reads a dotted quad the way a person would, leading zeros included: 192.168.001.010
// is the same address as 192.168.1.10, and masking only the canonical spelling would leak it.
func canonIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var o [4]byte
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return netip.Addr{}, false
		}
		o[i] = byte(n)
	}
	return netip.AddrFrom4(o), true
}

func placeholder(seen map[string]string, key, kind string) string {
	if p, ok := seen[key]; ok {
		return p
	}
	p := fmt.Sprintf("%s-%d", kind, len(seen)+1)
	seen[key] = p
	return p
}

// Mask replaces every MAC, IPv4 and IPv6 address (except loopback and the unspecified address,
// which say nothing about a network) and every known name in s.
func (m *masker) Mask(s string) string {
	s = reDiagMAC.ReplaceAllStringFunc(s, func(x string) string {
		return placeholder(m.macs, strings.ToLower(strings.ReplaceAll(x, "-", ":")), "mac")
	})
	s = reDiagIPv4.ReplaceAllStringFunc(s, func(x string) string {
		a, ok := canonIPv4(x)
		if !ok || a.IsLoopback() || a.IsUnspecified() {
			return x
		}
		return placeholder(m.ips, a.String(), "ip")
	})
	s = reDiagIPv6.ReplaceAllStringFunc(s, func(x string) string {
		if strings.Count(x, ":") < 2 {
			return x
		}
		ip := net.ParseIP(strings.SplitN(x, "%", 2)[0])
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
			return x
		}
		return placeholder(m.ips, ip.String(), "ip")
	})
	for i, re := range m.nameRes {
		// Two passes: a match consumes the character after it, which may start the next match.
		for pass := 0; pass < 2; pass++ {
			s = re.ReplaceAllString(s, "${1}"+m.namePlaceholders[i]+"${2}")
		}
	}
	return s
}

// Client keeps the name of a known program (claude-code, cursor, ...) and hides any other, which
// may be a host name or a person's.
func (m *masker) Client(name string) string {
	if contains(genericClients, name) {
		return name
	}
	return placeholder(m.clients, name, "client")
}

var reUCIValue = regexp.MustCompile(`^([A-Za-z0-9_@\[\].-]+)\.([A-Za-z0-9_]+)='(.*)'$`)

// harvestNames reads the names that identify this network from UCI and the lease file: the host
// name, static and leased DHCP names, the domain, SSIDs and WireGuard peer names. Only these
// options are kept; the rest of the output (keys among it) is read and dropped.
func harvestNames(ctx context.Context) map[string]string {
	names := map[string]string{}
	add := func(v, kind string) {
		if v = strings.TrimSpace(v); v != "" && v != "*" && names[v] == "" {
			names[v] = kind
		}
	}
	options := map[string]map[string]string{ // config -> option -> kind
		"system":   {"hostname": "host"},
		"dhcp":     {"name": "host", "domain": "domain", "hostname": "host"},
		"wireless": {"ssid": "ssid"},
		"network":  {"description": "peer", "hostname": "host"},
	}
	for cfg, opts := range options {
		out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "show", cfg)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if m := reUCIValue.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				if kind, ok := opts[m[2]]; ok {
					add(m[3], kind)
				}
			}
		}
	}
	if b, err := readSys("/tmp/dhcp.leases"); err == nil {
		for _, line := range strings.Split(b, "\n") {
			if f := strings.Fields(line); len(f) >= 4 {
				add(f[3], "host") // expiry mac ip name clientid
			}
		}
	}
	return names
}

// runDiag writes the bundle for the daemon whose config is at configPath.
func runDiag(w io.Writer, configPath string, nAudit int, detail bool) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	ctx := context.Background()
	m := newMasker(harvestNames(ctx))

	// The heading is ours and is not masked: a router with a host name of two letters must not
	// turn the words of the heading into placeholders.
	fmt.Fprintln(w, "openwrt-mcp diagnostic bundle")
	fmt.Fprintln(w, "Addresses, MACs and names are replaced by placeholders (ip-1, mac-1, host-1, ssid-1, ...); the same value")
	fmt.Fprintln(w, "always gets the same one. Audit arguments are never printed.")
	fmt.Fprintln(w)

	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	p("version    %s (%s %s/%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	p("board      %s", boardLine(ctx))
	state := "stopped"
	if daemonRunning(cfg.Listen) {
		state = "running"
	}
	sock := "disabled"
	if cfg.Socket != "" {
		sock = "enabled"
	}
	p("daemon     %s on %s; stdio bridge socket %s", state, orDefault(cfg.Listen, defaultListen), sock)
	p("tools      %d registered", len(allToolNames))
	p("settings   output masking %s, history keeps %d, audit log up to %d MB", onOff(cfg.RedactOutput), cfg.HistoryKeep, cfg.AuditMaxMB)

	expired := 0
	for _, pol := range cfg.Policies {
		if !pol.Expires.IsZero() && pol.Expires.Before(time.Now()) {
			expired++
		}
	}
	p("")
	p("policies   %d (%d expired)", len(cfg.Policies), expired)
	for _, pol := range cfg.Policies {
		exp := "never"
		if !pol.Expires.IsZero() {
			exp = pol.Expires.Format("2006-01-02")
			if pol.Expires.Before(time.Now()) {
				exp += " (expired)"
			}
		}
		line := fmt.Sprintf("  %s: %s on %s, %d/min, expires %s", m.Client(pol.Client),
			strings.Join(pol.Tools, ","), strings.Join(pol.Scopes, " "), pol.MaxPerMin, exp)
		if hit := pol.shellEquivalent(); len(hit) > 0 {
			line += "; shell-equivalent: " + describeShellEquivalent(hit)
		}
		p("%s", line)
	}

	rows := tailAudit(cfg.AuditPath, nAudit)
	p("")
	p("audit      last %d of the log", len(rows))
	for _, r := range rows {
		line := fmt.Sprintf("  %s %s %s %s", r.Time, m.Client(r.Client), r.Tool, r.Outcome)
		if detail {
			for _, x := range []string{r.Scope, r.Summary, r.Error} {
				if x != "" {
					line += " | " + x
				}
			}
		}
		p("%s", line)
	}
	_, err = io.WriteString(w, m.Mask(b.String()))
	return err
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// boardLine is the model and release from ubus, or why that is not available.
func boardLine(ctx context.Context) string {
	out, err := run(ctx, defaultCmdTimeout, "ubus", "call", "system", "board")
	if err != nil {
		return "(unavailable: " + firstLine(err.Error()) + ")"
	}
	var v struct {
		Model   string `json:"model"`
		Kernel  string `json:"kernel"`
		Release struct {
			Description string `json:"description"`
			Target      string `json:"target"`
		} `json:"release"`
	}
	if json.Unmarshal([]byte(out), &v) != nil {
		return "(unreadable ubus reply)"
	}
	return fmt.Sprintf("%s; %s (%s); kernel %s", v.Model, v.Release.Description, v.Release.Target, v.Kernel)
}
