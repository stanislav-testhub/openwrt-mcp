package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- system_status

type systemStatusIn struct {
	Mode string `json:"mode,omitempty" jsonschema:"status (default) | doctor: ranked health findings | audit: ranked security findings"`
}

// systemStatusScope makes doctor and audit separately grantable: a grant for '*' (both presets) covers
// them, a grant for system_status alone does not teach a client the router's security posture.
func systemStatusScope(in systemStatusIn) []string {
	if in.Mode == "doctor" || in.Mode == "audit" {
		return []string{in.Mode}
	}
	return nil
}

type ubusBoard struct {
	Hostname  string `json:"hostname"`
	Model     string `json:"model"`
	BoardName string `json:"board_name"`
	Kernel    string `json:"kernel"`
	Release   struct {
		Description string `json:"description"`
		Target      string `json:"target"`
		Revision    string `json:"revision"`
	} `json:"release"`
}

type ubusSysInfo struct {
	LocalTime int64   `json:"localtime"`
	Uptime    int64   `json:"uptime"`
	Load      []int64 `json:"load"`
	Memory    struct {
		Total, Free, Available, Cached, Buffered int64
	} `json:"memory"`
	Root struct{ Total, Used, Avail int64 } `json:"root"`
	Tmp  struct{ Total, Used, Avail int64 } `json:"tmp"`
}

type ubusIface struct {
	Interface string `json:"interface"`
	Up        bool   `json:"up"`
	Proto     string `json:"proto"`
	Device    string `json:"l3_device"`
	Uptime    int64  `json:"uptime"`
	Metric    int    `json:"metric"`
	IPv4      []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv4-address"`
	IPv6 []struct {
		Address string `json:"address"`
		Mask    int    `json:"mask"`
	} `json:"ipv6-address"`
	Route []struct {
		Target  string `json:"target"`
		Mask    int    `json:"mask"`
		Nexthop string `json:"nexthop"`
	} `json:"route"`
	Errors []struct {
		Code string `json:"code"`
	} `json:"errors"`
}

func interfaceDump(ctx context.Context) ([]ubusIface, error) {
	var d struct {
		Interface []ubusIface `json:"interface"`
	}
	err := runJSON(ctx, &d, "ubus", "call", "network.interface", "dump")
	return d.Interface, err
}

// systemStatus is the one call that orients an agent: what the box is, how loaded it is,
// which interfaces and radios are up, and what is outstanding (uncommitted uci edits, a
// pending rollback, package configs waiting for review). Each section degrades to a note
// rather than failing the whole call.
func (s *Server) systemStatus(ctx context.Context, in systemStatusIn) (string, string, error) {
	switch in.Mode {
	case "", "status":
	case "doctor":
		return healthFindings(ctx).render(), "doctor", nil
	case "audit":
		return auditFindings(ctx).render(), "audit", nil
	default:
		return "", "", invalid("mode must be status, doctor or audit, not %q", in.Mode)
	}
	var b strings.Builder
	var board ubusBoard
	if err := runJSON(ctx, &board, "ubus", "call", "system", "board"); err == nil {
		fmt.Fprintf(&b, "%s (%s) -- %s, kernel %s, host %s\n", board.Model, board.BoardName,
			board.Release.Description, board.Kernel, board.Hostname)
	} else {
		fmt.Fprintf(&b, "board: %v\n", err)
	}
	var si ubusSysInfo
	if err := runJSON(ctx, &si, "ubus", "call", "system", "info"); err == nil {
		load := make([]string, len(si.Load))
		for i, l := range si.Load {
			load[i] = fmt.Sprintf("%.2f", float64(l)/65536)
		}
		fmt.Fprintf(&b, "uptime %s, load %s\n", (time.Duration(si.Uptime) * time.Second).String(), strings.Join(load, " "))
		fmt.Fprintf(&b, "memory %d/%d MiB available; overlay %d/%d MiB free; /tmp %d/%d MiB free\n",
			si.Memory.Available>>20, si.Memory.Total>>20, si.Root.Avail>>10, si.Root.Total>>10,
			si.Tmp.Avail>>10, si.Tmp.Total>>10)
	}
	if t := temperatures(); t != "" {
		b.WriteString("temperatures: " + t + "\n")
	}
	if c, err := readSys("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		m, _ := readSys("/proc/sys/net/netfilter/nf_conntrack_max")
		fmt.Fprintf(&b, "conntrack %s/%s\n", strings.TrimSpace(c), strings.TrimSpace(m))
	}

	if ifs, err := interfaceDump(ctx); err == nil {
		b.WriteString("\ninterfaces:\n")
		for _, i := range ifs {
			state := "DOWN"
			if i.Up {
				state = "up " + (time.Duration(i.Uptime) * time.Second).String()
			}
			var addrs []string
			for _, a := range i.IPv4 {
				addrs = append(addrs, fmt.Sprintf("%s/%d", a.Address, a.Mask))
			}
			for _, a := range i.IPv6 {
				addrs = append(addrs, fmt.Sprintf("%s/%d", a.Address, a.Mask))
			}
			gw := ""
			for _, r := range i.Route {
				if r.Mask == 0 && (r.Target == "0.0.0.0" || r.Target == "::") {
					gw = fmt.Sprintf(" default via %s metric %d", r.Nexthop, i.Metric)
				}
			}
			errs := ""
			for _, e := range i.Errors {
				errs += " ERROR:" + e.Code
			}
			fmt.Fprintf(&b, "  %-12s %-9s %-10s %s %s%s%s\n", i.Interface, i.Proto, i.Device, state,
				strings.Join(addrs, " "), gw, errs)
		}
	} else {
		fmt.Fprintf(&b, "interfaces: %v\n", err)
	}

	var wl map[string]struct {
		Up         bool `json:"up"`
		Disabled   bool `json:"disabled"`
		Interfaces []struct {
			Ifname string `json:"ifname"`
			Config struct {
				SSID    string `json:"ssid"`
				Mode    string `json:"mode"`
				Network []string
			} `json:"config"`
		} `json:"interfaces"`
	}
	if err := runJSON(ctx, &wl, "ubus", "call", "network.wireless", "status"); err == nil {
		b.WriteString("\nradios:\n")
		for _, r := range sortedKeys(wl) {
			st := wl[r]
			state := "up"
			if st.Disabled {
				state = "disabled"
			} else if !st.Up {
				state = "DOWN"
			}
			var ssids []string
			for _, i := range st.Interfaces {
				ssids = append(ssids, fmt.Sprintf("%s=%q(%s)", i.Ifname, i.Config.SSID, i.Config.Mode))
			}
			fmt.Fprintf(&b, "  %s %s %s\n", r, state, strings.Join(ssids, " "))
		}
	}

	b.WriteString("\noutstanding:\n")
	n := 0
	if out, err := uncommitted(ctx, ""); err == nil && out != "" {
		fmt.Fprintf(&b, "  uncommitted uci changes (not ours):\n    %s\n", strings.ReplaceAll(out, "\n", "\n    "))
		n++
	}
	if p := s.pendingSummary(); p != "" {
		fmt.Fprintf(&b, "  uci_apply awaiting confirmation: %s\n", p)
		n++
	}
	if files := findApkNew(); len(files) > 0 {
		fmt.Fprintf(&b, "  %d .apk-new config file(s) awaiting review (pkg_config_diff)\n", len(files))
		n++
	}
	if n == 0 {
		b.WriteString("  nothing\n")
	}
	return b.String(), "system status", nil
}

// temperatures reads hwmon sensors, which on OpenWrt name themselves (cpu_thermal,
// mt7915_phy0, ...), falling back to the thermal zones.
func temperatures() string {
	var out []string
	hw, _ := filepath.Glob(sysPath("/sys/class/hwmon/hwmon*"))
	sort.Strings(hw)
	for _, h := range hw {
		name, _ := os.ReadFile(filepath.Join(h, "name"))
		t, err := os.ReadFile(filepath.Join(h, "temp1_input"))
		if err != nil {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(string(t))); err == nil {
			out = append(out, fmt.Sprintf("%s %.1fC", strings.TrimSpace(string(name)), float64(v)/1000))
		}
	}
	if len(out) > 0 {
		return strings.Join(out, ", ")
	}
	zones, _ := filepath.Glob(sysPath("/sys/class/thermal/thermal_zone*"))
	for _, z := range zones {
		typ, _ := os.ReadFile(filepath.Join(z, "type"))
		t, err := os.ReadFile(filepath.Join(z, "temp"))
		if err != nil {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(string(t))); err == nil {
			out = append(out, fmt.Sprintf("%s %.1fC", strings.TrimSpace(string(typ)), float64(v)/1000))
		}
	}
	return strings.Join(out, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- services (rpcd "rc")

type rcEntry struct {
	Start   int  `json:"start"`
	Stop    int  `json:"stop"`
	Enabled bool `json:"enabled"`
	Running bool `json:"running"`
}

func rcList(ctx context.Context) (map[string]rcEntry, error) {
	var m map[string]rcEntry
	err := runJSON(ctx, &m, "ubus", "call", "rc", "list")
	return m, err
}

type serviceListIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"only services whose name contains this"`
}

func serviceList(ctx context.Context, in serviceListIn) (string, string, error) {
	m, err := rcList(ctx)
	if err != nil {
		return "", "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-24s %-9s %-8s %s\n", "SERVICE", "BOOT", "STATE", "START/STOP")
	for _, name := range sortedKeys(m) {
		if in.Filter != "" && !strings.Contains(name, in.Filter) {
			continue
		}
		e := m[name]
		boot, state := "disabled", "stopped"
		if e.Enabled {
			boot = "enabled"
		}
		if e.Running {
			state = "running"
		}
		fmt.Fprintf(&b, "%-24s %-9s %-8s %d/%d\n", name, boot, state, e.Start, e.Stop)
	}
	b.WriteString("\n(\"stopped\" is also what one-shot init scripts without a procd instance report)")
	return b.String(), "listed services", nil
}

type serviceControlIn struct {
	Name   string `json:"name" jsonschema:"init script name as listed by service_list, e.g. 'dnsmasq'"`
	Action string `json:"action" jsonschema:"start | stop | restart | reload | enable | disable"`
	Wait   int    `json:"wait,omitempty" jsonschema:"seconds to wait for the service state to settle after the action (default 10, max 60)"`
}

var serviceActions = map[string]bool{"start": true, "stop": true, "restart": true, "reload": true, "enable": true, "disable": true}

// lifelineServices carry the path this tool is reached through (dropbear: the SSH session;
// network: the LAN; rpcd: the rc object this tool itself calls; openwrt-mcp: us). Stopping or
// disabling one cannot be undone through the tool, so it is refused here whatever the policy
// says. Restarting them is allowed -- they come back.
var lifelineServices = map[string]bool{"dropbear": true, "network": true, "rpcd": true, "openwrt-mcp": true}

// service_control reads the state back every servicePoll until serviceStableReads identical
// reads in a row (a service that comes up and dies again is not "running"), or the wait runs
// out. Variables so tests need not sleep for real.
var (
	servicePoll        = 500 * time.Millisecond
	serviceWaitUnit    = time.Second
	serviceStableReads = 3
)

func serviceControlScope(in serviceControlIn) []string { return []string{in.Name + "." + in.Action} }

var reServiceName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func serviceControl(ctx context.Context, in serviceControlIn) (string, string, error) {
	if !reServiceName.MatchString(in.Name) || !serviceActions[in.Action] {
		return "", "", invalid("need a service name and one of start|stop|restart|reload|enable|disable")
	}
	if lifelineServices[in.Name] && (in.Action == "stop" || in.Action == "disable") {
		return "", "", invalid("refusing to %s %s: it carries the connection this tool is reached "+
			"through, and nothing could undo it remotely. Do it from a console if you really mean it", in.Action, in.Name)
	}
	before, err := rcList(ctx)
	if err != nil {
		return "", "", err
	}
	if _, ok := before[in.Name]; !ok {
		return "", "", fmt.Errorf("no init script %q (see service_list)", in.Name)
	}
	args := fmt.Sprintf(`{"name":%q,"action":%q}`, in.Name, in.Action)
	out, err := run(ctx, 2*time.Minute, "ubus", "call", "rc", "init", args)
	if err != nil {
		return out, "", fmt.Errorf("%s %s: %w", in.Action, in.Name, err)
	}
	// rc init returns before a procd service has settled.
	wait := time.Duration(clampInt(in.Wait, 10, 1, 60)) * serviceWaitUnit
	e, took, settled := awaitService(ctx, in.Name, wait)
	if !settled {
		return fmt.Sprintf("%s %s: done, but the state did not settle within %s (last read enabled=%v running=%v; "+
				"it kept changing, which looks like a crash loop). Check logread.", in.Action, in.Name, wait, e.Enabled, e.Running),
			in.Action + " " + in.Name, nil
	}
	msg := fmt.Sprintf("%s %s: done. Now enabled=%v running=%v. Settled after %s.",
		in.Action, in.Name, e.Enabled, e.Running, took.Round(100*time.Millisecond))
	if why := contradiction(in.Action, e); why != "" {
		msg += " Note: " + why + " -- check logread."
	}
	return msg, in.Action + " " + in.Name, nil
}

// awaitService polls rc list until the service's state has been the same for serviceStableReads
// reads in a row. settled is false if wait ran out first (or ctx ended); e is the last state read.
func awaitService(ctx context.Context, name string, wait time.Duration) (e rcEntry, took time.Duration, settled bool) {
	start := time.Now()
	same := 0
	for first := true; ; first = false {
		if m, err := rcList(ctx); err == nil {
			cur := m[name]
			if !first && cur == e {
				same++
			} else {
				same = 1
			}
			e = cur
		} else {
			same = 0
		}
		if same >= serviceStableReads {
			return e, time.Since(start), true
		}
		if time.Since(start) >= wait || ctx.Err() != nil {
			return e, time.Since(start), false
		}
		time.Sleep(servicePoll)
	}
}

// contradiction names what the final state should have been when it is not.
func contradiction(action string, e rcEntry) string {
	switch {
	case (action == "start" || action == "restart" || action == "reload") && !e.Running:
		return "expected running=true (a one-shot init script without a procd instance always reports stopped)"
	case action == "stop" && e.Running:
		return "expected running=false"
	case action == "enable" && !e.Enabled:
		return "expected enabled=true"
	case action == "disable" && e.Enabled:
		return "expected enabled=false"
	}
	return ""
}

// ---------------------------------------------------------------- logread

type logreadIn struct {
	Lines    int    `json:"lines,omitempty" jsonschema:"how many of the most recent MATCHING lines to return (default 100, max 2000)"`
	Pattern  string `json:"pattern,omitempty" jsonschema:"only lines containing this substring (case-insensitive)"`
	Regex    string `json:"regex,omitempty" jsonschema:"only lines matching this RE2 regular expression"`
	Since    int    `json:"since_minutes,omitempty" jsonschema:"only lines from the last N minutes"`
	Offset   int    `json:"offset,omitempty" jsonschema:"skip the newest N matching lines, to page back; a cut result names the next offset"`
	Mode     string `json:"mode,omitempty" jsonschema:"lines (default) | summary: distinct messages with counts, times, worst severity"`
	Baseline string `json:"baseline,omitempty" jsonschema:"save: return a token for the messages in the log now. <token>: only messages not in it"`
}

// logread filters the whole ring buffer first and limits afterwards, so a rare message is
// not lost just because it scrolled past the last N lines of noise.
func (b *logBook) logread(ctx context.Context, in logreadIn) (string, string, error) {
	mode := in.Mode
	if mode == "" {
		mode = "lines"
	}
	if mode != "lines" && mode != "summary" {
		return "", "", invalid("mode must be lines or summary, not %q", in.Mode)
	}
	if in.Baseline != "" && in.Baseline != "save" && !reBaselineToken.MatchString(in.Baseline) {
		return "", "", invalid("baseline must be \"save\" or the 8-hex-digit token it returned")
	}
	n := clampInt(in.Lines, 100, 1, 2000)
	var re *regexp.Regexp
	if in.Regex != "" {
		var err error
		if re, err = regexp.Compile(in.Regex); err != nil {
			return "", "", invalid("bad regex: %w", err)
		}
	}
	out, err := run(ctx, defaultCmdTimeout, "logread")
	if err != nil {
		return out, "", err
	}
	var cutoff time.Time
	if in.Since > 0 {
		// logread stamps lines in router-local wall time, which Go cannot interpret without
		// zoneinfo (OpenWrt keeps a POSIX TZ string instead). Ask the router what time it
		// is in the same frame and compare wall clocks.
		if now, err := run(ctx, defaultCmdTimeout, "date", "+%Y-%m-%d %H:%M:%S"); err == nil {
			if t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(now)); err == nil {
				cutoff = t.Add(-time.Duration(in.Since) * time.Minute)
			}
		}
	}
	pat := strings.ToLower(in.Pattern)
	var keep []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if pat != "" && !strings.Contains(strings.ToLower(line), pat) {
			continue
		}
		if re != nil && !re.MatchString(line) {
			continue
		}
		if !cutoff.IsZero() && len(line) >= 24 {
			if t, err := time.Parse("Mon Jan _2 15:04:05 2006", line[:24]); err == nil && t.Before(cutoff) {
				continue
			}
		}
		keep = append(keep, line)
	}
	if in.Baseline == "save" {
		return b.saveBaseline(keep)
	}
	header := ""
	if in.Baseline != "" {
		var err error
		if keep, header, err = b.onlyNew(in.Baseline, keep); err != nil {
			return "", "", err
		}
	}
	if mode == "summary" {
		return summariseLog(keep, header, n, in.Offset), fmt.Sprintf("summary of %d lines", len(keep)), nil
	}
	withHeader := func(res string) string {
		if header == "" {
			return res
		}
		return header + "\n" + res
	}
	total := len(keep)
	// Pages count back from the newest line, so offset skips the newest ones.
	skip := clampInt(in.Offset, 0, 0, total)
	if total > 0 && in.Offset >= total {
		return withHeader(fmt.Sprintf("(no matching log lines at offset %d; %d match in total)", in.Offset, total)), "no lines at offset", nil
	}
	keep = keep[:total-skip]
	older := 0
	if len(keep) > n {
		older = len(keep) - n
		keep = keep[len(keep)-n:]
	}
	res := strings.Join(keep, "\n")
	if older > 0 {
		res += "\n" + truncNotice(fmt.Sprintf("%d older matching lines omitted", older),
			fmt.Sprintf("call again with offset=%d", skip+n))
	}
	if total == 0 {
		res = "(no matching log lines)"
	}
	return withHeader(res), fmt.Sprintf("%d of %d matching lines", len(keep), total), nil
}

// ---------------------------------------------------------------- exec

type execIn struct {
	Argv    []string `json:"argv" jsonschema:"command and arguments, executed directly without a shell. argv[0] is the policy scope."`
	Timeout int      `json:"timeout,omitempty" jsonschema:"seconds before the command is killed (default 30, max 300)"`
}

func execScope(in execIn) []string {
	if len(in.Argv) == 0 {
		return nil
	}
	return []string{in.Argv[0]}
}

func execTool(ctx context.Context, in execIn) (string, string, error) {
	if len(in.Argv) == 0 {
		return "", "", invalid("argv must not be empty")
	}
	out, err := run(ctx, clampSec(in.Timeout, 30, 300), in.Argv...)
	return out, strings.Join(in.Argv, " "), err
}

// ---------------------------------------------------------------- net_diag

type netDiagIn struct {
	Action string `json:"action" jsonschema:"ping | traceroute | nslookup | route | rule | neigh | wifi_survey | traffic | usage"`
	Target string `json:"target,omitempty" jsonschema:"host name or IP for ping/traceroute/nslookup; radio device for wifi_survey; interface for traffic; period date for usage"`
	Iface  string `json:"iface,omitempty" jsonschema:"source interface/device for ping/traceroute, e.g. 'br-WAN' or 'wg0' -- useful with several uplinks"`
	Count  int    `json:"count,omitempty" jsonschema:"ping count (default 4, max 10); seconds to sample for traffic (default 3, max 10)"`
	Server string `json:"server,omitempty" jsonschema:"DNS server to ask for nslookup (default: the router's resolver)"`
	Table  string `json:"table,omitempty" jsonschema:"routing table for route: 'main' (default), 'all', or a number/name"`
	IPv6   bool   `json:"ipv6,omitempty" jsonschema:"route/rule/neigh: show the IPv6 side"`
}

// A target is passed as an argument, never through a shell, but it must still not start
// with '-': ping and traceroute would read it as an option.
var reNetTarget = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._:%-]{0,252}$`)
var reNetName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@-]{0,31}$`)

func netDiagScope(in netDiagIn) []string {
	if in.Target != "" {
		return []string{in.Action + "." + in.Target}
	}
	return []string{in.Action}
}

func netDiag(ctx context.Context, in netDiagIn) (string, string, error) {
	switch in.Action {
	case "wifi_survey":
		return wifiSurvey(ctx, in.Target)
	case "traffic":
		return trafficDiag(ctx, in)
	case "usage":
		return nlbwUsage(ctx, in.Target)
	}
	fam := "-4"
	if in.IPv6 {
		fam = "-6"
	}
	needTarget := func() error {
		if !reNetTarget.MatchString(in.Target) {
			return invalid("%s needs a valid target host or IP", in.Action)
		}
		if in.Iface != "" && !reNetName.MatchString(in.Iface) {
			return invalid("bad iface %q", in.Iface)
		}
		return nil
	}
	var argv []string
	timeout := defaultCmdTimeout
	switch in.Action {
	case "ping":
		if err := needTarget(); err != nil {
			return "", "", err
		}
		argv = []string{"ping", "-c", strconv.Itoa(clampInt(in.Count, 4, 1, 10)), "-W", "2"}
		if strings.Contains(in.Target, ":") {
			argv = append(argv, "-6")
		}
		if in.Iface != "" {
			argv = append(argv, "-I", in.Iface)
		}
		argv = append(argv, in.Target)
	case "traceroute":
		if err := needTarget(); err != nil {
			return "", "", err
		}
		argv = []string{"traceroute", "-n", "-q", "1", "-w", "2", "-m", "20"}
		if strings.Contains(in.Target, ":") {
			argv = append(argv, "-6")
		}
		if in.Iface != "" {
			argv = append(argv, "-i", in.Iface)
		}
		argv = append(argv, in.Target)
		timeout = 90 * time.Second
	case "nslookup":
		if err := needTarget(); err != nil {
			return "", "", err
		}
		argv = []string{"nslookup", in.Target}
		if in.Server != "" {
			if !reNetTarget.MatchString(in.Server) {
				return "", "", invalid("bad server %q", in.Server)
			}
			argv = append(argv, in.Server)
		}
	case "route":
		table := orDefault(in.Table, "main")
		if !reNetName.MatchString(table) {
			return "", "", invalid("bad table %q", table)
		}
		argv = []string{"ip", fam, "route", "show", "table", table}
	case "rule":
		argv = []string{"ip", fam, "rule", "show"}
	case "neigh":
		argv = []string{"ip", fam, "neigh", "show"}
	default:
		return "", "", invalid("unknown action %q: use ping, traceroute, nslookup, route, rule, neigh, wifi_survey, traffic or usage", in.Action)
	}
	out, err := run(ctx, timeout, argv...)
	// ping exits non-zero on packet loss; the output is the answer, not an error.
	if err != nil && (in.Action == "ping" || in.Action == "traceroute") && out != "" {
		return out, strings.Join(argv, " "), nil
	}
	return out, strings.Join(argv, " "), err
}

// ---------------------------------------------------------------- sysupgrade / owut

type sysupgradeIn struct {
	Action string `json:"action" jsonschema:"list | test | check | backup. list: files a sysupgrade keeps; test: validate an image already on the router (sysupgrade -T); check: ask owut whether a newer release/packages exist; backup: write a config backup archive to /tmp"`
	Image  string `json:"image,omitempty" jsonschema:"for test: path of the image under /tmp, e.g. /tmp/firmware.bin"`
}

func sysupgradeScope(in sysupgradeIn) []string { return []string{in.Action} }

// There is deliberately no "flash" action. A sysupgrade reboots the router, cannot be
// rolled back by this daemon, and on a bad image leaves recovery to a serial console or the
// bootloader's web UI. Validate here; flash by hand.
func sysupgradeTool(ctx context.Context, in sysupgradeIn) (string, string, error) {
	switch in.Action {
	case "list":
		out, err := run(ctx, defaultCmdTimeout, "sysupgrade", "-l")
		return out, "listed preserved files", err
	case "test":
		clean := filepath.ToSlash(filepath.Clean(in.Image))
		if !strings.HasPrefix(clean, "/tmp/") || strings.Contains(clean, "..") {
			return "", "", invalid("image must be a file under /tmp")
		}
		out, err := run(ctx, 2*time.Minute, "sysupgrade", "-T", clean)
		if err != nil {
			return out, "image test failed", fmt.Errorf("image FAILED validation: %w", err)
		}
		return "Image passed sysupgrade's checks (nothing was flashed).\n" + out, "image test ok", nil
	case "check":
		if _, err := os.Stat(sysPath("/usr/bin/owut")); err != nil {
			return "", "", fmt.Errorf("owut is not installed. It is the OpenWrt 24.10+ attended-upgrade client " +
				"(builds an image with your installed packages via the ASU server): pkg_change add owut")
		}
		out, err := run(ctx, 2*time.Minute, "owut", "check")
		return out, "owut check", err
	case "backup":
		host, _ := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "system.@system[0].hostname")
		name := fmt.Sprintf("/tmp/backup-%s-%s.tar.gz", orDefault(sanitize(strings.TrimSpace(host)), "openwrt"),
			time.Now().UTC().Format("20060102-150405"))
		file := sysPath(name)
		// The archive holds every secret on the router. Create it 0600 first, so no secret is ever
		// written into a file other users can read, whatever the umask or sysupgrade's own tar does.
		if err := writePrivate(file, nil); err != nil {
			return "", "", fmt.Errorf("creating %s: %w", name, err)
		}
		out, err := run(ctx, 2*time.Minute, "sysupgrade", "-k", "-b", name)
		if err != nil {
			os.Remove(file)
			return out, "", fmt.Errorf("backup failed: %w", err)
		}
		if err := chmodFile(file, privateMode); err != nil { // in case tar replaced the file
			os.Remove(file)
			return "", "", fmt.Errorf("securing %s: %w", name, err)
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", "", err
		}
		if len(b) == 0 {
			os.Remove(file)
			return "", "", fmt.Errorf("backup failed: sysupgrade wrote an empty archive")
		}
		old := removeOldBackups(filepath.Dir(file), filepath.Base(file))
		sum := sha256.Sum256(b)
		msg := fmt.Sprintf("Backup written: %s (%d bytes, mode 0600, sha256 %s).\nIt holds secrets (wifi keys, "+
			"WireGuard private keys) and lives in RAM: copy it off the router, then delete it.",
			name, len(b), hex.EncodeToString(sum[:]))
		if old > 0 {
			msg += fmt.Sprintf("\nRemoved %d older archive(s) this tool made in /tmp.", old)
		}
		return msg, "backup " + name, nil
	}
	return "", "", invalid("unknown action %q: use list, test, check or backup", in.Action)
}

// reBackupName is exactly what the backup action names its archives. Only files with such a
// name are ever removed, so nothing an operator put in /tmp is touched.
var reBackupName = regexp.MustCompile(`^backup-[A-Za-z0-9_-]+-\d{8}-\d{6}\.tar\.gz$`)

// removeOldBackups deletes the archives the backup action made earlier, except keep, and
// returns how many it removed. Each one holds every secret on the router, so one at a time is
// enough, and a pile of them in RAM is how a copy gets forgotten.
func removeOldBackups(dir, keep string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.Name() == keep || !reBackupName.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n
}

func sanitize(s string) string {
	return regexp.MustCompile(`[^A-Za-z0-9_-]`).ReplaceAllString(s, "")
}

// jsonCompact is used where a decoded structure is re-emitted for the agent.
func jsonCompact(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
