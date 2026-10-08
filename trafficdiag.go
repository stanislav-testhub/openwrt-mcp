package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// net_diag wifi_survey, traffic and usage (ROADMAP 4.4 and 4.5). All three only read: a survey is
// the driver's own counters, traffic is /proc/net/dev twice and the conntrack table, usage is
// nlbwmon's database. None of them sends a packet or moves a radio off its channel, which is why
// they live under net_diag's existing grants. An active scan and Wake-on-LAN do not, and are not
// here.

// ---------------------------------------------------------------- wifi_survey

type surveyChannel struct {
	MHz    int   `json:"mhz"`
	Noise  int   `json:"noise"`
	Active int64 `json:"active_time"` // ms the radio spent on this channel
	Busy   int64 `json:"busy_time"`
	Rx     int64 `json:"rx_time"`
	Tx     int64 `json:"tx_time"`
}

// minObserved is how long the radio must have been on a channel before its figures mean
// anything. Every other channel holds the milliseconds of a scan at boot.
const minObservedMs = 10000

func radioOf(dev string) string {
	if i := strings.IndexByte(dev, '-'); i > 0 {
		return dev[:i]
	}
	return dev
}

func bandOf(mhz int) string {
	switch {
	case mhz < 3000:
		return "2.4 GHz"
	case mhz < 5925:
		return "5 GHz"
	}
	return "6 GHz"
}

func channelOf(mhz int) int {
	switch {
	case mhz == 2484:
		return 14
	case mhz < 3000:
		return (mhz - 2407) / 5
	case mhz < 5925:
		return (mhz - 5000) / 5
	}
	return (mhz - 5950) / 5
}

// noiseDBm turns the survey's noise byte, a signed dBm value read as unsigned, back into dBm.
func noiseDBm(n int) string {
	switch {
	case n == 0:
		return "n/a"
	case n > 127:
		return fmt.Sprintf("%d dBm", n-256)
	}
	return fmt.Sprintf("%d dBm", n)
}

func observedFor(ms int64) string {
	switch {
	case ms >= 3600_000:
		return fmt.Sprintf("%.1f h", float64(ms)/3600_000)
	case ms >= 60_000:
		return fmt.Sprintf("%.1f min", float64(ms)/60_000)
	}
	return fmt.Sprintf("%d s", ms/1000)
}

func pct(part, whole int64) float64 { return float64(part) * 100 / float64(whole) }

// wifiSurvey reports, for each radio, how busy the channel it stays on has been. One survey per
// radio: a second SSID on the same phy reports the same driver counters.
func wifiSurvey(ctx context.Context, target string) (string, string, error) {
	var devs []string
	if target != "" {
		if !reNetName.MatchString(target) {
			return "", "", invalid("bad device %q", target)
		}
		devs = []string{target}
	} else {
		var d struct {
			Devices []string `json:"devices"`
		}
		if err := runJSON(ctx, &d, "ubus", "call", "iwinfo", "devices"); err != nil {
			return "", "", err
		}
		seen := map[string]bool{}
		for _, dev := range d.Devices {
			if r := radioOf(dev); !seen[r] {
				seen[r] = true
				devs = append(devs, dev)
			}
		}
	}
	var b strings.Builder
	for _, dev := range devs {
		radio := radioOf(dev)
		arg := fmt.Sprintf(`{"device":%q}`, dev)
		var sv struct {
			Results []surveyChannel `json:"results"`
		}
		if err := runJSON(ctx, &sv, "ubus", "call", "iwinfo", "survey", arg); err != nil {
			fmt.Fprintf(&b, "%s (via %s): survey unavailable (%s)\n", radio, dev, trunc(strings.SplitN(err.Error(), "\n", 2)[0], 100))
			continue
		}
		var info struct {
			Frequency int `json:"frequency"`
		}
		_ = runJSON(ctx, &info, "ubus", "call", "iwinfo", "info", arg)

		var seen []surveyChannel
		for _, c := range sv.Results {
			if c.Active >= minObservedMs {
				seen = append(seen, c)
			}
		}
		sort.Slice(seen, func(i, j int) bool { return seen[i].MHz < seen[j].MHz })
		if len(seen) == 0 {
			fmt.Fprintf(&b, "%s (via %s): no channel observed for 10 s or more yet\n", radio, dev)
			continue
		}
		fmt.Fprintf(&b, "%s (via %s): %s\n", radio, dev, bandOf(seen[0].MHz))
		for _, c := range seen {
			cur := ""
			if c.MHz == info.Frequency {
				cur = " current"
			}
			fmt.Fprintf(&b, "  ch %d (%d MHz)%s: busy %.1f%%  rx %.1f%%  tx %.1f%%  noise %s  observed %s\n",
				channelOf(c.MHz), c.MHz, cur, pct(c.Busy, c.Active), pct(c.Rx, c.Active), pct(c.Tx, c.Active),
				noiseDBm(c.Noise), observedFor(c.Active))
		}
		b.WriteString("  other channels: not measured (a radio only measures the channel it is on)\n")
	}
	return strings.TrimRight(b.String(), "\n"), "wifi survey", nil
}

// ---------------------------------------------------------------- traffic

var trafficNow = time.Now

var trafficSleep = func(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

type ifaceCounters struct{ rxB, rxP, txB, txP int64 }

// readNetDev parses /proc/net/dev: "name: rxbytes rxpackets ... (8 receive fields) txbytes
// txpackets ...".
func readNetDev() (map[string]ifaceCounters, []string, error) {
	text, err := readSys("/proc/net/dev")
	if err != nil {
		return nil, nil, err
	}
	m := map[string]ifaceCounters{}
	var order []string
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 10 {
			continue
		}
		n := func(i int) int64 { v, _ := strconv.ParseInt(f[i], 10, 64); return v }
		name = strings.TrimSpace(name)
		m[name] = ifaceCounters{rxB: n(0), rxP: n(1), txB: n(8), txP: n(9)}
		order = append(order, name)
	}
	return m, order, nil
}

func delta(after, before int64) int64 {
	if after < before { // the counter was reset: no rate can be told
		return 0
	}
	return after - before
}

const (
	trafficIfaceRows = 10
	trafficTalkers   = 5
	conntrackMaxRead = 16 << 20
)

// leaseNames maps address and MAC to the host name in dnsmasq's lease file.
func leaseNames() (byIP, byMAC map[string]string) {
	byIP, byMAC = map[string]string{}, map[string]string{}
	text, err := readSys("/tmp/dhcp.leases")
	if err != nil {
		return
	}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[3] != "*" {
			byIP[f[2]] = f[3]
			byMAC[strings.ToLower(f[1])] = f[3]
		}
	}
	return
}

func trafficDiag(ctx context.Context, in netDiagIn) (string, string, error) {
	if in.Target != "" && !reNetName.MatchString(in.Target) {
		return "", "", invalid("bad interface %q", in.Target)
	}
	window := clampSec(in.Count, 3, 10)
	t0 := trafficNow()
	before, _, err := readNetDev()
	if err != nil {
		return "", "", fmt.Errorf("cannot read /proc/net/dev: %w", err)
	}
	trafficSleep(ctx, window)
	dt := trafficNow().Sub(t0).Seconds()
	if dt <= 0 {
		dt = window.Seconds()
	}
	after, order, err := readNetDev()
	if err != nil {
		return "", "", fmt.Errorf("cannot read /proc/net/dev: %w", err)
	}
	if in.Target != "" {
		if _, ok := after[in.Target]; !ok {
			return "", "", notFound("no interface %q in /proc/net/dev", in.Target)
		}
	}

	type row struct {
		name               string
		rxB, txB, rxP, txP float64
		total              int64
	}
	var rows []row
	for _, name := range order {
		if in.Target != "" && name != in.Target || in.Target == "" && name == "lo" {
			continue
		}
		a, b := after[name], before[name]
		d := ifaceCounters{delta(a.rxB, b.rxB), delta(a.rxP, b.rxP), delta(a.txB, b.txB), delta(a.txP, b.txP)}
		if in.Target == "" && d.rxB+d.txB == 0 {
			continue
		}
		rows = append(rows, row{name, float64(d.rxB) / dt, float64(d.txB) / dt, float64(d.rxP) / dt, float64(d.txP) / dt, d.rxB + d.txB})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].total > rows[j].total })
	if len(rows) > trafficIfaceRows {
		rows = rows[:trafficIfaceRows]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "traffic over %d s (this router's own interfaces: a client's traffic shows on its LAN port and on the uplink)\n", int(window.Seconds()))
	if len(rows) == 0 {
		b.WriteString("no traffic on any interface in that window\n")
	} else {
		fmt.Fprintf(&b, "%-12s %9s %9s %9s %9s\n", "IFACE", "RX/s", "TX/s", "RX pkt/s", "TX pkt/s")
		for _, r := range rows {
			fmt.Fprintf(&b, "%-12s %9s %9s %9d %9d\n", trunc(r.name, 12), humanBytes(int64(r.rxB))+"/s", humanBytes(int64(r.txB))+"/s", int64(r.rxP), int64(r.txP))
		}
	}
	b.WriteString("\n")
	b.WriteString(topTalkers())
	return strings.TrimRight(b.String(), "\n"), "traffic sample", nil
}

type talker struct {
	ip           string
	conns, bytes int64
}

// topTalkers ranks the sources in the conntrack table: by bytes when the kernel counts them,
// otherwise by number of connections. The source is the one of the original direction, so for a
// connection through NAT it is the LAN client.
func topTalkers() string {
	f, err := os.Open(sysPath("/proc/net/nf_conntrack"))
	if err != nil {
		return "top talkers: conntrack table unavailable (" + trunc(err.Error(), 80) + ")"
	}
	defer f.Close()
	raw, _ := io.ReadAll(io.LimitReader(f, conntrackMaxRead))
	acct, haveSysctl := false, false
	if v, err := readSys("/proc/sys/net/netfilter/nf_conntrack_acct"); err == nil {
		haveSysctl, acct = true, strings.TrimSpace(v) == "1"
	}
	by := map[string]*talker{}
	sawBytes := false
	for _, line := range strings.Split(string(raw), "\n") {
		src := ""
		var bytes int64
		for _, tok := range strings.Fields(line) {
			switch {
			case strings.HasPrefix(tok, "src=") && src == "":
				src = tok[4:]
			case strings.HasPrefix(tok, "bytes="):
				v, _ := strconv.ParseInt(tok[6:], 10, 64)
				bytes += v
				sawBytes = true
			}
		}
		if src == "" {
			continue
		}
		t := by[src]
		if t == nil {
			t = &talker{ip: src}
			by[src] = t
		}
		t.conns++
		t.bytes += bytes
	}
	if !haveSysctl {
		acct = sawBytes
	}
	list := make([]*talker, 0, len(by))
	for _, t := range by {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if acct && a.bytes != b.bytes {
			return a.bytes > b.bytes
		}
		if a.conns != b.conns {
			return a.conns > b.conns
		}
		return a.ip < b.ip
	})
	if len(list) > trafficTalkers {
		list = list[:trafficTalkers]
	}
	names, _ := leaseNames()
	var b strings.Builder
	b.WriteString("top talkers by source address in the conntrack table")
	if !acct {
		b.WriteString(" (byte counters are off: nf_conntrack_acct=0; ranked by connection count)")
	}
	b.WriteString(":\n")
	if len(list) == 0 {
		b.WriteString("  no connections\n")
	}
	for _, t := range list {
		label := t.ip
		if n := names[t.ip]; n != "" {
			label += " (" + trunc(n, 22) + ")"
		}
		fmt.Fprintf(&b, "  %-44s %4d conns", label, t.conns)
		if acct {
			b.WriteString("  " + humanBytes(t.bytes))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ---------------------------------------------------------------- usage (nlbwmon)

var reNlbwPeriod = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

const usageRows = 25

type usageRow struct {
	mac    string
	ips    []string
	conns  int64
	rx, tx int64
}

// nlbwUsage reads nlbwmon's totals per device. nlbwmon keeps accounting periods (a month by
// default), so this answers "this month", not "today".
func nlbwUsage(ctx context.Context, period string) (string, string, error) {
	if period != "" && !reNlbwPeriod.MatchString(period) {
		return "", "", invalid("a period is a date such as 2026-10-01, one of those listed under 'periods available'")
	}
	if _, err := os.Stat(sysPath("/usr/sbin/nlbw")); err != nil {
		return "", "", notFound("nlbwmon is not installed: install it with pkg_change action=add packages=nlbwmon, let it run for a while, then ask again")
	}
	argv := []string{"nlbw", "-c", "json", "-g", "mac,ip"}
	if period != "" {
		argv = append(argv, "-t", period)
	}
	out, err := run(ctx, 30*time.Second, argv...)
	if err != nil {
		return out, "", fmt.Errorf("nlbw: %w", err)
	}
	var doc struct {
		Columns []string            `json:"columns"`
		Data    [][]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return "", "", fmt.Errorf("unexpected nlbw output: %w", err)
	}
	col := map[string]int{}
	for i, c := range doc.Columns {
		col[c] = i
	}
	for _, need := range []string{"mac", "rx_bytes", "tx_bytes"} {
		if _, ok := col[need]; !ok {
			return "", "", fmt.Errorf("unexpected nlbw output: no %s column", need)
		}
	}
	num := func(raw json.RawMessage) int64 {
		var f float64
		_ = json.Unmarshal(raw, &f)
		return int64(f)
	}
	str := func(raw json.RawMessage) string {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	byMAC := map[string]*usageRow{}
	var macs []string
	for _, r := range doc.Data {
		if len(r) < len(doc.Columns) {
			continue
		}
		mac := strings.ToLower(str(r[col["mac"]]))
		u := byMAC[mac]
		if u == nil {
			u = &usageRow{mac: mac}
			byMAC[mac] = u
			macs = append(macs, mac)
		}
		u.rx += num(r[col["rx_bytes"]])
		u.tx += num(r[col["tx_bytes"]])
		if i, ok := col["conns"]; ok {
			u.conns += num(r[i])
		}
		if i, ok := col["ip"]; ok {
			if ip := str(r[i]); ip != "" && !contains(u.ips, ip) {
				u.ips = append(u.ips, ip)
			}
		}
	}
	rows := make([]*usageRow, 0, len(macs))
	for _, m := range macs {
		rows = append(rows, byMAC[m])
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].rx+rows[i].tx > rows[j].rx+rows[j].tx })

	_, byName := leaseNames()
	label := "current"
	if period != "" {
		label = period
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nlbwmon usage, accounting period %s (nlbwmon keeps a period per month by default, so this is not today's traffic): %d clients\n", label, len(rows))
	if len(rows) > 0 {
		fmt.Fprintf(&b, "%-22s %-17s %9s %9s %6s  %s\n", "HOST", "MAC", "RX", "TX", "CONNS", "ADDRESSES")
	}
	shown := rows
	if len(shown) > usageRows {
		shown = shown[:usageRows]
	}
	for _, u := range shown {
		fmt.Fprintf(&b, "%-22s %-17s %9s %9s %6d  %s\n", trunc(orDefault(byName[u.mac], "?"), 22), u.mac,
			humanBytes(u.rx), humanBytes(u.tx), u.conns, strings.Join(u.ips, " "))
	}
	if list, err := run(ctx, defaultCmdTimeout, "nlbw", "-c", "list"); err == nil {
		var ps []string
		for _, p := range strings.Fields(list) {
			if reNlbwPeriod.MatchString(p) {
				ps = append(ps, p)
			}
		}
		if len(ps) > 0 {
			fmt.Fprintf(&b, "periods available: %s\n", strings.Join(ps, " "))
		}
	}
	if len(rows) > usageRows {
		b.WriteString(truncNotice(fmt.Sprintf("%d more clients omitted", len(rows)-usageRows), fmt.Sprintf("only the largest %d are listed", usageRows)))
	}
	return strings.TrimRight(b.String(), "\n"), "nlbwmon usage", nil
}
