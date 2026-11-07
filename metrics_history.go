package main

import (
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Metrics history (ROADMAP 7.5): `system_status history=24h` summarises the RRD files collectd
// writes when luci-app-statistics is installed -- load, CPU, memory, temperature and the busiest
// interfaces -- as min/avg/max and a short trend, so "was it busy last night" has an answer. It
// reads with the `rrdtool fetch` command (luci-app-statistics depends on the rrdtool package, which
// ships it) and builds every path from names it listed in the data directory itself.

type historySpan struct {
	arg     string // rrdtool start offset
	label   string
	buckets int
	unit    string // what one trend bucket spans
}

var historySpans = map[string]historySpan{
	"1h":  {"-1h", "1 hour", 6, "10 min"},
	"6h":  {"-6h", "6 hours", 6, "1 h"},
	"24h": {"-24h", "24 hours", 8, "3 h"},
	"7d":  {"-7d", "7 days", 7, "1 day"},
}

const (
	defaultRRDDir      = "/tmp/rrd"
	maxHistoryIfaces   = 5
	maxHistoryThermals = 3
	maxHistoryCPUs     = 16
)

var (
	reRRDDir  = lazyRegexp(`^/[A-Za-z0-9._/-]{1,118}$`)
	reRRDName = lazyRegexp(`^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$`)
	reRRDRow  = lazyRegexp(`^(\d+):\s+(.*)$`)
)

type series struct {
	ts   []int64
	cols map[string][]float64 // data source name -> values, NaN where unknown
}

// rrdFetch runs `rrdtool fetch FILE AVERAGE -s <start>` and parses its table. The first line names
// the data sources; each later line is "timestamp: v1 v2 ..." and "nan"/"-nan" marks no data.
func rrdFetch(ctx context.Context, file string, sp historySpan) (*series, error) {
	out, err := run(ctx, defaultCmdTimeout*2, "rrdtool", "fetch", file, "AVERAGE", "-s", sp.arg)
	if err != nil {
		return nil, fmt.Errorf("rrdtool fetch %s: %w", file, err)
	}
	var names []string
	s := &series{cols: map[string][]float64{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if names == nil {
			if line != "" && !strings.Contains(line, ":") {
				names = strings.Fields(strings.TrimPrefix(line, "timestamp"))
			}
			continue
		}
		m := reRRDRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ts, _ := strconv.ParseInt(m[1], 10, 64)
		vals := strings.Fields(m[2])
		if len(vals) != len(names) {
			continue
		}
		s.ts = append(s.ts, ts)
		for i, v := range vals {
			f := math.NaN()
			if !strings.Contains(strings.ToLower(v), "nan") {
				if p, err := strconv.ParseFloat(v, 64); err == nil && !math.IsInf(p, 0) {
					f = p
				}
			}
			s.cols[names[i]] = append(s.cols[names[i]], f)
		}
	}
	if len(s.ts) == 0 {
		return nil, fmt.Errorf("rrdtool fetch %s: no rows in the output", file)
	}
	return s, nil
}

// metric is one line of the summary: a value per timestamp plus how to print it.
type metric struct {
	name string
	vals []float64
	ts   []int64
	fmt  func(float64) string
	sum  func(avg float64, seconds int64) string // optional: what the average adds up to over the window
}

func (m metric) line(sp historySpan) string {
	var last, max, total float64
	n := 0
	max = math.Inf(-1)
	first := int64(0)
	for i, v := range m.vals {
		if math.IsNaN(v) {
			continue
		}
		if first == 0 {
			first = m.ts[i]
		}
		last = v
		total += v
		n++
		max = math.Max(max, v)
	}
	if n == 0 {
		return m.name + ": no data in this window"
	}
	avg := total / float64(n)
	parts := []string{"now " + m.fmt(last), "avg " + m.fmt(avg), "max " + m.fmt(max)}
	if m.sum != nil {
		if s := m.sum(avg, int64(n)*stepOf(m.ts)); s != "" {
			parts = append(parts, s)
		}
	}
	return fmt.Sprintf("%s: %s; per %s: %s", m.name, strings.Join(parts, ", "), sp.unit, m.trend(sp))
}

func stepOf(ts []int64) int64 {
	if len(ts) < 2 {
		return 0
	}
	return (ts[len(ts)-1] - ts[0]) / int64(len(ts)-1)
}

// trend averages the samples into equal slices of the window, oldest first; "-" is a slice with no data.
func (m metric) trend(sp historySpan) string {
	out := make([]string, sp.buckets)
	for b := range out {
		lo, hi := b*len(m.vals)/sp.buckets, (b+1)*len(m.vals)/sp.buckets
		var sum float64
		n := 0
		for _, v := range m.vals[lo:hi] {
			if !math.IsNaN(v) {
				sum += v
				n++
			}
		}
		out[b] = "-"
		if n > 0 {
			out[b] = m.fmt(sum / float64(n))
		}
	}
	return strings.Join(out, " ")
}

func (m metric) coverage(sp historySpan) (first int64) {
	for i, v := range m.vals {
		if !math.IsNaN(v) {
			return m.ts[i]
		}
	}
	return 0
}

func fmtLoad(v float64) string   { return strconv.FormatFloat(v, 'f', 2, 64) }
func fmtPct(v float64) string    { return strconv.FormatFloat(v, 'f', 0, 64) + "%" }
func fmtTemp(v float64) string   { return strconv.FormatFloat(v, 'f', 0, 64) + "°C" }
func fmtRate(v float64) string   { return humanBytes(int64(v)) + "/s" }
func fmtBytesF(v float64) string { return humanBytes(int64(v)) }

func listRRD(dir string) []string {
	ents, err := os.ReadDir(sysPath(dir))
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range ents {
		if reRRDName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

func metricsHistory(ctx context.Context, key string) (string, error) {
	sp, ok := historySpans[key]
	if !ok {
		return "", invalid("history must be 1h, 6h, 24h or 7d, not %q", key)
	}
	dir := defaultRRDDir
	if t, err := uciShow(ctx, "luci_statistics", false); err == nil {
		if d := t.get("collectd_rrdtool", "DataDir"); reRRDDir.MatchString(d) && !strings.Contains(d, "..") {
			dir = strings.TrimRight(d, "/")
		}
	}
	hosts := listRRD(dir)
	if len(hosts) == 0 {
		return "", fmt.Errorf("no collectd data under %s: history needs luci-app-statistics with the rrdtool plugin enabled and collectd running (service_list detail=collectd)", dir)
	}
	host := hosts[0]
	base := dir + "/" + host
	var notes, lines []string
	if len(hosts) > 1 {
		notes = append(notes, fmt.Sprintf("%d host directories found, showing %s", len(hosts), host))
	}
	var all []metric
	add := func(ms ...metric) { all = append(all, ms...) }
	var fetchErr error
	fetch := func(rel string) *series {
		s, err := rrdFetch(ctx, base+"/"+rel, sp)
		if err != nil {
			fetchErr = err
		}
		return s
	}

	plugins := listRRD(base)
	has := func(prefix string) []string {
		var m []string
		for _, p := range plugins {
			if p == prefix || strings.HasPrefix(p, prefix+"-") {
				m = append(m, p)
			}
		}
		return m
	}

	if s := fetch("load/load.rrd"); s != nil && len(has("load")) > 0 {
		add(metric{"load (1 min)", s.cols["shortterm"], s.ts, fmtLoad, nil})
	}
	if cpus := has("cpu"); len(cpus) > 0 {
		if len(cpus) > maxHistoryCPUs {
			cpus = cpus[:maxHistoryCPUs]
		}
		var sum []float64
		var cnt []int
		var ts []int64
		used := 0
		for _, c := range cpus {
			s, err := rrdFetch(ctx, base+"/"+c+"/percent-idle.rrd", sp)
			if err != nil {
				continue
			}
			idle := s.cols["value"]
			if sum == nil {
				sum, cnt, ts = make([]float64, len(idle)), make([]int, len(idle)), s.ts
			}
			if len(idle) != len(sum) {
				continue
			}
			for i, v := range idle {
				if !math.IsNaN(v) {
					sum[i] += 100 - v
					cnt[i]++
				}
			}
			used++
		}
		busy := make([]float64, len(sum))
		for i := range busy {
			busy[i] = math.NaN()
			if cnt[i] > 0 {
				busy[i] = sum[i] / float64(cnt[i])
			}
		}
		if used > 0 {
			add(metric{"cpu busy (" + plural(used, "core") + ")", busy, ts, fmtPct, nil})
		}
	}
	if len(has("memory")) > 0 {
		parts := map[string][]float64{}
		var ts []int64
		for _, k := range []string{"used", "free", "buffered", "cached", "slab_recl", "slab_unrecl"} {
			if s, err := rrdFetch(ctx, base+"/memory/memory-"+k+".rrd", sp); err == nil {
				parts[k], ts = s.cols["value"], s.ts
			}
		}
		if len(parts["used"]) > 0 && len(parts["free"]) == len(parts["used"]) && len(parts["cached"]) == len(parts["used"]) && len(parts["buffered"]) == len(parts["used"]) {
			pct := make([]float64, len(ts))
			for i := range pct {
				total := 0.0
				for _, v := range parts {
					if len(v) == len(pct) {
						total += v[i] // NaN in any part makes the sample unknown
					}
				}
				pct[i] = parts["used"][i] / total * 100
			}
			add(metric{"memory used", pct, ts, fmtPct, nil})
		}
	}
	var thermals []string
	for _, p := range plugins {
		if strings.HasPrefix(p, "thermal-") {
			thermals = append(thermals, p)
		}
	}
	for i, p := range thermals {
		if i == maxHistoryThermals {
			notes = append(notes, fmt.Sprintf("%d more thermal sensors not shown", len(thermals)-maxHistoryThermals))
			break
		}
		for _, f := range listRRD(base + "/" + p) {
			if strings.HasPrefix(f, "temperature") && strings.HasSuffix(f, ".rrd") {
				if s := fetch(p + "/" + f); s != nil {
					add(metric{"temperature " + strings.TrimPrefix(p, "thermal-"), s.cols["value"], s.ts, fmtTemp, nil})
				}
				break
			}
		}
	}

	type traffic struct {
		iface   string
		rx, tx  metric
		carried float64
	}
	var ifs []traffic
	for _, p := range has("interface") {
		name := strings.TrimPrefix(p, "interface-")
		if name == "lo" || p == "interface" {
			continue
		}
		s, err := rrdFetch(ctx, base+"/"+p+"/if_octets.rrd", sp)
		if err != nil {
			continue
		}
		t := traffic{iface: name,
			rx: metric{name + " received", s.cols["rx"], s.ts, fmtRate, sumBytes},
			tx: metric{name + " sent", s.cols["tx"], s.ts, fmtRate, sumBytes}}
		for _, col := range [][]float64{s.cols["rx"], s.cols["tx"]} {
			for _, v := range col {
				if !math.IsNaN(v) {
					t.carried += v
				}
			}
		}
		ifs = append(ifs, t)
	}
	sort.SliceStable(ifs, func(i, j int) bool { return ifs[i].carried > ifs[j].carried })
	if len(ifs) > maxHistoryIfaces {
		notes = append(notes, fmt.Sprintf("%d quieter interfaces not shown", len(ifs)-maxHistoryIfaces))
		ifs = ifs[:maxHistoryIfaces]
	}
	for _, t := range ifs {
		add(t.rx, t.tx)
	}

	if len(all) == 0 {
		msg := "collectd has no load, CPU, memory, temperature or interface data in " + base
		if fetchErr != nil {
			msg += " (" + clip(fetchErr.Error(), 160) + ")"
		}
		return "", fmt.Errorf("%s", msg)
	}
	var oldest int64
	for _, m := range all {
		if f := m.coverage(sp); f != 0 && (oldest == 0 || f < oldest) {
			oldest = f
		}
	}
	for _, m := range all {
		lines = append(lines, m.line(sp))
	}
	head := fmt.Sprintf("history, last %s, from collectd on %s (one sample per %d s)", sp.label, host, stepOf(all[0].ts))
	if oldest != 0 {
		if span := all[0].ts[len(all[0].ts)-1] - oldest; span < parseSpanSeconds(key)*9/10 {
			notes = append(notes, fmt.Sprintf("data covers only the last %s: collectd started recently or the RRD files were lost (they live in RAM under /tmp)", humanSeconds(span)))
		}
	}
	out := head + "\n" + strings.Join(lines, "\n")
	if len(notes) > 0 {
		out += "\nnote: " + strings.Join(notes, "; ")
	}
	return out, nil
}

func sumBytes(avg float64, seconds int64) string {
	return "about " + humanBytes(int64(avg*float64(seconds))) + " in total"
}

func parseSpanSeconds(key string) int64 {
	n, _ := strconv.ParseInt(key[:len(key)-1], 10, 64)
	if strings.HasSuffix(key, "d") {
		return n * 86400
	}
	return n * 3600
}

func humanSeconds(s int64) string {
	switch {
	case s >= 3600:
		return fmt.Sprintf("%.1f hours", float64(s)/3600)
	case s >= 60:
		return fmt.Sprintf("%d minutes", s/60)
	}
	return fmt.Sprintf("%d seconds", s)
}
