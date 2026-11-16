package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// net_diag action=throughput and action=capture (ROADMAP 9.8). Both need a binary the router may
// not have, say so by name when it is missing, and have hard caps that no argument can raise.
// A raw capture never leaves this file: only the summary does.

const (
	maxThroughputSec = 5     // per direction: upload then download, so 10 s at most
	maxCaptureSec    = 10    //
	maxCapturePkts   = 2000  //
	captureSnaplen   = "128" // enough for headers and a DNS question, not for payloads
	maxFilterTokens  = 16
	maxFilterBytes   = 120
	maxTalkers       = 5
	maxDNSNames      = 10
)

var lookPath = exec.LookPath

func haveBinary(name string) bool { _, err := lookPath(name); return err == nil }

// ---------------------------------------------------------------- throughput

type iperfRun struct {
	Error string `json:"error"`
	End   struct {
		Sent struct {
			Bps     float64 `json:"bits_per_second"`
			Retrans int     `json:"retransmits"`
		} `json:"sum_sent"`
		Recv struct {
			Bps float64 `json:"bits_per_second"`
		} `json:"sum_received"`
	} `json:"end"`
}

func throughput(ctx context.Context, in netDiagIn) (string, string, error) {
	if !reNetTarget.MatchString(in.Target) {
		return "", "", invalid("throughput needs target = the host running `iperf3 -s`")
	}
	if !haveBinary("iperf3") {
		return "", "", notFound("iperf3 is not installed on the router (apk add iperf3)")
	}
	sec := clampInt(in.Count, 3, 1, maxThroughputSec)
	var b strings.Builder
	fmt.Fprintf(&b, "iperf3 to %s, %d s each way (this uses the link under test)\n", in.Target, sec)
	for _, dir := range []struct {
		label string
		rev   bool
	}{{"upload (router to server)", false}, {"download (server to router)", true}} {
		argv := []string{"iperf3", "-c", in.Target, "-t", strconv.Itoa(sec), "-J"}
		if in.IPv6 {
			argv = append(argv, "-6")
		} else {
			argv = append(argv, "-4")
		}
		if dir.rev {
			argv = append(argv, "-R")
		}
		out, err := run(ctx, time.Duration(sec+15)*time.Second, argv...)
		var r iperfRun
		if jerr := json.Unmarshal([]byte(out), &r); jerr != nil {
			if err == nil {
				err = fmt.Errorf("unexpected output")
			}
			fmt.Fprintf(&b, "%s: failed: %v\n", dir.label, err)
			continue
		}
		if r.Error != "" {
			fmt.Fprintf(&b, "%s: failed: %s\n", dir.label, clip(r.Error, 120))
			continue
		}
		if dir.rev {
			fmt.Fprintf(&b, "%s: %.1f Mbit/s\n", dir.label, r.End.Recv.Bps/1e6)
		} else {
			fmt.Fprintf(&b, "%s: %.1f Mbit/s, %s\n", dir.label, r.End.Sent.Bps/1e6, plural(r.End.Sent.Retrans, "retransmit"))
		}
	}
	return b.String(), "throughput " + in.Target, nil
}

// ---------------------------------------------------------------- capture

// BPF primitives a filter may use. No parentheses, no byte offsets (`tcp[13]`), no `-` options:
// a filter says which traffic, and cannot reach for anything else.
var bpfWords = map[string]bool{"host": true, "net": true, "port": true, "portrange": true, "src": true, "dst": true,
	"tcp": true, "udp": true, "icmp": true, "icmp6": true, "ip": true, "ip6": true, "arp": true,
	"and": true, "or": true, "not": true}

var reBPFValue = lazyRegexp(`^(?:\d{1,5}(?:-\d{1,5})?|[0-9A-Fa-f:.]{2,45}(?:/\d{1,3})?)$`)

// captureFilter checks a filter and returns it as the argv words tcpdump gets.
func captureFilter(f string) ([]string, error) {
	words := strings.Fields(f)
	if len(f) > maxFilterBytes || len(words) > maxFilterTokens {
		return nil, invalid("filter is limited to %d words and %d bytes", maxFilterTokens, maxFilterBytes)
	}
	for _, w := range words {
		lw := strings.ToLower(w)
		switch {
		case bpfWords[lw]:
		case reBPFValue.MatchString(w) && !bpfWords[lw]:
			if strings.Contains(w, "/") {
				if _, err := netip.ParsePrefix(w); err != nil {
					return nil, invalid("filter value %q is not a network", w)
				}
			} else if strings.ContainsAny(w, ".:") {
				if _, err := netip.ParseAddr(w); err != nil {
					return nil, invalid("filter value %q is not an address", w)
				}
			}
		default:
			return nil, invalid("filter word %q is not allowed; use host, net, port, portrange, src, dst, tcp, udp, icmp, icmp6, ip, ip6, arp, and, or, not and numbers or addresses", w)
		}
	}
	return words, nil
}

var (
	reCapStamp = lazyRegexp(`^\d+\.\d+ `)
	reCapLine  = lazyRegexp(`^(\d+\.\d+) (IP6?|ARP)\b(.*)$`)
	reCapPair  = lazyRegexp(`^ (\S+) > (\S+?):(.*)$`)
	reCapDNS   = lazyRegexp(`\b(?:A|AAAA|HTTPS|PTR|MX|TXT|SRV|CNAME)\? ([A-Za-z0-9._-]{1,253})\.? `)
)

// hostOfEndpoint drops the port: "192.168.1.5.443" and "2001:db8::1.443" both name a host.
func hostOfEndpoint(e string) string {
	i := strings.LastIndex(e, ".")
	if i <= 0 {
		return e
	}
	if strings.Contains(e, ":") || strings.Count(e, ".") == 4 {
		return e[:i]
	}
	return e
}

// endpointPort is the part after the last dot of "192.168.1.5.443" or "2001:db8::1.443".
func endpointPort(e string) string {
	if i := strings.LastIndex(e, "."); i > 0 {
		return e[i+1:]
	}
	return ""
}

func capture(ctx context.Context, in netDiagIn) (string, string, error) {
	if !reNetName.MatchString(in.Target) {
		return "", "", invalid("capture needs target = the interface to listen on, e.g. br-lan")
	}
	filter, err := captureFilter(in.Filter)
	if err != nil {
		return "", "", err
	}
	if !haveBinary("tcpdump") {
		return "", "", notFound("tcpdump is not installed on the router (apk add tcpdump)")
	}
	if _, order, derr := readNetDev(); derr == nil && !contains(order, in.Target) {
		return "", "", notFound("no interface %q in /proc/net/dev", in.Target)
	}
	sec := clampInt(in.Count, 5, 1, maxCaptureSec)
	argv := append([]string{"tcpdump", "-i", in.Target, "-nn", "-tt", "-l", "-p", "-s", captureSnaplen, "-c", strconv.Itoa(maxCapturePkts)}, filter...)
	// tcpdump ends at the packet cap or when the deadline kills it; the lines printed until then are the capture.
	out, err := run(ctx, time.Duration(sec)*time.Second, argv...)
	if err != nil && !isTimeout(err) {
		return "", "", fmt.Errorf("tcpdump: %w: %s", err, clip(strings.TrimSpace(out), 200))
	}
	return summariseCapture(out, in.Target, in.Filter, sec), "capture " + in.Target, nil
}

func isTimeout(err error) bool { return errCode(err) == codeTimeout }

func summariseCapture(out, iface, filter string, sec int) string {
	var n, resets, unread int
	var first, last float64
	proto := map[string]int{}
	bytesBy := map[string]int{}
	pktsBy := map[string]int{}
	names := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		m := reCapLine.FindStringSubmatch(line)
		if m == nil {
			if reCapStamp.MatchString(line) {
				unread++ // a frame tcpdump printed that is neither IP nor ARP: 802.11 from a monitor interface, for one
			}
			continue
		}
		ts, _ := strconv.ParseFloat(m[1], 64)
		if n == 0 {
			first = ts
		}
		last = ts
		n++
		rest := m[3]
		length := 0
		if i := strings.LastIndex(rest, "length "); i >= 0 {
			length, _ = strconv.Atoi(strings.Fields(rest[i+7:] + " ")[0])
		}
		pair := reCapPair.FindStringSubmatch(rest)
		switch {
		case m[2] == "ARP":
			proto["arp"]++
		case strings.Contains(rest, "Flags ["):
			proto["tcp"]++
			if f := rest[strings.Index(rest, "Flags [")+7:]; strings.HasPrefix(f, "R") {
				resets++
			}
		case pair != nil && (reCapDNS.MatchString(pair[3]) || endpointPort(pair[1]) == "53" || endpointPort(pair[2]) == "53"):
			proto["dns"]++ // a reply ("2/0/0 A 1.2.3.4") carries no question mark, so the port 53 end says it
		case strings.Contains(rest, "UDP"):
			proto["udp"]++
		case strings.Contains(rest, "ICMP"):
			proto["icmp"]++
		default:
			proto["other"]++
		}
		if p := pair; p != nil {
			src := hostOfEndpoint(p[1])
			bytesBy[src] += length
			pktsBy[src]++
			if d := reCapDNS.FindStringSubmatch(p[3]); d != nil {
				names[strings.TrimSuffix(strings.ToLower(d[1]), ".")]++
			}
		}
	}
	var b strings.Builder
	capped := ""
	if n >= maxCapturePkts {
		capped = " (stopped at the packet cap)"
	}
	f := ""
	if filter != "" {
		f = ", filter: " + filter
	}
	fmt.Fprintf(&b, "capture on %s, up to %d s%s: %s over %.1f s%s\n", iface, sec, f, plural(n, "packet"), last-first, capped)
	if n == 0 {
		if unread > 0 {
			fmt.Fprintf(&b, "no IP or ARP packets seen, but %s captured that this summary does not read (a monitor interface prints 802.11 frames; it reads IP, ARP and DNS only)\n", plural(unread, "frame"))
			return b.String()
		}
		b.WriteString("no packets seen\n")
		return b.String()
	}
	b.WriteString("protocols: " + countList(proto, 8) + "\n")
	fmt.Fprintf(&b, "tcp resets: %d\n", resets)
	type tk struct {
		host     string
		bytes, p int
	}
	var tks []tk
	for h, by := range bytesBy {
		tks = append(tks, tk{h, by, pktsBy[h]})
	}
	sort.Slice(tks, func(i, j int) bool {
		if tks[i].bytes != tks[j].bytes {
			return tks[i].bytes > tks[j].bytes
		}
		return tks[i].host < tks[j].host
	})
	b.WriteString("top senders (payload bytes seen, headers only captured):\n")
	for i, t := range tks {
		if i == maxTalkers {
			break
		}
		fmt.Fprintf(&b, "  %s: %d bytes, %s\n", t.host, t.bytes, plural(t.p, "packet"))
	}
	if unread > 0 {
		fmt.Fprintf(&b, "%s not summarised (neither IP nor ARP)\n", plural(unread, "other frame"))
	}
	if len(names) > 0 {
		b.WriteString("DNS names asked: " + clip(countList(names, maxDNSNames), 400) + "\n")
	}
	return b.String()
}

// countList is "a 12, b 3": the most frequent first, ties by name.
func countList(m map[string]int, limit int) string {
	type kv struct {
		k string
		v int
	}
	var l []kv
	for k, v := range m {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].v != l[j].v {
			return l[i].v > l[j].v
		}
		return l[i].k < l[j].k
	})
	var parts []string
	for i, e := range l {
		if i == limit {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(l)-limit))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------- bufferbloat (ROADMAP 7.7)

const (
	maxBloatSec = 10 // per direction; the router's link is saturated for twice this at most
	bloatOmit   = 1  // seconds iperf3 ramps up before the pings that count
)

// bloatRamp is how long iperf3 runs before the pings that count (a var so a test need not wait for it).
var bloatRamp = time.Duration(bloatOmit) * time.Second

var reRTT = lazyRegexp(`min/avg/max(?:/mdev)? = ([0-9.]+)/([0-9.]+)/([0-9.]+)`)
var reLoss = lazyRegexp(`([0-9.]+)% packet loss`)

// pingStats is the summary line of BusyBox ping or iputils ping.
type pingStats struct {
	avg, max float64
	loss     string
	ok       bool
}

func parsePing(out string) pingStats {
	var s pingStats
	if m := reRTT.FindStringSubmatch(out); m != nil {
		s.avg, _ = strconv.ParseFloat(m[2], 64)
		s.max, _ = strconv.ParseFloat(m[3], 64)
		s.ok = true
	}
	if m := reLoss.FindStringSubmatch(out); m != nil {
		s.loss = m[1] + "%"
	}
	return s
}

// bloatGrade is the added latency under load, graded the way the usual bufferbloat web tests do.
func bloatGrade(addedMs float64) string {
	switch {
	case addedMs < 5:
		return "A+"
	case addedMs < 30:
		return "A"
	case addedMs < 60:
		return "B"
	case addedMs < 200:
		return "C"
	case addedMs < 400:
		return "D"
	}
	return "F"
}

// bufferbloat measures how much latency the router's own uplink adds when it is full: ping the iperf3 server idle,
// then ping it again while iperf3 saturates the link upload and then download. The extra delay is queueing in the
// bottleneck's buffer, which SQM (cake) removes. It is bounded like throughput and says so: it uses the link under test.
func bufferbloat(ctx context.Context, in netDiagIn) (string, string, error) {
	if !reNetTarget.MatchString(in.Target) {
		return "", "", invalid("bufferbloat needs target = the host running `iperf3 -s`, reached over the link to test")
	}
	if !haveBinary("iperf3") {
		return "", "", notFound("iperf3 is not installed on the router (apk add iperf3)")
	}
	sec := clampInt(in.Count, 5, 3, maxBloatSec)
	pingArgv := func(n int) []string {
		a := []string{"ping", "-c", strconv.Itoa(n), "-W", "2"}
		if in.IPv6 || strings.Contains(in.Target, ":") {
			a = append(a, "-6")
		}
		return append(a, in.Target)
	}
	idleOut, _ := run(ctx, 20*time.Second, pingArgv(4)...)
	idle := parsePing(idleOut)
	if !idle.ok {
		return "", "", fmt.Errorf("%s does not answer ping, so latency cannot be measured: %s", in.Target, clip(strings.TrimSpace(idleOut), 160))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "bufferbloat to %s: ping alone, then ping while iperf3 fills the link for %d s each way (this uses the link under test)\n", in.Target, sec)
	fmt.Fprintf(&b, "idle: %.1f ms avg\n", idle.avg)
	worst := 0.0
	for _, dir := range []struct {
		label string
		rev   bool
	}{{"upload (router to server)", false}, {"download (server to router)", true}} {
		argv := []string{"iperf3", "-c", in.Target, "-t", strconv.Itoa(sec + bloatOmit), "-O", strconv.Itoa(bloatOmit), "-J"}
		if in.IPv6 {
			argv = append(argv, "-6")
		} else {
			argv = append(argv, "-4")
		}
		if dir.rev {
			argv = append(argv, "-R")
		}
		type result struct {
			out string
			err error
		}
		done := make(chan result, 1)
		go func() {
			out, err := run(ctx, time.Duration(sec+bloatOmit+15)*time.Second, argv...)
			done <- result{out, err}
		}()
		select { // let the transfer ramp up before the pings that count
		case <-time.After(bloatRamp):
		case <-ctx.Done():
		}
		loadedOut, _ := run(ctx, time.Duration(sec+10)*time.Second, pingArgv(sec)...)
		res := <-done
		loaded := parsePing(loadedOut)
		var r iperfRun
		bps := 0.0
		if jerr := json.Unmarshal([]byte(res.out), &r); jerr == nil && r.Error == "" {
			bps = r.End.Recv.Bps
			if !dir.rev {
				bps = r.End.Sent.Bps
			}
		} else if r.Error != "" {
			fmt.Fprintf(&b, "%s: iperf3 failed: %s\n", dir.label, clip(r.Error, 120))
			continue
		} else {
			fmt.Fprintf(&b, "%s: iperf3 failed: %v\n", dir.label, res.err)
			continue
		}
		if !loaded.ok {
			fmt.Fprintf(&b, "%s: %.1f Mbit/s, no ping answered while loaded (loss %s): the link was saturated past what ping survives\n", dir.label, bps/1e6, loaded.loss)
			worst = 1000
			continue
		}
		added := loaded.avg - idle.avg
		if added < 0 {
			added = 0
		}
		if added > worst {
			worst = added
		}
		fmt.Fprintf(&b, "%s: %.1f Mbit/s, ping %.1f ms avg (+%.1f), %.1f ms max, loss %s\n", dir.label, bps/1e6, loaded.avg, added, loaded.max, loaded.loss)
	}
	fmt.Fprintf(&b, "added latency under load: %.0f ms, grade %s", worst, bloatGrade(worst))
	if worst >= 30 {
		b.WriteString("\nthe link's queue fills under load: SQM (sqm-scripts with cake) on the WAN shaped a little under the measured rate removes it")
	}
	return b.String(), "bufferbloat " + in.Target, nil
}
