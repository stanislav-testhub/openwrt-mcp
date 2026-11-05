package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
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

var reBPFValue = regexp.MustCompile(`^(?:\d{1,5}(?:-\d{1,5})?|[0-9A-Fa-f:.]{2,45}(?:/\d{1,3})?)$`)

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
	reCapLine = regexp.MustCompile(`^(\d+\.\d+) (IP6?|ARP)\b(.*)$`)
	reCapPair = regexp.MustCompile(`^ (\S+) > (\S+?):(.*)$`)
	reCapDNS  = regexp.MustCompile(`\b(?:A|AAAA|HTTPS|PTR|MX|TXT|SRV|CNAME)\? ([A-Za-z0-9._-]{1,253})\.? `)
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
	var n, resets int
	var first, last float64
	proto := map[string]int{}
	bytesBy := map[string]int{}
	pktsBy := map[string]int{}
	names := map[string]int{}
	for _, line := range strings.Split(out, "\n") {
		m := reCapLine.FindStringSubmatch(line)
		if m == nil {
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
		case pair != nil && reCapDNS.MatchString(pair[3]):
			proto["dns"]++
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
