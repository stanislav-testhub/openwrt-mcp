package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func withBinaries(t *testing.T, names ...string) {
	t.Helper()
	old := lookPath
	lookPath = func(n string) (string, error) {
		for _, x := range names {
			if x == n {
				return "/usr/bin/" + n, nil
			}
		}
		return "", fmt.Errorf("not found")
	}
	t.Cleanup(func() { lookPath = old })
}

func TestCaptureFilterAllowList(t *testing.T) {
	good := []string{"", "host 192.168.1.5", "tcp and port 443", "src net 10.0.0.0/8 or dst port 53", "udp and not port 123",
		"portrange 1000-2000", "ip6 and host 2001:db8::1", "arp"}
	for _, f := range good {
		if _, err := captureFilter(f); err != nil {
			t.Errorf("%q refused: %v", f, err)
		}
	}
	bad := []string{"tcp[13] & 2 != 0", "(host 1.2.3.4)", "-w /tmp/x", "host 1.2.3.4; reboot", "ether host aa:bb:cc:dd:ee:ff",
		"vlan", "host example.com", "port 53 $(id)", "host 999.1.1.1", "net 10.0.0.0/99", "-z", "greater 1000",
		strings.Repeat("tcp or ", 20) + "udp", "host " + strings.Repeat("1", 130)}
	for _, f := range bad {
		if _, err := captureFilter(f); err == nil {
			t.Errorf("%q was accepted", f)
		}
	}
}

const dumpLines = `1700000000.000000 IP 192.168.1.20.51000 > 1.1.1.1.53: 1234+ A? ads.example.net. (34)
1700000000.100000 IP 192.168.1.20.51001 > 1.1.1.1.53: 1235+ AAAA? ads.example.net. (34)
1700000000.200000 IP 192.168.1.20.51002 > 1.1.1.1.53: 1236+ A? cdn.example.org. (34)
1700000001.000000 IP 192.168.1.30.40000 > 198.51.100.7.443: Flags [S], seq 1, win 64240, length 0
1700000001.100000 IP 198.51.100.7.443 > 192.168.1.30.40000: Flags [R.], seq 1, ack 2, length 0
1700000001.200000 IP 192.168.1.30.40000 > 198.51.100.7.443: Flags [P.], seq 2:1402, ack 1, length 1400
1700000002.000000 IP 192.168.1.20.123 > 203.0.113.5.123: UDP, length 48
1700000002.500000 ARP, Request who-has 192.168.1.1 tell 192.168.1.20, length 28
1700000003.000000 IP6 2001:db8::5.5000 > 2001:db8::1.80: Flags [S], seq 1, length 0
1700000003.500000 IP 192.168.1.20 > 192.168.1.1: ICMP echo request, id 1, seq 1, length 64
tcpdump: listening on br-lan, link-type EN10MB
`

func TestCaptureReturnsASummaryNeverThePackets(t *testing.T) {
	f, _ := wave1Router(t)
	withBinaries(t, "tcpdump")
	writeFixture(t, sysRoot, "proc/net/dev", "Inter-|   Receive\n face |bytes\n  br-lan: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n")
	f.on("tcpdump", dumpLines)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "capture", Target: "br-lan", Filter: "udp or tcp", Count: 99})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, out, "10 packets", "protocols: tcp 4, dns 3, arp 1, icmp 1, udp 1", "tcp resets: 1",
		"192.168.1.30: 1400 bytes, 2 packets", "ads.example.net 2", "cdn.example.org 1")
	// 2 tcp from .30 + 1 from 198.51.100.7 + 1 IPv6 = tcp 4; the headers of single packets never appear.
	mustNotContain(t, out, "seq ", "Flags [", "win 64240")
	argv := strings.Join(f.argvList()[len(f.argvList())-1], " ")
	for _, want := range []string{"-i br-lan", "-c 2000", "-s 128", "-nn", "udp or tcp"} {
		if !strings.Contains(argv, want) {
			t.Errorf("tcpdump argv %q lacks %q", argv, want)
		}
	}
	for _, bad := range []string{" -w", " -z", " -C"} {
		if strings.Contains(argv, bad) {
			t.Errorf("tcpdump argv %q has %q", argv, bad)
		}
	}
}

// The packet cap is tcpdump's own -c; when the output holds that many packets the summary says
// the capture stopped there.
func TestCaptureEndsAtThePacketCap(t *testing.T) {
	f, _ := wave1Router(t)
	withBinaries(t, "tcpdump")
	writeFixture(t, sysRoot, "proc/net/dev", "h\nh\n  br-lan: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n")
	var b strings.Builder
	for i := 0; i < maxCapturePkts; i++ {
		fmt.Fprintf(&b, "%d.%06d IP 192.168.1.20.1000 > 192.168.1.1.80: Flags [.], ack 1, length 10\n", 1700000000+i/1000, i%1000)
	}
	f.on("tcpdump", b.String())
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "capture", Target: "br-lan"})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, out, "2000 packets", "stopped at the packet cap")
	if len(out) > 1500 {
		t.Errorf("a capped capture summarises to %d bytes", len(out))
	}
}

func TestCaptureRefusals(t *testing.T) {
	wave1Router(t)
	writeFixture(t, sysRoot, "proc/net/dev", "h\nh\n  br-lan: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n")
	ctx := context.Background()
	withBinaries(t)
	if _, _, err := netDiag(ctx, netDiagIn{Action: "capture", Target: "br-lan"}); err == nil || !strings.Contains(err.Error(), "tcpdump is not installed") {
		t.Errorf("missing tcpdump: %v", err)
	}
	withBinaries(t, "tcpdump")
	for _, in := range []netDiagIn{{Action: "capture"}, {Action: "capture", Target: "-i"}, {Action: "capture", Target: "br-lan", Filter: "tcp[13]&2!=0"},
		{Action: "capture", Target: "eth9"}} {
		if _, _, err := netDiag(ctx, in); err == nil {
			t.Errorf("%+v was accepted", in)
		}
	}
}

func TestThroughputRunsBothDirectionsWithinTheCap(t *testing.T) {
	f, _ := wave1Router(t)
	withBinaries(t, "iperf3")
	f.onFn("iperf3", func(argv []string, _ string) (string, error) {
		if strings.Contains(strings.Join(argv, " "), " -R") {
			return `{"end":{"sum_received":{"bits_per_second":92400000}}}`, nil
		}
		return `{"end":{"sum_sent":{"bits_per_second":41300000,"retransmits":7}}}`, nil
	})
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "throughput", Target: "iperf.example.net", Count: 600})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, out, "5 s each way", "upload (router to server): 41.3 Mbit/s, 7 retransmits", "download (server to router): 92.4 Mbit/s")
	var runs int
	for _, a := range f.argvList() {
		line := strings.Join(a, " ")
		if strings.HasPrefix(line, "iperf3 ") {
			runs++
			if !strings.Contains(line, "-t 5") || !strings.Contains(line, "-c iperf.example.net") {
				t.Errorf("iperf3 argv %q", line)
			}
		}
	}
	if runs != 2 {
		t.Errorf("%d iperf3 runs", runs)
	}
}

func TestThroughputReportsServerErrorsAndRefusals(t *testing.T) {
	f, _ := wave1Router(t)
	ctx := context.Background()
	withBinaries(t)
	if _, _, err := netDiag(ctx, netDiagIn{Action: "throughput", Target: "h.example"}); err == nil || !strings.Contains(err.Error(), "iperf3 is not installed") {
		t.Errorf("missing iperf3: %v", err)
	}
	withBinaries(t, "iperf3")
	for _, tg := range []string{"", "-s", "a b", "x;y"} {
		if _, _, err := netDiag(ctx, netDiagIn{Action: "throughput", Target: tg}); err == nil {
			t.Errorf("target %q was accepted", tg)
		}
	}
	f.onFn("iperf3", func([]string, string) (string, error) {
		return `{"error":"error - unable to connect to server: Connection refused"}`, nil
	})
	out, _, err := netDiag(ctx, netDiagIn{Action: "throughput", Target: "h.example"})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, out, "upload (router to server): failed: error - unable to connect to server")
}

// Throughput loads the link and capture reads other people's traffic: neither is in a preset.
func TestPresetsDoNotGrantThroughputOrCapture(t *testing.T) {
	for _, name := range []string{"readonly", "operator"} {
		var scopes []string
		for _, b := range presets[name] {
			if contains(b.tools, "net_diag") {
				scopes = b.scopes
			}
		}
		for _, bad := range []string{"throughput.iperf.example.net", "capture.br-lan"} {
			if matchAny(scopes, bad) {
				t.Errorf("@%s grants %s", name, bad)
			}
		}
		for _, ok := range []string{"ping.1.1.1.1", "traceroute.9.9.9.9", "nslookup.example.com", "route", "rule", "neigh", "wifi_survey.radio0", "traffic.br-lan", "usage", "dns_path", "path"} {
			if !matchAny(scopes, ok) {
				t.Errorf("@%s lost %s", name, ok)
			}
		}
	}
}

// Lines as tcpdump 4.99 prints them on the 25.12.6 VM for one lookup: the replies have no question
// mark and the second one is cut by the snaplen ("[|domain]"). They are DNS, not "other".
func TestCaptureCountsDNSRepliesAsDNS(t *testing.T) {
	out := "1793913443.890284 IP 192.168.1.50.39083 > 192.168.1.1.53: 34806+ A? example.com. (29)\n" +
		"1793913443.890395 IP 192.168.1.1.53 > 192.168.1.50.39083: 34806 2/0/0 A 172.66.147.243, (61)\n" +
		"1793913443.890410 IP 192.168.1.50.39083 > 192.168.1.1.53: 34807+ AAAA? example.com. (29)\n" +
		"1793913443.890419 IP 192.168.1.1.53 > 192.168.1.50.39083: 34807 2/0/0 AAAA [|domain]\n"
	got := summariseCapture(out, "br-lan", "port 53", 5)
	wantAll(t, got, "protocols: dns 4", "DNS names asked: example.com 2")
	mustNotContain(t, got, "other")
}

// A monitor interface prints 802.11 frames, which are neither IP nor ARP. They are lines tcpdump
// printed, so the summary must say it did not read them rather than "no packets seen". These are the
// beacon lines tcpdump 4.99 prints on hwsim0 in the 25.12.6 VM (SSID shortened, it is untrusted text).
func TestCaptureSaysWhenFramesAreNotRead(t *testing.T) {
	frames := "1794157229.773034 1794157229773021us tsft 1.0 Mb/s 2412 MHz 11b Beacon (TEST) [1.0* 2.0*] ESS CH: 1\n" +
		"1794157229.875583 1794157229875566us tsft 1.0 Mb/s 2412 MHz 11b Beacon (TEST) [1.0* 2.0*] ESS CH: 1\n" +
		"2 packets captured\n"
	got := summariseCapture(frames, "hwsim0", "", 5)
	wantAll(t, got, "no IP or ARP packets seen", "2 frames captured")
	mustNotContain(t, got, "no packets seen\n")

	mixed := "1794157230.000001 IP 10.99.0.2 > 10.99.0.1: ICMP echo request, id 1, seq 1, length 64\n" + frames
	got = summariseCapture(mixed, "wlan0", "", 5)
	wantAll(t, got, "1 packet over", "protocols: icmp 1", "2 other frames not summarised")

	// Nothing printed at all stays "no packets seen".
	wantAll(t, summariseCapture("0 packets captured\n", "wlan0", "", 5), "no packets seen")
}
