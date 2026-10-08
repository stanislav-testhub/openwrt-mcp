package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// net_diag traffic and usage (ROADMAP 4.5). traffic samples /proc/net/dev twice a few seconds
// apart and ranks the conntrack table by source; usage reads nlbwmon's totals. Both only read.
//
// Expected figures are worked out by hand from the fixtures below.

const devHeader = "Inter-|   Receive                                                |  Transmit\n" +
	" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

func devLine(name string, rxB, rxP, txB, txP int64) string {
	return fmt.Sprintf("%6s: %d %d 0 0 0 0 0 0 %d %d 0 0 0 0 0 0\n", name, rxB, rxP, txB, txP)
}

// trafficFixture installs the first /proc/net/dev sample and a sleep that swaps in the second one
// and moves the clock on by exactly the time asked for.
func trafficFixture(t *testing.T, first, second string) (root string, slept *[]time.Duration) {
	t.Helper()
	root = withFixtureRoot(t)
	writeFixture(t, root, "proc/net/dev", devHeader+first)
	clock := time.Unix(1_800_000_000, 0)
	oldNow, oldSleep := trafficNow, trafficSleep
	var asked []time.Duration
	trafficNow = func() time.Time { return clock }
	trafficSleep = func(_ context.Context, d time.Duration) {
		asked = append(asked, d)
		clock = clock.Add(d)
		writeFixture(t, root, "proc/net/dev", devHeader+second)
	}
	t.Cleanup(func() { trafficNow, trafficSleep = oldNow, oldSleep })
	return root, &asked
}

func TestTrafficReportsRatesBetweenTwoSamples(t *testing.T) {
	// br-lan: +3 MiB received and +768 KiB sent over 3 s = 1.0M/s and 256K/s, 1000 and 500 packets/s.
	// wan: unchanged. lo: busy but never listed.
	first := devLine("lo", 1000, 10, 1000, 10) + devLine("br-lan", 10_000_000, 7_000, 2_000_000, 3_000) + devLine("wan", 5, 1, 5, 1)
	second := devLine("lo", 9_999_999, 99, 9_999_999, 99) + devLine("br-lan", 10_000_000+3*(1<<20), 7_000+3_000, 2_000_000+3*(256<<10), 3_000+1_500) + devLine("wan", 5, 1, 5, 1)
	_, slept := trafficFixture(t, first, second)
	root := sysRoot
	writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_acct", "1\n")

	out, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic"})
	if err != nil {
		t.Fatal(err)
	}
	if len(*slept) != 1 || (*slept)[0] != 3*time.Second {
		t.Fatalf("sampled over %v, want one 3 s wait", *slept)
	}
	var row string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "br-lan ") {
			row = l
		}
	}
	for _, want := range []string{"1.0M/s", "256K/s", "1000", "500"} {
		if !strings.Contains(row, want) {
			t.Errorf("br-lan row lacks %q: %q\n%s", want, row, out)
		}
	}
	if strings.Contains(out, "\nlo ") || strings.Contains(out, "\nwan ") {
		t.Errorf("loopback and idle interfaces must not be listed:\n%s", out)
	}
	if !strings.Contains(out, "over 3 s") {
		t.Errorf("the sampling window must be stated:\n%s", out)
	}
}

func TestTrafficSecondsAreClamped(t *testing.T) {
	for _, c := range []struct {
		count int
		want  time.Duration
	}{{0, 3 * time.Second}, {-5, 3 * time.Second}, {1, time.Second}, {10, 10 * time.Second}, {11, 10 * time.Second}, {99, 10 * time.Second}} {
		_, slept := trafficFixture(t, devLine("br-lan", 1, 1, 1, 1), devLine("br-lan", 2, 2, 2, 2))
		if _, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic", Count: c.count}); err != nil {
			t.Fatal(err)
		}
		if len(*slept) != 1 || (*slept)[0] != c.want {
			t.Errorf("count %d: waited %v, want %v", c.count, *slept, c.want)
		}
	}
}

func TestTrafficCounterThatWentBackwardsIsNotARate(t *testing.T) {
	trafficFixture(t, devLine("wg0", 5_000_000, 5_000, 5_000_000, 5_000), devLine("wg0", 100, 1, 100, 1))
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "wg0 ") && !strings.Contains(out, "no traffic") {
		t.Errorf("an interface that was reset must not show a rate:\n%s", out)
	}
}

func TestTrafficOfOneInterface(t *testing.T) {
	trafficFixture(t, devLine("br-lan", 0, 0, 0, 0)+devLine("wan", 0, 0, 0, 0), devLine("br-lan", 3000, 3, 0, 0)+devLine("wan", 6000, 6, 0, 0))
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic", Target: "wan"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "wan ") || strings.Contains(out, "br-lan") {
		t.Errorf("a target limits the result to that interface:\n%s", out)
	}
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic", Target: "nosuch0"}); errCode(err) != "NOT_FOUND" {
		t.Errorf("unknown interface: %v, want NOT_FOUND", err)
	}
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic", Target: "bad name!"}); errCode(err) != "VALIDATION" {
		t.Errorf("bad interface name: %v, want VALIDATION", err)
	}
	if got := netDiagScope(netDiagIn{Action: "traffic", Target: "wan"}); got[0] != "traffic.wan" {
		t.Errorf("scope = %v", got)
	}
}

const conntrackAcct = `ipv4     2 tcp      6 431999 ESTABLISHED src=192.0.2.10 dst=203.0.113.5 sport=40000 dport=443 packets=10 bytes=1000 src=203.0.113.5 dst=198.51.100.7 sport=443 dport=40000 packets=12 bytes=9000 [ASSURED] mark=0 use=2
ipv4     2 udp      17 25 src=192.0.2.10 dst=203.0.113.9 sport=5000 dport=53 packets=1 bytes=500 src=203.0.113.9 dst=198.51.100.7 sport=53 dport=5000 packets=1 bytes=1500 mark=0 use=1
ipv4     2 tcp      6 100 TIME_WAIT src=192.0.2.20 dst=203.0.113.5 sport=41000 dport=80 packets=3 bytes=100 src=203.0.113.5 dst=198.51.100.7 sport=80 dport=41000 packets=3 bytes=200 [ASSURED] mark=0 use=1
ipv6     10 udp     17 20 src=2001:db8::5 dst=2001:db8::9 sport=1000 dport=123 packets=1 bytes=76 src=2001:db8::9 dst=2001:db8::5 sport=123 dport=1000 packets=1 bytes=76 mark=0 use=1
`

func TestTrafficRanksTopTalkersByBytes(t *testing.T) {
	root, _ := trafficFixture(t, devLine("br-lan", 0, 0, 0, 0), devLine("br-lan", 1, 1, 1, 1))
	writeFixture(t, root, "proc/net/nf_conntrack", conntrackAcct)
	writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_acct", "1\n")
	writeFixture(t, root, "tmp/dhcp.leases", "0 00:00:5e:00:53:01 192.0.2.10 phone *\n")
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic"})
	if err != nil {
		t.Fatal(err)
	}
	// 192.0.2.10: (1000+9000) + (500+1500) = 12000 bytes over 2 connections; 192.0.2.20: 300; the
	// IPv6 source: 152.
	i10, i20, i6 := strings.Index(out, "192.0.2.10 (phone)"), strings.Index(out, "192.0.2.20"), strings.Index(out, "2001:db8::5")
	if i10 < 0 || i20 < 0 || i6 < 0 || !(i10 < i20 && i20 < i6) {
		t.Fatalf("talkers missing or out of order (by bytes, largest first):\n%s", out)
	}
	line := out[i10:]
	line = line[:strings.Index(line, "\n")]
	if !strings.Contains(line, "2 conns") || !strings.Contains(line, "12K") {
		t.Errorf("192.0.2.10 row = %q, want 2 conns and 12K", line)
	}
}

func TestTrafficRanksByConnectionsWhenByteCountersAreOff(t *testing.T) {
	root, _ := trafficFixture(t, devLine("br-lan", 0, 0, 0, 0), devLine("br-lan", 1, 1, 1, 1))
	writeFixture(t, root, "proc/net/nf_conntrack", conntrackAcct)
	writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_acct", "0\n")
	out, _, _ := netDiag(context.Background(), netDiagIn{Action: "traffic"})
	if !strings.Contains(out, "byte counters are off") || !strings.Contains(out, "ranked by connection count") {
		t.Errorf("must say why there are no byte figures:\n%s", out)
	}
	if strings.Index(out, "192.0.2.10") > strings.Index(out, "192.0.2.20") {
		t.Errorf("the host with 2 connections must come first:\n%s", out)
	}
}

func TestTrafficWithoutAConntrackTableStillAnswers(t *testing.T) {
	trafficFixture(t, devLine("br-lan", 0, 0, 0, 0), devLine("br-lan", 3000, 3, 0, 0))
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "traffic"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "br-lan") || !strings.Contains(out, "conntrack table unavailable") {
		t.Errorf("want the rates and a note about the table:\n%s", out)
	}
}

// ---------------------------------------------------------------- usage (nlbwmon)

const nlbwJSON = `{"columns":["mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],"data":[
 ["00:00:5e:00:53:01","192.0.2.10",100,5000000,5000,1000000,2000],
 ["00:00:5e:00:53:01","2001:db8::10",10,1000000,500,200000,300],
 ["00:00:5e:00:53:02","192.0.2.20",5,300000,100,100000,100]]}`

func usageFixture(t *testing.T) (*fakeRouter, string) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "usr/sbin/nlbw", "#!/bin/sh\n")
	writeFixture(t, root, "tmp/dhcp.leases", "0 00:00:5e:00:53:01 192.0.2.10 phone *\n")
	f := newFakeRouter(t)
	f.on("nlbw -c list", "2026-09-01\n2026-10-01\n")
	f.on("nlbw -c json -g mac,ip", nlbwJSON)
	return f, root
}

func TestUsageSumsEachDeviceAcrossItsAddresses(t *testing.T) {
	usageFixture(t)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "usage"})
	if err != nil {
		t.Fatal(err)
	}
	// 00:00:5e:00:53:01: rx 6,000,000 = 5.7M, tx 1,200,000 = 1.1M, 110 connections, two addresses.
	var phone, other string
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "phone "):
			phone = l
		case strings.Contains(l, "00:00:5e:00:53:02"):
			other = l
		}
	}
	for _, want := range []string{"00:00:5e:00:53:01", "5.7M", "1.1M", "110", "192.0.2.10", "2001:db8::10"} {
		if !strings.Contains(phone, want) {
			t.Errorf("phone row lacks %q: %q\n%s", want, phone, out)
		}
	}
	// 00:00:5e:00:53:02: rx 300,000 = 293K, tx 100,000 = 98K.
	for _, want := range []string{"293K", "98K"} {
		if !strings.Contains(other, want) {
			t.Errorf("second device row lacks %q: %q", want, other)
		}
	}
	if strings.Index(out, "phone ") > strings.Index(out, "00:00:5e:00:53:02") {
		t.Errorf("the device with more traffic must be first:\n%s", out)
	}
	if !strings.Contains(out, "periods available: 2026-09-01 2026-10-01") {
		t.Errorf("the accounting periods should be listed:\n%s", out)
	}
	if !strings.Contains(out, "accounting period") {
		t.Errorf("usage is per accounting period (monthly by default), and must say so:\n%s", out)
	}
}

func TestUsageOfAGivenPeriod(t *testing.T) {
	f, _ := usageFixture(t)
	f.on("nlbw -c json -g mac,ip -t 2026-09-01", nlbwJSON)
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "usage", Target: "2026-09-01"}); err != nil {
		t.Fatal(err)
	}
	if !f.ran("nlbw -c json -g mac,ip -t 2026-09-01") {
		t.Errorf("the period never reached nlbw:\n%s", f.allCalls())
	}
	for _, bad := range []string{"last-week", "2026-9-1", "2026-09-01; reboot", "x2026-09-01", "2026-09-01x", "-t", "../x"} {
		_, _, err := netDiag(context.Background(), netDiagIn{Action: "usage", Target: bad})
		if errCode(err) != "VALIDATION" {
			t.Errorf("period %q: %v, want VALIDATION", bad, err)
		}
	}
}

func TestUsageWithoutNlbwmonSaysWhatToInstall(t *testing.T) {
	withFixtureRoot(t)
	newFakeRouter(t)
	_, _, err := netDiag(context.Background(), netDiagIn{Action: "usage"})
	if err == nil || errCode(err) != "NOT_FOUND" || !strings.Contains(err.Error(), "pkg_change") || !strings.Contains(err.Error(), "nlbwmon") {
		t.Errorf("want NOT_FOUND naming the package and the tool to install it with, got %v", err)
	}
}

func TestUsageListsOnlyTheLargestAndSaysSo(t *testing.T) {
	f, _ := usageFixture(t)
	var rows []string
	for i := 0; i < 30; i++ {
		rows = append(rows, fmt.Sprintf(`["00:00:5e:00:54:%02x","192.0.2.%d",1,%d,1,1,1]`, i, i+1, (30-i)*1000))
	}
	f.on("nlbw -c json -g mac,ip", `{"columns":["mac","ip","conns","rx_bytes","rx_pkts","tx_bytes","tx_pkts"],"data":[`+strings.Join(rows, ",")+`]}`)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "usage"})
	if err != nil {
		t.Fatal(err)
	}
	if got := finalNotice(out); got != "[truncated: 5 more clients omitted; only the largest 25 are listed]" {
		t.Errorf("notice = %q", got)
	}
	if !strings.Contains(out, "00:00:5e:00:54:00") || strings.Contains(out, "00:00:5e:00:54:1d") {
		t.Errorf("the 25 largest must be listed and the smallest left out")
	}
}

// A column the JSON does not have is an error, not a row of zeros.
func TestUsageRefusesOutputItDoesNotUnderstand(t *testing.T) {
	f, _ := usageFixture(t)
	f.on("nlbw -c json -g mac,ip", `{"columns":["mac"],"data":[["00:00:5e:00:53:01"]]}`)
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "usage"}); err == nil {
		t.Error("output without byte counters was accepted")
	}
	f.on("nlbw -c json -g mac,ip", `not json`)
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "usage"}); err == nil {
		t.Error("garbage was accepted")
	}
}
