package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// logread mode=summary and baselines (ROADMAP 4.1). After a change the useful question is "what
// is new in the log", not "show me 500 lines": the summary collapses a log to its distinct
// messages (numbers, addresses and ids replaced by placeholders) with a count, first and last
// time and the worst severity, and a baseline remembers which messages existed at one moment.
//
// Expected values are written out here from the fixture, not computed by the code under test.
// The fixture is testdata/logread_sample.txt: synthetic, shaped after a real 25.12 log, with
// documentation addresses (RFC 5737) and MACs (00:00:5e:00:53:xx) only.

func sampleLog(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/logread_sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(b), "\n")
}

func TestNormaliseReplacesWhatVaries(t *testing.T) {
	cases := []struct{ in, want string }{
		{"DHCPACK(phy0-ap1) 192.0.2.10 00:00:5e:00:53:01 Smart-Bulb", "DHCPACK(phy0-ap1) <ip> <mac> Smart-Bulb"},
		{"USER root pid 12342 cmd /usr/bin/job.sh >/dev/null 2>&1", "USER root pid <n> cmd /usr/bin/job.sh >/dev/null <n>>&<n>"},
		{"STA 00:00:5E:00:53:01 RADIUS: starting accounting session 293C429C1FD7E6AA", "STA <mac> RADIUS: starting accounting session <hex>"},
		{"IEEE 802.11: associated (aid 6)", "IEEE <n>.<n>: associated (aid <n>)"},
		{"clock set at 12:30:45 UTC", "clock set at <time> UTC"},
		{"neighbour fe80::1c2d:3eff:fe4f:5a6b%br-lan gone", "neighbour <ip>%br-lan gone"},
		{"route 2001:db8::1 via 192.0.2.1/24", "route <ip> via <ip>/<n>"},
		{"[ 5123.000001] ieee80211 phy0: failed to assign queue 42", "ieee80211 phy0: failed to assign queue <n>"},
		{"fault at 0x7f3a2c10 in module", "fault at <hex> in module"},
		// An uptime or a lease time differs on every line; without a placeholder each occurrence of a
		// periodic message would be a new one in a baseline diff.
		{"SYS: CPU:3|LOAD:0.4|UPTIME:8d7h34m", "SYS: CPU:<n>|LOAD:<n>.<n>|UPTIME:<dur>"},
		{"lease time 12h, renew in 90s", "lease time <dur>, renew in <dur>"},
		{"  several   spaces\there ", "several spaces here"},
		{"Interface 'wan' is now up", "Interface 'wan' is now up"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normaliseLogMessage(c.in); got != c.want {
			t.Errorf("normalise(%q)\n got  %q\n want %q", c.in, got, c.want)
		}
	}
}

// A duration is digits and a unit letter that stand alone. Numbers inside a word, or followed by
// more letters, only look like one.
func TestNormaliseLeavesAlmostDurationsAlone(t *testing.T) {
	for _, s := range []string{"wlan1m up", "waited 5min", "kept 3days", "IEEE 802.11n", "UA-65D3C54 joined", "5GHz radio", "aid 6 mb1808s"} {
		if got := normaliseLogMessage(s); strings.Contains(got, "<dur>") {
			t.Errorf("normalise(%q) = %q, which treats a number in a word as a duration", s, got)
		}
	}
}

// Letters keep a number attached to them: phy0-ap1 and phy1-ap0 are different interfaces and a
// summary that merged them would hide which one misbehaves.
func TestNormaliseKeepsNumbersThatAreNames(t *testing.T) {
	for _, s := range []string{"phy0-ap1: up", "eth1 link is down", "br-lan2 forwarding", "robot_vac_mb1808 online"} {
		if got := normaliseLogMessage(s); got != s {
			t.Errorf("normalise(%q) = %q, want it unchanged", s, got)
		}
	}
}

func FuzzNormaliseLogMessage(f *testing.F) {
	for _, s := range []string{"", "a", "1", "00:00:5e:00:53:01", "fe80::1", "::", "1:2:3", "0x", "[ 1.2]", "\x00\xff",
		"192.0.2.1:80", "deadbeef", "12:30:45:67", strings.Repeat("1:", 200), "é1é2é", "<n> <mac> <ip> <hex> <time>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := normaliseLogMessage(s)
		if again := normaliseLogMessage(got); again != got {
			t.Fatalf("not idempotent:\n in    %q\n once  %q\n twice %q", s, got, again)
		}
		if len(got) > 3*len(s)+3 {
			t.Fatalf("grew from %d to %d bytes: %q -> %q", len(s), len(got), s, got)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("made invalid UTF-8 from valid: %q -> %q", s, got)
		}
	})
}

func TestParseLogLine(t *testing.T) {
	l := parseLogLine("Mon Jan  5 10:00:59 2026 daemon.notice hostapd: phy0-ap1: AP-STA-CONNECTED 00:00:5e:00:53:01")
	if l.proc != "hostapd" || l.sev != "notice" || l.rank != 5 || l.msg != "phy0-ap1: AP-STA-CONNECTED 00:00:5e:00:53:01" ||
		!l.hasTime || l.when.Format("Jan _2 15:04:05") != "Jan  5 10:00:59" {
		t.Errorf("hostapd line: %+v", l)
	}
	l = parseLogLine("Mon Jan  5 10:00:00 2026 cron.err crond[2058]: USER root pid 1001 cmd /usr/bin/job-a.sh")
	if l.proc != "crond" || l.sev != "err" || l.rank != 3 {
		t.Errorf("pid must not be part of the process: %+v", l)
	}
	l = parseLogLine("Mon Jan  5 10:01:41 2026 kern.err kernel: [ 5123.000001] ieee80211 phy0: failed")
	if l.proc != "kernel" || l.sev != "err" {
		t.Errorf("kernel line: %+v", l)
	}
	for _, s := range []string{"not a syslog line at all", "", "Mon Jan  5 10:00:00 2026", "Mon Jan  5 10:00:00 2026 daemon.info"} {
		l = parseLogLine(s)
		if l.proc != "-" || l.sev != "-" || l.msg != s {
			t.Errorf("parseLogLine(%q) = %+v, want an unparsed line", s, l)
		}
	}
	for sev, want := range map[string]int{"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7} {
		if got := parseLogLine("Mon Jan  5 10:00:00 2026 daemon." + sev + " p: m").rank; got != want {
			t.Errorf("rank(%s) = %d, want %d", sev, got, want)
		}
	}
}

var reSummaryRow = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\d+)\s+(\w{3} [ \d]\d \d\d:\d\d:\d\d)\s+(\w{3} [ \d]\d \d\d:\d\d:\d\d)\s{2}(.*)$`)

type summaryRow struct {
	proc, sev, first, last, msg string
	count                       int
}

func parseSummary(t *testing.T, out string) []summaryRow {
	t.Helper()
	var rows []summaryRow
	for _, line := range strings.Split(out, "\n") {
		m := reSummaryRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var n int
		fmt.Sscan(m[3], &n)
		rows = append(rows, summaryRow{m[1], m[2], m[4], m[5], m[6], n})
	}
	return rows
}

func TestSummaryOfTheSampleLog(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", sampleLog(t))
	out, _, err := newTestLogs().logread(context.Background(), logreadIn{Mode: "summary"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "20 lines, 12 distinct messages, processes: 7; oldest Jan  5 10:00:00, newest Jan  5 10:02:20\n") {
		t.Errorf("header wrong:\n%s", out)
	}
	want := []summaryRow{
		{"crond", "err", "Jan  5 10:00:00", "Jan  5 10:02:00", "USER root pid <n> cmd /usr/bin/job-a.sh", 3},
		{"crond", "err", "Jan  5 10:00:00", "Jan  5 10:02:00", "USER root pid <n> cmd /usr/bin/job-b.sh >/dev/null <n>>&<n>", 2},
		{"dropbear", "err", "Jan  5 10:00:05", "Jan  5 10:02:05", "Bad password attempt for 'root' from <ip>:<n>", 3},
		{"kernel", "info", "Jan  5 10:01:40", "Jan  5 10:02:20", "br-lan: port <n>(eth0) entered forwarding state", 2},
		{"kernel", "err", "Jan  5 10:01:41", "Jan  5 10:01:41", "ieee80211 phy0: failed to assign queue <n>", 1},
		{"hostapd", "notice", "Jan  5 10:00:58", "Jan  5 10:00:58", "phy0-ap1: AP-STA-DISCONNECTED <mac>", 1},
		{"hostapd", "notice", "Jan  5 10:00:59", "Jan  5 10:00:59", "phy0-ap1: AP-STA-CONNECTED <mac> auth_alg=open", 1},
		{"hostapd", "info", "Jan  5 10:00:59", "Jan  5 10:00:59", "phy0-ap1: STA <mac> RADIUS: starting accounting session <hex>", 1},
		{"netifd", "notice", "Jan  5 10:01:30", "Jan  5 10:01:30", "Network device 'eth1' link is down", 1},
		{"dnsmasq-dhcp", "info", "Jan  5 10:00:22", "Jan  5 10:01:22", "DHCPDISCOVER(phy0-ap1) <mac>", 2},
		{"dnsmasq-dhcp", "info", "Jan  5 10:00:23", "Jan  5 10:01:23", "DHCPACK(phy0-ap1) <ip> <mac> host-a", 2},
		{"-", "-", "", "", "", 1},
	}
	got := parseSummary(t, out)
	// The unparsed line has no time, so it never matches the row pattern; check it separately.
	if !strings.Contains(out, "not a syslog line at all") {
		t.Errorf("the unparsed line is missing:\n%s", out)
	}
	want = want[:len(want)-1]
	// Within a process, rows go by count then message; the hostapd rows have equal counts and
	// sort by message, so compare as sets per process while keeping the process order.
	if len(got) < len(want) {
		t.Fatalf("got %d rows, want %d:\n%s", len(got), len(want), out)
	}
	var order []string
	for _, r := range got {
		if len(order) == 0 || order[len(order)-1] != r.proc {
			order = append(order, r.proc)
		}
	}
	if strings.Join(order, ",") != "crond,dropbear,kernel,hostapd,netifd,dnsmasq-dhcp" {
		t.Errorf("process order = %v; want by worst severity, then count, then name", order)
	}
	seen := map[string]bool{}
	for _, r := range got {
		seen[fmt.Sprintf("%+v", r)] = true
	}
	for _, w := range want {
		if !seen[fmt.Sprintf("%+v", w)] {
			t.Errorf("missing row %+v in:\n%s", w, out)
		}
	}
}

func TestSummaryAppliesTheFiltersFirst(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", sampleLog(t))
	out, _, err := newTestLogs().logread(context.Background(), logreadIn{Mode: "summary", Pattern: "hostapd"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "3 lines, 3 distinct messages, processes: 1;") || strings.Contains(out, "crond") {
		t.Errorf("filter not applied before summarising:\n%s", out)
	}
}

func TestSummaryPages(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", sampleLog(t))
	lg := newTestLogs()
	out, _, _ := lg.logread(context.Background(), logreadIn{Mode: "summary", Lines: 5})
	if got := finalNotice(out); got != "[truncated: 7 more messages omitted; call again with offset=5]" {
		t.Errorf("notice = %q", got)
	}
	out, _, _ = lg.logread(context.Background(), logreadIn{Mode: "summary", Lines: 5, Offset: 9})
	if strings.Contains(out, "truncated") || !strings.Contains(out, "DHCPACK") {
		t.Errorf("last page wrong:\n%s", out)
	}
}

func TestBadModeAndBaselineAreRefusedWithAValidationCode(t *testing.T) {
	newFakeRouter(t)
	lg := newTestLogs()
	for _, in := range []logreadIn{{Mode: "everything"}, {Baseline: "../etc"}, {Baseline: "ABCDEFGH"}, {Baseline: "abc"}} {
		_, _, err := lg.logread(context.Background(), in)
		if err == nil || errCode(err) != "VALIDATION" {
			t.Errorf("%+v: err=%v, want a VALIDATION error", in, err)
		}
	}
}

// ---------------------------------------------------------------- baselines

func TestBaselineShowsOnlyMessagesThatAreNew(t *testing.T) {
	f := newFakeRouter(t)
	full := sampleLog(t)
	var before []string
	for _, l := range strings.Split(full, "\n") {
		if !strings.Contains(l, "dropbear") && !strings.Contains(l, "kern.err") {
			before = append(before, l)
		}
	}
	lg := newTestLogs()
	ctx := context.Background()

	f.on("logread", strings.Join(before, "\n"))
	saved, _, err := lg.logread(ctx, logreadIn{Baseline: "save"})
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`baseline ([0-9a-f]{8}) saved: 10 distinct messages`).FindStringSubmatch(saved)
	if m == nil {
		t.Fatalf("save must name an 8-hex-digit token and the message count:\n%s", saved)
	}
	token := m[1]

	f.on("logread", full)
	out, _, err := lg.logread(ctx, logreadIn{Mode: "summary", Baseline: token})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "since baseline "+token+": 2 of 12 distinct messages are new") {
		t.Errorf("header wrong:\n%s", out)
	}
	rows := parseSummary(t, out)
	if len(rows) != 2 || rows[0].proc != "dropbear" || rows[0].count != 3 || rows[1].proc != "kernel" || rows[1].sev != "err" {
		t.Errorf("want only the dropbear and kernel-error messages, got %+v", rows)
	}
	if strings.Contains(out, "crond") {
		t.Errorf("a message that existed at baseline time came back:\n%s", out)
	}

	// The same baseline applies to plain lines: only lines of a new kind, newest last.
	out, _, _ = lg.logread(ctx, logreadIn{Baseline: token})
	if strings.Count(out, "Bad password") != 3 || !strings.Contains(out, "failed to assign queue 42") || strings.Contains(out, "crond") {
		t.Errorf("lines mode with a baseline:\n%s", out)
	}
}

func TestBaselineCountsAMessageAsSeenWhateverItsNumbers(t *testing.T) {
	f := newFakeRouter(t)
	lg := newTestLogs()
	ctx := context.Background()
	f.on("logread", "Mon Jan  5 10:00:00 2026 daemon.info dnsmasq-dhcp[1]: DHCPACK(phy0-ap1) 192.0.2.10 00:00:5e:00:53:01 host-a")
	saved, _, _ := lg.logread(ctx, logreadIn{Baseline: "save"})
	token := regexp.MustCompile(`[0-9a-f]{8}`).FindString(saved)
	f.on("logread", "Mon Jan  5 11:00:00 2026 daemon.info dnsmasq-dhcp[7]: DHCPACK(phy0-ap1) 192.0.2.99 00:00:5e:00:53:77 host-a")
	out, _, _ := lg.logread(ctx, logreadIn{Mode: "summary", Baseline: token})
	if !strings.Contains(out, "0 of 1 distinct messages are new") || len(parseSummary(t, out)) != 0 {
		t.Errorf("a new address and MAC made a known message look new:\n%s", out)
	}
}

func TestUnknownBaselineIsNotFoundAndSaysHowToRecover(t *testing.T) {
	newFakeRouter(t).on("logread", sampleLog(t))
	_, _, err := newTestLogs().logread(context.Background(), logreadIn{Baseline: "00000000"})
	if err == nil || errCode(err) != "NOT_FOUND" || !strings.Contains(err.Error(), "baseline=save") ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("want NOT_FOUND naming baseline=save and the restart, got %v", err)
	}
}

func TestOnlyTheNewestBaselinesAreKept(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", sampleLog(t))
	lg := newTestLogs()
	ctx := context.Background()
	var tokens []string
	for i := 0; i < maxBaselines+1; i++ {
		saved, _, err := lg.logread(ctx, logreadIn{Baseline: "save"})
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, regexp.MustCompile(`[0-9a-f]{8}`).FindString(saved))
	}
	if _, _, err := lg.logread(ctx, logreadIn{Baseline: tokens[0]}); errCode(err) != "NOT_FOUND" {
		t.Errorf("the oldest baseline survived %d newer ones: %v", maxBaselines, err)
	}
	if _, _, err := lg.logread(ctx, logreadIn{Baseline: tokens[1]}); err != nil {
		t.Errorf("the second oldest baseline was dropped: %v", err)
	}
	// Using a baseline keeps it: it is the most recently used now, so a new save evicts another.
	if _, _, err := lg.logread(ctx, logreadIn{Baseline: "save"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lg.logread(ctx, logreadIn{Baseline: tokens[1]}); err != nil {
		t.Errorf("a baseline that was just used was evicted: %v", err)
	}
}

// A baseline is fingerprints, not log text: a log line can carry a secret, and nothing here is
// the place to keep one.
func TestABaselineHoldsNoLogText(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", "Mon Jan  5 10:00:00 2026 daemon.err app[1]: login failed password=hunter2-SECRET-MARKER")
	lg := newTestLogs()
	if _, _, err := lg.logread(context.Background(), logreadIn{Baseline: "save"}); err != nil {
		t.Fatal(err)
	}
	if dump := fmt.Sprintf("%#v %+v", lg, lg); strings.Contains(dump, "SECRET-MARKER") || strings.Contains(dump, "hunter2") {
		t.Errorf("log text reached the baseline store: %s", dump)
	}
}

func TestBaselineSaveIgnoresPagingAndFilters(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", sampleLog(t))
	lg := newTestLogs()
	saved, _, err := lg.logread(context.Background(), logreadIn{Baseline: "save", Pattern: "hostapd", Lines: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(saved, "saved: 3 distinct messages") {
		t.Errorf("a baseline is of the filtered log, not of one page of it:\n%s", saved)
	}
}

func newTestLogs() *logBook { return &logBook{} }

// A baseline has a ceiling, so a log of endless distinct messages cannot grow the daemon.
func TestABaselineHasALimit(t *testing.T) {
	var lines []string
	name := func(i int) string { // letters only, so every message stays distinct after normalising
		s := ""
		for n := i; ; n /= 26 {
			s += string(rune('a' + n%26))
			if n < 26 {
				return s
			}
		}
	}
	for i := 0; i < maxBaselineKeys+1; i++ {
		lines = append(lines, "Mon Jan  5 10:00:00 2026 daemon.info app[1]: event "+name(i))
	}
	newFakeRouter(t).on("logread", strings.Join(lines, "\n"))
	_, _, err := newTestLogs().logread(context.Background(), logreadIn{Baseline: "save"})
	if err == nil || errCode(err) != "VALIDATION" || !strings.Contains(err.Error(), "20001 distinct messages") {
		t.Fatalf("want a VALIDATION error naming the count, got %v", err)
	}
}
