package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The truncation contract (ROADMAP 4.7). Whenever a result is cut, its last line says so in one
// machine-readable shape, "[truncated: <what> ...; <how to get the rest>]", and a tool that can
// page names the offset to ask for next. A cut result never looks complete. For an error result
// the notice is the last line before the "[code: X]" line.
//
// Expected texts are written out here, not built from the helpers under test.

var reTruncLine = regexp.MustCompile(`^\[truncated: [^\n\]]+\]$`)

// finalNotice is the last line of text, ignoring the error code line.
func finalNotice(text string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if n := len(lines); n > 0 && strings.HasPrefix(lines[n-1], "[code: ") {
		lines = lines[:n-1]
	}
	return lines[len(lines)-1]
}

func TestTheByteCapEndsWithTheNotice(t *testing.T) {
	got := capBytes(strings.Repeat("x", 100), 10)
	want := regexp.MustCompile(`\n\n\[truncated: 100 bytes total, 10 shown; [^\n\]]+\]$`)
	if !want.MatchString(got) {
		t.Errorf("byte-cap notice has the wrong shape: %q", got)
	}
}

func TestUbusPruningEndsWithTheNotice(t *testing.T) {
	nums := make([]string, 5000)
	for i := range nums {
		nums[i] = fmt.Sprint(i)
	}
	out := pruneUbusJSON(`{"series": [` + strings.Join(nums, ",") + `]}`)
	last := finalNotice(out)
	if !reTruncLine.MatchString(last) || !strings.HasPrefix(last, "[truncated: 4984 array element(s) dropped; arrays capped at 16,") {
		t.Errorf("prune notice has the wrong shape: %q", last)
	}
}

func TestShortenedLinesAreNamedOnTheLastLine(t *testing.T) {
	s := testServer(t, "")
	out := s.presentOutput("net_diag", nil, "short\n"+strings.Repeat("a", 3000)+"\nshort")
	if !strings.Contains(out, "…[+1976 bytes]") {
		t.Fatalf("the inline cut marker went missing: %q", out[:60])
	}
	if last := finalNotice(out); last != "[truncated: 1 line(s) cut at 1024 bytes; narrow the request or filter the output]" {
		t.Errorf("last line = %q", last)
	}
	if out2 := s.presentOutput("net_diag", nil, "short\nshort"); strings.Contains(out2, "[truncated") {
		t.Errorf("an uncut result carries a notice: %q", out2)
	}
}

// logread pages back from the newest line: offset is how many of the newest MATCHING lines to
// skip, so the next page is the one before.
func TestLogreadPagesBackFromTheNewestLine(t *testing.T) {
	f := newFakeRouter(t)
	var log []string
	for i := 1; i <= 30; i++ {
		log = append(log, fmt.Sprintf("Mon Jan  1 00:00:%02d 2026 daemon.info proc[1]: event %02d", i, i))
	}
	f.on("logread", strings.Join(log, "\n"))
	ctx := context.Background()

	out, _, err := logread(ctx, logreadIn{Lines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "event 30") || !strings.Contains(out, "event 21") || strings.Contains(out, "event 20") {
		t.Errorf("first page should be events 21..30:\n%s", out)
	}
	if got := finalNotice(out); got != "[truncated: 20 older matching lines omitted; call again with offset=10]" {
		t.Errorf("first page notice = %q", got)
	}

	out, _, _ = logread(ctx, logreadIn{Lines: 10, Offset: 10})
	if !strings.Contains(out, "event 20") || !strings.Contains(out, "event 11") || strings.Contains(out, "event 21") || strings.Contains(out, "event 10") {
		t.Errorf("second page should be events 11..20:\n%s", out)
	}
	if got := finalNotice(out); got != "[truncated: 10 older matching lines omitted; call again with offset=20]" {
		t.Errorf("second page notice = %q", got)
	}

	out, _, _ = logread(ctx, logreadIn{Lines: 10, Offset: 20})
	if !strings.Contains(out, "event 10") || !strings.Contains(out, "event 01") || strings.Contains(out, "truncated") {
		t.Errorf("last page should be events 01..10 with no notice:\n%s", out)
	}

	out, _, _ = logread(ctx, logreadIn{Lines: 10, Offset: 30})
	if out != "(no matching log lines at offset 30; 30 match in total)" {
		t.Errorf("past the end: %q", out)
	}
}

func TestPkgQueryPagesAndKeepsTheTotal(t *testing.T) {
	f := newFakeRouter(t)
	var list []string
	for i := 0; i < 450; i++ {
		list = append(list, fmt.Sprintf("pkg%03d-1.0 x86_64 {feeds/base/pkg%03d} (MIT) [installed]", i, i))
	}
	f.on("apk list --installed", strings.Join(list, "\n"))
	ctx := context.Background()

	out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "installed"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pkg000-1.0\n") || !strings.Contains(out, "pkg199-1.0\n") || strings.Contains(out, "pkg200-1.0") {
		t.Errorf("first page should be pkg000..pkg199")
	}
	if !strings.Contains(out, "(450 packages)\n") {
		t.Errorf("the total must stay visible on every page:\n...%s", out[len(out)-120:])
	}
	if got := finalNotice(out); got != "[truncated: 250 more lines omitted; call again with offset=200]" {
		t.Errorf("notice = %q", got)
	}

	out, _, _ = pkgQuery(ctx, pkgQueryIn{Action: "installed", Offset: 400})
	if !strings.Contains(out, "pkg449-1.0\n") || strings.Contains(out, "pkg399-1.0") || strings.Contains(out, "truncated") ||
		!strings.HasSuffix(out, "(450 packages)") {
		t.Errorf("last page wrong:\n%s", out)
	}
}

func TestNetworkClientsPages(t *testing.T) {
	root := withFixtureRoot(t)
	var leases []string
	for i := 0; i < 150; i++ {
		leases = append(leases, fmt.Sprintf("0 aa:bb:cc:00:%02x:%02x 192.168.1.%d host%03d *", i/256, i%256, i+10, i))
	}
	writeFixture(t, root, "tmp/dhcp.leases", strings.Join(leases, "\n")+"\n")
	f := newFakeRouter(t)
	f.on("uci -q show dhcp", "")
	f.on("ip -j neigh show", "[]")
	f.on("ubus call iwinfo devices", `{"devices":[]}`)
	ctx := context.Background()

	out, _, err := networkClients(ctx, networkClientsIn{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "host000 ") || !strings.Contains(out, "host099 ") || strings.Contains(out, "host100 ") {
		t.Errorf("first page should be host000..host099")
	}
	if !strings.Contains(out, "150 client(s)") {
		t.Errorf("the total must stay visible:\n%s", out[len(out)-200:])
	}
	if got := finalNotice(out); got != "[truncated: 50 more rows omitted; call again with offset=100]" {
		t.Errorf("notice = %q", got)
	}

	out, _, _ = networkClients(ctx, networkClientsIn{Offset: 100})
	if !strings.Contains(out, "host149 ") || strings.Contains(out, "host099 ") || strings.Contains(out, "truncated") {
		t.Errorf("last page wrong:\n%s", out)
	}
}

// The generic layer: every golden call against a backend that answers with a huge, long-lined
// text. Whatever a tool does with it, a result that was cut must say so on its last line. This
// is the net under tools that cut nothing themselves, and under tools added later.
func TestNoToolCutsAResultWithoutTheNotice(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	huge := strings.Repeat(strings.Repeat("y", 1500)+"\n", 200) // 300 KB, every line over the line cap
	for _, p := range []string{"ubus", "uci", "ip", "nft", "fw4", "logread", "apk", "wg", "ping", "traceroute",
		"nslookup", "sysupgrade", "owut", "ls", "/sbin/reload_config"} {
		f.on(p, huge)
	}
	s := testServer(t, grantAll())
	cs := connectClient(t, s, "c")

	cut := 0
	for _, g := range goldenCalls {
		out, _ := callTextAllowingProtocolError(t, cs, g.tool, g.args)
		if len(out) < maxResultBytes-1024 && !strings.Contains(out, "…[+") {
			continue // nothing was cut
		}
		cut++
		if last := finalNotice(out); !reTruncLine.MatchString(last) {
			t.Errorf("%s %v: a cut result ends with %.100q, not a truncation notice", g.tool, g.args, last)
		}
	}
	if cut < 3 {
		t.Errorf("only %d golden calls produced a cut result; the fake no longer exercises the cap", cut)
	}
}
