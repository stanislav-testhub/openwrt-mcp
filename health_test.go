package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// system_status mode=doctor (ROADMAP 4.2): a severity-ranked list of findings about the router's
// own health. Every finding has one fixture that triggers it and the healthy router that does
// not, and the numeric thresholds are tried one below, at and one above the line.
//
// Expected severities and wording are written out here from the spec, not read off the code.

// docFixture is a healthy 25.12 router, as the commands and files the doctor reads would show it.
type docFixture struct {
	board, info, ifaces, wireless, procd, rc string
	connCount, connMax                       string // "" = the file is absent
	kernelPkg                                string
	chronyc                                  string // "" = chronyc is not installed
	apkNew                                   []string
	failing                                  map[string]bool // commands that fail
}

const (
	okBoard = `{"kernel":"6.12.94","hostname":"router","model":"Test Board","board_name":"test","release":{"description":"OpenWrt 25.12.5"}}`
	okInfo  = `{"localtime":1791429618,"uptime":1000,"memory":{"total":1000000000,"available":500000000},` +
		`"root":{"total":100000,"used":10000,"avail":90000},"tmp":{"total":500000,"used":50000,"avail":450000}}`
	okIfaces = `{"interface":[
		{"interface":"loopback","up":true,"proto":"static","ipv4-address":[{"address":"127.0.0.1","mask":8}]},
		{"interface":"lan","up":true,"proto":"static","ipv4-address":[{"address":"192.0.2.1","mask":24}]},
		{"interface":"wan","up":true,"proto":"dhcp","ipv4-address":[{"address":"198.51.100.7","mask":24}]}]}`
	okWireless = `{"radio0":{"up":true,"disabled":false,"interfaces":[{"ifname":"phy0-ap0","config":{"ssid":"Home","mode":"ap"}}]},
		"radio1":{"up":true,"disabled":false,"interfaces":[{"ifname":"phy1-ap0","config":{"ssid":"Home5","mode":"ap"}}]}}`
	okProcd = `{"dnsmasq":{"instances":{"dnsmasq":{"running":true,"pid":10}}},
		"urandom_seed":{"instances":{"urandom_seed":{"running":false,"exit_code":0}}},
		"firewall":{"triggers":[]}}`
	okRC       = `{"dnsmasq":{"start":19,"stop":0,"enabled":true,"running":true},"adguardhome":{"start":18,"stop":81,"enabled":true,"running":false},"firewall":{"enabled":true,"running":false}}`
	okKernel   = "kernel-6.12.94~5a6c1f71be683ae9980b15d3ce73e24d-r1 aarch64_cortex-a53 {feeds/base/kernel/linux} (GPL-2.0-only) [installed]"
	okTracking = "C0A8010B,192.0.2.11,3,1521136300.287655566,-0.000123840,-0.000069160,0.000028337,0.230,0.001,0.036,0.000451237,0.001032500,64.2,Normal"
)

func newDocFixture() *docFixture {
	return &docFixture{board: okBoard, info: okInfo, ifaces: okIfaces, wireless: okWireless, procd: okProcd, rc: okRC,
		connCount: "100", connMax: "1000", kernelPkg: okKernel, chronyc: okTracking, failing: map[string]bool{}}
}

func (d *docFixture) install(t *testing.T) *fakeRouter {
	t.Helper()
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	on := func(argv, out string) {
		if d.failing[argv] {
			f.fail(argv, "boom")
			return
		}
		f.on(argv, out)
	}
	on("ubus call system board", d.board)
	on("ubus call system info", d.info)
	on("ubus call network.interface dump", d.ifaces)
	on("ubus call network.wireless status", d.wireless)
	on("ubus call service list", d.procd)
	on("ubus call rc list", d.rc)
	on("apk list --installed kernel", d.kernelPkg)
	if d.connCount != "" {
		writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_count", d.connCount+"\n")
		writeFixture(t, root, "proc/sys/net/netfilter/nf_conntrack_max", d.connMax+"\n")
	}
	if d.chronyc != "" {
		writeFixture(t, root, "usr/bin/chronyc", "#!/bin/sh\n")
		on("chronyc -c tracking", d.chronyc)
	}
	for _, p := range d.apkNew {
		writeFixture(t, root, p, "x\n")
	}
	return f
}

func findingIDs(r *findingsRun) string {
	var ids []string
	for _, f := range r.findings {
		ids = append(ids, f.id)
	}
	return strings.Join(ids, ",")
}

func (r *findingsRun) byID(id string) *finding {
	for i := range r.findings {
		if r.findings[i].id == id {
			return &r.findings[i]
		}
	}
	return nil
}

func TestDoctorFindsNothingOnAHealthyRouter(t *testing.T) {
	newDocFixture().install(t)
	r := healthFindings(context.Background())
	if len(r.findings) != 0 || len(r.skipped) != 0 {
		t.Fatalf("a healthy router got findings %q, skipped %v", findingIDs(r), r.skipped)
	}
	out := r.render()
	if !strings.HasPrefix(out, "doctor: no findings") || !strings.Contains(out, "checked: ") || !strings.Contains(out, "nothing was changed") {
		t.Errorf("render:\n%s", out)
	}
	for _, want := range []string{"radios", "interfaces", "services", "conntrack", "storage", "apk-new", "ntp", "kernel"} {
		if !strings.Contains(out, want) {
			t.Errorf("the list of what was checked misses %q:\n%s", want, out)
		}
	}
}

func TestDoctorFindings(t *testing.T) {
	type tc struct {
		name string
		mut  func(d *docFixture)
		id   string
		sev  severity
		ev   string // a word the evidence must contain
	}
	badWireless := func(radio1 string) func(d *docFixture) {
		return func(d *docFixture) {
			d.wireless = `{"radio0":{"up":true,"disabled":false,"interfaces":[]},"radio1":` + radio1 + `}`
		}
	}
	conn := func(count string) func(d *docFixture) {
		return func(d *docFixture) { d.connCount = count }
	}
	storage := func(rootAvail, tmpAvail int) func(d *docFixture) {
		return func(d *docFixture) {
			d.info = fmt.Sprintf(`{"localtime":1791429618,"root":{"total":100000,"avail":%d},"tmp":{"total":500000,"avail":%d}}`, rootAvail, tmpAvail)
		}
	}
	cases := []tc{
		{"radio down", badWireless(`{"up":false,"disabled":false,"interfaces":[]}`), "radio-down", sevMedium, "radio1"},
		{"radio whose setup failed", badWireless(`{"up":false,"disabled":false,"retry_setup_failed":true,"interfaces":[]}`), "radio-down", sevHigh, "radio1"},
		{"interface up without an address", func(d *docFixture) {
			d.ifaces = `{"interface":[{"interface":"wan","up":true,"proto":"dhcp"}]}`
		}, "iface-no-address", sevMedium, "wan"},
		{"interface that reports an error", func(d *docFixture) {
			d.ifaces = `{"interface":[{"interface":"wan","up":false,"proto":"pppoe","errors":[{"code":"AUTH_FAILED"}]}]}`
		}, "iface-error", sevMedium, "AUTH_FAILED"},
		{"enabled daemon that died", func(d *docFixture) {
			d.procd = `{"adguardhome":{"instances":{"adguardhome":{"running":false,"exit_code":1}}}}`
		}, "service-crashed", sevMedium, "adguardhome"},
		{"conntrack at 80%", conn("800"), "conntrack-high", sevMedium, "800/1000"},
		{"conntrack at 95%", conn("950"), "conntrack-high", sevHigh, "950/1000"},
		{"overlay with 9% free", storage(9000, 450000), "overlay-full", sevMedium, "9%"},
		{"overlay with 4% free", storage(4000, 450000), "overlay-full", sevHigh, "4%"},
		{"overlay with exactly 5% free", storage(5000, 450000), "overlay-full", sevMedium, "5%"},
		{"tmp with 9% free", storage(90000, 45000), "tmp-full", sevLow, "9%"},
		{"pending .apk-new", func(d *docFixture) { d.apkNew = []string{"etc/config/dhcp.apk-new"} }, "apk-new-pending", sevLow, "/etc/config/dhcp.apk-new"},
		{"chrony not synchronised", func(d *docFixture) {
			d.chronyc = "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,0.000000000,0.000000000,0.0,Not synchronised"
		}, "ntp-unsynced", sevMedium, "Not synchronised"},
		{"clock never set", func(d *docFixture) {
			d.chronyc = ""
			d.info = `{"localtime":1000,"root":{"total":100000,"avail":90000},"tmp":{"total":500000,"avail":450000}}`
		}, "clock-unset", sevMedium, "1970"},
		{"newer kernel installed than running", func(d *docFixture) {
			d.board = strings.Replace(okBoard, "6.12.94", "6.12.93", 1)
		}, "reboot-needed", sevMedium, "6.12.93"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDocFixture()
			c.mut(d)
			d.install(t)
			r := healthFindings(context.Background())
			f := r.byID(c.id)
			if f == nil {
				t.Fatalf("no %s finding; got %q (skipped %v)", c.id, findingIDs(r), r.skipped)
			}
			if f.sev != c.sev {
				t.Errorf("severity = %v, want %v", f.sev, c.sev)
			}
			if !strings.Contains(f.evidence, c.ev) {
				t.Errorf("evidence %q lacks %q", f.evidence, c.ev)
			}
			if f.msg == "" || f.next == "" {
				t.Errorf("a finding needs a message and a next step: %+v", f)
			}
		})
	}
}

// What must NOT raise a finding: the same inputs one step on the safe side of each line.
func TestDoctorStaysQuietOnTheSafeSideOfEveryLine(t *testing.T) {
	cases := []struct {
		name string
		mut  func(d *docFixture)
	}{
		{"radio the user disabled", func(d *docFixture) {
			d.wireless = `{"radio0":{"up":false,"disabled":true,"interfaces":[]}}`
		}},
		{"conntrack at 79%", func(d *docFixture) { d.connCount = "799" }},
		{"overlay with exactly 10% free", func(d *docFixture) {
			d.info = `{"localtime":1791429618,"root":{"total":100000,"avail":10000},"tmp":{"total":500000,"avail":450000}}`
		}},
		{"tmp with exactly 10% free", func(d *docFixture) {
			d.info = `{"localtime":1791429618,"root":{"total":100000,"avail":90000},"tmp":{"total":500000,"avail":50000}}`
		}},
		{"one-shot init script that exited cleanly", func(d *docFixture) {
			d.procd = `{"podkop":{"instances":{"instance1":{"running":false,"exit_code":0}}}}`
		}},
		{"service that stopped without an exit code", func(d *docFixture) {
			d.procd = `{"x":{"instances":{"x":{"running":false}}}}`
			d.rc = `{"x":{"enabled":true,"running":false}}`
		}},
		{"crashed service the user disabled", func(d *docFixture) {
			d.procd = `{"adguardhome":{"instances":{"adguardhome":{"running":false,"exit_code":1}}}}`
			d.rc = `{"adguardhome":{"enabled":false,"running":false}}`
		}},
		{"service with one instance still running", func(d *docFixture) {
			d.procd = `{"chronyd":{"instances":{"instance1":{"running":true},"instance2":{"running":false,"exit_code":1}}}}`
			d.rc = `{"chronyd":{"enabled":true,"running":true}}`
		}},
		{"interface that is down without an error", func(d *docFixture) {
			d.ifaces = `{"interface":[{"interface":"wg0","up":false,"proto":"wireguard"}]}`
		}},
		{"wireguard interface up with no address list", func(d *docFixture) {
			d.ifaces = `{"interface":[{"interface":"wg0","up":true,"proto":"wireguard"}]}`
		}},
		{"chrony synchronised with a different leap status", func(d *docFixture) {
			d.chronyc = strings.Replace(okTracking, "Normal", "Insert second", 1)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDocFixture()
			c.mut(d)
			d.install(t)
			r := healthFindings(context.Background())
			if len(r.findings) != 0 {
				t.Errorf("got findings %q: %+v", findingIDs(r), r.findings)
			}
		})
	}
}

// The line is "at or above 80%": 799 of 1000 is quiet and 800 is not; 949 is medium and 950 high.
func TestConntrackThresholdsAreExact(t *testing.T) {
	for _, c := range []struct {
		count string
		id    string
		sev   severity
	}{{"799", "", 0}, {"800", "conntrack-high", sevMedium}, {"949", "conntrack-high", sevMedium}, {"950", "conntrack-high", sevHigh}, {"1000", "conntrack-high", sevHigh}} {
		d := newDocFixture()
		d.connCount = c.count
		d.install(t)
		f := healthFindings(context.Background()).byID("conntrack-high")
		switch {
		case c.id == "" && f != nil:
			t.Errorf("count %s raised %+v", c.count, *f)
		case c.id != "" && (f == nil || f.sev != c.sev):
			t.Errorf("count %s: got %v, want %v", c.count, f, c.sev)
		}
	}
}

// A check that cannot get its data is reported as not checked, never as a finding and never as a
// silent pass, and the other checks still run.
func TestDoctorSaysWhatItCouldNotCheck(t *testing.T) {
	d := newDocFixture()
	d.failing["ubus call network.wireless status"] = true
	d.connCount = ""
	d.chronyc = ""
	d.install(t)
	r := healthFindings(context.Background())
	if len(r.findings) != 0 {
		t.Errorf("a failed command became a finding: %q", findingIDs(r))
	}
	joined := strings.Join(r.skipped, "\n")
	for _, want := range []string{"radios", "conntrack"} {
		if !strings.Contains(joined, want) {
			t.Errorf("skipped list misses %q: %v", want, r.skipped)
		}
	}
	out := r.render()
	if !strings.Contains(out, "not checked: ") || !strings.Contains(out, "radios") {
		t.Errorf("render must list what was not checked:\n%s", out)
	}
	if !strings.Contains(out, "interfaces") {
		t.Errorf("the checks that could run were dropped:\n%s", out)
	}
	// Without chronyc the doctor can only judge the clock, and says so.
	if !strings.Contains(out, "ntp: no chronyc") {
		t.Errorf("limit of the NTP check not stated:\n%s", out)
	}
}

func TestFindingsAreRankedBySeverityThenId(t *testing.T) {
	r := &findingsRun{title: "doctor", findings: []finding{
		{sev: sevLow, id: "b-low", msg: "m", next: "n"},
		{sev: sevHigh, id: "z-high", msg: "m", next: "n"},
		{sev: sevMedium, id: "m-med", msg: "m", next: "n"},
		{sev: sevHigh, id: "a-high", msg: "m", next: "n"},
	}}
	out := r.render()
	if !strings.HasPrefix(out, "doctor: 4 findings (2 high, 1 medium, 1 low); advisory") {
		t.Errorf("header:\n%s", out)
	}
	order := []string{"[high] a-high", "[high] z-high", "[medium] m-med", "[low] b-low"}
	last := -1
	for _, o := range order {
		i := strings.Index(out, o)
		if i < 0 || i < last {
			t.Fatalf("%q is missing or out of order in:\n%s", o, out)
		}
		last = i
	}
}

// Every next step names a tool that exists, and every doc link is one that was opened by hand.
func TestFindingNextStepsNameRealToolsAndDocsAreVerified(t *testing.T) {
	re := regexp.MustCompile(`\b(?:uci|pkg|wg|mfa|net|service|system|ubus|firewall|network)_[a-z_]+\b`)
	for id, h := range allFindingHints() {
		for _, name := range re.FindAllString(h.next, -1) {
			if !contains(allToolNames, name) {
				t.Errorf("finding %s: next step names %q, which is not a tool", id, name)
			}
		}
		if h.doc != "" && !contains(verifiedDocs, h.doc) {
			t.Errorf("finding %s: %s is not in verifiedDocs; open it, then add it", id, h.doc)
		}
	}
	for _, u := range verifiedDocs {
		if !strings.HasPrefix(u, "https://openwrt.org/docs/") {
			t.Errorf("%s is not an OpenWrt wiki page", u)
		}
	}
}

// Both modes are read-only by construction: whatever they run is something a read-only tool may
// run. This holds the doctor and the audit to the same oracle the golden calls are held to.
func TestDoctorAndAuditIssueOnlyReadOnlyCommands(t *testing.T) {
	check := func(t *testing.T, f *fakeRouter) {
		t.Helper()
		argvs := f.argvList()
		if len(argvs) == 0 {
			t.Fatal("nothing ran")
		}
		for _, argv := range argvs {
			if !readOnlyCommand(argv) {
				t.Errorf("a read-only mode ran %q", strings.Join(argv, " "))
			}
		}
	}
	t.Run("doctor", func(t *testing.T) {
		f := newDocFixture().install(t)
		healthFindings(context.Background())
		check(t, f)
		if !f.ran("chronyc -c tracking") {
			t.Error("the fixture no longer exercises the chrony path")
		}
	})
	t.Run("audit", func(t *testing.T) {
		a := newAuditFixture()
		a.network, a.wgdump = "network.wg0=interface\nnetwork.wg0.proto='wireguard'\n", ""
		f := a.install(t)
		auditFindings(context.Background())
		check(t, f)
		if !f.ran("apk audit") {
			t.Error("the fixture no longer exercises apk audit")
		}
	})
}

// doctor and audit are separately grantable: a client holding system_status for one of them does
// not get the other, and a '*' grant (what both presets give) covers all three.
func TestDoctorAndAuditAreSeparatelyGrantable(t *testing.T) {
	newDocFixture().install(t)
	grant := func(scope string) string {
		return "\nconfig policy\n\toption client 'c'\n\tlist tools 'system_status'\n\tlist scopes '" + scope + "'\n"
	}
	cs := connectClient(t, testServer(t, grant("doctor")), "c")
	if out, isErr := callText(t, cs, "system_status", map[string]any{"mode": "doctor"}); isErr || !strings.Contains(out, "\ndoctor: ") ||
		!strings.HasPrefix(out, "[untrusted text: ") {
		t.Errorf("a doctor grant should allow doctor: %v\n%s", isErr, out)
	}
	out, isErr := callText(t, cs, "system_status", map[string]any{"mode": "audit"})
	if !isErr || !strings.Contains(out, "openwrt-mcp allow c system_status 'audit'") {
		t.Errorf("a doctor grant must not allow audit, and the denial must name the grant to ask for:\n%s", out)
	}
	if out, isErr := callText(t, cs, "system_status", nil); isErr {
		t.Errorf("plain system_status keeps working under any grant: %s", out)
	}
	all := connectClient(t, testServer(t, grant("*")), "c")
	for _, mode := range []string{"doctor", "audit"} {
		if out, isErr := callText(t, all, "system_status", map[string]any{"mode": mode}); isErr {
			t.Errorf("a '*' grant must cover %s: %s", mode, out)
		}
	}
	if out, isErr := callText(t, all, "system_status", map[string]any{"mode": "everything"}); !isErr || !strings.Contains(out, "[code: VALIDATION]") {
		t.Errorf("a bad mode is a VALIDATION error:\n%s", out)
	}
}
