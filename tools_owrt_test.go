package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkClientsJoinsLeasesNeighboursAndWifi(t *testing.T) {
	root := withFixtureRoot(t)
	exp := time.Now().Add(2 * time.Hour).Unix()
	writeFixture(t, root, "tmp/dhcp.leases",
		fmtInt(exp)+" aa:bb:cc:00:00:01 192.168.1.10 phone *\n"+
			"0 aa:bb:cc:00:00:02 192.168.10.20 printer *\n")
	f := newFakeRouter(t)
	f.on("uci -q show dhcp", "dhcp.nas=host\ndhcp.nas.name='nas'\ndhcp.nas.mac='AA:BB:CC:00:00:03'\ndhcp.nas.ip='192.168.1.5'\n"+
		"dhcp.gone=host\ndhcp.gone.name='gone'\ndhcp.gone.mac='AA:BB:CC:00:00:09'\n")
	f.on("ip -j neigh show", `[{"dst":"192.168.1.5","dev":"br-lan","lladdr":"aa:bb:cc:00:00:03","state":["REACHABLE"]},
		{"dst":"fe80::1","dev":"br-lan","lladdr":"aa:bb:cc:00:00:01","state":["STALE"]}]`)
	f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0","phy1-sta0"]}`)
	f.on(`ubus call iwinfo info {"device":"phy0-ap0"}`, `{"ssid":"Home","mode":"Master"}`)
	f.on(`ubus call iwinfo info {"device":"phy1-sta0"}`, `{"ssid":"Upstream","mode":"Client"}`)
	f.on(`ubus call iwinfo assoclist {"device":"phy0-ap0"}`,
		`{"results":[{"mac":"AA:BB:CC:00:00:01","signal":-61,"connected_time":3600,"rx":{"rate":144000},"tx":{"rate":72000}}]}`)

	out, _, err := networkClients(context.Background(), networkClientsIn{})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	find := func(host string) string {
		for _, l := range lines {
			if strings.HasPrefix(l, host+" ") {
				return l
			}
		}
		t.Fatalf("no row for %s:\n%s", host, out)
		return ""
	}
	phone := find("phone")
	for _, want := range []string{"192.168.1.10", "Home(phy0-ap0)", "-61dBm", "1h0m0s", "144/72M"} {
		if !strings.Contains(phone, want) {
			t.Errorf("phone row missing %q: %s", want, phone)
		}
	}
	if strings.Contains(phone, "fe80") {
		t.Error("link-local neighbour address listed as a client IP")
	}
	if !strings.Contains(find("nas"), "static") || !strings.Contains(find("printer"), "infinite") {
		t.Errorf("lease column wrong:\n%s", out)
	}
	if strings.Contains(out, "gone") {
		t.Error("a static lease for an absent device was listed as a client")
	}
	if !strings.HasPrefix(lines[1], "phone") {
		t.Error("wireless clients should sort first")
	}
	// The station interface is not an AP; its association list is not ours to list.
	if f.ran(`ubus call iwinfo assoclist {"device":"phy1-sta0"}`) {
		t.Error("queried clients of a non-AP interface")
	}
}

func TestLogreadFiltersBeforeLimiting(t *testing.T) {
	f := newFakeRouter(t)
	var log []string
	for i := 0; i < 500; i++ {
		log = append(log, "Tue Sep 30 12:00:00 2026 daemon.info dnsmasq[1]: noise")
	}
	log = append(log, "Tue Sep 30 12:00:01 2026 daemon.err hostapd: phy0-ap0: DFS radar detected")
	for i := 0; i < 500; i++ {
		log = append(log, "Tue Sep 30 12:00:02 2026 daemon.info dnsmasq[1]: noise")
	}
	f.on("logread", strings.Join(log, "\n"))
	out, _, err := logread(context.Background(), logreadIn{Lines: 10, Pattern: "RADAR"})
	if err != nil || !strings.Contains(out, "DFS radar") {
		t.Fatalf("a rare line was lost behind noise: %v\n%s", err, out)
	}
	out, _, _ = logread(context.Background(), logreadIn{Lines: 5, Regex: `dnsmasq\[\d\]`})
	if !strings.Contains(out, "[1000 matching lines, showing the last 5]") {
		t.Errorf("limit not reported: %.200s", out)
	}
	if _, _, err := logread(context.Background(), logreadIn{Regex: "("}); err == nil {
		t.Error("bad regex accepted")
	}
}

func TestLogreadSince(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", "Tue Sep 30 10:00:00 2026 old\nTue Sep 30 11:55:00 2026 new\n")
	f.on("date", "2026-09-30 12:00:00\n")
	out, _, _ := logread(context.Background(), logreadIn{Since: 10})
	if strings.Contains(out, "old") || !strings.Contains(out, "new") {
		t.Errorf("since filter wrong:\n%s", out)
	}
}

func TestServiceControlRefusesToCutTheLifeline(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"dropbear":{"enabled":true,"running":true},"network":{"enabled":true}}`)
	for _, in := range []serviceControlIn{{Name: "dropbear", Action: "stop"}, {Name: "network", Action: "disable"}, {Name: "openwrt-mcp", Action: "stop"}} {
		if _, _, err := serviceControl(context.Background(), in); err == nil {
			t.Errorf("%s %s was allowed", in.Action, in.Name)
		}
	}
	if f.ran("ubus call rc init") {
		t.Error("rc init reached for a refused action")
	}
	f.on("ubus call rc init", "")
	if _, _, err := serviceControl(context.Background(), serviceControlIn{Name: "dropbear", Action: "restart"}); err != nil {
		t.Errorf("restart of dropbear should be allowed: %v", err)
	}
	if _, _, err := serviceControl(context.Background(), serviceControlIn{Name: "nosuch", Action: "restart"}); err == nil {
		t.Error("unknown service accepted")
	}
}

func TestNetDiagRejectsOptionInjection(t *testing.T) {
	newFakeRouter(t)
	for _, target := range []string{"-f", "--help", "a b", "x;reboot", ""} {
		if _, _, err := netDiag(context.Background(), netDiagIn{Action: "ping", Target: target}); err == nil {
			t.Errorf("target %q accepted", target)
		}
	}
	if _, _, err := netDiag(context.Background(), netDiagIn{Action: "ping", Target: "1.1.1.1", Iface: "-x"}); err == nil {
		t.Error("iface starting with '-' accepted")
	}
}

func TestNetDiagPingLossIsAnAnswerNotAnError(t *testing.T) {
	f := newFakeRouter(t)
	f.fail("ping -c 4 -W 2 -I br-WAN 192.0.2.1", "4 packets transmitted, 0 received, 100% packet loss")
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "ping", Target: "192.0.2.1", Iface: "br-WAN"})
	if err != nil || !strings.Contains(out, "100% packet loss") {
		t.Errorf("got %v / %q", err, out)
	}
}

func TestCompactApkList(t *testing.T) {
	in := "luci-26.270.72870~a24d1f2 noarch {feeds/luci/feeds/luci/collections/luci} (Apache-2.0) [upgradable from: luci-26.268.33051~dd3d1cb]\n" +
		"dnsmasq-2.93-r1 aarch64_cortex-a53 {feeds/base/network/services/dnsmasq} (GPL-2.0) [installed]\n"
	out := compactApkList(in)
	if !strings.Contains(out, "luci-26.270.72870~a24d1f2 [upgradable from: luci-26.268.33051~dd3d1cb]") ||
		!strings.Contains(out, "dnsmasq-2.93-r1\n") || strings.Contains(out, "feeds/") || !strings.Contains(out, "(2 packages)") {
		t.Errorf("compact list:\n%s", out)
	}
}

func TestPkgChangeSimulatesUnlessCommitted(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk update", "OK")
	f.on("apk --simulate add tcpdump", "(1/1) Installing tcpdump")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}})
	if err != nil || !strings.Contains(out, "SIMULATION") {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.ran("apk add") {
		t.Error("a simulation installed the package")
	}
	if _, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"--force-broken-world"}}); err == nil {
		t.Error("an option smuggled in as a package name")
	}
}

func TestPkgChangeReportsNewApkNewFiles(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk update", "OK")
	f.onFn("apk add dnsmasq-full", func([]string, string) (string, error) {
		writeFixture(t, root, "etc/config/dhcp.apk-new", "x")
		return "OK", nil
	})
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"dnsmasq-full"}, Commit: true})
	if err != nil || !strings.Contains(out, "/etc/config/dhcp.apk-new") {
		t.Errorf("new .apk-new not reported: %v\n%s", err, out)
	}
}

func TestPkgChangeScope(t *testing.T) {
	if got := pkgChangeScope(pkgChangeIn{Action: "upgrade"}); len(got) != 1 || got[0] != "upgrade" {
		t.Errorf("full upgrade scope = %v", got)
	}
	got := pkgChangeScope(pkgChangeIn{Action: "add", Packages: []string{"a", "b"}})
	if strings.Join(got, " ") != "add.a add.b" {
		t.Errorf("scopes = %v", got)
	}
}

func TestPkgConfigDiffAndKeepCurrent(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/luci", "config core main\n\toption lang 'auto'\n\toption mediaurlbase '/luci-static/bootstrap'\n")
	writeFixture(t, root, "etc/config/luci.apk-new", "config core main\n\toption lang 'auto'\n\toption mediaurlbase '/luci-static/openwrt2020'\n")
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf", "same\n")
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf.apk-new", "same\n")
	out, _, err := pkgConfigDiff(context.Background(), pkgConfigDiffIn{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 .apk-new", "-\toption mediaurlbase '/luci-static/bootstrap'",
		"+\toption mediaurlbase '/luci-static/openwrt2020'", "identical"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output missing %q:\n%s", want, out)
		}
	}
	s := testServer(t, "")
	if _, _, err := s.pkgConfigResolve(context.Background(), "c", pkgConfigResolveIn{Path: "/etc/avahi/avahi-daemon.conf", Action: "keep_current"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/avahi/avahi-daemon.conf.apk-new")); !os.IsNotExist(err) {
		t.Error(".apk-new not removed")
	}
	if _, _, err := s.pkgConfigResolve(context.Background(), "c", pkgConfigResolveIn{Path: "/etc/../etc/shadow", Action: "use_new"}); err == nil {
		t.Error("a path with no .apk-new was accepted")
	}
}

func TestUnifiedDiff(t *testing.T) {
	a := strings.Split("1\n2\n3\n4\n5\n6\n7\n8\n9", "\n")
	b := strings.Split("1\n2\n3\n4\nX\n6\n7\n8\n9\n10", "\n")
	d := unifiedDiff(a, b, 1)
	want := "@@ line 4 @@\n 4\n-5\n+X\n 6\n@@ line 9 @@\n 9\n+10"
	if d != want {
		t.Errorf("diff:\n%s\nwant:\n%s", d, want)
	}
	if unifiedDiff(a, a, 2) != "" {
		t.Error("identical inputs produced a diff")
	}
}

func TestSysupgradeNeverFlashesAndConfinesTest(t *testing.T) {
	newFakeRouter(t)
	if _, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "flash"}); err == nil {
		t.Error("an unknown action (flash) was accepted")
	}
	for _, img := range []string{"/etc/passwd", "/tmp/../etc/x", "relative.bin"} {
		if _, _, err := sysupgradeTool(context.Background(), sysupgradeIn{Action: "test", Image: img}); err == nil {
			t.Errorf("test accepted image %q outside /tmp", img)
		}
	}
}

func TestFirewallShowValidatesNames(t *testing.T) {
	f := newFakeRouter(t)
	f.on("nft list chain inet fw4 forward_lan", "chain forward_lan {}")
	if out, _, err := firewallShow(context.Background(), firewallShowIn{View: "chain", Chain: "forward_lan"}); err != nil || !strings.Contains(out, "forward_lan") {
		t.Errorf("%v %s", err, out)
	}
	if _, _, err := firewallShow(context.Background(), firewallShowIn{View: "chain", Chain: "x; flush ruleset"}); err == nil {
		t.Error("chain name with nft syntax accepted")
	}
}

func TestSystemStatusDegradesPerSection(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "sys/class/hwmon/hwmon0/name", "cpu_thermal\n")
	writeFixture(t, root, "sys/class/hwmon/hwmon0/temp1_input", "50831\n")
	writeFixture(t, root, "etc/config/dhcp.apk-new", "x")
	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"GL.iNet GL-MT6000","board_name":"glinet,gl-mt6000","kernel":"6.12.94","hostname":"OpenWrt","release":{"description":"OpenWrt 25.12.5"}}`)
	f.on("uci changes", "")
	s := testServer(t, "")
	out, _, err := s.systemStatus(context.Background(), systemStatusIn{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"GL-MT6000", "OpenWrt 25.12.5", "cpu_thermal 50.8C", "1 .apk-new", "interfaces:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// A router-rewritten UCI file and the package's hand-formatted default must compare by
// setting, not by quoting and tabs.
func TestPkgConfigDiffIgnoresUCIFormatting(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/luci", "config core 'main'\n\toption lang 'auto'\n")
	writeFixture(t, root, "etc/config/luci.apk-new", "config core main\n    option lang   auto\n")
	f := newFakeRouter(t)
	// Stand-in for uci's parser: read the private copy and emit one normalised line per word run.
	f.onFn("uci -q -c", func(argv []string, _ string) (string, error) {
		b, err := os.ReadFile(filepath.Join(filepath.FromSlash(argv[3]), argv[len(argv)-1]))
		if err != nil {
			return "", err
		}
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.Join(strings.Fields(strings.ReplaceAll(l, "'", "")), " "); l != "" {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n"), nil
	})
	out, _, err := pkgConfigDiff(context.Background(), pkgConfigDiffIn{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "only formatting differs") {
		t.Errorf("formatting-only difference reported as a change:\n%s", out)
	}
	if !f.ran("uci -q -c") || strings.Contains(f.allCalls(), "/tmp/.uci") {
		t.Errorf("did not normalise through a private uci copy:\n%s", f.allCalls())
	}
}
