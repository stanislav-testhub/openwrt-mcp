package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Adapter verbs (ROADMAP 9.1, L3): scope per verb, risk classes in the presets, argument kinds
// validated before any argv is built, and a verb that does not change state fails.

func callControl(t *testing.T, in serviceControlIn) (string, error) {
	t.Helper()
	out, _, err := serviceControl(context.Background(), in)
	return out, err
}

func TestVerbLineNamesEachVerbAndItsRisk(t *testing.T) {
	f, _ := wave1Router(t)
	f.on("pidof banip", "")
	out := strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: "banip"})), "\n")
	wantAll(t, out, "service_control verbs: refresh (routine); unban arg=ip (routine)")
	if l := verbLine("mwan3"); !strings.Contains(l, "ifdown arg=iface (disruptive, needs its own grant)") {
		t.Errorf("mwan3 verbs: %q", l)
	}
}

func TestRoutineVerbsAreInOperatorAndDisruptiveOnesAreNot(t *testing.T) {
	var scopes []string
	for _, b := range presets["operator"] {
		if contains(b.tools, "service_control") {
			scopes = b.scopes
		}
	}
	for _, want := range []string{"adblock.refresh", "banip.unban", "banip.refresh", "adblock-fast.refresh", "dnsmasq.restart"} {
		if !matchAny(scopes, want) {
			t.Errorf("@operator does not cover %s", want)
		}
	}
	for _, not := range []string{"adblock.suspend", "adblock-fast.pause", "mwan3.ifdown", "mwan3.ifup", "adblock.resume"} {
		if matchAny(scopes, not) {
			t.Errorf("@operator covers the disruptive verb %s", not)
		}
	}
	if matchAny(presets["readonly"][0].scopes, "x") && contains(presets["readonly"][0].tools, "service_control") {
		t.Error("@readonly grants service_control")
	}
}

func TestEveryVerbIsOnARegisteredAdapter(t *testing.T) {
	for _, v := range adapterVerbs {
		if _, ok := adapterFor(v.service); !ok {
			t.Errorf("verb %s %s is on %s, which has no adapter", v.service, v.name, v.service)
		}
	}
}

func TestInitScriptVerbRunsTheFixedCommand(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"adblock":{"enabled":true,"running":true,"start":30,"stop":4}}`)
	f.on("/etc/init.d/adblock reload", "")
	out, err := callControl(t, serviceControlIn{Name: "adblock", Action: "refresh"})
	if err != nil || !strings.Contains(out, "adblock refresh: done") {
		t.Fatalf("out %q err %v", out, err)
	}
	if _, err := callControl(t, serviceControlIn{Name: "adblock", Action: "refresh", Arg: "x"}); err == nil {
		t.Error("an argument to an argument-less verb was accepted")
	}
}

func TestUnbanRemovesFromEverySetAndChecksTheResult(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"banip":{"enabled":true,"running":true,"start":99,"stop":0}}`)
	writeFixture(t, root, "var/run/banIP/banIP.runtime.json", `{"status":"enabled","active_feeds":["threat.v4","country.v4","allow.v6"]}`)
	banned := map[string]bool{"threat.v4": true, "country.v4": true}
	f.onFn("nft get element inet banIP", func(argv []string, _ string) (string, error) {
		if banned[argv[5]] {
			return "ok", nil
		}
		return "", errors.New("exit status 1")
	})
	f.onFn("nft delete element inet banIP", func(argv []string, _ string) (string, error) {
		delete(banned, argv[5])
		return "", nil
	})
	out, err := callControl(t, serviceControlIn{Name: "banip", Action: "unban", Arg: "203.0.113.9"})
	if err != nil || !strings.Contains(out, "removed from threat.v4, country.v4") {
		t.Fatalf("out %q err %v", out, err)
	}
	if _, err := callControl(t, serviceControlIn{Name: "banip", Action: "unban", Arg: "203.0.113.9"}); err == nil {
		t.Error("unban of an address that is not banned succeeded")
	}
}

func TestUnbanThatLeavesTheAddressBannedFails(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"banip":{"enabled":true,"running":true,"start":99,"stop":0}}`)
	writeFixture(t, root, "var/run/banIP/banIP.runtime.json", `{"active_feeds":["threat.v4"]}`)
	f.on("nft get element inet banIP", "ok")
	f.on("nft delete element inet banIP", "")
	if _, err := callControl(t, serviceControlIn{Name: "banip", Action: "unban", Arg: "203.0.113.9"}); err == nil || !strings.Contains(err.Error(), "still in") {
		t.Errorf("a no-op unban reported success: %v", err)
	}
}

func TestVerbArgumentsAreValidatedByKind(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"banip":{"enabled":true,"running":true,"start":99,"stop":0},"mwan3":{"enabled":true,"running":true,"start":19,"stop":1}}`)
	f.on("uci -q show mwan3", "mwan3.wan=interface\n")
	for _, bad := range []string{"1.2.3.4; reboot", "-h", "example.com", ""} {
		if _, err := callControl(t, serviceControlIn{Name: "banip", Action: "unban", Arg: bad}); err == nil {
			t.Errorf("unban accepted %q", bad)
		}
	}
	for _, bad := range []string{"wan; reboot", "../x", "nosuch", ""} {
		if _, err := callControl(t, serviceControlIn{Name: "mwan3", Action: "ifdown", Arg: bad}); err == nil {
			t.Errorf("ifdown accepted %q", bad)
		}
	}
	for _, a := range f.argvList() {
		if strings.Contains(strings.Join(a, " "), "reboot") || a[0] == "mwan3" {
			t.Errorf("a bad argument reached a command: %v", a)
		}
	}
}

func TestMwan3IfdownRunsForAKnownInterface(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"mwan3":{"enabled":true,"running":true,"start":19,"stop":1}}`)
	f.on("uci -q show mwan3", "mwan3.wanb=interface\n")
	f.on("mwan3 ifdown wanb", "")
	if _, err := callControl(t, serviceControlIn{Name: "mwan3", Action: "ifdown", Arg: "wanb"}); err != nil {
		t.Fatal(err)
	}
}

func TestStandardActionsRejectAnArgAndUnknownVerbsListTheOnesThatExist(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"banip":{"enabled":true,"running":true,"start":99,"stop":0}}`)
	if _, err := callControl(t, serviceControlIn{Name: "banip", Action: "restart", Arg: "x"}); err == nil {
		t.Error("arg accepted for a standard action")
	}
	_, err := callControl(t, serviceControlIn{Name: "banip", Action: "explode"})
	if err == nil || !strings.Contains(err.Error(), "refresh, unban") {
		t.Errorf("unknown verb error: %v", err)
	}
}

func TestBanIPRefreshExplainsADisabledBanIP(t *testing.T) {
	f, root := wave1Router(t)
	writeFixture(t, root, "var/run/banip_runtime.json", `{"status":"disabled","version":"1.5.6-r7"}`)
	f.fail("/etc/init.d/banip reload", "")
	v, _ := verbFor("banip", "refresh")
	_, _, err := runVerb(context.Background(), v, "")
	if err == nil || !strings.Contains(err.Error(), "banIP is disabled") {
		t.Fatalf("err = %v", err)
	}
	for _, c := range f.argvList() {
		if strings.Contains(strings.Join(c, " "), "init.d/banip") {
			t.Errorf("reload was run on a disabled banIP: %v", c)
		}
	}
}

func TestDDNSUpdateClearsTheLastSendRecordOfEnabledServicesAndRestarts(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"ddns":{"enabled":true,"running":true,"start":95,"stop":10}}`)
	f.on("uci -q show ddns", "ddns.global=ddns\nddns.lab=service\nddns.lab.enabled='1'\nddns.off=service\nddns.off.enabled='0'\nddns.global.ddns_rundir='/var/run/ddns'\n")
	f.on("rm -f /var/run/ddns/lab.update", "")
	f.on("/etc/init.d/ddns restart", "")
	out, err := callControl(t, serviceControlIn{Name: "ddns", Action: "update"})
	if err != nil || !strings.Contains(out, "ddns update: done") || !strings.Contains(out, "for lab;") {
		t.Fatalf("out %q err %v", out, err)
	}
	var cmds []string
	for _, a := range f.argvList() {
		cmds = append(cmds, strings.Join(a, " "))
	}
	all := strings.Join(cmds, "\n")
	if strings.Contains(all, "off.update") {
		t.Errorf("the disabled service was touched:\n%s", all)
	}
	if strings.Index(all, "rm -f /var/run/ddns/lab.update") > strings.Index(all, "/etc/init.d/ddns restart") {
		t.Errorf("restart ran before the record was cleared:\n%s", all)
	}
}

func TestDDNSUpdateWithNoEnabledServiceFailsWithoutRunningAnything(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"ddns":{"enabled":true,"running":true,"start":95,"stop":10}}`)
	f.on("uci -q show ddns", "ddns.lab=service\nddns.lab.enabled='0'\n")
	if _, err := callControl(t, serviceControlIn{Name: "ddns", Action: "update"}); err == nil || !strings.Contains(err.Error(), "no enabled ddns service") {
		t.Fatalf("err %v", err)
	}
	for _, a := range f.argvList() {
		if a[0] == "rm" || a[0] == "/etc/init.d/ddns" {
			t.Errorf("ran %v", a)
		}
	}
}

const upnpLeases2 = "TCP:18080:192.168.1.50:8080:1794502827:miniupnpc\nUDP:19000:192.168.1.50:9000:1793901629:test video\n"

func upnpRouter(t *testing.T) (*fakeRouter, string) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call rc list", `{"miniupnpd":{"enabled":true,"running":true,"start":94,"stop":15}}`)
	f.on("uci -q show upnpd", "upnpd.config=upnpd\nupnpd.config.upnp_lease_file='/var/run/miniupnpd.leases'\n")
	writeFixture(t, root, "var/run/miniupnpd.leases", upnpLeases2)
	return f, filepath.Join(root, "var/run/miniupnpd.leases")
}

func TestUPnPUnmapDropsOneLeaseAndRestartsTheDaemon(t *testing.T) {
	f, lease := upnpRouter(t)
	f.onFn("sed -i", func(argv []string, _ string) (string, error) {
		if argv[3] != "/^TCP:18080:/d" || argv[4] != "/var/run/miniupnpd.leases" {
			t.Errorf("sed argv %v", argv)
		}
		return "", os.WriteFile(lease, []byte("UDP:19000:192.168.1.50:9000:1793901629:test video\n"), 0o644)
	})
	f.on("/etc/init.d/miniupnpd restart", "")
	out, err := callControl(t, serviceControlIn{Name: "miniupnpd", Action: "unmap", Arg: " tcp:18080 "})
	if err != nil || !strings.Contains(out, "miniupnpd unmap TCP:18080: done") {
		t.Fatalf("out %q err %v", out, err)
	}
	var cmds []string
	for _, a := range f.argvList() {
		cmds = append(cmds, strings.Join(a, " "))
	}
	all := strings.Join(cmds, "\n")
	if strings.Index(all, "sed -i") > strings.Index(all, "/etc/init.d/miniupnpd restart") || !strings.Contains(all, "sed -i") {
		t.Errorf("the lease must be edited before the restart:\n%s", all)
	}
}

func TestUPnPUnmapRefusesWhatIsNotMappedOrNotAMapping(t *testing.T) {
	f, _ := upnpRouter(t)
	if _, err := callControl(t, serviceControlIn{Name: "miniupnpd", Action: "unmap", Arg: "tcp:19000"}); err == nil || !strings.Contains(err.Error(), "no UPnP mapping TCP 19000") {
		t.Errorf("err %v", err)
	}
	for _, bad := range []string{"", "18080", "tcp:", "tcp:0", "tcp:65536", "tcp:018080", "icmp:80", "tcp:80;rm", "tcp:8080/../x", "tcp:-1"} {
		if _, err := callControl(t, serviceControlIn{Name: "miniupnpd", Action: "unmap", Arg: bad}); err == nil {
			t.Errorf("unmap accepted %q", bad)
		}
	}
	for _, a := range f.argvList() {
		if a[0] == "sed" || a[0] == "/etc/init.d/miniupnpd" {
			t.Errorf("ran %v", a)
		}
	}
}

func TestUPnPUnmapReportsAMappingThatIsBackAfterTheRestart(t *testing.T) {
	f, _ := upnpRouter(t)
	f.on("sed -i", "")
	f.on("/etc/init.d/miniupnpd restart", "")
	if _, err := callControl(t, serviceControlIn{Name: "miniupnpd", Action: "unmap", Arg: "tcp:18080"}); err == nil || !strings.Contains(err.Error(), "is back in the lease file") {
		t.Errorf("a failed removal was reported as done: %v", err)
	}
}
