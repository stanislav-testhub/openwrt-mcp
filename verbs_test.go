package main

import (
	"context"
	"errors"
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
