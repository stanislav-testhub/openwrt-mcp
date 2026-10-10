package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Cross-config references (ROADMAP 5.10). Every expected value below is what the OpenWrt
// documentation says a field holds (firewall zone.network is a list of interfaces, rule.src a
// zone, and so on), not what refs.go happens to do.

func refTrees(cfgs map[string]string) map[string]*uciTree {
	out := map[string]*uciTree{}
	for c, show := range cfgs {
		out[c] = parseUCIShow(show)
	}
	return out
}

// refStrings flattens a result to "config.section[.option] target" lines.
func refStrings(r refResult) (defs, uses []string) {
	for _, d := range r.defs {
		defs = append(defs, d.config+"."+d.section+" "+d.target)
	}
	for _, u := range r.uses {
		p := u.config + "." + u.section
		if u.option != "" {
			p += "." + u.option
		}
		uses = append(uses, p+" "+u.target)
	}
	return defs, uses
}

var refCases = []struct {
	what, cfg, show, name string
	defs, uses            []string
}{
	// ---- network
	{"interface device names a device", "network", "network.lan=interface\nnetwork.lan.device='br-lan'", "br-lan",
		nil, []string{"network.lan.device device"}},
	{"interface device @name is an alias of an interface", "network", "network.wan6=interface\nnetwork.wan6.device='@wan'", "wan",
		nil, []string{"network.wan6.device interface"}},
	{"legacy ifname holds several devices", "network", "network.lan=interface\nnetwork.lan.ifname='eth0 eth1'", "eth1",
		nil, []string{"network.lan.ifname device"}},
	{"tunlink names an interface", "network", "network.six=interface\nnetwork.six.tunlink='wan'", "wan",
		nil, []string{"network.six.tunlink interface"}},
	{"device ports are devices", "network", "network.@device[0]=device\nnetwork.@device[0].name='br-lan'\nnetwork.@device[0].ports='lan1' 'lan2'", "lan2",
		nil, []string{"network.@device[0].ports device"}},
	{"a device is defined by its name option", "network", "network.@device[0]=device\nnetwork.@device[0].name='br-lan'\nnetwork.@device[0].ports='lan1'", "br-lan",
		[]string{"network.@device[0] device"}, nil},
	{"a vlan device's ifname is its parent device", "network", "network.@device[1]=device\nnetwork.@device[1].type='8021q'\nnetwork.@device[1].ifname='eth0'\nnetwork.@device[1].name='eth0.10'", "eth0",
		nil, []string{"network.@device[1].ifname device"}},
	{"bridge-vlan device", "network", "network.@bridge-vlan[0]=bridge-vlan\nnetwork.@bridge-vlan[0].device='br-lan'", "br-lan",
		nil, []string{"network.@bridge-vlan[0].device device"}},
	{"route interface", "network", "network.@route[0]=route\nnetwork.@route[0].interface='lan'", "lan",
		nil, []string{"network.@route[0].interface interface"}},
	{"route6 interface", "network", "network.@route6[0]=route6\nnetwork.@route6[0].interface='lan'", "lan",
		nil, []string{"network.@route6[0].interface interface"}},
	{"ip rule in", "network", "network.@rule[0]=rule\nnetwork.@rule[0].in='lan'\nnetwork.@rule[0].out='wan'", "lan",
		nil, []string{"network.@rule[0].in interface"}},
	{"ip rule out", "network", "network.@rule[0]=rule\nnetwork.@rule[0].in='lan'\nnetwork.@rule[0].out='wan'", "wan",
		nil, []string{"network.@rule[0].out interface"}},
	{"ip rule6 in", "network", "network.@rule6[0]=rule6\nnetwork.@rule6[0].in='lan'", "lan",
		nil, []string{"network.@rule6[0].in interface"}},
	{"ip rule6 out", "network", "network.@rule6[0]=rule6\nnetwork.@rule6[0].in='lan'\nnetwork.@rule6[0].out='wan'", "wan",
		nil, []string{"network.@rule6[0].out interface"}},
	{"an interface is a section of type interface", "network", "network.lan=interface\nnetwork.loopback=interface\nnetwork.globals=globals", "lan",
		[]string{"network.lan interface"}, nil},
	{"a legacy ifname @name is an alias of an interface too", "network", "network.wan6=interface\nnetwork.wan6.ifname='@wan'", "wan",
		nil, []string{"network.wan6.ifname interface"}},
	{"an interface is found by its exact section name", "network", "network.LAN=interface", "lan", nil, nil},
	{"a globals section is no interface", "network", "network.lan=interface\nnetwork.globals=globals", "globals",
		nil, nil},

	// ---- firewall
	{"zone network list, and the zone's own name", "firewall", "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan' 'lan6'", "lan6",
		nil, []string{"firewall.@zone[0].network interface"}},
	{"a zone is defined by its name option", "firewall", "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'", "lan",
		[]string{"firewall.@zone[0] zone"}, []string{"firewall.@zone[0].network interface"}},
	{"zone network as one space-separated option", "firewall", "firewall.@zone[0]=zone\nfirewall.@zone[0].network='lan lan6'", "lan6",
		nil, []string{"firewall.@zone[0].network interface"}},
	{"zone device", "firewall", "firewall.@zone[1]=zone\nfirewall.@zone[1].name='vpn'\nfirewall.@zone[1].device='wg0'", "wg0",
		nil, []string{"firewall.@zone[1].device device"}},
	{"a zone is found by its exact name", "firewall", "firewall.@zone[0]=zone\nfirewall.@zone[0].name='LAN'", "lan", nil, nil},
	{"an option of another config's rule is not a reference", "firewall", "firewall.@rule[0]=rule\nfirewall.@rule[0].in='lan'\nfirewall.@rule[0].use_policy='lan'", "lan",
		nil, nil},
	{"rule src", "firewall", "firewall.@rule[2]=rule\nfirewall.@rule[2].src='wan'\nfirewall.@rule[2].dest='lan'", "wan",
		nil, []string{"firewall.@rule[2].src zone"}},
	{"rule dest", "firewall", "firewall.@rule[2]=rule\nfirewall.@rule[2].src='wan'\nfirewall.@rule[2].dest='lan'", "lan",
		nil, []string{"firewall.@rule[2].dest zone"}},
	{"forwarding src", "firewall", "firewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='wan'", "lan",
		nil, []string{"firewall.@forwarding[0].src zone"}},
	{"forwarding dest", "firewall", "firewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='wan'", "wan",
		nil, []string{"firewall.@forwarding[0].dest zone"}},
	{"redirect src", "firewall", "firewall.@redirect[0]=redirect\nfirewall.@redirect[0].src='wan'\nfirewall.@redirect[0].dest='lan'", "wan",
		nil, []string{"firewall.@redirect[0].src zone"}},
	{"redirect dest", "firewall", "firewall.@redirect[0]=redirect\nfirewall.@redirect[0].src='wan'\nfirewall.@redirect[0].dest='lan'", "lan",
		nil, []string{"firewall.@redirect[0].dest zone"}},

	// ---- dhcp
	{"dhcp interface", "dhcp", "dhcp.lan=dhcp\ndhcp.lan.interface='lan'", "lan",
		nil, []string{"dhcp.lan.interface interface"}},
	{"dnsmasq interface list", "dhcp", "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].interface='lan' 'guest'", "guest",
		nil, []string{"dhcp.@dnsmasq[0].interface interface"}},
	{"dnsmasq notinterface list", "dhcp", "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].notinterface='wan'", "wan",
		nil, []string{"dhcp.@dnsmasq[0].notinterface interface"}},

	// ---- wireless
	{"wifi-iface network list", "wireless", "wireless.a=wifi-iface\nwireless.a.network='lan' 'guest'", "guest",
		nil, []string{"wireless.a.network interface"}},
	{"wifi-iface network as one space-separated option", "wireless", "wireless.a=wifi-iface\nwireless.a.network='lan guest'", "guest",
		nil, []string{"wireless.a.network interface"}},
	{"wifi-iface device is a radio", "wireless", "wireless.a=wifi-iface\nwireless.a.device='radio0'", "radio0",
		nil, []string{"wireless.a.device radio"}},
	{"a radio is a wifi-device section", "wireless", "wireless.radio0=wifi-device\nwireless.a=wifi-iface\nwireless.a.device='radio0'", "radio0",
		[]string{"wireless.radio0 radio"}, []string{"wireless.a.device radio"}},
	{"wifi-vlan network", "wireless", "wireless.@wifi-vlan[0]=wifi-vlan\nwireless.@wifi-vlan[0].network='guest'", "guest",
		nil, []string{"wireless.@wifi-vlan[0].network interface"}},

	// ---- sqm
	{"sqm queue interface is a device", "sqm", "sqm.eth1=queue\nsqm.eth1.interface='eth1'", "eth1",
		nil, []string{"sqm.eth1.interface device"}},

	// ---- mwan3
	{"an mwan3 interface section is named after the interface", "mwan3", "mwan3.wan=interface\nmwan3.wan.enabled='1'", "wan",
		nil, []string{"mwan3.wan interface"}},
	{"an mwan3 interface section for another interface is not a hit", "mwan3", "mwan3.wan=interface", "lan", nil, nil},
	{"mwan3 member interface", "mwan3", "mwan3.wan_m1=member\nmwan3.wan_m1.interface='wan'", "wan",
		nil, []string{"mwan3.wan_m1.interface interface"}},
	{"an mwan3 member is a section of type member", "mwan3", "mwan3.wan_m1=member\nmwan3.wan_m1.interface='wan'", "wan_m1",
		[]string{"mwan3.wan_m1 member"}, nil},
	{"mwan3 policy use_member", "mwan3", "mwan3.balanced=policy\nmwan3.balanced.use_member='wan_m1' 'wanb_m1'", "wanb_m1",
		nil, []string{"mwan3.balanced.use_member member"}},
	{"an mwan3 policy is a section of type policy", "mwan3", "mwan3.balanced=policy\nmwan3.balanced.use_member='wan_m1'", "balanced",
		[]string{"mwan3.balanced policy"}, nil},
	{"mwan3 rule use_policy", "mwan3", "mwan3.default_rule=rule\nmwan3.default_rule.use_policy='balanced'", "balanced",
		nil, []string{"mwan3.default_rule.use_policy policy"}},

	// ---- what is not a reference
	{"a Wi-Fi key or SSID equal to the name is not a reference", "wireless",
		"wireless.a=wifi-iface\nwireless.a.ssid='lan'\nwireless.a.key='lan'\nwireless.a.ifname='lan'", "lan", nil, nil},
	{"a rule's name is not a reference", "firewall", "firewall.@rule[0]=rule\nfirewall.@rule[0].name='lan'\nfirewall.@rule[0].src_ip='lan'", "lan",
		nil, nil},
	{"a host's name is not a reference", "dhcp", "dhcp.pi=host\ndhcp.pi.name='lan'\ndhcp.pi.interface='lan2'", "lan", nil, nil},
	{"network is a reference on a zone, not on a rule", "firewall", "firewall.@rule[0]=rule\nfirewall.@rule[0].network='lan'", "lan",
		nil, nil},
	{"a part of a name is not the name", "firewall",
		"firewall.@zone[0]=zone\nfirewall.@zone[0].network='lan2' 'wlan' 'guest_lan' 'lan.10'", "lan", nil, nil},
	{"a name is matched exactly, case included", "dhcp", "dhcp.lan=dhcp\ndhcp.lan.interface='LAN'", "lan", nil, nil},
	{"the same name in another case is its own name", "dhcp", "dhcp.lan=dhcp\ndhcp.lan.interface='LAN'", "LAN",
		nil, []string{"dhcp.lan.interface interface"}},
	{"a config with no reference fields is not searched", "system", "system.@system[0]=system\nsystem.@system[0].network='lan'", "lan", nil, nil},
}

func TestRefsKnowTheReferenceFieldsOfEachConfig(t *testing.T) {
	for _, tc := range refCases {
		t.Run(tc.what, func(t *testing.T) {
			defs, uses := refStrings(findRefs(refTrees(map[string]string{tc.cfg: tc.show}), tc.name))
			if !reflect.DeepEqual(defs, tc.defs) || !reflect.DeepEqual(uses, tc.uses) {
				t.Errorf("name %q in\n%s\ndefs = %q, want %q\nuses = %q, want %q", tc.name, tc.show, defs, tc.defs, uses, tc.uses)
			}
		})
	}
}

// Across configs the hits come in the order of refConfigs, then file order, so two runs read alike.
func TestRefsOrderIsStable(t *testing.T) {
	trees := refTrees(map[string]string{
		"wireless": "wireless.a=wifi-iface\nwireless.a.network='lan'",
		"dhcp":     "dhcp.lan=dhcp\ndhcp.lan.interface='lan'",
		"firewall": "firewall.@zone[0]=zone\nfirewall.@zone[0].network='lan'\nfirewall.@rule[0]=rule\nfirewall.@rule[0].src='lan'",
	})
	_, uses := refStrings(findRefs(trees, "lan"))
	want := []string{"firewall.@zone[0].network interface", "firewall.@rule[0].src zone", "dhcp.lan.interface interface", "wireless.a.network interface"}
	if !reflect.DeepEqual(uses, want) {
		t.Errorf("uses = %q, want %q", uses, want)
	}
}

func TestRefConfigsAreTheSearchedOnesInOrder(t *testing.T) {
	want := []string{"network", "firewall", "dhcp", "wireless", "sqm", "mwan3"}
	if got := refConfigs(); !reflect.DeepEqual(got, want) {
		t.Errorf("refConfigs() = %q, want %q", got, want)
	}
}

// A spec for a config that refConfigs does not list would never be read.
func TestEveryRefSpecIsInASearchedConfig(t *testing.T) {
	for _, s := range append(append([]refSpec(nil), refDefs...), refUses...) {
		if !contains(refConfigs(), s.config) {
			t.Errorf("%s %s %s is in a config the search does not read", s.config, s.typ, s.option)
		}
	}
}

func TestRefsRenderNamesWhatDefinesAndWhatUsesAName(t *testing.T) {
	trees := refTrees(map[string]string{
		"network":  "network.lan=interface\nnetwork.lan.device='br-lan'",
		"firewall": "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'\nfirewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'",
		"mwan3":    "mwan3.lan=interface",
	})
	got := renderRefs("lan", findRefs(trees, "lan"), []string{"network", "firewall", "mwan3"}, []string{"dhcp", "wireless", "sqm"})
	want := `references to "lan"; searched network, firewall, mwan3; not on this router: dhcp, wireless, sqm
defined as (2):
  network.lan: interface
  firewall.@zone[0]: zone
used as (3):
  firewall.@zone[0].network: interface (zone "lan")
  firewall.@forwarding[0].src: zone (forwarding)
  mwan3.lan: interface`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRefsRenderSaysSoWhenNothingDefinesOrUsesTheName(t *testing.T) {
	got := renderRefs("nope", findRefs(refTrees(map[string]string{"network": "network.lan=interface"}), "nope"), []string{"network"}, nil)
	want := `references to "nope"; searched network
defined as: nothing (no interface, zone, device, radio, member or policy has this name)
used as: nowhere`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// A section's name option is operator text: it is quoted, so a newline in it cannot start a line
// that reads as another hit.
func TestRefsQuoteTheSectionName(t *testing.T) {
	trees := refTrees(map[string]string{"firewall": "firewall.@rule[0]=rule\nfirewall.@rule[0].name='x\"; y'\nfirewall.@rule[0].src='lan'"})
	got := renderRefs("lan", findRefs(trees, "lan"), []string{"firewall"}, nil)
	if !strings.Contains(got, `(rule "x\"; y")`) {
		t.Errorf("section name not quoted:\n%s", got)
	}
}

// ---------------------------------------------------------------- the tool

const (
	refsNetwork = "network.loopback=interface\nnetwork.loopback.device='lo'\n" +
		"network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.lan.proto='static'\nnetwork.lan.ipaddr='192.0.2.1'\n" +
		"network.wan=interface\nnetwork.wan.device='eth1'\n" +
		"network.wan6=interface\nnetwork.wan6.device='@wan'\n" +
		"network.@device[0]=device\nnetwork.@device[0].name='br-lan'\nnetwork.@device[0].type='bridge'\nnetwork.@device[0].ports='lan1' 'lan2'\n"
	refsFirewall = "firewall.@zone[0]=zone\nfirewall.@zone[0].name='lan'\nfirewall.@zone[0].network='lan'\n" +
		"firewall.@zone[1]=zone\nfirewall.@zone[1].name='wan'\nfirewall.@zone[1].network='wan' 'wan6'\n" +
		"firewall.@forwarding[0]=forwarding\nfirewall.@forwarding[0].src='lan'\nfirewall.@forwarding[0].dest='wan'\n" +
		"firewall.@rule[0]=rule\nfirewall.@rule[0].name='Allow-SSH'\nfirewall.@rule[0].src='wan'\nfirewall.@rule[0].dest_port='22'\n"
	refsDHCP     = "dhcp.lan=dhcp\ndhcp.lan.interface='lan'\ndhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].interface='lan'\n"
	refsWireless = "wireless.radio0=wifi-device\nwireless.default_radio0=wifi-iface\nwireless.default_radio0.device='radio0'\n" +
		"wireless.default_radio0.network='lan'\nwireless.default_radio0.ssid='ExampleNet'\nwireless.default_radio0.key='correct-horse-battery'\n"
)

// refsRouter installs the fixture configs (sqm and mwan3 are not installed) and the `uci show`
// that reads them.
func refsRouter(t *testing.T) *fakeRouter {
	t.Helper()
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	for c, show := range map[string]string{"network": refsNetwork, "firewall": refsFirewall, "dhcp": refsDHCP, "wireless": refsWireless} {
		writeFixture(t, root, "etc/config/"+c, "config x\n")
		f.on("uci -q show "+c, show)
		f.on("uci -q -X show "+c, show)
	}
	return f
}

func TestUciGetRefsFindsEveryUseOfAName(t *testing.T) {
	refsRouter(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	out, isErr := callText(t, cs, "uci_get", map[string]any{"refs": "lan"})
	if isErr {
		t.Fatal(out)
	}
	want := `references to "lan"; searched network, firewall, dhcp, wireless; not on this router: sqm, mwan3
defined as (2):
  network.lan: interface
  firewall.@zone[0]: zone
used as (5):
  firewall.@zone[0].network: interface (zone "lan")
  firewall.@forwarding[0].src: zone (forwarding)
  dhcp.lan.interface: interface (dhcp)
  dhcp.@dnsmasq[0].interface: interface (dnsmasq)
  wireless.default_radio0.network: interface (wifi-iface)`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	for _, leak := range []string{"correct-horse", "ExampleNet", "192.0.2.1"} {
		if strings.Contains(out, leak) {
			t.Errorf("the search printed %q, which no reference field holds", leak)
		}
	}
}

func TestUciGetRefsConfigNarrowsTheSearch(t *testing.T) {
	f := refsRouter(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	out, isErr := callText(t, cs, "uci_get", map[string]any{"refs": "lan", "config": "firewall"})
	if isErr {
		t.Fatal(out)
	}
	if !strings.HasPrefix(out, "references to \"lan\"; searched firewall\n") || strings.Contains(out, "dhcp.lan.interface") {
		t.Errorf("config=firewall still searched the others:\n%s", out)
	}
	for _, c := range []string{"network", "dhcp", "wireless"} {
		if f.ran("uci -q show " + c) {
			t.Errorf("read %s although config=firewall", c)
		}
	}
}

func TestUciGetRefsHonoursIDs(t *testing.T) {
	f := refsRouter(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	if out, isErr := callText(t, cs, "uci_get", map[string]any{"refs": "lan", "ids": true}); isErr {
		t.Fatal(out)
	}
	if !f.ran("uci -q -X show firewall") || f.ran("uci -q show firewall") {
		t.Errorf("ids=true did not read stable ids:\n%s", f.allCalls())
	}
}

func TestUciGetRefsRefusesWhatItCannotMean(t *testing.T) {
	f := refsRouter(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	for _, tc := range []struct {
		what string
		args map[string]any
		want string
	}{
		{"a section", map[string]any{"refs": "lan", "section": "lan"}, "give no section, option or history"},
		{"an option", map[string]any{"refs": "lan", "section": "lan", "option": "device"}, "give no section, option or history"},
		{"an option alone", map[string]any{"refs": "lan", "option": "device"}, "give no section, option or history"},
		{"history", map[string]any{"refs": "lan", "config": "dhcp", "history": "list"}, "give no section, option or history"},
		{"a config with no reference fields", map[string]any{"refs": "lan", "config": "system"}, "searches network, firewall, dhcp, wireless, sqm, mwan3"},
		{"a config that is not installed", map[string]any{"refs": "lan", "config": "sqm"}, "no UCI config \"sqm\""},
		{"a space", map[string]any{"refs": "lan guest"}, "refs must be one name"},
		{"a wildcard", map[string]any{"refs": "*"}, "refs must be one name"},
		{"a quote", map[string]any{"refs": "lan'"}, "refs must be one name"},
		{"a leading @", map[string]any{"refs": "@lan"}, "refs must be one name"},
		{"too long", map[string]any{"refs": strings.Repeat("a", 65)}, "refs must be one name"},
		{"a bad config", map[string]any{"refs": "lan", "config": "x y"}, "bad config"},
	} {
		out, isErr := callText(t, cs, "uci_get", tc.args)
		if !isErr || !strings.Contains(out, tc.want) || !strings.Contains(out, "[code: ") {
			t.Errorf("%s: isErr=%v, want a coded error containing %q, got %q", tc.what, isErr, tc.want, out)
		}
	}
	f.noCalls(t, "a refused search")
}

// A search reads six configs, so it is its own permission: a grant on the configs it reads does
// not cover it, and its grant covers no config read.
func TestUciGetRefsHasItsOwnScope(t *testing.T) {
	refsRouter(t)
	for _, tc := range []struct {
		grant string
		refs  bool
		get   bool
	}{
		{"*", true, true},
		{"refs", true, false},
		{"firewall.*", false, true},
		{"dhcp", false, true},
		{"network firewall dhcp wireless sqm mwan3", false, true},
	} {
		cs := connectClient(t, testServer(t, policyFor("c", []string{"uci_get"}, strings.Fields(tc.grant)...)), "c")
		out, isErr := callText(t, cs, "uci_get", map[string]any{"refs": "lan"})
		if isErr == tc.refs {
			t.Errorf("grant %q: refs isErr=%v, want %v: %s", tc.grant, isErr, !tc.refs, out)
		}
		if isErr && !strings.Contains(out, "openwrt-mcp allow c uci_get 'refs'") {
			t.Errorf("grant %q: the denial does not name the scope to grant: %s", tc.grant, out)
		}
	}
}

func TestUciGetRefsScopeIsTheSameWhateverTheName(t *testing.T) {
	for _, in := range []uciGetIn{{Refs: "lan"}, {Refs: "wan", Config: "firewall"}, {Refs: "x", IDs: true}} {
		if got := uciGetScope(in); !reflect.DeepEqual(got, []string{"refs"}) {
			t.Errorf("uciGetScope(%+v) = %q, want [refs]", in, got)
		}
	}
	if got := uciGetScope(uciGetIn{Config: "dhcp", Section: "lan"}); !reflect.DeepEqual(got, []string{"dhcp.lan"}) {
		t.Errorf("a plain read changed scope: %q", got)
	}
}

// A config that is there but will not print is an error, never an empty answer: "no references"
// would be read as "safe to delete".
func TestUciGetRefsFailsLoudlyWhenAConfigCannotBeRead(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	writeFixture(t, root, "etc/config/network", "config x\n")
	writeFixture(t, root, "etc/config/firewall", "config x\n")
	f.on("uci -q show network", refsNetwork)
	f.fail("uci -q show firewall", "uci: Parse error")
	_, _, err := uciRefs(context.Background(), uciGetIn{Refs: "lan"})
	if err == nil || !strings.Contains(err.Error(), "firewall") {
		t.Fatalf("a firewall config that will not parse gave %v", err)
	}
}

func TestUciGetKeepsRequiringAConfigWithoutRefs(t *testing.T) {
	_, _, err := uciGet(context.Background(), uciGetIn{})
	if err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Errorf("err = %v", err)
	}
}

func FuzzRefsParsers(f *testing.F) {
	f.Add("firewall.@zone[0]=zone\nfirewall.@zone[0].network='lan' 'lan6'\n", "lan")
	f.Add("network.wan6=interface\nnetwork.wan6.device='@wan'\n", "wan")
	f.Add("mwan3.wan=interface\nmwan3.x=policy\nmwan3.x.use_member='a' 'b'\n", "wan")
	f.Fuzz(func(t *testing.T, show, name string) {
		trees := map[string]*uciTree{}
		for _, c := range refConfigs() {
			trees[c] = parseUCIShow(show)
		}
		out := renderRefs(name, findRefs(trees, name), refConfigs(), nil)
		if !strings.HasPrefix(out, "references to ") {
			t.Fatalf("no header: %q", out)
		}
	})
}
