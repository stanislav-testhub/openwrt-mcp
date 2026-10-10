package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Dry-run warnings (ROADMAP 5.9) and the management path that follows the session (MCP-2).
// The router below is shaped like the one in probe_test.go (a bridged LAN with the SSH listener,
// a WAN, a rule for SSH) plus the things a warning is about: a guest network with its zone, DHCP
// pool and SSID, a WireGuard interface and its zone, and one network that is open already.
const (
	adviceNetwork = `network.guest=interface
network.guest.proto='static'
network.guest.device='br-guest'
network.guest.ipaddr='198.51.100.1/24'
network.wg0=interface
network.wg0.proto='wireguard'
network.wg0.listen_port='51820'
network.wg0.addresses='10.0.0.1/24'
network.branch=interface
network.branch.proto='static'
network.branch.device='eth1'
network.branch.ipaddr='203.0.113.9/24'
network.oldstyle=interface
network.oldstyle.proto='static'
network.oldstyle.ifname='eth2'
network.globals=globals
network.globals.ula_prefix='fd00:db8::/48'
network.@device[1]=device
network.@device[1].name='eth3'
network.@device[1].type='8021q'
`
	adviceFirewall = `firewall.@zone[2]=zone
firewall.@zone[2].name='guest'
firewall.@zone[2].network='guest'
firewall.@zone[2].input='REJECT'
firewall.@zone[3]=zone
firewall.@zone[3].name='vpn'
firewall.@zone[3].network='wg0'
firewall.@zone[3].input='REJECT'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='guest'
firewall.@forwarding[0].dest='wan'
firewall.@forwarding[1]=forwarding
firewall.@forwarding[1].src='lan'
firewall.@forwarding[1].dest='legacy'
`
	adviceDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].interface='lan'
dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.lan.start='100'
dhcp.guest=dhcp
dhcp.guest.interface='guest'
`
	adviceWireless = `wireless.radio0=wifi-device
wireless.radio0.band='5g'
wireless.radio1=wifi-device
wireless.radio1.band='2g'
wireless.wifinet0=wifi-iface
wireless.wifinet0.device='radio0'
wireless.wifinet0.network='lan'
wireless.wifinet0.mode='ap'
wireless.wifinet0.ssid='ExampleNet'
wireless.wifinet0.encryption='psk2'
wireless.wifinet1=wifi-iface
wireless.wifinet1.device='radio1'
wireless.wifinet1.network='guest'
wireless.wifinet1.mode='ap'
wireless.wifinet1.ssid='ExampleGuest'
wireless.wifinet1.encryption='owe'
wireless.wifinet2=wifi-iface
wireless.wifinet2.device='radio1'
wireless.wifinet2.network='guest'
wireless.wifinet2.mode='ap'
wireless.wifinet2.ssid='ExampleOpen'
wireless.wifinet2.encryption='none'
`
	adviceSystem = "system.@system[0]=system\nsystem.@system[0].hostname='example'\n"
)

// Two things in this router are already wrong, so that "not news" can be told from "new": the
// SSH rule is open to the WAN (mgmtFirewall), wifinet2 has no encryption, and forwarding 1 names a
// zone that does not exist.
func adviceFixture(t *testing.T, policies string) (*Server, *fakeRouter, *uciModel) {
	t.Helper()
	root := withFixtureRoot(t)
	for _, c := range []string{"network", "dropbear", "firewall", "dhcp", "wireless", "system"} {
		writeFixture(t, root, "etc/config/"+c, "config x '"+c+"'\n")
	}
	f := newFakeRouter(t)
	_, model := fakeUCIWith(t, f, false)
	model.seed("network", mgmtNetwork+adviceNetwork)
	model.seed("dropbear", mgmtDropbear)
	model.seed("firewall", mgmtFirewall+adviceFirewall)
	model.seed("dhcp", adviceDHCP)
	model.seed("wireless", adviceWireless)
	model.seed("system", adviceSystem)
	return testServer(t, policies), f, model
}

func mk(config, section, typ string) UCIChange {
	return UCIChange{Config: config, Section: section, Type: typ}
}

func rm(config, section string) UCIChange {
	return UCIChange{Config: config, Section: section, Delete: true}
}

func dryRun(t *testing.T, s *Server, ctx context.Context, changes ...UCIChange) string {
	t.Helper()
	out, _, err := s.uciApply(ctx, "c", uciApplyIn{DryRun: true, Changes: changes})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	return out
}

// warningsOf is the warnings paragraph of a dry run, "" when there is none.
func warningsOf(out string) string {
	_, rest, ok := strings.Cut(out, "warnings from this change:")
	if !ok {
		return ""
	}
	para, _, _ := strings.Cut(rest, "\n\n")
	return para
}

func TestADryRunWarnsAboutWhatTheChangeMakesWorse(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes []UCIChange
		want    []string // substrings of the warnings paragraph
		not     []string
	}{
		// ---- the firewall: a port opened to the internet
		{"a rule that accepts a port from the WAN", []UCIChange{
			mk("firewall", "allow_web", "rule"), chg("firewall", "allow_web", "name", "Allow-Web"),
			chg("firewall", "allow_web", "src", "wan"), chg("firewall", "allow_web", "dest_port", "443"),
			chg("firewall", "allow_web", "proto", "tcp"), chg("firewall", "allow_web", "target", "ACCEPT")},
			[]string{"[medium] wan-port-open", "Allow-Web", "tcp/443"}, nil},
		{"the same rule from the LAN is not a WAN exposure", []UCIChange{
			mk("firewall", "allow_web", "rule"), chg("firewall", "allow_web", "src", "lan"),
			chg("firewall", "allow_web", "dest_port", "443"), chg("firewall", "allow_web", "target", "ACCEPT")},
			[]string{"no findings"}, []string{"wan-port-open"}},
		{"a rule that is switched off opens nothing", []UCIChange{
			mk("firewall", "allow_web", "rule"), chg("firewall", "allow_web", "src", "wan"),
			chg("firewall", "allow_web", "dest_port", "443"), chg("firewall", "allow_web", "target", "ACCEPT"),
			chg("firewall", "allow_web", "enabled", "0")},
			[]string{"no findings"}, []string{"wan-port-open"}},
		{"a rule that drops is no exposure", []UCIChange{
			mk("firewall", "allow_web", "rule"), chg("firewall", "allow_web", "src", "wan"),
			chg("firewall", "allow_web", "dest_port", "443"), chg("firewall", "allow_web", "target", "DROP")},
			[]string{"no findings"}, []string{"wan-port-open"}},
		{"ping from the WAN is not a port", []UCIChange{
			mk("firewall", "allow_ping", "rule"), chg("firewall", "allow_ping", "src", "wan"),
			chg("firewall", "allow_ping", "proto", "icmp"), chg("firewall", "allow_ping", "target", "ACCEPT")},
			[]string{"no findings"}, []string{"wan-port-open"}},
		{"a port forward from the WAN", []UCIChange{
			mk("firewall", "web_fwd", "redirect"), chg("firewall", "web_fwd", "name", "Web-Forward"),
			chg("firewall", "web_fwd", "src", "wan"), chg("firewall", "web_fwd", "src_dport", "8080"),
			chg("firewall", "web_fwd", "dest_ip", "192.0.2.10"), chg("firewall", "web_fwd", "dest_port", "80")},
			[]string{"[medium] wan-redirect", "Web-Forward", "192.0.2.10:80"}, nil},
		{"a port forward from the LAN is not a WAN exposure", []UCIChange{
			mk("firewall", "web_fwd", "redirect"), chg("firewall", "web_fwd", "src", "lan"),
			chg("firewall", "web_fwd", "src_dport", "8080"), chg("firewall", "web_fwd", "dest_ip", "192.0.2.10")},
			[]string{"no findings"}, []string{"wan-redirect"}},
		{"the WAN zone accepts input", []UCIChange{chg("firewall", "@zone[1]", "input", "ACCEPT")},
			[]string{"[high] wan-zone-input-accept", "zone wan: input=ACCEPT"}, nil},
		{"the WAN zone accepts forwarding", []UCIChange{chg("firewall", "@zone[1]", "forward", "ACCEPT")},
			[]string{"[high] wan-zone-forward-accept"}, nil},
		{"the WAN zone input is restated", []UCIChange{chg("firewall", "@zone[1]", "input", "REJECT")},
			[]string{"no findings"}, nil},
		{"a LAN zone that forwards is not the internet", []UCIChange{chg("firewall", "@zone[0]", "forward", "ACCEPT")},
			[]string{"no findings"}, []string{"wan-zone"}},
		{"an exposure that was already there is not news", []UCIChange{chg("firewall", "@rule[0]", "comment", "kept")},
			[]string{"no findings"}, []string{"wan-port-open"}},
		{"the same rule on another port is a new exposure", []UCIChange{chg("firewall", "@rule[0]", "dest_port", "2223")},
			[]string{"wan-port-open", "2223"}, nil},

		// ---- SSH
		{"password logins switched on", []UCIChange{chg("dropbear", "@dropbear[0]", "PasswordAuth", "on")},
			[]string{"[medium] ssh-password-auth"}, nil},
		{"the SSH port moves", []UCIChange{chg("dropbear", "@dropbear[0]", "Port", "2223")},
			[]string{"no findings"}, []string{"ssh-password-auth"}},

		// ---- Wi-Fi
		{"an encrypted network loses its encryption", []UCIChange{chg("wireless", "wifinet0", "encryption", "none")},
			[]string{"[high] ssid-open", "wifinet0", "ExampleNet"}, nil},
		{"an encrypted network changes cipher", []UCIChange{chg("wireless", "wifinet0", "encryption", "sae")},
			[]string{"no findings"}, []string{"ssid-open"}},
		{"another finding with the same evidence is news (WPS on the network that was open)", []UCIChange{chg("wireless", "wifinet2", "wps_pushbutton", "1")},
			[]string{"[medium] wps-on", "wifinet2"}, []string{"ssid-open"}},
		{"a network that was open and stays open is not news", []UCIChange{chg("wireless", "wifinet2", "hidden", "1")},
			[]string{"no findings"}, []string{"ssid-open"}},

		// ---- configs only the reference check reads
		{"a DHCP pool changes", []UCIChange{chg("dhcp", "lan", "limit", "50")},
			[]string{"no findings", "checked: ", ", references"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := adviceFixture(t, "")
			w := warningsOf(dryRun(t, s, context.Background(), tc.changes...))
			if w == "" {
				t.Fatal("the dry run has no warnings paragraph")
			}
			for _, x := range tc.want {
				if !strings.Contains(w, x) {
					t.Errorf("warnings lack %q:\n%s", x, w)
				}
			}
			for _, x := range tc.not {
				if strings.Contains(w, x) {
					t.Errorf("warnings should not contain %q:\n%s", x, w)
				}
			}
		})
	}
}

func TestEachWarningLinksToTheWikiAndNamesTheNextStep(t *testing.T) {
	s, _, _ := adviceFixture(t, "")
	w := warningsOf(dryRun(t, s, context.Background(), chg("firewall", "@zone[1]", "input", "ACCEPT")))
	for _, x := range []string{"  next: ", "  docs: https://openwrt.org/docs/"} {
		if !strings.Contains(w, x) {
			t.Errorf("a warning lacks %q:\n%s", x, w)
		}
	}
}

func TestWarningsComeAfterTheValidationReportAndBeforeTheNextStep(t *testing.T) {
	s, _, _ := adviceFixture(t, "")
	out := dryRun(t, s, context.Background(), chg("firewall", "@zone[1]", "input", "ACCEPT"))
	i, j, k := strings.Index(out, "uci would change"), strings.Index(out, "warnings from this change"), strings.Index(out, "Call uci_apply again")
	if i < 0 || j < i || k < j {
		t.Errorf("order wrong (change %d, warnings %d, next step %d):\n%s", i, j, k, out)
	}
}

// Warnings are for the dry run: the apply that follows has already been shown them, and it must
// not pay for reading six configs twice.
func TestARealApplyReadsNoWarnings(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{chg("firewall", "@zone[1]", "input", "ACCEPT")}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "warnings from this change") || f.ran("uci -q -X show") {
		t.Errorf("a real apply computed warnings:\n%s\n%s", out, f.allCalls())
	}
}

func TestAChangeNoWarningRuleReadsSaysNothingAndReadsNothing(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	out := dryRun(t, s, context.Background(), chg("system", "@system[0]", "hostname", "other"))
	if strings.Contains(out, "warnings") || f.ran("uci -q -X show") {
		t.Errorf("a change to system raised or computed warnings:\n%s\n%s", out, f.allCalls())
	}
}

func TestADryRunStillRevertsWhatItStagedAfterReadingTheWarnings(t *testing.T) {
	s, f, model := adviceFixture(t, "")
	dryRun(t, s, context.Background(), chg("firewall", "@zone[1]", "input", "ACCEPT"))
	if got := model.working["firewall"]["@zone[1]"].opts["input"]; len(got) != 1 || got[0] != "REJECT" {
		t.Errorf("the staged change was left behind: %v", got)
	}
	if f.ran("uci commit") {
		t.Error("a dry run committed")
	}
}

// ---------------------------------------------------------------- references

func TestADryRunWarnsAboutNamesTheChangeLeavesDangling(t *testing.T) {
	deleteGuest := []UCIChange{rm("network", "guest")}
	for _, tc := range []struct {
		name    string
		changes []UCIChange
		want    []string
		not     []string
	}{
		{"an interface deleted while a zone, a pool and an SSID still use it", deleteGuest,
			[]string{"[medium] ref-removed", `interface "guest"`, `firewall.@zone[2].network (zone "guest")`,
				"dhcp.guest.interface (dhcp)", "wireless.wifinet1.network (wifi-iface)", "uci_get refs=guest", "(+1 more)",
				"docs: " + docNetwork}, []string{"ref-unknown"}},
		{"the same deletion with every use removed too", []UCIChange{rm("network", "guest"), rm("firewall", "@zone[2]"),
			rm("firewall", "@forwarding[0]"), rm("dhcp", "guest"), rm("wireless", "wifinet1"), rm("wireless", "wifinet2")},
			[]string{"no findings"}, []string{"ref-removed"}},
		{"a zone deleted while a forwarding still names it", []UCIChange{rm("firewall", "@zone[2]")},
			[]string{"ref-removed", `zone "guest"`, "firewall.@forwarding[0].src (forwarding)", "docs: " + docFirewall}, nil},
		{"a zone renamed leaves its rules behind", []UCIChange{chg("firewall", "@zone[2]", "name", "visitors")},
			[]string{"ref-removed", `zone "guest"`}, nil},
		{"a radio deleted while an SSID still rides on it", []UCIChange{rm("wireless", "radio1")},
			[]string{"ref-removed", `radio "radio1"`, "wireless.wifinet1.device (wifi-iface)", "docs: " + docWifi}, nil},
		{"a zone named in the wrong case", []UCIChange{chg("firewall", "@rule[1]", "src", "WAN")},
			[]string{"[medium] ref-unknown", `zone "WAN"`, `did you mean "wan"`}, []string{"ref-removed"}},
		{"a zone with no near miss", []UCIChange{chg("firewall", "@rule[1]", "src", "wann")},
			[]string{"ref-unknown", `zone "wann"`}, []string{"did you mean"}},
		{"an interface named in the wrong case in a zone", []UCIChange{{Op: "add_list", Config: "firewall", Section: "@zone[2]", Option: "network", Value: "Guest"}},
			[]string{"ref-unknown", `interface "Guest"`, `did you mean "guest"`}, nil},
		{"an alias to an interface in the wrong case", []UCIChange{mk("network", "wan6", "interface"), chg("network", "wan6", "device", "@Wan")},
			[]string{"ref-unknown", `interface "Wan"`, `did you mean "wan"`}, nil},
		{"the any-zone wildcard is a zone, and it includes the WAN", []UCIChange{chg("firewall", "@rule[1]", "src", "*")},
			[]string{"wan-port-open"}, []string{"ref-"}},
		{"a new interface and the zone that lists it, together", []UCIChange{mk("network", "office", "interface"),
			mk("firewall", "office", "zone"), chg("firewall", "office", "name", "office"), chg("firewall", "office", "network", "office")},
			[]string{"no findings"}, []string{"ref-"}},
		{"a zone that lists an interface that does not exist", []UCIChange{mk("firewall", "office", "zone"),
			chg("firewall", "office", "name", "office"), chg("firewall", "office", "network", "office")},
			[]string{"ref-unknown", `interface "office"`}, nil},
		{"a second bad name in a field that already had one", []UCIChange{chg("firewall", "@forwarding[1]", "dest", "legacy2")},
			[]string{"ref-unknown", `zone "legacy2"`}, nil},
		{"a near miss must be a name of the same kind", []UCIChange{mk("firewall", "office", "zone"), chg("firewall", "office", "name", "office"),
			chg("firewall", "office", "network", "Office")},
			[]string{"ref-unknown", `interface "Office"`}, []string{"did you mean"}},
		{"a rule's name is not a zone", []UCIChange{chg("firewall", "@forwarding[1]", "dest", "Allow-DHCP-Renew")},
			[]string{"ref-unknown", `zone "Allow-DHCP-Renew"`}, nil},
		{"a section of another type is not an interface", []UCIChange{{Op: "add_list", Config: "firewall", Section: "@zone[2]", Option: "network", Value: "globals"}},
			[]string{"ref-unknown", `interface "globals"`}, nil},
		{"an ip rule's src and dest are prefixes, not zones", []UCIChange{mk("network", "r1", "rule"), chg("network", "r1", "src", "192.0.2.0/24"),
			chg("network", "r1", "dest", "198.51.100.0/24"), chg("network", "r1", "lookup", "100")},
			[]string{"no findings"}, []string{"ref-"}},
		{"a name that already dangled is not news", []UCIChange{chg("firewall", "@forwarding[1]", "enabled", "0")},
			[]string{"no findings"}, []string{"legacy"}},
		{"dnsmasq may list device names, so its interface list is not judged", []UCIChange{chg("dhcp", "@dnsmasq[0]", "interface", "br-lan")},
			[]string{"no findings"}, []string{"ref-"}},
		{"a physical device is not a reference to a section", []UCIChange{chg("network", "guest", "device", "eth9")},
			[]string{"no findings"}, []string{"ref-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := adviceFixture(t, "")
			w := warningsOf(dryRun(t, s, context.Background(), tc.changes...))
			if w == "" {
				t.Fatal("the dry run has no warnings paragraph")
			}
			for _, x := range tc.want {
				if !strings.Contains(w, x) {
					t.Errorf("warnings lack %q:\n%s", x, w)
				}
			}
			for _, x := range tc.not {
				if strings.Contains(w, x) {
					t.Errorf("warnings should not contain %q:\n%s", x, w)
				}
			}
		})
	}
}

func TestTheReferenceWarningNamesAtMostThreeUsesAndCountsTheRest(t *testing.T) {
	s, _, model := adviceFixture(t, "")
	for i := 0; i < 4; i++ {
		model.committed["firewall"][ruleName(i)] = &modelSec{typ: "rule", opts: map[string][]string{"dest": {"guest"}}}
	}
	model.revert("firewall")
	w := warningsOf(dryRun(t, s, context.Background(), rm("firewall", "@zone[2]")))
	if !strings.Contains(w, "(+2 more)") || strings.Count(w, "firewall.") != 3 {
		t.Errorf("the evidence should name three uses and count the rest:\n%s", w)
	}
}

func ruleName(i int) string { return "fill_" + string(rune('a'+i)) }

func TestAConfigThatCannotBeReadIsNotCheckedAndSaysSo(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	f.fail("uci -q -X show dhcp", "uci: Parse error")
	w := warningsOf(dryRun(t, s, context.Background(), rm("network", "guest")))
	if !strings.Contains(w, "not checked:") || !strings.Contains(w, "references") || !strings.Contains(w, "dhcp") {
		t.Errorf("an unreadable config must be named, not read as a clean bill:\n%s", w)
	}
	if strings.Contains(w, "dhcp.guest.interface") {
		t.Errorf("a use in an unreadable config cannot be reported:\n%s", w)
	}
}

func TestAConfigThatIsNotInstalledIsNotAFailure(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	f.fail("uci -q -X show sqm", "") // as uci answers for a config that is not there
	f.fail("uci -q -X show mwan3", "")
	w := warningsOf(dryRun(t, s, context.Background(), chg("firewall", "@zone[1]", "input", "ACCEPT")))
	if strings.Contains(w, "sqm") || strings.Contains(w, "mwan3") {
		t.Errorf("an add-on that is not installed must not appear:\n%s", w)
	}
}

// ---------------------------------------------------------------- the session's radio

const (
	adviceWifiStatus = `{"radio0":{"up":true,"interfaces":[{"section":"wifinet0","ifname":"phy0-ap0"}]},` +
		`"radio1":{"up":true,"interfaces":[{"section":"wifinet1","ifname":"phy1-ap0"},{"section":"wifinet2","ifname":"phy1-ap1"}]}}`
	onWifi  = `{"results":[{"mac":"02:00:5E:00:53:01","signal":-50}]}`
	offWifi = `{"results":[]}`
)

func wifiPeer(t *testing.T, f *fakeRouter, assoc0 string) context.Context {
	t.Helper()
	f.on("ip neigh show", "192.0.2.50 dev br-lan lladdr 02:00:5e:00:53:01 REACHABLE\n192.0.2.51 dev br-lan lladdr 02:00:5e:00:53:99 STALE")
	f.on("ubus call network.wireless status", adviceWifiStatus)
	f.on("ubus call iwinfo assoclist", offWifi)
	f.onFn("ubus call iwinfo assoclist", func(argv []string, _ string) (string, error) {
		if strings.Contains(strings.Join(argv, " "), "phy0-ap0") {
			return assoc0, nil
		}
		return offWifi, nil
	})
	return withProfile(context.Background(), sessionProfile{Peer: netip.MustParseAddr("192.0.2.50")})
}

func TestADryRunWarnsWhenItTurnsOffTheRadioTheSessionIsOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changes []UCIChange
		assoc0  string
		want    bool
	}{
		{"the radio is disabled", []UCIChange{chg("wireless", "radio0", "disabled", "1")}, onWifi, true},
		{"the SSID is disabled", []UCIChange{chg("wireless", "wifinet0", "disabled", "1")}, onWifi, true},
		{"the SSID is deleted", []UCIChange{rm("wireless", "wifinet0")}, onWifi, true},
		{"the radio is deleted", []UCIChange{rm("wireless", "radio0")}, onWifi, true},
		{"another SSID is disabled", []UCIChange{chg("wireless", "wifinet1", "disabled", "1")}, onWifi, false},
		{"another radio is disabled", []UCIChange{chg("wireless", "radio1", "disabled", "1")}, onWifi, false},
		{"the session is not on Wi-Fi", []UCIChange{chg("wireless", "radio0", "disabled", "1")}, offWifi, false},
		{"the radio keeps running", []UCIChange{chg("wireless", "wifinet0", "ssid", "Renamed")}, onWifi, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, _ := adviceFixture(t, "")
			ctx := wifiPeer(t, f, tc.assoc0)
			w := warningsOf(dryRun(t, s, ctx, tc.changes...))
			got := strings.Contains(w, "radio-in-use")
			if got != tc.want {
				t.Errorf("radio-in-use = %v, want %v:\n%s", got, tc.want, w)
			}
			if tc.want && (!strings.Contains(w, "[high] radio-in-use") || !strings.Contains(w, "wifinet0") || !strings.Contains(w, "radio0") ||
				!strings.Contains(w, "docs: https://openwrt.org/docs/")) {
				t.Errorf("the warning should name the SSID section and the radio, rank high and link the wiki:\n%s", w)
			}
		})
	}
}

func TestTheRadioLookupRunsOnlyWhenAChangeTakesWiFiDown(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	ctx := wifiPeer(t, f, onWifi)
	dryRun(t, s, ctx, chg("wireless", "wifinet0", "ssid", "Renamed"))
	if f.ran("ip neigh") || f.ran("ubus call network.wireless") || f.ran("ubus call iwinfo") {
		t.Errorf("the session's radio was looked up for a change that keeps every radio up:\n%s", f.allCalls())
	}
}

func TestWithoutAPeerThereIsNoRadioLookupAndNoWarning(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	wifiPeer(t, f, onWifi)
	w := warningsOf(dryRun(t, s, context.Background(), chg("wireless", "radio0", "disabled", "1")))
	if strings.Contains(w, "radio-in-use") || f.ran("ip neigh") {
		t.Errorf("a session with no known peer was matched to a radio:\n%s\n%s", w, f.allCalls())
	}
}

func TestARadioThatWasAlreadyOffIsNotNews(t *testing.T) {
	s, f, model := adviceFixture(t, "")
	model.committed["wireless"]["radio0"].opts["disabled"] = []string{"1"}
	model.revert("wireless")
	ctx := wifiPeer(t, f, onWifi)
	w := warningsOf(dryRun(t, s, ctx, chg("wireless", "wifinet0", "ssid", "Renamed")))
	if strings.Contains(w, "radio-in-use") {
		t.Errorf("a radio that was off before the change was reported as turned off by it:\n%s", w)
	}
}

func TestARadioLookupThatFailsIsNoWarningAndNoError(t *testing.T) {
	for _, broken := range []string{"ip neigh show", "ubus call network.wireless status"} {
		t.Run(broken, func(t *testing.T) {
			s, f, _ := adviceFixture(t, "")
			ctx := wifiPeer(t, f, onWifi)
			f.fail(broken, "boom")
			w := warningsOf(dryRun(t, s, ctx, chg("wireless", "radio0", "disabled", "1")))
			if strings.Contains(w, "radio-in-use") {
				t.Errorf("a failed lookup produced a warning:\n%s", w)
			}
		})
	}
}

// ---------------------------------------------------------------- MCP-2: the path follows the session

const (
	viaWG  = "198.51.100.7 dev wg0 src 10.0.0.1 uid 0\n    cache"
	viaLAN = "192.0.2.50 dev br-lan src 192.0.2.1 uid 0\n    cache"
)

func sessionCtx(peer string) context.Context {
	return withProfile(context.Background(), sessionProfile{Peer: netip.MustParseAddr(peer)})
}

func TestTheManagementPathFollowsTheInterfaceTheSessionArrivesOn(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  UCIChange
		route   string // what `ip route get` prints; "" runs no route lookup
		peer    string
		want    string // substring of the reasons, "" for none
		noRoute bool   // the lookup is not made at all
	}{
		{"the tunnel's address", chg("network", "wg0", "addresses", "10.9.0.1/24"), viaWG, "198.51.100.7", "network.wg0 is the interface this session arrives on", false},
		{"the tunnel's port", chg("network", "wg0", "listen_port", "51821"), viaWG, "198.51.100.7", "network.wg0", false},
		{"the tunnel's key", chg("network", "wg0", "private_key", "not-a-real-key"), viaWG, "198.51.100.7", "network.wg0", false},
		{"the tunnel is switched off", chg("network", "wg0", "disabled", "1"), viaWG, "198.51.100.7", "network.wg0", false},
		{"the tunnel is deleted", rm("network", "wg0"), viaWG, "198.51.100.7", "network.wg0", false},
		{"the tunnel's MTU is not the path", chg("network", "wg0", "mtu", "1380"), viaWG, "198.51.100.7", "", false},
		{"the tunnel's zone", chg("firewall", "@zone[3]", "input", "ACCEPT"), viaWG, "198.51.100.7", "zone vpn", false},
		{"a device the session arrives on, with no interface of its own", chg("network", "@device[1]", "type", "bridge"), "203.0.113.50 dev eth3 src 203.0.113.9", "203.0.113.50", "device eth3", false},
		{"an interface found by its device", chg("network", "branch", "ipaddr", "203.0.113.10/24"), "203.0.113.50 dev eth1 src 203.0.113.9", "203.0.113.50", "network.branch is the interface this session arrives on", false},
		{"an interface found by its legacy ifname", chg("network", "oldstyle", "proto", "dhcp"), "203.0.113.60 dev eth2", "203.0.113.60", "network.oldstyle is the interface this session arrives on", false},
		{"the LAN keeps its own wording when the session comes through it", chg("network", "lan", "ipaddr", "198.51.100.1/24"), viaLAN, "192.0.2.50", "network.lan is the interface the management path rides on", false},
		{"a session on the LAN adds nothing", chg("network", "wg0", "addresses", "10.9.0.1/24"), viaLAN, "192.0.2.50", "", false},
		{"nobody on the tunnel: it is only an interface", chg("network", "wg0", "addresses", "10.9.0.1/24"), "", "", "", true},
		{"a route that cannot be resolved", chg("network", "wg0", "addresses", "10.9.0.1/24"), "RTNETLINK answers: Network is unreachable", "198.51.100.7", "", false},
		{"a peer on loopback", chg("network", "wg0", "addresses", "10.9.0.1/24"), "local 127.0.0.1 dev lo src 127.0.0.1", "127.0.0.1", "", true},
		{"a route that lands on the router itself", chg("network", "wg0", "addresses", "10.9.0.1/24"), "local 192.0.2.1 dev lo src 192.0.2.1 uid 0", "192.0.2.1", "", false},
		{"an IPv6 peer", chg("network", "wg0", "addresses", "10.9.0.1/24"), "2001:db8::50 from :: dev wg0 proto kernel src 2001:db8::1 metric 256 pref medium", "2001:db8::50", "network.wg0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, f, _ := adviceFixture(t, "")
			ctx := context.Background()
			if tc.peer != "" {
				ctx = sessionCtx(tc.peer)
				f.on("ip route get "+tc.peer, tc.route)
			}
			got := strings.Join(mgmtReasons(ctx, []UCIChange{tc.change}), "; ")
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("reasons = %q, want %q", got, tc.want)
			}
			if tc.noRoute && f.ran("ip route") {
				t.Errorf("a route lookup was made:\n%s", f.allCalls())
			}
		})
	}
}

func TestTheSessionsRouteIsLookedUpOnceAndOnlyForAChangeThatCanMatter(t *testing.T) {
	_, f, _ := adviceFixture(t, "")
	ctx := sessionCtx("198.51.100.7")
	f.on("ip route get 198.51.100.7", viaWG)
	mgmtReasons(ctx, []UCIChange{chg("dhcp", "lan", "start", "100")})
	if f.ran("ip route") {
		t.Error("the route was looked up for a change to dhcp")
	}
	mgmtReasons(ctx, []UCIChange{chg("network", "wg0", "addresses", "10.9.0.1/24"), chg("network", "wg0", "listen_port", "1")})
	n := 0
	for _, c := range strings.Split(f.allCalls(), "\n") {
		if strings.HasPrefix(c, "ip route get") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d route lookups for one change list, want 1", n)
	}
}

func TestTheDryRunSaysWhyTheTunnelIsThePath(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	f.on("ip route get 198.51.100.7", viaWG)
	out := dryRun(t, s, sessionCtx("198.51.100.7"), chg("network", "wg0", "addresses", "10.9.0.1/24"))
	if !strings.Contains(out, "management path:") || !strings.Contains(out, "network.wg0 is the interface this session arrives on") {
		t.Errorf("the dry run should name the interface the session rides on:\n%s", out)
	}
}

// Over the real bridge: sshd's SSH_CLIENT reaches the handler as the session's peer.
func TestThePeerReachesTheHandlerOverTheBridge(t *testing.T) {
	s, f, _ := adviceFixture(t, policyFor("c", []string{"uci_apply"}, "network.*"))
	f.on("ip route get 192.0.2.7", "192.0.2.7 dev wg0 src 10.0.0.1 uid 0\n    cache")
	args := `{"dry_run":true,"changes":[{"config":"network","section":"wg0","option":"addresses","value":"10.9.0.1/24"}]}`
	out, errOut, err := runCallCLI(t, s, "c", "call uci_apply "+args)
	if err != nil || errOut != "" {
		t.Fatalf("stderr %q, err %v", errOut, err)
	}
	if !strings.Contains(out, "network.wg0 is the interface this session arrives on") {
		t.Errorf("SSH_CLIENT did not reach the management view:\n%s", out)
	}
}

func TestParsePeerKeepsOnlyAnAddress(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.50", "192.0.2.50"},
		{"2001:db8::50", "2001:db8::50"},
		{"::ffff:192.0.2.50", "192.0.2.50"},
		{"fe80::1%br-lan", "fe80::1"},
		{"", ""},
		{"stdio", ""},
		{"192.0.2.50 51234 22", ""},
		{"192.0.2.50; reboot", ""},
		{"192.0.2.256", ""},
	} {
		got := parsePeer(tc.in)
		if tc.want == "" && got.IsValid() || tc.want != "" && got.String() != tc.want {
			t.Errorf("parsePeer(%q) = %v, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPeerDeviceReadsTheInterfaceOutOfIPRouteGet(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.0.2.50 dev br-lan src 192.0.2.1 uid 0\n    cache", "br-lan"},
		{"198.51.100.7 via 203.0.113.1 dev eth1 src 203.0.113.9", "eth1"},
		{"2001:db8::50 from :: dev wg0 proto kernel src 2001:db8::1 metric 256", "wg0"},
		{"local 127.0.0.1 dev lo src 127.0.0.1", ""},
		{"RTNETLINK answers: Network is unreachable", ""},
		{"192.0.2.50 dev", ""},
		{"", ""},
	} {
		if got := peerDevice(tc.in); got != tc.want {
			t.Errorf("peerDevice(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A change only raises warnings in the configs the checks and the reference search read, so each
// of them must be on the list.
func TestWarningsAreWorkedOutForEveryConfigTheChecksRead(t *testing.T) {
	for _, c := range []string{"firewall", "dropbear", "uhttpd", "upnpd", "wireless", "network", "dhcp", "sqm", "mwan3"} {
		if !warnsOn([]UCIChange{{Config: "system"}, {Config: c}}) {
			t.Errorf("a change to %s raises no warnings", c)
		}
	}
	for _, c := range []string{"system", "rpcd", "openwrt-mcp", ""} {
		if warnsOn([]UCIChange{{Config: c}}) {
			t.Errorf("a change to %q reads six configs for nothing", c)
		}
	}
	if warnsOn(nil) {
		t.Error("no changes, no warnings")
	}
}

// positionalNames prints `uci show` the way it does without -X: an unnamed section is @type[N].
func positionalNames(show string) string {
	typ := map[string]string{}
	var ids []string
	for _, m := range regexp.MustCompile(`(?m)^\w+\.(cfg[0-9a-f]{6})=(\S+)$`).FindAllStringSubmatch(show, -1) {
		typ[m[1]] = m[2]
		ids = append(ids, m[1])
	}
	n := map[string]int{}
	for _, id := range ids {
		pos := fmt.Sprintf("@%s[%d]", typ[id], n[typ[id]])
		n[typ[id]]++
		show = strings.ReplaceAll(strings.ReplaceAll(show, "."+id+"=", "."+pos+"="), "."+id+".", "."+pos+".")
	}
	return show
}

// An unnamed section is @type[N] to `uci show` and cfgXXXXXX to `uci -X show`; N moves when an
// earlier section goes. Warnings compare two readings, so they must read the ids: otherwise
// deleting a harmless rule would make an old, unnamed WAN rule look like the change's doing.
func TestWarningsReadSectionIdsSoDeletingAnEarlierRuleDoesNotMakeAnOldOneNew(t *testing.T) {
	s, f, model := adviceFixture(t, "")
	model.seed("firewall", `firewall.cfg0a0001=rule
firewall.cfg0a0001.name='Harmless'
firewall.cfg0a0001.src='lan'
firewall.cfg0a0001.target='ACCEPT'
firewall.cfg0a0002=rule
firewall.cfg0a0002.src='wan'
firewall.cfg0a0002.dest_port='8443'
firewall.cfg0a0002.target='ACCEPT'
firewall.cfg0a0003=zone
firewall.cfg0a0003.name='wan'
firewall.cfg0a0003.input='REJECT'
`)
	f.onFn("uci -q show", func(argv []string, _ string) (string, error) {
		out, err := model.show(argv[len(argv)-1])
		return positionalNames(out), err
	})
	w := warningsOf(dryRun(t, s, context.Background(), rm("firewall", "cfg0a0001")))
	if strings.Contains(w, "wan-port-open") || !strings.Contains(w, "no findings") {
		t.Errorf("an old unnamed rule was reported as new once an earlier one went:\n%s", w)
	}
	n := 0
	for _, a := range f.argvList() {
		if strings.Join(a, " ") == "uci -q -X show firewall" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("the firewall was read with ids %d times, want twice (live, then staged)", n)
	}
}

func TestAnMwan3SectionIsNamedAfterItsInterfaceAndAPolicyUsesAMemberByName(t *testing.T) {
	s, _, model := adviceFixture(t, "")
	writeFixture(t, sysRoot, "etc/config/mwan3", "config x 'mwan3'\n")
	model.seed("mwan3", `mwan3.wan=interface
mwan3.ghost=interface
mwan3.wan_m1=member
mwan3.wan_m1.interface='wan'
mwan3.balanced=policy
mwan3.balanced.use_member='wan_m1'
`)
	for _, tc := range []struct {
		name    string
		changes []UCIChange
		want    []string
	}{
		{"a network interface deleted while mwan3 still balances over it", []UCIChange{rm("network", "wan")},
			[]string{"ref-removed", `interface "wan"`, "mwan3.wan,", "mwan3.wan_m1.interface (member)"}},
		{"a member deleted while a policy still uses it", []UCIChange{rm("mwan3", "wan_m1")},
			[]string{"ref-removed", `member "wan_m1"`, "mwan3.balanced.use_member (policy)"}},
		{"a rule that names a policy nobody defined", []UCIChange{mk("mwan3", "r1", "rule"), chg("mwan3", "r1", "use_policy", "balancd")},
			[]string{"ref-unknown", `policy "balancd"`, "mwan3.r1.use_policy (rule)"}},
		{"mwan3 knows an interface network does not: that was true before", []UCIChange{chg("mwan3", "wan_m1", "metric", "2")},
			[]string{"no findings"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := warningsOf(dryRun(t, s, context.Background(), tc.changes...))
			for _, x := range tc.want {
				if !strings.Contains(w, x) {
					t.Errorf("warnings lack %q:\n%s", x, w)
				}
			}
		})
	}
}

// A reading that fails on either side is not a reading: comparing a config with nothing would
// make all of it look new, or all of it look gone.
func TestAConfigThatWillNotPrintOnOneSideOnlyIsNamedAndNotCompared(t *testing.T) {
	for _, failOn := range []int{1, 2} {
		t.Run(map[int]string{1: "live", 2: "staged"}[failOn], func(t *testing.T) {
			s, f, model := adviceFixture(t, "")
			n := 0
			f.onFn("uci -q -X show dhcp", func([]string, string) (string, error) {
				n++
				if n == failOn {
					return "uci: Parse error", errors.New("exit status 1")
				}
				return model.show("dhcp")
			})
			w := warningsOf(dryRun(t, s, context.Background(), rm("network", "guest")))
			if !strings.Contains(w, "not checked:") || !strings.Contains(w, "references (dhcp would not print)") {
				t.Errorf("a config that failed on one reading must be named:\n%s", w)
			}
			if strings.Contains(w, "dhcp.guest") {
				t.Errorf("a config read on one side only was compared:\n%s", w)
			}
		})
	}
}

func TestAWirelessConfigThatWillNotPrintStagedIsNoPanicAndNoRadioWarning(t *testing.T) {
	s, f, model := adviceFixture(t, "")
	n := 0
	f.onFn("uci -q -X show wireless", func([]string, string) (string, error) {
		n++
		if n >= 2 {
			return "uci: Parse error", errors.New("exit status 1")
		}
		return model.show("wireless")
	})
	ctx := wifiPeer(t, f, onWifi)
	w := warningsOf(dryRun(t, s, ctx, chg("wireless", "radio0", "disabled", "1")))
	if strings.Contains(w, "radio-in-use") || !strings.Contains(w, "not checked:") || !strings.Contains(w, "references (wireless would not print)") {
		t.Errorf("a staged config that will not print must be named, not guessed at:\n%s", w)
	}
}

// The session's interface may not answer, and another one's answer must still be heard.
func TestTheRadioLookupHearsTheOtherInterfacesWhenOneWillNotAnswer(t *testing.T) {
	s, f, _ := adviceFixture(t, "")
	f.on("ip neigh show", "192.0.2.50 dev br-lan lladdr 02:00:5e:00:53:01 REACHABLE")
	f.on("ubus call network.wireless status", adviceWifiStatus)
	f.onFn("ubus call iwinfo assoclist", func(argv []string, _ string) (string, error) {
		if strings.Contains(strings.Join(argv, " "), "phy0-ap0") {
			return "not json", nil
		}
		return onWifi, nil
	})
	ctx := withProfile(context.Background(), sessionProfile{Peer: netip.MustParseAddr("192.0.2.50")})
	w := warningsOf(dryRun(t, s, ctx, chg("wireless", "wifinet1", "disabled", "1")))
	if !strings.Contains(w, "radio-in-use") || !strings.Contains(w, "wifinet1") {
		t.Errorf("an interface that would not answer hid the one the session is on:\n%s", w)
	}
}

// Over the bridge as stdio opens it: sshd's address is on the hello line, and the session's
// handlers see it.
func TestThePeerReachesAStdioSession(t *testing.T) {
	s, f, _ := adviceFixture(t, policyFor("c", []string{"uci_apply"}, "network.*"))
	f.on("ip route get 198.51.100.7", viaWG)
	srvSide, cliSide := net.Pipe()
	go s.handleBridge(srvSide)
	_ = cliSide.SetDeadline(time.Now().Add(10 * time.Second))
	w := bufio.NewWriter(cliSide)
	w.WriteString(`{"client":"c","origin":"ssh from 198.51.100.7","peer":"198.51.100.7"}` + "\n")
	w.Flush()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
		Connect(context.Background(), &mcp.IOTransport{Reader: cliSide, Writer: cliSide}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	out, isErr := callText(t, cs, "uci_apply", map[string]any{"dry_run": true, "changes": []map[string]any{
		{"config": "network", "section": "wg0", "option": "addresses", "value": "10.9.0.1/24"}}})
	if isErr || !strings.Contains(out, "network.wg0 is the interface this session arrives on") {
		t.Errorf("the stdio session's peer did not reach the management view (error %v):\n%s", isErr, out)
	}
}

func FuzzAdviceParsers(f *testing.F) {
	for _, s := range []string{viaWG, viaLAN, "", "dev", "dev dev dev", mgmtFirewall + adviceFirewall, adviceDHCP, adviceWireless} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = peerDevice(s)
		_ = parsePeer(s)
		tr := parseUCIShow(s)
		_ = refGaps(map[string]*uciTree{"firewall": tr, "network": tr, "dhcp": tr, "wireless": tr, "mwan3": tr})
	})
}
