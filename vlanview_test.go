package main

import (
	"context"
	"strings"
	"testing"
)

// The port flags below are the ones the OpenWrt DSA documentation lists for `list ports` in a bridge-vlan section:
// t tagged, u untagged, * PVID, no flag tagged.

const vlanNetwork = `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3' 'lan4'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='10'
network.@bridge-vlan[0].alias='iot'
network.@bridge-vlan[0].ports='lan3:u*' 'lan4:t'
network.@bridge-vlan[0].local='0'
network.@bridge-vlan[1]=bridge-vlan
network.@bridge-vlan[1].device='br-lan'
network.@bridge-vlan[1].vlan='1'
network.@bridge-vlan[1].ports='lan1:u*' 'lan2:u*' 'lan4'
`

func TestVLANMatrix(t *testing.T) {
	want := `br-lan
VLAN    lan1  lan2  lan3  lan4  (bridge)
1       U*    U*    -     T     T
10 iot  -     -     U*    T     -
T tagged, U untagged, * PVID (untagged ingress lands here), - not a member; (bridge) is option local`
	if got := renderVLANMatrix(parseUCIShow(vlanNetwork)); got != want {
		t.Errorf("matrix\n--- got\n%s\n--- want\n%s", got, want)
	}
}

func TestVLANMatrixWarnings(t *testing.T) {
	cfg := `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].ports='lan1' 'lan2'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='10'
network.@bridge-vlan[0].ports='lan1:u*' 'wan:t'
network.@bridge-vlan[1]=bridge-vlan
network.@bridge-vlan[1].device='br-lan'
network.@bridge-vlan[1].vlan='20'
network.@bridge-vlan[1].ports='lan1:u*'
network.@bridge-vlan[2]=bridge-vlan
network.@bridge-vlan[2].device='br-lan'
network.@bridge-vlan[2].vlan='20'
network.@bridge-vlan[3]=bridge-vlan
network.@bridge-vlan[3].device='br-lan'
network.@bridge-vlan[3].vlan='5000'
network.@bridge-vlan[4]=bridge-vlan
network.@bridge-vlan[4].vlan='7'
`
	got := renderVLANMatrix(parseUCIShow(cfg))
	for _, w := range []string{
		"warning: br-lan: VLAN 20 is defined in 2 bridge-vlan sections",
		"warning: br-lan: lan1 has a PVID in VLANs 10, 20; a port has one",
		"warning: br-lan: wan is in a VLAN but is not a port of the bridge's device section",
		"warning: @bridge-vlan[3]: needs option device and a vlan between 1 and 4094",
		"warning: @bridge-vlan[4]: needs option device and a vlan between 1 and 4094",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestVLANMatrixCleanConfigHasNoWarnings(t *testing.T) {
	if got := renderVLANMatrix(parseUCIShow(vlanNetwork)); strings.Contains(got, "warning") {
		t.Errorf("a valid config drew a warning:\n%s", got)
	}
}

func TestVLANMatrixWithoutBridgeVLANs(t *testing.T) {
	cfg := "network.lan=interface\nnetwork.lan.device='br-lan'\nnetwork.@switch_vlan[0]=switch_vlan\n"
	got := renderVLANMatrix(parseUCIShow(cfg))
	if !strings.Contains(got, "no bridge-vlan sections") || !strings.Contains(got, "swconfig") {
		t.Errorf("a router without bridge-vlan must say so and point at swconfig: %q", got)
	}
}

func TestVLANViewRefusesOtherSelectors(t *testing.T) {
	for _, in := range []uciGetIn{
		{View: "nope"},
		{View: "vlan_matrix", Config: "firewall"},
		{View: "vlan_matrix", Section: "lan"},
		{View: "vlan_matrix", History: "list"},
		{View: "vlan_matrix", Refs: "lan"},
	} {
		if _, _, err := uciVLANView(context.Background(), in); err == nil {
			t.Errorf("%+v should be refused", in)
		}
	}
}

func TestVLANViewScopeIsTheWholeNetworkConfig(t *testing.T) {
	// A view reads the whole config, so it needs the same grant as reading the whole config, not a narrower one.
	if got := uciGetScope(uciGetIn{View: "vlan_matrix"}); len(got) != 1 || got[0] != "network" {
		t.Errorf("scope %v", got)
	}
}

// `uci show network` as a 25.12.6 x86 VM printed it with two staged bridge-vlan sections (eth3 is not a port of br-lan).
func TestVLANMatrixOnRealUCIOutput(t *testing.T) {
	cfg := `network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='eth0'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='1'
network.@bridge-vlan[0].ports='eth0:u*'
network.@bridge-vlan[1]=bridge-vlan
network.@bridge-vlan[1].device='br-lan'
network.@bridge-vlan[1].vlan='30'
network.@bridge-vlan[1].alias='iot'
network.@bridge-vlan[1].local='0'
network.@bridge-vlan[1].ports='eth0:t' 'eth3:u*'
`
	want := `br-lan
VLAN    eth0  eth3  (bridge)
1       U*    -     T
30 iot  T     U*    -
T tagged, U untagged, * PVID (untagged ingress lands here), - not a member; (bridge) is option local
warning: br-lan: eth3 is in a VLAN but is not a port of the bridge's device section`
	if got := renderVLANMatrix(parseUCIShow(cfg)); got != want {
		t.Errorf("--- got\n%s\n--- want\n%s", got, want)
	}
}
