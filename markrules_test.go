package main

import (
	"strings"
	"testing"
)

// Rules in the forms pbr, tailscale and podkop write (see markowners_test.go), with the address
// conditions that decide who is caught. pbr reaches its mark chains by goto from a rule that names
// the client or a set; the chains themselves carry no condition.
const clientRules = `table inet fw4 {
	set pbr_wg_4_src_ip_cfg016ff5 {
		type ipv4_addr
		flags interval
	}
	chain mangle_prerouting {
		type filter hook prerouting priority mangle; policy accept;
		jump pbr_prerouting
	}
	chain pbr_prerouting {
		ip saddr { 192.168.1.77 } ip daddr != 192.168.1.0/24 goto pbr_mark_0x020000
		ip saddr { 192.168.1.90 } goto pbr_mark_0x030000
		ip saddr @pbr_wg_4_src_ip_cfg016ff5 goto pbr_mark_0x010000
	}
	chain pbr_mark_0x020000 {
		meta mark set meta mark & 0xff00ffff | 0x00020000 return
	}
	chain pbr_mark_0x030000 {
		meta mark set meta mark & 0xff00ffff | 0x00030000 return
	}
	chain pbr_mark_0x010000 {
		meta mark set meta mark & 0xff00ffff | 0x00010000 return
	}
	chain podkop_remark {
		type filter hook prerouting priority -120; policy accept;
		iifname { "br-lan", "tailscale0" } ip daddr 198.18.0.0/15 meta l4proto { tcp, udp } meta mark set meta mark | 0x00100000
	}
}
table ip filter {
	chain ts-forward {
		iifname "tailscale0*" counter packets 0 bytes 0 meta mark set meta mark & 0xff04ffff | 0x00040000
	}
}
`

func TestClientMarkRulesNameTheRulesThatCatchOneClient(t *testing.T) {
	f := newFakeRouter(t)
	f.on("nft get element inet fw4 pbr_wg_4_src_ip_cfg016ff5 { 192.168.1.77 }", "")
	yes, maybe := clientMarkRules(t.Context(), clientRules, "192.168.1.77", "br-lan", "1.1.1.1")
	got := strings.Join(yes, "\n")
	wantAll(t, got, "pbr, chain pbr_mark_0x020000", "pbr, chain pbr_mark_0x010000")
	mustNotContain(t, got, "0x030000", "tailscale", "podkop")
	if len(maybe) != 0 {
		t.Errorf("nothing to guess about, got %v", maybe)
	}
	// the same client going to the fake-IP range is also caught by podkop; the destination condition now fits
	yes, _ = clientMarkRules(t.Context(), clientRules, "192.168.1.77", "br-lan", "198.18.0.5")
	wantAll(t, strings.Join(yes, "\n"), "podkop, chain podkop_remark")
	// a client in neither set
	f.fail("nft get element inet fw4 pbr_wg_4_src_ip_cfg016ff5 { 192.168.1.50 }", "No such file or directory")
	yes, _ = clientMarkRules(t.Context(), clientRules, "192.168.1.50", "br-lan", "1.1.1.1")
	if len(yes) != 0 {
		t.Errorf("an unlisted client is caught by %v", yes)
	}
}

func TestPathNamesTheMarkRuleForTheClient(t *testing.T) {
	f := newFakeRouter(t)
	withFixtureRoot(t)
	f.on("ip -4 neigh show", "192.168.1.77 dev br-lan lladdr aa:bb:cc:00:11:22 REACHABLE\n")
	f.on("ip -4 route get 1.1.1.1", "1.1.1.1 from 192.168.1.77 via 203.0.113.1 dev wan table main\n")
	f.on("ip -4 rule show", "29998:\tfrom all fwmark 0x20000/0xff0000 lookup pbr_wg0\n32766:\tfrom all lookup main\n")
	f.on("nft -t list ruleset", clientRules)
	f.on("nft get element inet fw4 pbr_wg_4_src_ip_cfg016ff5 { 192.168.1.77 }", "")
	got := netDiagText(t, netDiagIn{Action: "path", Src: "192.168.1.77", Target: "1.1.1.1"})
	wantAll(t, got, "nftables rule that catches this client: pbr, chain pbr_mark_0x020000", "ports, protocols and connection state are not evaluated")
}
