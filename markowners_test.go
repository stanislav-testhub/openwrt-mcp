package main

import (
	"strings"
	"testing"
)

// A real ruleset from the 25.12.6 VM with mwan3 2.12.0 (iptables-nft: the MARK value is hidden) and
// pbr 1.2.2 (native nft marks), taken with `make capture`.
func TestMarkOwnersFromARealMwan3AndPbrRuleset(t *testing.T) {
	us := parseMarkOwners(captured(t, "nft-marks", "01.txt"))
	var names []string
	for _, u := range us {
		names = append(names, u.describe())
	}
	got := strings.Join(names, "\n")
	wantAll(t, got, "mwan3: bits 0xff00, value not visible", "pbr: bits 0xff0000, writes 0x10000 0x20000 0x30000")
	if c := markConflicts(us); len(c) != 0 {
		t.Errorf("mwan3 0xff00 and pbr 0xff0000 do not overlap, got %q", c)
	}
	rules := captured(t, "nft-marks", "02.txt")
	ms, _ := markMap(rules)
	byTable := map[string]string{}
	for _, m := range ms {
		byTable[m.table] = ruleOwners(m, us)
	}
	if byTable["pbr_wan"] != "pbr" || byTable["1"] != "mwan3" {
		t.Errorf("rule owners: %v", byTable)
	}
}

// Synthetic, written from the add-ons' sources and not captured: tailscale marks with
// 0xff0000/0x40000 in its ts-* chains, podkop sets a whole mark in its own table.
const syntheticMarks = `table inet fw4 {
	chain pbr_prerouting {
		ip saddr 192.0.2.5 goto pbr_mark_0x040000
	}
	chain pbr_mark_0x040000 {
		meta mark set meta mark & 0xff03ffff | 0x00040000
	}
}
table ip filter {
	chain ts-forward {
		meta mark set meta mark & 0xff00ffff | 0x00040000
		meta mark & 0x00ff0000 == 0x00040000 accept
	}
}
table inet PodkopTable {
	chain mangle {
		meta l4proto tcp meta mark set 0x00000105
	}
}
`

func TestMarkConflictsNameTheCollidingAddOns(t *testing.T) {
	got := strings.Join(markConflicts(parseMarkOwners(syntheticMarks)), "\n")
	wantAll(t, got, "pbr and tailscale both write mark 0x40000", "podkop sets the whole mark")
	mustNotContain(t, got, "fw4")
}

func TestMarkOwnersIgnoreWhatIsNotARoutingAddOn(t *testing.T) {
	us := parseMarkOwners("table inet fw4 {\n\tchain mangle_forward {\n\t\tmeta mark set 0x1\n\t}\n}\n")
	if len(us) != 0 {
		t.Errorf("fw4 chains are not an add-on: %+v", us)
	}
}

// The forms tailscale and podkop write on a real GL-MT6000 (OpenWrt 25.12.6), rewritten by hand with
// neutral addresses: podkop's whole-mark write is followed by `counter`, its OR form lives in an fw4
// chain called podkop_remark, and tailscale keeps the rest of the mark. They use different values
// inside tailscale's field, so they do not collide, but podkop does set the whole mark.
const liveFormMarks = `table inet fw4 {
	chain podkop_remark {
		iifname { "br-lan", "tailscale0" } ip daddr 198.18.0.0/15 meta l4proto { tcp, udp } meta mark set meta mark | 0x00100000
	}
}
table ip filter {
	chain ts-forward {
		iifname "tailscale0*" counter packets 0 bytes 0 meta mark set meta mark & 0xff04ffff | 0x00040000
		meta mark & 0x00ff0000 == 0x00040000 counter packets 0 bytes 0 accept
	}
}
table inet PodkopTable {
	chain mangle {
		iifname @interfaces ip daddr 198.18.0.0/15 meta l4proto tcp meta mark set 0x00100000 counter packets 0 bytes 0
	}
	chain proxy {
		meta mark 0x00200000 counter packets 0 bytes 0 return
		meta mark & 0x00100000 == 0x00100000 meta l4proto tcp tproxy ip to 127.0.0.1:1602 counter packets 0 bytes 0
	}
}
`

func TestMarkOwnersReadTheFormsTailscaleAndPodkopWriteOnARealRouter(t *testing.T) {
	us := parseMarkOwners(liveFormMarks)
	var names []string
	for _, u := range us {
		names = append(names, u.describe())
	}
	got := strings.Join(names, "\n")
	wantAll(t, got, "podkop: bits 0x300000, writes 0x100000", "tailscale: bits 0xff0000, writes 0x40000")
	mustNotContain(t, got, "value not visible")
	c := strings.Join(markConflicts(us), "\n")
	wantAll(t, c, "podkop sets the whole mark")
	mustNotContain(t, c, "without sharing a mask", "both write")
}
