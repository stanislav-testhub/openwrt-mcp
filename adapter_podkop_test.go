package main

import (
	"reflect"
	"strings"
	"testing"
)

func pkDetail(t *testing.T) []string {
	t.Helper()
	return detailBody(t, listServices(t, serviceListIn{Detail: "podkop"}))
}

func TestPodkopDetailForARunningSetup(t *testing.T) {
	adapterRouter(t)
	want := []string{
		"podkop 0.7.22, sing-box 1.12.4",
		"sing-box: running, pid 7851",
		"nft: table PodkopTable loaded, 3 chains, 3 sets",
		"dnsmasq upstream servers: 127.0.0.1#5354; podkop leaves dnsmasq alone (dont_touch_dhcp 1)",
		"settings: dns udp 9.9.9.9, bootstrap 9.9.9.9, sources br-lan tailscale0, log warn, list update 1d, quic blocked, yacd off",
		"sections (4):",
		"main: vpn via wg0; community lists: russia_inside, geoblock; domains: dynamic list (2); subnets: dynamic list (1)",
		"viaproxy: proxy (url config); domains: text list",
		"blocked: block; community lists: telegram",
		"skipped: exclusion; domains: disabled",
	}
	if got := pkDetail(t); !reflect.DeepEqual(got, want) {
		t.Errorf("podkop detail:\n got %q\nwant %q", got, want)
	}
}

// podkop's proxy sections hold the credentials of the proxy (vless links, outbound JSON). The
// adapter reads the config but prints only the fixed fields above.
func TestPodkopDetailPrintsNoProxyCredentialsOrDomainLists(t *testing.T) {
	adapterRouter(t)
	out := strings.Join(pkDetail(t), "\n")
	for _, canary := range []string{
		"vless://", "canary-uuid", "canary.example.net", "CanaryPublicKey", "sid=canary", // proxy_string
		"canary-selector", "canary-outbound-secret", // selector links, outbound json
		"canary-one.example", "canary-two.example", "example.com", "example.org", "192.0.2.0/24", // user lists
		"/etc/sing-box/config.json", "/tmp/podkop-cache", // paths
	} {
		if strings.Contains(out, canary) {
			t.Errorf("the detail leaks %q:\n%s", canary, out)
		}
	}
}

func TestPodkopDetailWhenNothingIsRunning(t *testing.T) {
	f, _ := adapterRouter(t)
	f.fail("pidof sing-box", "")
	f.fail("sing-box version", "")
	f.fail("nft list table inet PodkopTable", "Error: No such file or directory")
	got := pkDetail(t)
	if got[0] != "podkop 0.7.22" || got[1] != "sing-box: not running" || got[2] != "nft: table PodkopTable not loaded" {
		t.Errorf("a stopped setup:\n%q", got)
	}
}

func TestPodkopDetailWhenTheVersionIsUnknown(t *testing.T) {
	f, root := adapterRouter(t)
	writeFixture(t, root, "usr/lib/podkop/constants.sh", "PODKOP_VERSION=\"0.7.22; reboot\"\n")
	if got := pkDetail(t)[0]; got != "podkop (version unknown), sing-box 1.12.4" {
		t.Errorf("odd version: %q", got)
	}
	for _, odd := range []string{"0.7.22;reboot", "$(reboot)", strings.Repeat("9", 33)} {
		writeFixture(t, root, "usr/lib/podkop/constants.sh", "PODKOP_VERSION=\""+odd+"\"\n")
		if got := pkDetail(t)[0]; got != "podkop (version unknown), sing-box 1.12.4" {
			t.Errorf("version %q: %q", odd, got)
		}
	}
	writeFixture(t, root, "usr/lib/podkop/constants.sh", "# no version here\n")
	f.on("sing-box version", "sing-box version 1.12.4 with extras\n")
	if got := pkDetail(t)[0]; got != "podkop (version unknown), sing-box 1.12.4" {
		t.Errorf("no version: %q", got)
	}
	f.on("sing-box version", "something else entirely\n")
	if got := pkDetail(t)[0]; got != "podkop (version unknown)" {
		t.Errorf("odd sing-box version: %q", got)
	}
	for _, short := range []string{"sing-box version\n", "sing-box\n", "\n", ""} {
		f.on("sing-box version", short)
		if got := pkDetail(t)[0]; got != "podkop (version unknown)" {
			t.Errorf("sing-box said %q: %q", short, got)
		}
	}
}

func TestPodkopDetailWithNoSections(t *testing.T) {
	f, _ := adapterRouter(t)
	f.on("uci -q show podkop", "podkop.settings=settings\n")
	got := pkDetail(t)
	if got[len(got)-2] != "settings: quic allowed, yacd off" || got[len(got)-1] != "sections (0)" {
		t.Errorf("no sections: %q", got)
	}
}

func TestPodkopDetailAboutDnsmasq(t *testing.T) {
	f, _ := adapterRouter(t)
	uci := adapterFixture(t, "podkop_uci.txt")
	for _, c := range []struct{ touch, server, want string }{
		{"1", "", "dnsmasq upstream servers: (none set); podkop leaves dnsmasq alone (dont_touch_dhcp 1)"},
		{"1", "9.9.9.9", "dnsmasq upstream servers: 9.9.9.9; podkop leaves dnsmasq alone (dont_touch_dhcp 1)"},
		{"0", "127.0.0.42", "dnsmasq upstream servers: 127.0.0.42; podkop is in the DNS path"},
		{"1", "127.0.0.42 9.9.9.9", "dnsmasq upstream servers: 127.0.0.42, 9.9.9.9; podkop is in the DNS path"},
		{"0", "9.9.9.9", "dnsmasq upstream servers: 9.9.9.9; podkop expects 127.0.0.42, so DNS bypasses it"},
		{"0", "", "dnsmasq upstream servers: (none set); podkop expects 127.0.0.42, so DNS bypasses it"},
	} {
		f.on("uci -q show podkop", strings.Replace(uci, "podkop.settings.dont_touch_dhcp='1'", "podkop.settings.dont_touch_dhcp='"+c.touch+"'", 1))
		f.on("uci -q get dhcp.@dnsmasq[0].server", c.server+"\n")
		if got := pkDetail(t)[3]; got != c.want {
			t.Errorf("touch=%s server=%q:\n got %q\nwant %q", c.touch, c.server, got, c.want)
		}
	}
}

func TestPodkopDetailShowsTheSettingsThatMatter(t *testing.T) {
	f, _ := adapterRouter(t)
	uci := adapterFixture(t, "podkop_uci.txt")
	uci = strings.Replace(uci, "podkop.settings.enable_yacd='0'", "podkop.settings.enable_yacd='1'", 1)
	uci = strings.Replace(uci, "podkop.settings.disable_quic='1'", "podkop.settings.disable_quic='0'", 1)
	uci = strings.Replace(uci, "podkop.settings.dns_type='udp'", "podkop.settings.dns_type='doh'", 1)
	f.on("uci -q show podkop", uci)
	want := "settings: dns doh 9.9.9.9, bootstrap 9.9.9.9, sources br-lan tailscale0, log warn, list update 1d, quic allowed, yacd on"
	if got := pkDetail(t)[4]; got != want {
		t.Errorf("settings line:\n got %q\nwant %q", got, want)
	}
}

func TestPodkopDetailWhenTheConfigCannotBeRead(t *testing.T) {
	f, _ := adapterRouter(t)
	f.fail("uci -q show podkop", "uci: Entry not found")
	got := pkDetail(t)
	if got[0] != "podkop 0.7.22, sing-box 1.12.4" || !contains(got, "podkop config unreadable: uci show podkop: exit status 1 uci: Entry not found") {
		t.Errorf("got %q", got)
	}
	for _, l := range got {
		if strings.HasPrefix(l, "settings:") || strings.HasPrefix(l, "sections") {
			t.Errorf("settings printed without a config: %q", l)
		}
	}
	// Without the config nothing is known about dont_touch_dhcp, so no verdict on the DNS path.
	if got[3] != "dnsmasq upstream servers: 127.0.0.1#5354" {
		t.Errorf("dnsmasq line without a config: %q", got[3])
	}
}

func TestPodkopDetailBoundsTheSectionList(t *testing.T) {
	f, _ := adapterRouter(t)
	var b strings.Builder
	b.WriteString("podkop.settings=settings\n")
	for i := 0; i < 30; i++ {
		b.WriteString("podkop.s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "=section\n")
		b.WriteString("podkop.s" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".connection_type='block'\n")
	}
	f.on("uci -q show podkop", b.String())
	got := pkDetail(t)
	var shown int
	for _, l := range got {
		if strings.HasSuffix(l, ": block") {
			shown++
		}
	}
	if shown != 20 || !contains(got, "sections (30):") || got[len(got)-1] != "... 10 more sections not shown" {
		t.Errorf("shown %d, last %q", shown, got[len(got)-1])
	}
}

func TestPodkopDetailCountsChainsAndSetsWithTheRightPlural(t *testing.T) {
	f, _ := adapterRouter(t)
	for nft, want := range map[string]string{
		"table inet PodkopTable {\n}\n":                                                   "nft: table PodkopTable loaded, 0 chains, 0 sets",
		"table inet PodkopTable {\n\tset s {\n\t}\n\tchain c {\n\t}\n}\n":                 "nft: table PodkopTable loaded, 1 chain, 1 set",
		"table inet PodkopTable {\n\tset a {\n\t}\n\tset b {\n\t}\n\tchain c {\n\t}\n}\n": "nft: table PodkopTable loaded, 1 chain, 2 sets",
	} {
		f.on("nft list table inet PodkopTable", nft)
		if got := pkDetail(t)[2]; got != want {
			t.Errorf("nft %q -> %q, want %q", nft, got, want)
		}
	}
}

func TestPodkopDetailRecognisesItsOwnDnsAddressOnly(t *testing.T) {
	f, _ := adapterRouter(t)
	for server, inPath := range map[string]bool{
		"127.0.0.42": true, "127.0.0.42#53": true, "127.0.0.420": false, "127.0.0.4": false, "9.127.0.0.42": false,
	} {
		f.on("uci -q get dhcp.@dnsmasq[0].server", server+"\n")
		got := pkDetail(t)[3]
		if has := strings.Contains(got, "podkop is in the DNS path"); has != inPath {
			t.Errorf("server %q: %q (in path wanted: %v)", server, got, inPath)
		}
	}
}

func TestPodkopDetailSectionsWithMissingOrOddFields(t *testing.T) {
	f, _ := adapterRouter(t)
	f.on("uci -q show podkop", strings.Join([]string{
		"podkop.settings=settings",
		"podkop.a=section",
		"podkop.b=section", "podkop.b.connection_type='vpn'",
		"podkop.c=section", "podkop.c.connection_type='proxy'",
		"podkop.d=section", "podkop.d.connection_type='weird\x1b[2J type!'",
		"podkop.e=section", "podkop.e.connection_type='vpn'", "podkop.e.interface='wg0'",
		"podkop.f=section", "podkop.f.connection_type='proxy'", "podkop.f.proxy_config_type='selector'",
		"",
	}, "\n"))
	got := pkDetail(t)
	want := []string{
		"settings: quic allowed, yacd off",
		"sections (6):",
		"a: (connection_type not set)",
		"b: vpn",
		"c: proxy",
		"d: weird type!",
		"e: vpn via wg0",
		"f: proxy (selector config)",
	}
	if i := indexOf(got, want[0]); i < 0 || !reflect.DeepEqual(got[i:], want) {
		t.Errorf("sections:\n got %q\nwant %q", got, want)
	}
}

func FuzzRenderPodkopConfig(f *testing.F) {
	f.Add("podkop.settings=settings\npodkop.main=section\npodkop.main.connection_type='vpn'\n")
	f.Add("podkop.x=section\npodkop.x.user_domains='a' 'b\n")
	f.Add("garbage\n\n=\n.\n..=\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = podkopConfigLines(parseUCIShow(s))
	})
}
