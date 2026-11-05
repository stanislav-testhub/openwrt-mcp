package main

import (
	"strings"
	"testing"
)

// Wave 2 resolver adapters (ROADMAP 9.4). Fixtures are synthetic, from the add-ons' UCI schemas.

const wave2RC = `{
  "smartdns": {"enabled": true, "running": true, "start": 19, "stop": 10},
  "stubby":   {"enabled": true, "running": true, "start": 50, "stop": 4},
  "unbound":  {"enabled": true, "running": true, "start": 25, "stop": 4}
}`

func wave2Router(t *testing.T) *fakeRouter {
	t.Helper()
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call rc list", wave2RC)
	return f
}

func TestUnboundOnPort53ReportsModeAndCacheStats(t *testing.T) {
	f := wave2Router(t)
	f.on("pidof unbound", "900\n")
	f.on("uci -q show unbound", "unbound.ub_main=unbound\nunbound.ub_main.dhcp_link='dnsmasq'\nunbound.ub_main.validator='1'\nunbound.ub_main.forward_upstream='0'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#1053\n")
	f.on("unbound-control stats_noreset", "total.num.queries=100\ntotal.num.cachehits=70\ntotal.num.cachemiss=30\n")
	got := strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: "unbound"})), "\n")
	for _, w := range []string{"unbound: running, pid 900", "listen port: 53", "dhcp link: dnsmasq", "DNSSEC validator: on", "recursive", "queries 100, cache hits 70, misses 30"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestUnboundOnAnotherPortIsCheckedAgainstDnsmasq(t *testing.T) {
	f := wave2Router(t)
	f.on("pidof unbound", "900\n")
	f.on("uci -q show unbound", "unbound.ub_main=unbound\nunbound.ub_main.listen_port='5335'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "9.9.9.9\n")
	got := strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: "unbound"})), "\n")
	if !strings.Contains(got, "dnsmasq forwards to it: no") || !strings.Contains(got, "unbound-control not available") {
		t.Errorf("unbound off the path:\n%s", got)
	}
}

func TestStubbyShowsUpstreamsAndWiring(t *testing.T) {
	f := wave2Router(t)
	f.on("pidof stubby", "910\n")
	f.on("uci -q show stubby", "stubby.global=stubby\nstubby.global.listen_address='127.0.0.1@5453'\nstubby.@resolver[0]=resolver\nstubby.@resolver[0].address='9.9.9.9'\nstubby.@resolver[0].tls_auth_name='dns.quad9.net'\nstubby.@resolver[0].tls_pubkey_pinset='canary-pin'\nstubby.@resolver[1]=resolver\nstubby.@resolver[1].address='1.1.1.1'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#5453\n")
	got := strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: "stubby"})), "\n")
	mustNotContain(t, got, "canary-pin")
	for _, w := range []string{"stubby: running", "9.9.9.9, TLS name dns.quad9.net", "1.1.1.1, TLS name not set (no authentication)", "dnsmasq forwards to it: yes"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestSmartDNSPrintsHostsNotURLs(t *testing.T) {
	f := wave2Router(t)
	f.on("pidof smartdns", "920\n")
	f.on("uci -q show smartdns", "smartdns.@smartdns[0]=smartdns\nsmartdns.@smartdns[0].port='6053'\nsmartdns.@smartdns[0].redirect='dnsmasq-upstream'\nsmartdns.@server[0]=server\nsmartdns.@server[0].type='https'\nsmartdns.@server[0].ip='https://dns.example/dns-query/canary-token'\nsmartdns.@server[1]=server\nsmartdns.@server[1].ip='8.8.8.8'\nsmartdns.@server[1].enabled='0'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "")
	got := strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: "smartdns"})), "\n")
	mustNotContain(t, got, "canary-token", "dns-query")
	for _, w := range []string{"listen port: 6053", "https dns.example, enabled", "udp 8.8.8.8, disabled", "dnsmasq forwards to it: yes"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

// ---------------------------------------------------------------- net_diag dns_path / path

func netDiagText(t *testing.T, in netDiagIn) string {
	t.Helper()
	out, _, err := netDiag(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDNSPathNamesEachHopAndTheBlockers(t *testing.T) {
	f := newFakeRouter(t)
	withFixtureRoot(t)
	f.on("ubus call rc list", `{"adblock":{"enabled":true,"running":true,"start":30,"stop":4},"adguardhome":{"enabled":true,"running":true,"start":30,"stop":4},"https-dns-proxy":{"enabled":true,"running":true,"start":80,"stop":4},"stubby":{"enabled":false,"running":false,"start":50,"stop":4}}`)
	f.on("uci -q show https-dns-proxy", hdpUCI)
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#5053 9.9.9.9\n")
	got := netDiagText(t, netDiagIn{Action: "dns_path"})
	for _, w := range []string{"clients ask dnsmasq on port 53", "dnsmasq -> 127.0.0.1#5053 -> https-dns-proxy (dns.nextdns.io)", "dnsmasq -> 9.9.9.9 (plain DNS, not encrypted)", "blockers enabled: adblock, adguardhome", "WARNING: more than one blocker"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	mustNotContain(t, got, "canary-profile-id")
}

func TestPathShowsTheRouteTheMarkMapAndPolicyHits(t *testing.T) {
	f := newFakeRouter(t)
	withFixtureRoot(t)
	f.on("ip -4 neigh show", "192.168.1.77 dev br-lan lladdr aa:bb:cc:00:11:22 REACHABLE\n")
	f.on("ip -4 route get 1.1.1.1", "1.1.1.1 from 192.168.1.77 via 203.0.113.1 dev wan table main\n    cache iif br-lan\n")
	f.on("ip -4 rule show", "0:\tfrom all lookup local\n29998:\tfrom all fwmark 0x20000/0xff0000 lookup pbr_wg0\n29999:\tfrom all fwmark 0x3f00/0x3f00 lookup 100\n32766:\tfrom all lookup main\n")
	f.on("uci -q show pbr", pbrUCI)
	got := netDiagText(t, netDiagIn{Action: "path", Src: "AA:BB:CC:00:11:22", Target: "1.1.1.1"})
	for _, w := range []string{"client 192.168.1.77 on br-lan -> 1.1.1.1", "unmarked traffic: 1.1.1.1 from 192.168.1.77 via 203.0.113.1 dev wan table main", "mark 0x20000/0xff0000 -> table pbr_wg0", `pbr policy "Plex" sends this client out of wg0`} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
	if strings.Contains(got, "WARNING") {
		t.Errorf("disjoint masks flagged:\n%s", got)
	}
}

func TestPathFlagsOverlappingMarkMasks(t *testing.T) {
	_, overlaps := markMap("100:\tfrom all fwmark 0x10000/0xff0000 lookup a\n200:\tfrom all fwmark 0x300/0xff00ff lookup b\n")
	if len(overlaps) != 1 {
		t.Errorf("overlaps = %v", overlaps)
	}
}

func TestPathRejectsAnUnknownClientAndANameTarget(t *testing.T) {
	f := newFakeRouter(t)
	withFixtureRoot(t)
	f.on("ip -4 neigh show", "")
	if _, _, err := netDiag(t.Context(), netDiagIn{Action: "path", Src: "192.168.1.9", Target: "1.1.1.1"}); err == nil {
		t.Error("unknown client accepted")
	}
	if _, _, err := netDiag(t.Context(), netDiagIn{Action: "path", Src: "192.168.1.9", Target: "example.com"}); err == nil {
		t.Error("name target accepted")
	}
}
