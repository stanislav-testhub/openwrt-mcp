package main

import (
	"context"
	"net"
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

// A dnsmasq upstream no add-on config claims (a proxy stack's DNS port) is named by the process
// that holds the port, read from /proc, so the wave 4 stacks need no port table of their own.
func TestDNSPathNamesTheProcessBehindAnUnclaimedLocalPort(t *testing.T) {
	f := newFakeRouter(t)
	withFixtureRoot(t)
	f.on("ubus call rc list", `{}`)
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#7874 127.0.0.1#7999\n")
	writeFixture(t, sysRoot, "proc/net/udp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"+
		"   1: 0100007F:1EC2 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 55501 2 0000000000000000 0\n")
	holdSocket(t, "321", "clash\x1b[31m", "55501")
	got := netDiagText(t, netDiagIn{Action: "dns_path"})
	wantAll(t, got, "dnsmasq -> 127.0.0.1#7874 -> (process clash", "no add-on config claims this port",
		"dnsmasq -> 127.0.0.1#7999 -> (a local listener this tool does not know)")
	mustNotContain(t, got, "\x1b")
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

// ---------------------------------------------------------------- UCI-driven wave 2 adapters

func addRC(f *fakeRouter, names ...string) {
	var parts []string
	for _, n := range names {
		parts = append(parts, `"`+n+`":{"enabled":true,"running":true,"start":50,"stop":4}`)
	}
	f.on("ubus call rc list", "{"+strings.Join(parts, ",")+"}")
}

func body(t *testing.T, svc string) string {
	t.Helper()
	return strings.Join(detailBody(t, listServices(t, serviceListIn{Detail: svc})), "\n")
}

func wantAll(t *testing.T, got string, ws ...string) {
	t.Helper()
	for _, w := range ws {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestWatchcatListsRules(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "watchcat")
	f.on("pidof watchcat.sh", "30\n")
	f.on("uci -q show watchcat", "watchcat.@watchcat[0]=watchcat\nwatchcat.@watchcat[0].mode='ping_reboot'\nwatchcat.@watchcat[0].pinghosts='192.168.1.1'\nwatchcat.@watchcat[0].period='6h'\nwatchcat.@watchcat[1]=watchcat\nwatchcat.@watchcat[1].mode='run_script'\nwatchcat.@watchcat[1].script='/root/canary-script.sh'\n")
	got := body(t, "watchcat")
	mustNotContain(t, got, "canary-script")
	wantAll(t, got, "rules (2):", "ping_reboot, period 6h, ping 192.168.1.1", "run_script, runs a script")
}

func TestOpenVPNShowsRoleAndNeverTheKeyFiles(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "openvpn")
	f.on("ubus call service list", `{"openvpn":{"instances":{"office":{"running":true}}}}`)
	f.on("uci -q show openvpn", "openvpn.office=openvpn\nopenvpn.office.enabled='1'\nopenvpn.office.client='1'\nopenvpn.office.proto='udp'\nopenvpn.office.dev='tun0'\nopenvpn.office.remote='vpn.example.com 1194'\nopenvpn.office.key='/etc/openvpn/canary.key'\nopenvpn.office.auth_user_pass='/etc/openvpn/canary.auth'\nopenvpn.office.redirect_gateway='def1'\nopenvpn.srv=openvpn\nopenvpn.srv.enabled='0'\n")
	got := body(t, "openvpn")
	mustNotContain(t, got, "canary")
	wantAll(t, got, "an instance is running", "office, enabled, client, udp, dev tun0, remote vpn.example.com, redirects the default route", "srv, disabled, server")
}

func TestNextDNSMasksTheProfileAndChecksTheWiring(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "nextdns")
	f.on("pidof nextdns", "41\n")
	f.on("uci -q show nextdns", "nextdns.main=nextdns\nnextdns.main.enabled='1'\nnextdns.main.config='abc123canary'\nnextdns.main.listen='127.0.0.1:5342'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#5342\n")
	got := body(t, "nextdns")
	mustNotContain(t, got, "abc123canary")
	wantAll(t, got, "profile: set (id not shown)", "dnsmasq forwards to it: yes")
}

func TestQosifyAndTravelmateSummaries(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "qosify", "travelmate")
	f.on("pidof qosify", "51\n")
	f.on("uci -q show qosify", "qosify.wan=interface\nqosify.wan.name='wan'\nqosify.wan.bandwidth_up='20mbit'\nqosify.wan.bandwidth_down='100mbit'\nqosify.c1=class\n")
	f.on("pidof travelmate.sh", "")
	f.on("uci -q show travelmate", "travelmate.global=travelmate\ntravelmate.global.trm_enabled='1'\ntravelmate.@uplink[0]=uplink\ntravelmate.@uplink[0].ssid='canary-ssid'\n")
	wantAll(t, body(t, "qosify"), "wan: enabled, up 20mbit, down 100mbit", "classes: 1")
	tm := body(t, "travelmate")
	mustNotContain(t, tm, "canary-ssid")
	wantAll(t, tm, "travelmate.sh: not running", "configured uplinks: 1")
}

func TestZeroTierDoesNotPrintNetworkNames(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "zerotier")
	f.on("pidof zerotier-one", "60\n")
	f.on("zerotier-cli listnetworks", "200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>\n200 listnetworks 8056c2e21c000001 canary name aa:bb:cc:dd:ee:ff OK PRIVATE ztabc 10.147.17.5/24\n")
	got := body(t, "zerotier")
	mustNotContain(t, got, "canary")
	wantAll(t, got, "networks (1):", "8056c2e21c000001: OK, PRIVATE, dev ztabc, addresses 10.147.17.5/24")
}

func TestNetBirdKeepsOnlyKnownFields(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "netbird")
	f.on("pidof netbird", "70\n")
	f.on("netbird status", "Daemon version: 0.30.1\nManagement: Connected\nSignal: Connected\nSetup key: canary-key\nNetBird IP: 100.64.0.5/16\nPeers count: 2/3 Connected\n")
	got := body(t, "netbird")
	mustNotContain(t, got, "canary-key")
	wantAll(t, got, "Management: Connected", "Peers count: 2/3 Connected")
}

func TestWave2SecondBatchNeverPrintsSecrets(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "cloudflared", "frpc", "frps", "collectd", "swanctl")
	f.on("pidof cloudflared", "1\n")
	f.on("uci -q show cloudflared", "cloudflared.config=cloudflared\ncloudflared.config.enabled='1'\ncloudflared.config.token='canary-tunnel-token'\n")
	f.on("pidof frpc", "2\n")
	f.on("uci -q show frpc", "frpc.main=frpc\nfrpc.main.server_addr='frp.example.com'\nfrpc.main.server_port='7000'\nfrpc.main.token='canary-frp'\nfrpc.@conf[0]=conf\n")
	f.on("pidof frps", "")
	f.on("uci -q show frps", "frps.main=frps\nfrps.main.dashboard_port='7500'\nfrps.main.dashboard_pwd='canary-dash'\n")
	f.on("pidof collectd", "3\n")
	f.on("uci -q show luci_statistics", "luci_statistics.collectd_rrdtool=statistics\nluci_statistics.collectd_rrdtool.DataDir='/tmp/rrd'\nluci_statistics.collectd_cpu=statistics\nluci_statistics.collectd_cpu.enable='1'\nluci_statistics.collectd_ping=statistics\nluci_statistics.collectd_ping.enable='0'\n")
	f.on("pidof charon", "4\n")
	f.on("swanctl --list-sas", "site: #1, ESTABLISHED, IKEv2, canary-spi\n  net: #1, reqid 1, INSTALLED, TUNNEL\n")
	all := ""
	for _, s := range []string{"cloudflared", "frpc", "frps", "collectd", "swanctl"} {
		all += body(t, s) + "\n"
	}
	mustNotContain(t, all, "canary")
	wantAll(t, all, "tunnel token: set (not shown)", "server: frp.example.com:7000", "proxies: 1", "token: not set (any client may connect)", "password set",
		"data directory: /tmp/rrd, in RAM, lost on reboot", "plugins enabled (1): cpu", "IKE SAs established: 1", "child SAs installed: 1")
}

func TestAuditFlagsAnFrpServerWithoutAToken(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "frps")
	f.on("ubus call rc list", `{"frps":{"enabled":true,"running":true,"start":99,"stop":1}}`)
	f.on("uci -q show frps", "frps.main=frps\n")
	if auditFindings(context.Background()).byID("frps-open") == nil {
		t.Error("token-less frps not flagged")
	}
	f.on("uci -q show frps", "frps.main=frps\nfrps.main.token='x'\n")
	if auditFindings(context.Background()).byID("frps-open") != nil {
		t.Error("frps with a token flagged")
	}
}

// Found on a real router: collectd installed without luci-app-statistics has no luci_statistics
// config, which is not a fault.
func TestCollectdWithoutLuciStatisticsIsNotAFault(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "collectd")
	f.on("pidof collectd", "3\n")
	f.fail("uci -q show luci_statistics", "")
	out := body(t, "collectd")
	wantAll(t, out, "collectd: running", "no luci_statistics config: luci-app-statistics is not installed")
	mustNotContain(t, out, "unreadable")
}

func TestIPSpecMatchHandlesCIDRsNegationAndNames(t *testing.T) {
	cases := []struct {
		spec    []string
		ip      string
		match   bool
		unknown int
	}{
		{[]string{"192.168.1.0/24"}, "192.168.1.9", true, 0},
		{[]string{"192.168.1.0/24"}, "192.168.2.9", false, 0},
		{[]string{"10.0.0.1 10.0.0.2"}, "10.0.0.2", true, 0},
		{[]string{"10.0.0.1,10.0.0.2"}, "10.0.0.3", false, 0},
		{[]string{"!192.168.1.5"}, "192.168.1.6", true, 0},
		{[]string{"!192.168.1.5"}, "192.168.1.5", false, 0},
		{[]string{"192.168.1.0/24 !192.168.1.5"}, "192.168.1.5", false, 0},
		{[]string{"example.com", "10.1.1.1"}, "10.1.1.1", true, 1},
		{[]string{"example.com", "@set"}, "10.1.1.1", false, 2},
		{[]string{"2001:db8::/32"}, "2001:db8::1", true, 0},
		{[]string{"2001:db8::/32"}, "10.1.1.1", false, 0},
		{nil, "10.1.1.1", false, 0},
	}
	for _, c := range cases {
		m, u := ipSpecMatch(c.spec, net.ParseIP(c.ip))
		if m != c.match || u != c.unknown {
			t.Errorf("ipSpecMatch(%q, %s) = %v, %d; want %v, %d", c.spec, c.ip, m, u, c.match, c.unknown)
		}
	}
}
