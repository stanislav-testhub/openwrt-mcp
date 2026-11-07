package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// These run the adapters against scrubbed captures from a real router: OpenWrt 24.10.8 (x86 VM) with
// banip 1.5.6-r7, adblock-fast 1.2.4-r4 and mwan3 2.11.16-r5 installed, taken with `make capture`
// (ROADMAP 9.2, 9.7). The services were installed but banip disabled and adblock-fast failed to
// start (no DNS on that VM), so these are two real "not working" states and one working one.
// What is not covered: a running banIP or a loaded adblock-fast list.

func captured(t *testing.T, svc, file string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/captured/" + svc + "/" + file)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := strings.Cut(string(b), "\n") // the first line names the command
	return body
}

func TestBanIPOnItsRealRuntimeFile(t *testing.T) {
	_, root := wave1Router(t)
	writeFixture(t, root, "var/run/banip_runtime.json", captured(t, "banip", "03.txt"))
	got := strings.Join(detail(t, "banip"), "\n")
	wantAll(t, got, "status: disabled, banip 1.5.6-r7", "elements: 0 (chains: 0, sets: 0, rules: 0)", "feeds: none active",
		"NOTE: status is disabled, so nothing is being filtered")
	mustNotContain(t, got, "WARNING: no WAN interface", "- (1)")
}

func TestAdblockFastOnItsRealServiceDataAfterAFailedStart(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"adblock-fast"}`, captured(t, "adblock-fast", "01.txt"))
	f.on("uci -q show adblock-fast", captured(t, "adblock-fast", "02.txt"))
	got := strings.Join(detail(t, "adblock-fast"), "\n")
	wantAll(t, got, "adblock-fast: registered, no running instance", "status: failed", "errors: errorNoHeartbeat, errorOhSnap",
		"warnings: warningMissingRecommendedPackages", "16 list sources configured")
	// The list URLs are in the service data and never printed.
	mustNotContain(t, got, "https://", "hagezi")
}

func TestMwan3OnItsRealStatus(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call mwan3 status {"section":"interfaces"}`, captured(t, "mwan3", "02.txt"))
	f.on(`ubus call mwan3 status {"section":"policies"}`, captured(t, "mwan3", "03.txt"))
	got := strings.Join(detail(t, "mwan3"), "\n")
	wantAll(t, got, "interfaces (4):", "wan: online, link up, tracking active, 2 of 4 track IPs up", "wan6: unknown, disabled, link down, tracking down",
		"policies (5):", "balanced: wan 100%", "wanb_only: no active member")
}

// pbr 1.2.2-r20 and https-dns-proxy 2026.05.06-r1, 24.10.8 VM, installed with stock config (pbr enabled
// and started, no policy in use). Not covered: a pbr policy that really routes traffic.
func TestPbrOnItsRealServiceData(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"pbr"}`, captured(t, "pbr", "01.txt"))
	f.on("uci -q show pbr", captured(t, "pbr", "02.txt"))
	got := strings.Join(detail(t, "pbr"), "\n")
	wantAll(t, got, "gateways (1):", "wan: table 256, mark 0x010000, priority 30000", "warnings: warningResolverNotSupported",
		"settings: enabled, resolver set dnsmasq.nftset", "policies (3):", "Plex/Emby Local Server: via wan, disabled")
}

func TestHTTPSDNSProxyOnItsRealConfig(t *testing.T) {
	f, _ := wave1Router(t)
	f.on("pidof https-dns-proxy", captured(t, "https-dns-proxy", "01.txt"))
	f.on("uci -q show https-dns-proxy", captured(t, "https-dns-proxy", "02.txt"))
	f.on("uci -q get dhcp.@dnsmasq[0].server", captured(t, "https-dns-proxy", "03.txt"))
	got := strings.Join(detail(t, "https-dns-proxy"), "\n")
	wantAll(t, got, "instances (2):", "cloudflare-dns.com, listens on 127.0.0.1:5053, bootstrap DNS set",
		"dns.google, listens on 127.0.0.1:5054", "https-dns-proxy is in the DNS path")
}

// The same two add-ons doing their job: banIP 1.5.6-r7 active with the doh and tor feeds, adblock-fast
// after a run that loaded 239,581 domains (the VM got DNS through https-dns-proxy to a resolver IP).
func TestBanIPOnItsRealActiveRuntimeFile(t *testing.T) {
	_, root := wave1Router(t)
	writeFixture(t, root, "var/run/banip_runtime.json", captured(t, "banip-active", "03.txt"))
	got := strings.Join(detail(t, "banip"), "\n")
	wantAll(t, got, "status: active, banip 1.5.6-r7", "elements: 2 229 (chains: 7, sets: 10, rules: 37)", "feeds (10): allowlist.v4MAC",
		"doh.v4", "tor.v4", "wan interfaces: wan")
	mustNotContain(t, got, "NOTE: status is", "WARNING")
}

func TestAdblockFastOnItsRealServiceDataAfterARun(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"adblock-fast"}`, captured(t, "adblock-fast-active", "01.txt"))
	f.on("uci -q show adblock-fast", captured(t, "adblock-fast-active", "02.txt"))
	got := strings.Join(detail(t, "adblock-fast"), "\n")
	wantAll(t, got, "status: blocking", "is blocking 239581 domains", "warnings: warningMissingRecommendedPackages")
	mustNotContain(t, got, "https://", "failed")
}

// OpenWrt 25.12.6 (x86 VM, apk): banip 1.9.1-r5 and adblock-fast 1.2.4-r4. banIP 1.9 keeps its
// version in backend_ver; adblock-fast ships every list source disabled on 25.12, so a fresh start
// fails with errorNothingToDo.
func TestBanIPOnItsReal25RuntimeFile(t *testing.T) {
	_, root := wave1Router(t)
	writeFixture(t, root, "var/run/banIP/banIP.runtime.json", captured(t, "banip-2512", "03.txt"))
	got := strings.Join(detail(t, "banip"), "\n")
	wantAll(t, got, "status: active, banip 1.9.1-r5", "elements: 2 230 (chains: 7, sets: 10, rules: 38)", "doh.v4", "wan interfaces: wan")
	mustNotContain(t, got, "NOTE: status is", "WARNING")
}

func TestAdblockFastOnItsReal25ServiceDataWithNothingEnabled(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"adblock-fast"}`, captured(t, "adblock-fast-2512", "01.txt"))
	f.on("uci -q show adblock-fast", captured(t, "adblock-fast-2512", "02.txt"))
	got := strings.Join(detail(t, "adblock-fast"), "\n")
	wantAll(t, got, "status: failed", "errors: errorNothingToDo, errorOhSnap", "16 list sources configured, none enabled, so there is nothing to download")
}

// adblock 4.4.2-r4 on the 24.10.8 VM after a real run of the adguard feed (187,749 domains). The
// runtime file there is /var/run/adb_runtime.json and the version key is adblock_version.
func TestAdblockOnItsRealRuntimeFileAfterARun(t *testing.T) {
	f, root := wave1Router(t)
	f.on(`ubus call service list {"name":"adblock"}`, `{}`)
	writeFixture(t, root, "var/run/adb_runtime.json", captured(t, "adblock-active", "02.txt"))
	got := strings.Join(detail(t, "adblock"), "\n")
	wantAll(t, got, "status: enabled, adblock 4.4.2-r4", "blocked domains: 187 749", "feeds (1): adguard",
		"dns_backend: dnsmasq (2.93-r1)", "last run: mode: restart")
	mustNotContain(t, got, "output not recognised", "not readable")
}

// The merged list of adblock 4.4.2 sits in dnsmasq's conf dir, named in run_directories, and holds
// `local=/name/` lines (the list here was cut to the entries the test asks about).
func TestAdblockQueryOnItsRealListLocationAndFormat(t *testing.T) {
	f, root := wave1Router(t)
	f.on(`ubus call service list {"name":"adblock"}`, `{}`)
	writeFixture(t, root, "var/run/adb_runtime.json", captured(t, "adblock-active", "02.txt"))
	writeFixture(t, root, "tmp/dnsmasq.cfg01411c.d/adb_list.overall", "local=/marketing.example/\nlocal=/doubleclick.net/\n")
	if got := queryOut(t, "adblock", "stats.doubleclick.net"); !strings.Contains(got, "blocked: stats.doubleclick.net matches an entry for doubleclick.net") {
		t.Errorf("blocked:\n%s", got)
	}
	if got := queryOut(t, "adblock", "openwrt.org"); !strings.Contains(got, "not blocked: openwrt.org") {
		t.Errorf("not blocked:\n%s", got)
	}
}

// miniupnpd 2.3.9-r1 on the 24.10.8 VM with one real mapping made by upnpc (miniupnpc 2.2.8) over
// UPnP IGD. miniupnpd refuses mappings while the WAN address is private, so the VM had external_ip set to
// a public-looking address; the lease file format is what a real mapping produces.
func TestUPnPOnItsRealUCIAndLeaseFileWithAMapping(t *testing.T) {
	f, root := wave1Router(t)
	f.on("pidof miniupnpd", "901\n")
	f.on("uci -q show upnpd", captured(t, "upnp-active", "01.txt"))
	writeFixture(t, root, "var/run/miniupnpd.leases", captured(t, "upnp-active", "02.txt"))
	got := strings.Join(detail(t, "miniupnpd"), "\n")
	wantAll(t, got, "settings: enabled, protocols UPnP+NAT-PMP, internal lan", "secure mode on", "mappings (1):", "TCP 8080 -> 192.168.1.1:8080 (miniupnpc)")
	mustNotContain(t, got, "WARNING")
}

// ddns-scripts 2.8.2-r68 on the 24.10.8 VM after a real update: a custom update_url answered by a local
// receiver, lookup_host that does not resolve. The .ip file is empty then (it holds the DNS answer, not
// what the provider was told), the .update file still records the update.
func TestDDNSOnItsRealStateFilesAfterAnUpdate(t *testing.T) {
	f, root := wave1Router(t)
	f.on("pidof dynamic_dns_updater.sh", "1201\n")
	f.on("uci -q show ddns", captured(t, "ddns-active", "01.txt"))
	f.on("ubus call network.interface.lan status", `{"up":true,"ipv4-address":[{"address":"192.168.1.1","mask":24}]}`)
	writeFixture(t, root, "var/run/ddns/lab.ip", captured(t, "ddns-active", "02.txt"))
	writeFixture(t, root, "var/run/ddns/lab.update", captured(t, "ddns-active", "03.txt"))
	got := strings.Join(detail(t, "ddns"), "\n")
	wantAll(t, got, "lab: enabled, lab.example.com, custom update URL, IPv4", "registered unknown, WAN 192.168.1.1, last update ")
	mustNotContain(t, got, "WARNING", "no update recorded", "127.0.0.1:18080")
}

// pbr 1.2.2-r20 on the 24.10.8 VM with two policies of its own: one via wan (it produced a real nft rule
// and a mark chain), one via wg0, which pbr has no gateway for and reported as errorPolicyUnknownInterface.
func TestPbrOnItsRealServiceDataWithAPolicyItCouldNotApply(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"pbr"}`, captured(t, "pbr-active", "01.txt"))
	f.on("uci -q show pbr", captured(t, "pbr-active", "02.txt"))
	got := strings.Join(detail(t, "pbr"), "\n")
	wantAll(t, got, "errors: errorPolicyUnknownInterface", "to-quad9-wg: via wg0, NOTE: pbr has no gateway for this interface, so the policy is not applied",
		"lan-host-wan: via wan")
	mustNotContain(t, got, "lan-host-wan: via wan, NOTE", "Plex/Emby Local Server: via wan, NOTE")
}

// pbr 1.2.2-r20 on the 25.12.6 VM with a second uplink (eth2 as wan2): pbr made a routing table and a mark
// for it, and a policy for one LAN client via wan2 produced a real nft rule and `ip route get` with that mark
// left through eth2. The adapter must list three gateways and not flag the wan2 policy.
func TestPbrWithASecondUplinkOnItsRealServiceData(t *testing.T) {
	f, _ := wave1Router(t)
	f.on(`ubus call service list {"name":"pbr"}`, captured(t, "pbr-two-uplinks", "01.txt"))
	f.on("uci -q show pbr", captured(t, "pbr-two-uplinks", "02.txt"))
	got := strings.Join(detail(t, "pbr"), "\n")
	wantAll(t, got, "gateways (3):", "wan2: table 258, mark 0x030000, priority 29998, create", "client via wan2: via wan2", "udp dns via wan: via wan")
	mustNotContain(t, got, "client via wan2: via wan2, NOTE", "udp dns via wan: via wan, NOTE")
	q := queryOut(t, "pbr", "192.168.1.50")
	wantAll(t, q, "policy client via wan2: src_addr contains 192.168.1.50, via wan2")
	mustNotContain(t, q, "udp dns via wan")
}

// query on the real pbr data (24.10.8 VM, two policies of its own) and the stock mwan3 rules.
func TestPbrQueryOnItsRealPolicies(t *testing.T) {
	f, _ := wave1Router(t)
	f.on("uci -q show pbr", captured(t, "pbr-active", "02.txt"))
	if got := queryOut(t, "pbr", "192.168.1.50"); !strings.Contains(got, "policy lan-host-wan: src_addr contains 192.168.1.50, via wan") {
		t.Errorf("src:\n%s", got)
	}
	if got := queryOut(t, "pbr", "198.51.100.2"); !strings.Contains(got, "policy to-quad9-wg: dest_addr contains 198.51.100.2, via wg0") {
		t.Errorf("dest:\n%s", got)
	}
	got := queryOut(t, "pbr", "10.1.2.3")
	wantAll(t, got, "no pbr policy lists 10.1.2.3 in src_addr or dest_addr")
	mustNotContain(t, got, "policy lan-host-wan", "policy to-quad9-wg")
}

func TestMwan3QueryOnItsRealStockRules(t *testing.T) {
	f, _ := wave1Router(t)
	f.on("uci -q show mwan3", captured(t, "mwan3", "01.txt"))
	f.on(`ubus call mwan3 status {"section":"policies"}`, captured(t, "mwan3", "03.txt"))
	got := queryOut(t, "mwan3", "8.8.8.8")
	wantAll(t, got, "as destination: rule default_rule_v4 (dest_ip 0.0.0.0/0) uses policy balanced", "members now: wan 100%",
		"not evaluated: 1 rule without an address")
	if got6 := queryOut(t, "mwan3", "2606:4700::1111"); !strings.Contains(got6, "rule default_rule_v6 (dest_ip ::/0)") {
		t.Errorf("v6:\n%s", got6)
	}
}

// collectd 5.12 with luci-app-statistics (26.304) and rrdtool 1.0.50 on the 25.12.6 VM, a few minutes
// after the service started: `rrdtool fetch` prints a header of data source names, a blank line and
// "timestamp:  value ..." rows, with -nan where nothing was stored yet.
func historyRouter(t *testing.T) *fakeRouter {
	f, root := wave1Router(t)
	f.on("uci -q show luci_statistics", captured(t, "statistics-active", "01.txt"))
	for _, p := range []string{"load/load", "cpu-0/percent-idle", "cpu-1/percent-idle", "interface-br-lan/if_octets", "interface-lo/if_octets",
		"memory/memory-used", "memory/memory-free", "memory/memory-buffered", "memory/memory-cached", "memory/memory-slab_recl", "memory/memory-slab_unrecl"} {
		writeFixture(t, root, "tmp/rrd/OpenWrt/"+p+".rrd", "")
	}
	for i, p := range []string{"load/load", "cpu-0/percent-idle", "interface-br-lan/if_octets", "memory/memory-used", "memory/memory-free",
		"memory/memory-buffered", "memory/memory-cached", "memory/memory-slab_recl", "memory/memory-slab_unrecl"} {
		f.on("rrdtool fetch /tmp/rrd/OpenWrt/"+p+".rrd AVERAGE -s", captured(t, "statistics-active", fmt.Sprintf("%02d.txt", i+2)))
	}
	f.on("rrdtool fetch /tmp/rrd/OpenWrt/cpu-1/percent-idle.rrd AVERAGE -s", captured(t, "statistics-active", "03.txt"))
	f.on("rrdtool fetch /tmp/rrd/OpenWrt/interface-lo/if_octets.rrd AVERAGE -s", captured(t, "statistics-active", "04.txt"))
	return f
}

func TestHistorySummarisesTheRealRrdtoolOutput(t *testing.T) {
	f := historyRouter(t)
	out, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{History: "1h"})
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, out, "history, last 1 hour, from collectd on OpenWrt (one sample per 30 s)",
		"load (1 min): now 0.00, avg 0.02, max 0.06; per 10 min: - - - - - 0.02", "cpu busy (2 cores): now 0%", "memory used: now 11%",
		"br-lan received: now 20B/s, avg 19B/s, max 20B/s", "br-lan sent: now 23B/s", "data covers only the last 3 minutes")
	mustNotContain(t, out, "interface-lo", "lo received", "nan")
	for _, a := range f.argvList() {
		if a[0] == "rrdtool" && (a[1] != "fetch" || !strings.HasPrefix(a[2], "/tmp/rrd/OpenWrt/")) {
			t.Errorf("unexpected rrdtool call %v", a)
		}
	}
}

func TestHistoryRefusesAnUnknownWindowAndMissingData(t *testing.T) {
	historyRouter(t)
	for _, bad := range []string{"2h", "24h; reboot", "../x", "1d"} {
		if _, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{History: bad}); err == nil {
			t.Errorf("history=%q accepted", bad)
		}
	}
	if _, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{History: "1h", Mode: "doctor"}); err == nil {
		t.Error("history together with mode accepted")
	}
	// No data directory: say what is missing instead of an empty table.
	f, _ := wave1Router(t)
	f.fail("uci -q show luci_statistics", "uci: Entry not found")
	_, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{History: "24h"})
	if err == nil || !strings.Contains(err.Error(), "luci-app-statistics") {
		t.Errorf("missing data: %v", err)
	}
}

func TestHistoryNeedsItsOwnScope(t *testing.T) {
	if got := systemStatusScope(systemStatusIn{History: "24h"}); len(got) != 1 || got[0] != "history" {
		t.Errorf("scope %v", got)
	}
}

// usteer 2025.10.04, DAWN 2025.11.07 and openNDS 10.3.1 on the 25.12.6 VM. The VM has no Wi-Fi hardware
// that hostapd would take (the hwsim radios never came up), so usteer and DAWN were captured with no
// access point and no peer: what they print with clients is built from field names, not seen.
func wifiRoamRouter(t *testing.T) *fakeRouter {
	f, _ := wave1Router(t)
	addRC(f, "usteer", "dawn", "opennds")
	f.on("pidof usteerd", "11232\n")
	f.on("pidof dawn", "10060\n")
	f.on("pidof opennds", "10253\n")
	return f
}

func TestUsteerOnItsRealIdleState(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("ubus call usteer get_config", captured(t, "usteer-active", "02.txt"))
	f.on("ubus call usteer local_info", captured(t, "usteer-active", "03.txt"))
	f.on("ubus call usteer remote_hosts", captured(t, "usteer-active", "04.txt"))
	f.on("ubus call usteer get_clients", captured(t, "usteer-active", "05.txt"))
	got := body(t, "usteer")
	wantAll(t, got, "usteerd: running", "policies on: band steering every 120 s (min signal -60, station delta 5)",
		"policies off: load balancing, client roaming, minimum-SNR kick", "exchanges state over: br-lan", "steering applies to every SSID",
		"local nodes: none", "0 other usteer hosts seen, 0 clients tracked", "nothing is steered between access points")
	mustNotContain(t, got, "WARNING", "does not answer")
}

// Field names after usteer's documentation; client addresses are never printed.
func TestUsteerCountsClientsAndPeersWithoutPrintingAddresses(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("ubus call usteer get_config", `{"band_steering_interval":0,"load_balancing_threshold":3,"roam_scan_snr":-70,"roam_trigger_snr":-75,"local_mode":true,"ssid_list":["Home"]}`)
	f.on("ubus call usteer local_info", `{"phy0-ap0":{"ssid":"Home","freq":2437,"n_assoc":2,"load":31},"phy1-ap0":{"ssid":"Home","freq":5180,"n_assoc":0}}`)
	f.on("ubus call usteer remote_hosts", `{"10.0.0.2":{"id":7}}`)
	f.on("ubus call usteer get_clients", `{"aa:bb:cc:dd:ee:01":{},"aa:bb:cc:dd:ee:02":{}}`)
	got := body(t, "usteer")
	wantAll(t, got, "policies off: band steering", "load balancing at a difference of 3 stations", "WARNING: local_mode is on",
		"steering limited to 1 SSID", "local nodes (2):", `phy0-ap0: ssid "Home", 2437 MHz, 2 clients, load 31%`,
		"1 other usteer host seen, 2 clients tracked")
	mustNotContain(t, got, "aa:bb:cc", "nothing is steered")
}

func TestDAWNOnItsRealIdleState(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("uci -q show dawn", captured(t, "dawn-active", "01.txt"))
	f.fail("ubus list hostapd.*", "Command failed: Not found")
	f.on("ubus call dawn get_network", captured(t, "dawn-active", "03.txt"))
	f.on("ubus call dawn get_hearing_map", captured(t, "dawn-active", "04.txt"))
	got := body(t, "dawn")
	wantAll(t, got, "dawn: running", "AP discovery: TCP with umdns discovery", "traffic between APs is not encrypted",
		"no hostapd interface on ubus", "network view: 0 access points on 0 SSIDs (0 local)", "hearing map: 0 clients heard")
}

func TestDAWNWarnsAboutTheShippedKeyAndNeverPrintsKeys(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("uci -q show dawn", "dawn.@network[0]=network\ndawn.@network[0].network_option='3'\ndawn.@network[0].use_symm_enc='1'\ndawn.@network[0].shared_key='Niiiiiiiiiiiiick'\ndawn.@network[0].iv='CanaryIV123456789'\n")
	f.on("ubus list hostapd.*", "hostapd.phy0-ap0\nhostapd.phy1-ap0\n")
	got := body(t, "dawn")
	wantAll(t, got, "AP discovery: TCP", "encrypted with the key the package ships with", "2 hostapd interfaces on ubus")
	mustNotContain(t, got, "Niiiiiiiiiiiiick", "CanaryIV")
}

func TestOpenNDSOnItsRealStatus(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("ndsctl status", captured(t, "opennds-active", "02.txt"))
	f.on("uci -q show opennds", "opennds.@opennds[0]=opennds\nopennds.@opennds[0].faskey='CanaryFasKey0123456789'\n")
	got := body(t, "opennds")
	wantAll(t, got, "opennds: running", "version 10.3.1, up 6m 26s, managing br-lan", "clients now: 0, authenticated since start: 0",
		"FAS: Secure Level 1, host status.client", "idle timeout: preauthenticated 30m, authenticated 120m",
		"binauth script: /usr/lib/opennds/binauth_log.sh", "FAS key set (not shown)")
	mustNotContain(t, got, "CanaryFasKey", "/opennds_preauth", "Walledgarden")
}

func TestOpenNDSWhenItsSocketDoesNotAnswer(t *testing.T) {
	f := wifiRoamRouter(t)
	f.fail("ndsctl status", "Failed to connect to opennds")
	got := body(t, "opennds")
	wantAll(t, got, "ndsctl does not answer: Failed to connect to opennds")
}

// OpenVPN 2.7.8 on the 25.12.6 VM: a TLS server with one client connected from a LAN namespace. The init
// script makes every instance write /var/run/openvpn.<section>.status (version 1, comma separated).
func TestOpenVPNServerWithAClientOnItsRealStatusFile(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "openvpn")
	f.on(`ubus call service list {"name":"openvpn"}`, captured(t, "openvpn-active", "01.txt"))
	f.on("uci -q show openvpn", captured(t, "openvpn-active", "02.txt"))
	writeFixture(t, root, "var/run/openvpn.srv.status", captured(t, "openvpn-active", "03.txt"))
	got := strings.Join(detail(t, "openvpn"), "\n")
	wantAll(t, got, "connected clients (1) (as of 2026-11-05 20:30:56):", `"client" at 192.168.1.100 (in 4K, out 5K, since 2026-11-05 20:30:15)`)
	mustNotContain(t, got, "udp4:", ":37509")
}

// The same version in client mode (status written with `--status FILE 5`): only tunnel counters.
func TestOpenVPNClientStatusHasOnlyCounters(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "openvpn")
	f.on(`ubus call service list {"name":"openvpn"}`, `{"openvpn":{"instances":{"cli":{"running":true}}}}`)
	f.on("uci -q show openvpn", "openvpn.cli=openvpn\nopenvpn.cli.enabled='1'\nopenvpn.cli.client='1'\n")
	writeFixture(t, root, "var/run/openvpn.cli.status", "OpenVPN STATISTICS\nUpdated,2026-11-05 20:30:20\nTUN/TAP read bytes,440\nTUN/TAP write bytes,0\nTCP/UDP read bytes,4478\nTCP/UDP write bytes,4366\nAuth read bytes,0\nEND\n")
	got := strings.Join(detail(t, "openvpn"), "\n")
	wantAll(t, got, "tunnel: carried 4K in, 4K out on the wire (as of 2026-11-05 20:30:20)")
}

func TestOpenVPNWithoutAStatusFileOrWithAnEmptyServer(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "openvpn")
	f.on(`ubus call service list {"name":"openvpn"}`, `{"openvpn":{"instances":{"srv":{"running":true}}}}`)
	f.on("uci -q show openvpn", "openvpn.srv=openvpn\nopenvpn.srv.enabled='1'\nopenvpn.off=openvpn\nopenvpn.off.enabled='0'\n")
	got := strings.Join(detail(t, "openvpn"), "\n")
	wantAll(t, got, "status file not written yet")
	if strings.Count(got, "status file") != 1 {
		t.Errorf("a disabled instance got a status line:\n%s", got)
	}
	writeFixture(t, root, "var/run/openvpn.srv.status", "OpenVPN CLIENT LIST\nUpdated,2026-11-05 20:28:54\nCommon Name,Real Address,Bytes Received,Bytes Sent,Connected Since\nROUTING TABLE\nVirtual Address,Common Name,Real Address,Last Ref\nGLOBAL STATS\nMax bcast/mcast queue length,0\nEND\n")
	wantAll(t, strings.Join(detail(t, "openvpn"), "\n"), "connected clients: none (as of 2026-11-05 20:28:54)")
}

// frp 0.66.0 on the 25.12.6 VM, stock configs: the package's own section is `common` (written as [common]
// in the generated ini), every other `conf` section is one proxy. The adapters once read a section `main`.
func TestFrpcOnItsRealStockConfig(t *testing.T) {
	f, _ := wave1Router(t)
	addRC(f, "frpc")
	f.on("pidof frpc", captured(t, "frpc-stock", "01.txt"))
	f.on("uci -q show frpc", captured(t, "frpc-stock", "02.txt"))
	got := strings.Join(detail(t, "frpc"), "\n")
	wantAll(t, got, "server: ", ":7000", "token: not set", "proxies: 1", "ssh, tcp, local ", ":22, remote port 6000")
	mustNotContain(t, got, "server: not set")
}

func TestFrpsOnItsRealStockConfigAndTheFindingFollowsTheToken(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "frps")
	f.on("pidof frps", captured(t, "frps-stock", "01.txt"))
	f.on("uci -q show frps", captured(t, "frps-stock", "02.txt"))
	got := strings.Join(detail(t, "frps"), "\n")
	wantAll(t, got, "bind port: 7000", "token: not set (any client may connect)")
	installAddonConfig(t, root, "frps")
	f.on("ubus call rc list", `{"frps":{"enabled":true,"running":true,"start":99,"stop":1}}`)
	if auditFindings(context.Background()).byID("frps-open") == nil {
		t.Error("a token-less stock frps was not flagged")
	}
	f.on("uci -q show frps", captured(t, "frps-stock", "02.txt")+"frps.common.token='x'\n")
	if auditFindings(context.Background()).byID("frps-open") != nil {
		t.Error("frps with a token in its real `common` section was flagged")
	}
}

// strongSwan 6.0.7 on the 25.12.6 VM. Idle: one connection loaded, no peer (the plugin warnings are real
// stderr that `swanctl` prints and the adapter's command capture mixes in). Active: two charon daemons in
// network namespaces joined by a veth pair, PSK, IKEv2; the listing is from the responder.
func swanRouter(t *testing.T) *fakeRouter {
	f, _ := wave1Router(t)
	addRC(f, "swanctl")
	f.on("pidof charon", captured(t, "swanctl-idle", "01.txt"))
	return f
}

func TestStrongSwanIdleNamesTheConnectionThatHasNoSA(t *testing.T) {
	f := swanRouter(t)
	f.on("swanctl --list-sas", captured(t, "swanctl-idle", "02.txt"))
	f.on("swanctl --list-conns", captured(t, "swanctl-idle", "03.txt"))
	got := strings.Join(detail(t, "swanctl"), "\n")
	wantAll(t, got, "IKE SAs established: 0", "child SAs installed: 0", "configured but with no SA now: site")
	mustNotContain(t, got, "plugin ", "192.168.1.1")
}

func TestStrongSwanEstablishedListsEachSAWithoutAddresses(t *testing.T) {
	f := swanRouter(t)
	f.on("swanctl --list-sas", captured(t, "swanctl-active", "01.txt"))
	f.on("swanctl --list-conns", captured(t, "swanctl-idle", "03.txt"))
	got := strings.Join(detail(t, "swanctl"), "\n")
	wantAll(t, got, "IKE SAs established: 1", "child SAs installed: 1", "site: ESTABLISHED, IKEv2, up 12s", "child net: INSTALLED TUNNEL", "peer names are chosen by the peer")
	mustNotContain(t, got, "configured but with no SA", "192.168.1.", "@")
}

// usteer 2022.08.18 and DAWN 2023.05.14 on the 24.10.8 VM with a real radio: an RTL8852BE passed through from
// the host, hostapd (wpad-mbedtls) running one 5 GHz AP, and a phone associated. usteer also lists stations
// that only sent probe requests ("connected": false), which are not clients of this AP.
func TestUsteerWithARealRadioAndAConnectedPhone(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("ubus call usteer get_config", captured(t, "usteer-ap", "02.txt"))
	f.on("ubus call usteer local_info", captured(t, "usteer-ap", "03.txt"))
	f.on("ubus call usteer remote_hosts", captured(t, "usteer-ap", "04.txt"))
	f.on("ubus call usteer get_clients", captured(t, "usteer-ap", "05.txt"))
	got := body(t, "usteer")
	wantAll(t, got, "local nodes (1):", `hostapd.phy0-ap0: ssid "owlab-test", 5180 MHz, 1 client, load 0%`, "0 other usteer hosts seen")
	mustNotContain(t, got, "02:00:00", "does not answer")
}

func TestDAWNWithARealRadioAndAConnectedPhone(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("uci -q show dawn", captured(t, "dawn-ap", "01.txt"))
	f.on("ubus list hostapd.*", captured(t, "dawn-ap", "02.txt"))
	f.on("ubus call dawn get_network", captured(t, "dawn-ap", "03.txt"))
	f.on("ubus call dawn get_hearing_map", captured(t, "dawn-ap", "04.txt"))
	got := body(t, "dawn")
	wantAll(t, got, "dawn: running", "1 hostapd interface on ubus", "network view: 1 access point on 1 SSID (1 local)")
	mustNotContain(t, got, "02:00:00", "Niiiiiiiiiiiiick")
	if strings.Contains(got, "hearing map: 0 clients") {
		t.Errorf("the hearing map had no client:\n%s", got)
	}
}

func TestUsteerSeesAPeerHostOnItsRealData(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("ubus call usteer get_config", captured(t, "usteer-peer", "02.txt"))
	f.on("ubus call usteer local_info", captured(t, "usteer-peer", "03.txt"))
	f.on("ubus call usteer remote_hosts", captured(t, "usteer-peer", "04.txt"))
	f.on("ubus call usteer get_clients", captured(t, "usteer-peer", "05.txt"))
	got := body(t, "usteer")
	wantAll(t, got, "local nodes (1):", "1 client, load 0%", "1 other usteer host seen")
	mustNotContain(t, got, "02:00:00", "does not answer", "192.168.1.151")
}

func TestDAWNSeesAPeerAccessPointOnItsRealData(t *testing.T) {
	f := wifiRoamRouter(t)
	f.on("uci -q show dawn", captured(t, "dawn-peer", "01.txt"))
	f.on("ubus list hostapd.*", captured(t, "dawn-peer", "02.txt"))
	f.on("ubus call dawn get_network", captured(t, "dawn-peer", "03.txt"))
	f.on("ubus call dawn get_hearing_map", captured(t, "dawn-peer", "04.txt"))
	got := body(t, "dawn")
	wantAll(t, got, "dawn: running", "network view: 2 access points on 1 SSID (1 local)", "hearing map: 1 client heard")
	mustNotContain(t, got, "02:00:00", "Niiiiiiiiiiiiick", "ow2512")
}

func TestZeroTierOnARealNetworkItCannotJoin(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "zerotier")
	f.on("pidof zerotier-one", "60\n")
	f.on("zerotier-cli listnetworks", captured(t, "zerotier-notfound", "01.txt"))
	got := body(t, "zerotier")
	wantAll(t, got, "networks (1):", "8056c2e21c000001: NOT_FOUND, PRIVATE, dev ztmjfmfyq5, addresses -")
}

// travelmate 2.2.1 on the 24.10.8 VM, associated with a WPA2 access point on a virtual radio. The
// access point's network is the router's own LAN subnet, which travelmate itself complains about.
func TestTravelmateOnARealConnectedUplink(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "travelmate")
	f.on("pidof travelmate.sh", "1234\n")
	f.on("uci -q show travelmate", captured(t, "travelmate-connected", "01.txt"))
	writeFixture(t, root, "tmp/trm_runtime.json", captured(t, "travelmate-connected", "02.txt"))
	got := body(t, "travelmate")
	wantAll(t, got, "status: connected (net ok/100), travelmate 2.2.1-r6", "uplink: radio radio1, SSID owlab-roam, interface trm_wwan",
		"WARNING: the uplink's subnet 192.168.1.0 is the LAN's subnet", "configured uplinks: 1")
	mustNotContain(t, got, "redacted", "02:00:00")
}

// travelmate 2.4.9 on the 25.12.6 VM: another runtime file and another version key; the uplink is
// associated but the internet check fails.
func TestTravelmateOnItsReal25RuntimeFile(t *testing.T) {
	f, root := wave1Router(t)
	addRC(f, "travelmate")
	f.on("pidof travelmate.sh", "")
	f.on("uci -q show travelmate", captured(t, "travelmate-2512", "01.txt"))
	writeFixture(t, root, "var/run/travelmate/travelmate.runtime.json", captured(t, "travelmate-2512", "02.txt"))
	got := body(t, "travelmate")
	wantAll(t, got, "status: connected, net nok/100, travelmate 2.4.9-r6", "uplink: radio radio1, SSID owlab-roam",
		"WARNING: associated, but travelmate's internet check fails", "WARNING: the uplink's subnet 192.168.1.0")
	mustNotContain(t, got, "redacted", "memory:")
}

// zerotier 1.16.2 on the 25.12.6 VM, joined to a private network served by a local controller
// (the official zerotier/zerotier image). After the controller withdraws the authorization the
// client keeps the address it was given, so ACCESS_DENIED still lists one.
func TestZeroTierOnAJoinedAndAuthorizedNetwork(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "zerotier")
	f.on("pidof zerotier-one", "60\n")
	f.on("zerotier-cli listnetworks", captured(t, "zerotier-ok", "01.txt"))
	got := body(t, "zerotier")
	wantAll(t, got, "networks (1):", "1877ac0fee65a3b6: OK, PRIVATE, dev ztc6m4tlcy, addresses 10.147.20.13/24")
	mustNotContain(t, got, "owlab-test", "02:00:00")
}

func TestZeroTierWhenTheControllerWithdrewTheAuthorization(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "zerotier")
	f.on("pidof zerotier-one", "60\n")
	f.on("zerotier-cli listnetworks", captured(t, "zerotier-denied", "01.txt"))
	got := body(t, "zerotier")
	wantAll(t, got, "1877ac0fee65a3b6: ACCESS_DENIED, PRIVATE")
	mustNotContain(t, got, "owlab-test")
}

// NetBird 0.82.0, status of a connected peer of a cloud account (taken from a container: the 0.59.13
// client on the 24.10 VM could not dial the management service, "connect: invalid argument").
func TestNetBirdOnARealConnectedPeer(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "netbird")
	f.on("pidof netbird", "70\n")
	f.on("netbird status", captured(t, "netbird-connected", "01.txt"))
	got := body(t, "netbird")
	wantAll(t, got, "Daemon version: 0.82.0", "Management: Connected", "Signal: Connected", "NetBird IP: 100.65.141.182/16", "Peers count: 0/1 Connected")
	mustNotContain(t, got, "owlab-test-container", "netbird.cloud", "2001:db8")
}

// samba4 4.22.7 on 25.12.6 with a share that lists one user. The password hash and the user's
// name stay out of the detail.
func TestSamba4OnARealShareThatNeedsALogin(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "samba4")
	f.on("pidof smbd", captured(t, "samba4-login", "02.txt"))
	f.on("uci -q show samba4", captured(t, "samba4-login", "01.txt"))
	got := body(t, "samba4")
	wantAll(t, got, "bound to: lan", "shares (1):", "data (/srv/data): login required, writable")
	mustNotContain(t, got, "smbtest", "guest access")
}

// netbird 0.59.13 on 24.10.8 next to mwan3: NetBird marks its own sockets 0x1bd00, and mwan3's rule
// "fwmark 0x3d00/0x3f00 blackhole" matches that mark, so every connect to the management server fails
// with EINVAL. Found with strace; the daemon reached the server once the two rules were removed.
func TestNetBirdWarnsWhenAnFwmarkRuleBlackholesItsSockets(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "netbird")
	f.on("pidof netbird", "70\n")
	f.on("netbird status", captured(t, "netbird-mwan3", "02.txt"))
	f.on("ip -4 rule show", captured(t, "netbird-mwan3", "01.txt"))
	got := body(t, "netbird")
	wantAll(t, got, "WARNING", "0x3d00/0x3f00 blackhole", "0x1bd00", "mwan3")
}

func TestNetBirdSaysNothingAboutMarksWhenNoRuleCatchesThem(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "netbird")
	f.on("pidof netbird", "70\n")
	f.on("netbird status", captured(t, "netbird-connected", "01.txt"))
	f.on("ip -4 rule show", "0:\tfrom all lookup local\n30000:\tfrom all fwmark 0x10000/0xff0000 lookup pbr_wan\n32766:\tfrom all lookup main\n")
	mustNotContain(t, body(t, "netbird"), "WARNING")
}

// youtubeUnblock 1.3.1 from the project's release (x86_64 apk) on 25.12.6, running with the stock
// config: the chain is in inet fw4 as the source said, the section is named youtubeUnblock.
func TestYoutubeUnblockOnItsRealRunningInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "youtubeUnblock")
	f.on("pidof youtubeUnblock", captured(t, "youtubeunblock-running", "01.txt"))
	f.on("nft list chain inet fw4 youtubeUnblock", captured(t, "youtubeunblock-running", "02.txt"))
	f.on("uci -q show youtubeUnblock", captured(t, "youtubeunblock-running", "03.txt"))
	got := body(t, "youtubeUnblock")
	wantAll(t, got, "youtubeUnblock: running", "nft chain youtubeUnblock in fw4: loaded", "config strategy: ui_flags", "queue number: 537", "packet mark: 32768", "sections: 1")
	mustNotContain(t, got, "googlevideo")
}

// nikki 2026.10.10 with mihomo-meta 1.19.32 from the project's release (x86_64 apk) on 25.12.6,
// enabled with a local profile. The stock config carries an API secret and a web login password
// (both masked in the capture) and a subscription URL: none may reach the detail.
func TestNikkiOnItsRealRunningInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "nikki")
	f.on("pidof mihomo", captured(t, "nikki-running", "01.txt"))
	f.on("nft list table inet nikki", captured(t, "nikki-running", "02.txt"))
	f.on("uci -q show nikki", captured(t, "nikki-running", "03.txt"))
	got := body(t, "nikki")
	wantAll(t, got, "mihomo: running", "nft table nikki: loaded", "enabled in config: 1", "TCP mode: redirect", "subscriptions: 1")
	mustNotContain(t, got, "example.com", "redacted", "zashboard")
}

// zapret v72.13 from the project's openwrt-embedded bundle (x86_64 binaries) on 25.12.6, nfqws mode
// on and tpws off: nfqws runs, the table inet zapret is loaded, tpws is reported as not running.
func TestZapretOnItsRealNfqwsInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "zapret")
	f.on("pidof nfqws", captured(t, "zapret-running", "01.txt"))
	f.fail("pidof tpws", "")
	f.on("nft list table inet zapret", captured(t, "zapret-running", "03.txt"))
	got := body(t, "zapret")
	wantAll(t, got, "nfqws: running", "tpws: not running", "nft table zapret: loaded")
}

// luci-app-openclash 0.48.002 from the project's release (apk) on 25.12.6, with mihomo as its core
// and a local profile. The process is called clash, its rules live in inet fw4 (no table of its own),
// and the stock config holds a dashboard password that must stay out of the detail.
func TestOpenClashOnItsRealRunningInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "openclash")
	f.on("pidof clash", captured(t, "openclash-running", "01.txt"))
	f.on("uci -q show openclash", captured(t, "openclash-running", "02.txt"))
	got := body(t, "openclash")
	wantAll(t, got, "clash: running", "enabled in config: 1", "mode: fake-ip", "dashboard secret: set (not shown)")
	mustNotContain(t, got, "redacted", "jsdelivr")
}

// luci-app-passwall 26.11.3 from the project's release (apk) on 25.12.6, stock config. The package's
// own dependencies are not in the official feed, so the files were unpacked and the stack never ran:
// this checks the config layout the adapter reads (@global[0], nodes, shunt_rules) against the real one.
func TestPasswallOnItsRealStockConfig(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall")
	f.fail("pidof xray", "")
	f.fail("pidof sing-box", "")
	f.fail("nft list table inet passwall", "no such table")
	f.on("uci -q show passwall", captured(t, "passwall-stock", "01.txt"))
	got := body(t, "passwall")
	wantAll(t, got, "enabled in config: 0", "DNS mode: tcp", "nodes: 1", "shunt rules: 6", "nft table passwall: not loaded")
}

// luci-app-homeproxy 26.298 (ImmortalWrt feed) on 25.12.6 with the feed's sing-box 1.13.21: homeproxy
// writes a config with inbound fields that sing-box 1.13 removed, so the service stops at once. The
// reason is only in /var/run/homeproxy/homeproxy.log; the detail now carries its last error lines.
func TestHomeProxyShowsWhyItStoppedOnItsRealLog(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "var/run/homeproxy/homeproxy.log", captured(t, "homeproxy-failing", "03.txt"))
	f := newFakeRouter(t)
	addRC(f, "homeproxy")
	f.fail("pidof sing-box", "")
	f.on("uci -q show homeproxy", captured(t, "homeproxy-failing", "02.txt"))
	got := body(t, "homeproxy")
	wantAll(t, got, "sing-box: not running", "last error: wrong client configuration detected", "legacy inbound fields", "removed in sing-box 1.13.0")
	mustNotContain(t, got, "\x1b")
}

// v2rayA from the official 25.12.6 feed, stock config: the web API listens on all addresses by default.
func TestV2rayAOnItsRealStockInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "v2raya")
	f.on("pidof v2raya", captured(t, "v2raya-running", "01.txt"))
	f.on("uci -q show v2raya", captured(t, "v2raya-running", "02.txt"))
	got := body(t, "v2raya")
	wantAll(t, got, "v2raya: running", "enabled in config: 1", "API address: 0.0.0.0:2017")
}

// luci-app-passwall2 26.11.3 from the project's release (apk), stock config on 25.12.6, unpacked only:
// this checks the layout the adapter reads (@global[0], named nodes and shunt rules).
func TestPasswall2OnItsRealStockConfig(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall2")
	f.fail("pidof xray", "")
	f.fail("pidof sing-box", "")
	f.fail("nft list table inet passwall2", "no such table")
	f.on("uci -q show passwall2", captured(t, "passwall2-stock", "01.txt"))
	got := body(t, "passwall2")
	wantAll(t, got, "enabled in config: 0", "remote DNS protocol: tcp", "nodes: 2", "shunt rules: 8", "nft table passwall2: not loaded")
}

// The wave 4 stacks on 24.10.8 (opkg), from the projects' own packages: the same adapters read the same
// layouts there as on 25.12. The detail of each running stack is checked against what its capture holds.
func TestWave4OnItsReal2410Installs(t *testing.T) {
	cases := []struct {
		svc  string
		on   func(f *fakeRouter)
		want []string
		not  []string
	}{
		{"youtubeUnblock", func(f *fakeRouter) {
			f.on("pidof youtubeUnblock", captured(t, "youtubeunblock-2410", "01.txt"))
			f.on("nft list chain inet fw4 youtubeUnblock", captured(t, "youtubeunblock-2410", "02.txt"))
			f.on("uci -q show youtubeUnblock", captured(t, "youtubeunblock-2410", "03.txt"))
		}, []string{"youtubeUnblock: running", "nft chain youtubeUnblock in fw4: loaded", "queue number: 537"}, []string{"googlevideo"}},
		{"nikki", func(f *fakeRouter) {
			f.on("pidof mihomo", captured(t, "nikki-2410", "01.txt"))
			f.on("nft list table inet nikki", captured(t, "nikki-2410", "02.txt"))
			f.on("uci -q show nikki", captured(t, "nikki-2410", "03.txt"))
		}, []string{"mihomo: running", "nft table nikki: loaded", "TCP mode: redirect", "subscriptions: 1"}, []string{"example.com", "redacted"}},
		{"zapret", func(f *fakeRouter) {
			f.on("pidof nfqws", captured(t, "zapret-2410", "01.txt"))
			f.fail("pidof tpws", "")
			f.on("nft list table inet zapret", captured(t, "zapret-2410", "03.txt"))
		}, []string{"nfqws: running", "tpws: not running", "nft table zapret: loaded"}, nil},
		{"openclash", func(f *fakeRouter) {
			f.on("pidof clash", captured(t, "openclash-2410", "01.txt"))
			f.on("uci -q show openclash", captured(t, "openclash-2410", "02.txt"))
		}, []string{"clash: running", "enabled in config: 1", "dashboard secret: set (not shown)"}, []string{"redacted", "jsdelivr"}},
		{"homeproxy", func(f *fakeRouter) {
			f.on("pidof sing-box", captured(t, "homeproxy-2410", "01.txt"))
			f.on("uci -q show homeproxy", captured(t, "homeproxy-2410", "02.txt"))
		}, []string{"sing-box: running", "routing mode: gfwlist", "nodes: 1"}, []string{"last error", "sing-box said"}},
		{"passwall", func(f *fakeRouter) {
			f.fail("pidof xray", "")
			f.fail("pidof sing-box", "")
			f.fail("nft list table inet passwall", "no such table")
			f.on("uci -q show passwall", captured(t, "passwall-2410", "01.txt"))
		}, []string{"enabled in config: 0", "nodes: 1", "shunt rules: 6"}, nil},
		{"passwall2", func(f *fakeRouter) {
			f.fail("pidof xray", "")
			f.fail("pidof sing-box", "")
			f.fail("nft list table inet passwall2", "no such table")
			f.on("uci -q show passwall2", captured(t, "passwall2-2410", "01.txt"))
		}, []string{"enabled in config: 0", "nodes: 2", "shunt rules: 8"}, nil},
		{"v2raya", func(f *fakeRouter) {
			f.on("pidof v2raya", captured(t, "v2raya-2410", "01.txt"))
			f.on("uci -q show v2raya", captured(t, "v2raya-2410", "02.txt"))
		}, []string{"v2raya: running", "API address: 0.0.0.0:2017"}, nil},
	}
	for _, c := range cases {
		t.Run(c.svc, func(t *testing.T) {
			withFixtureRoot(t)
			f := newFakeRouter(t)
			addRC(f, c.svc)
			c.on(f)
			got := body(t, c.svc)
			wantAll(t, got, c.want...)
			if len(c.not) > 0 {
				mustNotContain(t, got, c.not...)
			}
		})
	}
}

// frpc and frps on one 25.12.6 router (frp 0.66.0, stock config): the client logged in to the server
// and the sockets say so. The server's side of the connection is an IPv6 socket (it listens on ":::7000").
func TestFrpWhenTheClientHasLoggedInToTheServer(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "frpc", "frps")
	writeFixture(t, root, "proc/net/tcp", captured(t, "frp-connected", "05.txt"))
	writeFixture(t, root, "proc/net/tcp6", captured(t, "frp-connected", "06.txt"))
	f.on("pidof frpc", captured(t, "frp-connected", "01.txt"))
	f.on("uci -q show frpc", captured(t, "frp-connected", "02.txt"))
	f.on("pidof frps", captured(t, "frp-connected", "03.txt"))
	f.on("uci -q show frps", captured(t, "frp-connected", "04.txt"))
	wantAll(t, body(t, "frpc"), "connection to the server: 1 established TCP connection", "server: 127.0.0.1:7000")
	wantAll(t, body(t, "frps"), "clients connected: 1 established TCP connection")
}

// The client keeps running and retrying while its server is stopped: "running" alone would hide that.
func TestFrpcSaysWhenItHasNoConnectionToItsServer(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "frpc")
	writeFixture(t, root, "proc/net/tcp", captured(t, "frp-server-down", "05.txt"))
	writeFixture(t, root, "proc/net/tcp6", captured(t, "frp-server-down", "06.txt"))
	f.on("pidof frpc", captured(t, "frp-server-down", "01.txt"))
	f.on("uci -q show frpc", captured(t, "frp-server-down", "02.txt"))
	got := body(t, "frpc")
	wantAll(t, got, "frpc: running", "no established connection to port 7000")
	mustNotContain(t, got, "1 established")
}

// nlbwmon 2025.06.02 on 25.12.6, real output: a LAN client downloaded 20 MB over HTTPS through the
// router. The router's own traffic and a row whose layer7 is null (plain IP) sit next to it.
func nlbwmonOnRealOutput(t *testing.T) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "usr/sbin/nlbw", "x")
	f := newFakeRouter(t)
	f.on("nlbw -c json -g mac,ip", captured(t, "nlbwmon-usage", "01.txt"))
	f.on("nlbw -c json -g mac,ip,layer7", captured(t, "nlbwmon-usage", "02.txt"))
	f.on("nlbw -c list", captured(t, "nlbwmon-usage", "03.txt"))
}

func TestNlbwmonUsagePerClientOnRealOutput(t *testing.T) {
	nlbwmonOnRealOutput(t)
	got, _, err := nlbwUsage(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, got, "2 clients", "192.168.1.50", "periods available: 2026-11-01")
	if strings.Index(got, "192.168.1.50") > strings.Index(got, "192.168.1.100") {
		t.Errorf("the heaviest client is not first:\n%s", got)
	}
}

func TestNlbwmonUsageOfOneClientByProtocolOnRealOutput(t *testing.T) {
	nlbwmonOnRealOutput(t)
	got, _, err := nlbwClientUsage(context.Background(), "", "192.168.1.50")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, got, "nlbwmon usage of 192.168.1.50", "HTTPS", "ICMP")
	mustNotContain(t, got, "192.168.1.100")
	other, _, err := nlbwClientUsage(context.Background(), "", "192.168.1.100")
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, other, "HTTPS", "ICMP", "other") // the null layer7 row is "other"
}

// pbr 1.2.2 on 25.12.6 with a second uplink. With mwan3 stopped, a policy sent a LAN client out of
// wan2 and the request reached the upstream; with mwan3 running the same request timed out, because
// mwan3's fwmark rules (priority 2001) are checked before pbr's (29997 and up).
func pbrOnRealRules(t *testing.T, capture string) string {
	t.Helper()
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "pbr")
	f.on("ubus call service list", captured(t, capture, "01.txt"))
	f.on("uci -q show pbr", captured(t, capture, "02.txt"))
	f.on("ip -4 rule show", captured(t, capture, "03.txt"))
	return body(t, "pbr")
}

func TestPbrWarnsWhenMwan3sRulesComeFirst(t *testing.T) {
	got := pbrOnRealRules(t, "pbr-with-mwan3")
	wantAll(t, got, "WARNING: mwan3 is active too", "priority up to 2001", "from 29997")
}

func TestPbrAloneHasNoMwan3Warning(t *testing.T) {
	got := pbrOnRealRules(t, "pbr-alone")
	mustNotContain(t, got, "mwan3")
}

// homeproxy 26.298 with sing-box 1.12.22 on 25.12.6: it runs and carries a LAN client's traffic (301 with
// the socks node up, 000 with it stopped). The log still holds the earlier failure with sing-box 1.13, so the
// detail must not call a running service broken: its last lines say "started".
func TestHomeProxyRunningOnItsRealLogThatStillHoldsAnOldFailure(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "var/run/homeproxy/homeproxy.log", captured(t, "homeproxy-proxying", "03.txt"))
	f := newFakeRouter(t)
	addRC(f, "homeproxy")
	f.on("pidof sing-box", captured(t, "homeproxy-proxying", "01.txt"))
	f.on("uci -q show homeproxy", captured(t, "homeproxy-proxying", "02.txt"))
	got := body(t, "homeproxy")
	wantAll(t, got, "sing-box: running", "routing mode: global")
	mustNotContain(t, got, "last error", "sing-box said")
}

// passwall 26.11.3 started from the unpacked project package on 25.12.6 (dns_shunt dnsmasq, one socks
// node): xray runs, the nft table is loaded and a LAN client's request went through the node.
func TestPasswallOnItsRealRunningInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall")
	f.on("pidof xray", captured(t, "passwall-running", "01.txt"))
	f.on("pidof sing-box", captured(t, "passwall-running", "02.txt"))
	f.on("nft list table inet passwall", captured(t, "passwall-running", "03.txt"))
	f.on("uci -q show passwall", captured(t, "passwall-running", "04.txt"))
	got := body(t, "passwall")
	wantAll(t, got, "xray: running", "enabled in config: 1", "nodes: 2")
	mustNotContain(t, got, "not loaded")
}

// passwall2 26.11.3 started from the unpacked project package on 25.12.6. Without coreutils-nohup it
// loads its nft rules and redirects DNS and TCP to an xray that never started, so the LAN loses name
// resolution; with it, a client's request went through the node.
func TestPasswall2OnItsRealRunningInstall(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall2")
	f.on("pidof xray", captured(t, "passwall2-running", "01.txt"))
	f.on("pidof sing-box", captured(t, "passwall2-running", "02.txt"))
	f.on("nft list table inet passwall2", captured(t, "passwall2-running", "03.txt"))
	f.on("uci -q show passwall2", captured(t, "passwall2-running", "04.txt"))
	got := body(t, "passwall2")
	wantAll(t, got, "xray: running", "enabled in config: 1", "nft table passwall2: loaded")
}

func TestPasswall2WarnsWhenItsRulesAreLoadedButNothingRuns(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall2")
	f.fail("pidof xray", "")
	f.fail("pidof sing-box", "")
	f.on("nft list table inet passwall2", captured(t, "passwall2-no-nohup", "03.txt"))
	f.on("uci -q show passwall2", captured(t, "passwall2-no-nohup", "04.txt"))
	wantAll(t, body(t, "passwall2"), "xray: not running", "nft table passwall2: loaded", "WARNING: its firewall rules are loaded", "coreutils-nohup")
}
