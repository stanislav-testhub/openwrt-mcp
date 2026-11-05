package main

import (
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
