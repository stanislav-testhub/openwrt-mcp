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
