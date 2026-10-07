package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ROADMAP 3.9. `diag` output goes into public bug reports, so the test that matters is the one
// that tries to make it leak: generated addresses and names, in contexts a real log has them in,
// and nothing of them may survive.

func TestMaskerHidesEveryAddressAndNameItIsGiven(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	pool := []string{"Stas-iPhone", "My Home WiFi", "cafe_5G", "nas.lan", "Телефон-Ани", "kids-tablet", "printer", "Living Room TV"}
	for round := 0; round < 300; round++ {
		var ip4s, ip6s, macs, names []string
		for i := rng.Intn(4); i >= 0; i-- {
			ip4s = append(ip4s, fmt.Sprintf("%d.%d.%d.%d", []int{10, 100, 172, 192, 203, 8, 45}[rng.Intn(7)], rng.Intn(256), rng.Intn(256), 1+rng.Intn(254)))
			ip6s = append(ip6s, fmt.Sprintf("2001:db8:%x:%x::%x", rng.Intn(65536), rng.Intn(65536), 1+rng.Intn(65535)))
			mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256), rng.Intn(256))
			if rng.Intn(2) == 0 {
				mac = strings.ToUpper(strings.ReplaceAll(mac, ":", "-"))
			}
			macs = append(macs, mac)
			names = append(names, pool[rng.Intn(len(pool))])
		}
		known := map[string]string{}
		for _, n := range names {
			known[n] = "host"
		}
		m := newMasker(known)

		contexts := []string{"%s", "lease %s", "scope dhcp.%s.mac", `"%s"`, "ssid=%s, next", "%s/24", "[%s]:51820", "from %s port 22", "x\t%s\n"}
		var all []string
		all = append(all, ip4s...)
		all = append(all, ip6s...)
		all = append(all, macs...)
		all = append(all, names...)
		var in []string
		for _, v := range all {
			in = append(in, fmt.Sprintf(contexts[rng.Intn(len(contexts))], v))
		}
		text := strings.Join(in, " ; ")
		out := m.Mask(text)

		for _, v := range all {
			if strings.Contains(strings.ToLower(out), strings.ToLower(v)) {
				t.Fatalf("round %d: %q survived masking\n in  %s\n out %s", round, v, text, out)
			}
		}
		// The same value always gets the same placeholder, and two values never share one.
		again := m.Mask(text)
		if again != out {
			t.Fatalf("round %d: masking twice gave different text", round)
		}
		for _, group := range [][]string{ip4s, ip6s} {
			seen := map[string]string{}
			for _, v := range group {
				p := m.Mask(v)
				if prev, dup := seen[p]; dup && prev != v {
					t.Fatalf("round %d: %q and %q share the placeholder %q", round, prev, v, p)
				}
				seen[p] = v
			}
		}
	}
}

func TestMaskerLeavesWhatSaysNothingAboutANetwork(t *testing.T) {
	m := newMasker(map[string]string{"nas": "host", "Home WiFi": "ssid"})
	for _, same := range []string{
		"127.0.0.1:8730", "::1", "0.0.0.0", "[::]:80", "25.12.5", "6.12.74", "2026-10-07T22:01:02Z", "v1.3.0",
		"nasty", "nasal", "unassuming", "ip-1", "uci_apply dhcp.*", "GL.iNet GL-MT6000", "256.1.1.1.1",
	} {
		if got := m.Mask(same); got != same {
			t.Errorf("%q became %q", same, got)
		}
	}
	// Each case gets a fresh masker, so its placeholder number is always 1 of its kind.
	for _, tc := range [][2]string{
		{"nas", "host-1"},
		{"the NAS.", "the host-1."},
		{"nas,nas,nas", "host-1,host-1,host-1"},
		{"HOME WIFI", "ssid-1"},
		{"AA:BB:CC:DD:EE:FF", "mac-1"},
		{"aa-bb-cc-dd-ee-ff", "mac-1"},
		{"192.168.1.10/24", "ip-1/24"},
		{"192.168.001.010", "ip-1"}, // another spelling of the same address
		{"010.000.000.001", "ip-1"},
		{"::ffff:192.168.1.10", "::ffff:ip-1"},
		{"fe80::1%br-lan up", "ip-1 up"},
		{"2001:db8::7", "ip-1"},
		{"[2001:db8::7]:51820", "[ip-1]:51820"},
		{"1.2.3.4 and 1.2.3.4", "ip-1 and ip-1"},
		{"mac 02:00:00:00:00:01", "mac mac-1"},
		{"300.1.1.1", "300.1.1.1"},
	} {
		m := newMasker(map[string]string{"nas": "host", "Home WiFi": "ssid"})
		if got := m.Mask(tc[0]); got != tc[1] {
			t.Errorf("Mask(%q) = %q, want %q", tc[0], got, tc[1])
		}
	}
	// And in one masker, numbers go up in order of first appearance, and a repeat keeps its number.
	m = newMasker(nil)
	if got := m.Mask("10.0.0.1 10.0.0.2 10.0.0.1 aa:bb:cc:dd:ee:01 aa:bb:cc:dd:ee:02 aa:bb:cc:dd:ee:01"); got != "ip-1 ip-2 ip-1 mac-1 mac-2 mac-1" {
		t.Errorf("numbering: %q", got)
	}
}

// A host called "pi" is a name like any other; only a single character is too short to hide.
func TestShortNamesAreHiddenAndOneLetterIsNot(t *testing.T) {
	m := newMasker(map[string]string{"pi": "host", "x": "host"})
	if got := m.Mask("set pi to 10.0.0.9; x marks it, pie is food"); got != "set host-1 to ip-1; x marks it, pie is food" {
		t.Errorf("got %q", got)
	}
}

func TestClientNamesAreHiddenUnlessTheyNameAProgram(t *testing.T) {
	m := newMasker(nil)
	for _, generic := range []string{"claude-code", "claude-desktop", "cursor", "codex", "gemini", "vscode", "stdio"} {
		if got := m.Client(generic); got != generic {
			t.Errorf("%s became %s", generic, got)
		}
	}
	if a, b := m.Client("stas-laptop"), m.Client("stas-laptop"); a != "client-1" || a != b {
		t.Errorf("a private client name: %s, %s", a, b)
	}
	if m.Client("kids-ipad") != "client-2" {
		t.Error("a second private client name did not get its own placeholder")
	}
}

// The factory host name is not private, and masking it would garble the release string.
func TestTheDefaultHostNameIsNotMasked(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("uci -q show system", "system.@system[0].hostname='OpenWrt'\n")
	for _, c := range []string{"dhcp", "wireless", "network"} {
		f.on("uci -q show "+c, "")
	}
	names := harvestNames(t.Context())
	if len(names) != 0 {
		t.Fatalf("harvested %v from a router with the default host name", names)
	}
	if got := newMasker(names).Mask("OpenWrt 25.12.5 r33051"); got != "OpenWrt 25.12.5 r33051" {
		t.Errorf("the release string became %q", got)
	}
}

func TestHarvestNamesReadsOnlyTheOptionsThatIdentifyANetwork(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("uci -q show system", "system.@system[0]=system\nsystem.@system[0].hostname='Stas-Router'\nsystem.@system[0].timezone='UTC'\n")
	f.on("uci -q show dhcp", "dhcp.@dnsmasq[0].domain='home.lan'\ndhcp.@host[0].name='NAS'\ndhcp.@host[0].mac='aa:bb:cc:dd:ee:ff'\ndhcp.@host[0].ip='192.168.1.50'\n")
	f.on("uci -q show wireless", "wireless.wifinet0.ssid='My Home WiFi'\nwireless.wifinet0.key='hunter2hunter2'\nwireless.wifinet1.ssid='My Home WiFi'\n")
	f.on("uci -q show network", "network.wg0.private_key='SECRETKEYSECRETKEY'\nnetwork.cfg1.description='dads phone'\nnetwork.lan.ipaddr='192.168.1.1'\n")
	writeFixture(t, root, "tmp/dhcp.leases", "1700000000 aa:bb:cc:00:00:01 192.168.1.60 Anyas-Laptop 01:aa:bb:cc:00:00:01\n1700000001 aa:bb:cc:00:00:02 192.168.1.61 * *\n")

	got := harvestNames(t.Context())
	want := map[string]string{
		"Stas-Router": "host", "home.lan": "domain", "NAS": "host", "My Home WiFi": "ssid", "dads phone": "peer", "Anyas-Laptop": "host",
	}
	if len(got) != len(want) {
		t.Errorf("harvested %v, want %v", got, want)
	}
	for v, kind := range want {
		if got[v] != kind {
			t.Errorf("%q: kind %q, want %q", v, got[v], kind)
		}
	}
	for v := range got {
		if strings.Contains(v, "hunter2") || strings.Contains(v, "SECRETKEY") {
			t.Errorf("a secret was harvested: %q", v)
		}
	}
}

// The whole command: a router with private names everywhere a name can be, a policy and an audit
// log that mention them, and a bundle that must say what a maintainer needs and nothing else.
func TestDiagBundleIsReadableAndLeaksNothing(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"Example Board X1","kernel":"6.12.74","release":{"description":"OpenWrt 25.12.5 r32000","target":"ramips/mt7621"}}`)
	f.on("uci -q show system", "system.@system[0].hostname='Stas-Router'\n")
	f.on("uci -q show dhcp", "dhcp.@host[0].name='Annas-Laptop'\n")
	f.on("uci -q show wireless", "wireless.wifinet0.ssid='Cafe Stas 5G'\n")
	f.on("uci -q show network", "")
	writeFixture(t, root, "tmp/dhcp.leases", "")

	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	lines := []string{
		`{"time":"2026-10-07T20:00:00Z","client":"claude-code","tool":"system_status","outcome":"ok","duration_ms":12}`,
		`{"time":"2026-10-07T20:01:00Z","client":"stas-laptop","tool":"uci_apply","scope":"dhcp.annas_laptop.ip","args":{"value":"192.168.1.50"},"outcome":"ok","summary":"set Annas-Laptop to 192.168.1.50","duration_ms":1500}`,
		`{"time":"2026-10-07T20:02:00Z","client":"stas-laptop","tool":"wg_remove_client","scope":"wireguard.wg0.phone","outcome":"error","error":"no peer 00:11:22:33:44:55 on Cafe Stas 5G","duration_ms":3}`,
		`{"time":"2026-10-07T20:03:00Z","client":"claude-code","tool":"logread","outcome":"denied","duration_ms":0}`,
	}
	if err := os.WriteFile(audit, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "openwrt-mcp")
	body := "config server\n\toption listen '127.0.0.1:1'\n\toption audit '" + filepath.ToSlash(audit) + "'\n" +
		grantBlock("claude-code", "system_status", "*", "2099-01-01T00:00:00Z") +
		grantBlock("stas-laptop", "exec", "/bin/sh", "2020-01-01T00:00:00Z")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := runDiag(&out, cfg, 20, false); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"openwrt-mcp diagnostic bundle", "Addresses, MACs and names are replaced", "version    " + version,
		"board      Example Board X1; OpenWrt 25.12.5 r32000 (ramips/mt7621); kernel 6.12.74",
		"daemon     stopped on 127.0.0.1:1", "tools      23 registered",
		"policies   2 (1 expired)",
		"  claude-code: system_status on *, ", "  client-1: exec on /bin/sh, ",
		"expires 2099-01-01", "expires 2020-01-01 (expired)", "shell-equivalent: sh",
		"audit      last 4 of the log",
		"  2026-10-07T20:00:00Z claude-code system_status ok",
		"  2026-10-07T20:01:00Z client-1 uci_apply ok",
		"  2026-10-07T20:02:00Z client-1 wg_remove_client error",
		"  2026-10-07T20:03:00Z claude-code logread denied",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the bundle lacks %q:\n%s", want, s)
		}
	}
	// By default nothing free-form from the audit log is printed at all.
	for _, leak := range []string{"stas-laptop", "Stas-Router", "Annas", "annas_laptop", "Cafe", "192.168", "00:11:22", "phone", "set ", "no peer"} {
		if strings.Contains(strings.ToLower(s), strings.ToLower(leak)) {
			t.Errorf("%q is in the default bundle:\n%s", leak, s)
		}
	}

	// --detail adds the free text, masked like the rest.
	out.Reset()
	if err := runDiag(&out, cfg, 20, true); err != nil {
		t.Fatal(err)
	}
	d := out.String()
	for _, want := range []string{"| dhcp.annas_laptop.ip", "| set host-1 to ip-1", "| no peer mac-1 on ssid-1", "| wireguard.wg0.phone"} {
		if !strings.Contains(d, want) {
			t.Errorf("--detail lacks %q:\n%s", want, d)
		}
	}
	for _, leak := range []string{"stas-laptop", "Stas-Router", "Annas-Laptop", "Cafe", "192.168", "00:11:22"} {
		if strings.Contains(strings.ToLower(d), strings.ToLower(leak)) {
			t.Errorf("%q is in the --detail bundle:\n%s", leak, d)
		}
	}

	// --audit 0 drops the log entirely.
	out.Reset()
	if err := runDiag(&out, cfg, 0, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "2026-10-07T") {
		t.Errorf("audit lines printed with --audit 0:\n%s", out.String())
	}
}

func TestDiagSaysSoWhenTheRouterCannotBeAsked(t *testing.T) {
	withFixtureRoot(t)
	newFakeRouter(t) // answers nothing: every command fails
	cfg := filepath.Join(t.TempDir(), "openwrt-mcp")
	if err := os.WriteFile(cfg, []byte("config server\n\toption listen '127.0.0.1:1'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runDiag(&out, cfg, 5, false); err != nil {
		t.Fatalf("diag failed instead of reporting what it could: %v", err)
	}
	if !strings.Contains(out.String(), "board      (unavailable:") {
		t.Errorf("no explanation for a missing board:\n%s", out.String())
	}
}
