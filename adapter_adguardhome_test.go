package main

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func agDetail(t *testing.T) []string {
	t.Helper()
	return detailBody(t, listServices(t, serviceListIn{Detail: "adguardhome"}))
}

func TestAdGuardHomeDetailForARunningInstance(t *testing.T) {
	adapterRouter(t)
	want := []string{
		"AdGuard Home: running, pid 8330",
		"config: /etc/adguardhome/adguardhome.yaml, schema 34",
		"web UI: 0.0.0.0:3000",
		"dns: listens on 127.0.0.1:5354",
		"protection: on, filtering on, safe browsing off, parental off",
		"upstreams (5): https://dns.example.net, tls://dns.example.org:853, 9.9.9.9, [/lan/]192.0.2.1, sdns://(stamp)",
		"upstream file: /etc/adguardhome/upstreams.txt",
		"bootstrap: 9.9.9.9, 149.112.112.112",
		"filter lists: 2 of 3 enabled; custom rules: 2 active of 4",
		"query log: on, statistics: on, cache: on, dnssec: on",
		"dnsmasq upstream servers: 127.0.0.1#5354 (AdGuard Home)",
	}
	if got := agDetail(t); !reflect.DeepEqual(got, want) {
		t.Errorf("AdGuard Home detail:\n got %q\nwant %q", got, want)
	}
}

// The config holds the web UI login, upstream tokens, DNS rewrites, client MACs and filter
// lists. Only the fixed fields above are ever printed.
func TestAdGuardHomeDetailPrintsNoCredentialsOrPrivateLists(t *testing.T) {
	adapterRouter(t)
	out := strings.Join(agDetail(t), "\n")
	for _, canary := range []string{
		"canary-admin", "CanaryHash", "$2a$", // the web UI login
		"canarytoken123", "dns-query", "canaryuser", "canarypass", "AgcAAAAA", // upstream tokens, stamps
		"CanaryPrivateKeyPem", "canary.key", // TLS key
		"canary-rewrite", "192.0.2.99", "canary-client", "02:00:00:00:00:01", // rewrites and clients
		"list-one", "List one", "example.org/list", "commented-out", "ads.example.com", // filter lists and rules
	} {
		if strings.Contains(out, canary) {
			t.Errorf("the detail leaks %q:\n%s", canary, out)
		}
	}
}

func TestAdGuardHomeDetailWhenItIsNotRunning(t *testing.T) {
	f, _ := adapterRouter(t)
	f.fail("pidof AdGuardHome", "")
	got := agDetail(t)
	if got[0] != "AdGuard Home: not running" || got[1] != "config: /etc/adguardhome/adguardhome.yaml, schema 34" {
		t.Errorf("a stopped instance should still show its config:\n%q", got)
	}
}

func TestAdGuardHomeDetailShowsProtectionSwitchedOff(t *testing.T) {
	f, root := adapterRouter(t)
	y := adapterFixture(t, "adguardhome.yaml")
	off := strings.Replace(y, "  protection_enabled: true", "  protection_enabled: false", 1)
	writeFixture(t, root, "etc/adguardhome/adguardhome.yaml", off)
	if got := agDetail(t)[4]; got != "protection: OFF, filtering on, safe browsing off, parental off" {
		t.Errorf("protection line = %q", got)
	}
	timed := strings.Replace(off, "protection_disabled_until: null", "protection_disabled_until: 2026-10-08T12:00:00+02:00", 1)
	writeFixture(t, root, "etc/adguardhome/adguardhome.yaml", timed)
	if got := agDetail(t)[4]; got != "protection: OFF until 2026-10-08T12:00:00+02:00, filtering on, safe browsing off, parental off" {
		t.Errorf("timed protection line = %q", got)
	}
	_ = f
}

func TestAdGuardHomeDetailFollowsTheConfigFileOption(t *testing.T) {
	f, root := adapterRouter(t)
	writeFixture(t, root, "srv/agh/custom.yaml", strings.Replace(adapterFixture(t, "adguardhome.yaml"), "schema_version: 34", "schema_version: 99", 1))
	f.on("uci -q get adguardhome.config.config_file", "/srv/agh/custom.yaml\n")
	if got := agDetail(t)[1]; got != "config: /srv/agh/custom.yaml, schema 99" {
		t.Errorf("config line = %q", got)
	}

	// With no option set the packaged default is read.
	f.fail("uci -q get adguardhome.config.config_file", "")
	if got := agDetail(t)[1]; got != "config: /etc/adguardhome/adguardhome.yaml, schema 34" {
		t.Errorf("default config line = %q", got)
	}
}

// The option is root-writable configuration, not a promise that it names a YAML file.
func TestAdGuardHomeDetailReadsOnlyAYamlFileOnAnAbsolutePath(t *testing.T) {
	f, root := adapterRouter(t)
	writeFixture(t, root, "etc/shadow", "root:canary-shadow-hash:0:0:99999:7:::\n")
	for _, path := range []string{"/etc/shadow", "etc/adguardhome/adguardhome.yaml", "/etc/../etc/shadow.yaml", "/etc/a b.yaml", "/etc/x.yaml\n/etc/shadow"} {
		f.on("uci -q get adguardhome.config.config_file", path+"\n")
		got := agDetail(t)
		joined := strings.Join(got, "\n")
		if !strings.Contains(joined, "config_file option is not an absolute path to a .yaml file; not read") {
			t.Errorf("path %q was not refused:\n%s", path, joined)
		}
		if strings.Contains(joined, "canary-shadow") || strings.Contains(joined, "schema") {
			t.Errorf("path %q was read:\n%s", path, joined)
		}
	}
}

func TestAdGuardHomeDetailWhenTheConfigCannotBeRead(t *testing.T) {
	f, root := adapterRouter(t)
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/missing.yaml\n")
	got := agDetail(t)
	if got[0] != "AdGuard Home: running, pid 8330" || !strings.HasPrefix(got[1], "config unreadable: ") {
		t.Errorf("got %q", got)
	}
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/huge.yaml\n")
	writeFixture(t, root, "etc/adguardhome/huge.yaml", strings.Repeat("# padding\n", 300<<10))
	if got := agDetail(t); got[1] != "config too large to read (over 2 MiB)" {
		t.Errorf("huge config: %q", got)
	}
}

func TestAdGuardHomeDetailAboutDnsmasq(t *testing.T) {
	f, _ := adapterRouter(t)
	for server, want := range map[string]string{
		"":                              "dnsmasq upstream servers: (none set)",
		"192.0.2.53":                    "dnsmasq upstream servers: 192.0.2.53",
		"127.0.0.1#5354 192.0.2.53":     "dnsmasq upstream servers: 127.0.0.1#5354 (AdGuard Home), 192.0.2.53",
		"127.0.0.1#5355":                "dnsmasq upstream servers: 127.0.0.1#5355",
		"127.0.0.1#15354":               "dnsmasq upstream servers: 127.0.0.1#15354",
		"/lan/192.0.2.1 127.0.0.1#5354": "dnsmasq upstream servers: /lan/192.0.2.1, 127.0.0.1#5354 (AdGuard Home)",
	} {
		f.on("uci -q get dhcp.@dnsmasq[0].server", server+"\n")
		got := agDetail(t)
		if last := got[len(got)-1]; last != want {
			t.Errorf("servers %q -> %q, want %q", server, last, want)
		}
	}
}

func TestAdGuardHomeDetailReadsThePlainYamlAdGuardWrites(t *testing.T) {
	f, root := adapterRouter(t)
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/min.yaml\n")
	// Comments, quoting, CRLF, flow lists and an empty section.
	writeFixture(t, root, "etc/adguardhome/min.yaml", strings.Join([]string{
		"# AdGuard Home",
		"http:",
		`  address: "[::]:3001" # the UI`,
		"dns:",
		"  bind_hosts: [127.0.0.1, '::1']",
		"  port: 5354",
		"  upstream_dns: []",
		"  bootstrap_dns:",
		"    - 9.9.9.9 # quad9",
		"  cache_enabled: false",
		"filters: []",
		"user_rules: []",
		"schema_version: 34",
		"",
	}, "\r\n"))
	want := []string{
		"AdGuard Home: running, pid 8330",
		"config: /etc/adguardhome/min.yaml, schema 34",
		"web UI: [::]:3001",
		"dns: listens on 127.0.0.1:5354, [::1]:5354",
		"upstreams (0)",
		"bootstrap: 9.9.9.9",
		"filter lists: 0 of 0 enabled; custom rules: 0 active of 0",
		"cache: off",
		"dnsmasq upstream servers: 127.0.0.1#5354 (AdGuard Home)",
	}
	if got := agDetail(t); !reflect.DeepEqual(got, want) {
		t.Errorf("plain yaml:\n got %q\nwant %q", got, want)
	}
}

func TestAdGuardHomeDetailBoundsTheUpstreamList(t *testing.T) {
	f, root := adapterRouter(t)
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/many.yaml\n")
	var y strings.Builder
	y.WriteString("dns:\n  port: 53\n  upstream_dns:\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&y, "    - 192.0.2.%d\n", i)
	}
	writeFixture(t, root, "etc/adguardhome/many.yaml", y.String())
	var up string
	for _, l := range agDetail(t) {
		if strings.HasPrefix(l, "upstreams") {
			up = l
		}
	}
	if !strings.HasPrefix(up, "upstreams (12): ") || !strings.HasSuffix(up, ", +4 more") || strings.Count(up, "192.0.2.") != 8 {
		t.Errorf("upstream line = %q", up)
	}
}

// Only what the config says is reported: a config with nothing in it gets no invented lines.
func TestAdGuardHomeDetailOfAnEmptyOrMinimalConfig(t *testing.T) {
	f, root := adapterRouter(t)
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/e.yaml\n")
	f.fail("uci -q get dhcp.@dnsmasq[0].server", "")
	writeFixture(t, root, "etc/adguardhome/e.yaml", "")
	want := []string{
		"AdGuard Home: running, pid 8330",
		"config: /etc/adguardhome/e.yaml",
		"dns: listen port not found in the config",
		"upstreams (0)",
		"filter lists: 0 of 0 enabled; custom rules: 0 active of 0",
		"dnsmasq upstream servers: (none set)",
	}
	if got := agDetail(t); !reflect.DeepEqual(got, want) {
		t.Errorf("empty config:\n got %q\nwant %q", got, want)
	}
	writeFixture(t, root, "etc/adguardhome/e.yaml", "dns:\n  port: 53\n")
	if got := agDetail(t)[2]; got != "dns: listens on port 53" {
		t.Errorf("a port with no bind hosts: %q", got)
	}
}

func TestAdGuardHomeDetailConfigSizeBoundary(t *testing.T) {
	f, root := adapterRouter(t)
	f.on("uci -q get adguardhome.config.config_file", "/etc/adguardhome/edge.yaml\n")
	writeFixture(t, root, "etc/adguardhome/edge.yaml", strings.Repeat("#\n", agMaxConfig/2))
	if got := agDetail(t); got[1] != "config: /etc/adguardhome/edge.yaml" {
		t.Errorf("a config of exactly the limit was not read: %q", got[1])
	}
	writeFixture(t, root, "etc/adguardhome/edge.yaml", strings.Repeat("#\n", agMaxConfig/2)+"#")
	if got := agDetail(t); got[1] != "config too large to read (over 2 MiB)" {
		t.Errorf("a config one byte over the limit was read: %q", got[1])
	}
}

func TestAdGuardHomeDetailProtectionSwitchedOffWithNoEndTime(t *testing.T) {
	_, root := adapterRouter(t)
	y := strings.Replace(adapterFixture(t, "adguardhome.yaml"), "  protection_enabled: true", "  protection_enabled: false", 1)
	for _, until := range []string{"null", "~", `""`} {
		writeFixture(t, root, "etc/adguardhome/adguardhome.yaml", strings.Replace(y, "protection_disabled_until: null", "protection_disabled_until: "+until, 1))
		if got := agDetail(t)[4]; got != "protection: OFF, filtering on, safe browsing off, parental off" {
			t.Errorf("until %s: %q", until, got)
		}
	}
}

func FuzzSummariseAdGuardHome(f *testing.F) {
	if b, err := os.ReadFile("testdata/adapters/adguardhome.yaml"); err == nil {
		f.Add(string(b))
	}
	for _, s := range []string{"", "dns:\n  upstream_dns:\n    - [/", "filters:\n  - enabled:\n  -\n", "\t\t:::\n- - -\n", "dns: [a, b\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if lines, _ := summariseAdGuardHome("/x.yaml", s); len(lines) == 0 {
			t.Error("no lines")
		}
	})
}
