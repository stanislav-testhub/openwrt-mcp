package main

import (
	"context"
	"strings"
	"testing"
)

// Findings from add-ons (ROADMAP 9.1, L5). Inputs are synthetic, like the adapters' (see
// adapters_wave1_test.go).

func installAddonConfig(t *testing.T, root, name string) {
	writeFixture(t, root, "etc/config/"+name, "# present\n")
}

func TestAuditFlagsATtydShellWithNoLogin(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "ttyd")
	f.on("uci -q show ttyd", "ttyd.a=ttyd\nttyd.a.command='/bin/sh'\nttyd.b=ttyd\nttyd.b.command='/bin/sh'\nttyd.b.interface='@lan'\n"+
		"ttyd.c=ttyd\nttyd.c.command='/bin/login'\nttyd.d=ttyd\nttyd.d.command='/bin/sh'\nttyd.d.credential='u:canary-pass'\n"+
		"ttyd.e=ttyd\nttyd.e.command='/bin/sh'\nttyd.e.enable='0'\n")
	r := auditFindings(context.Background())
	var open []finding
	for _, x := range r.findings {
		if x.id == "ttyd-open" {
			open = append(open, x)
		}
	}
	if len(open) != 2 || open[0].sev != sevHigh && open[1].sev != sevHigh {
		t.Fatalf("want two ttyd-open findings (a: every interface, b: lan), got %+v", open)
	}
	for _, x := range open {
		if strings.Contains(x.evidence+x.msg, "canary-pass") || strings.Contains(x.msg, "ttyd.c") || strings.Contains(x.msg, "ttyd.d") {
			t.Errorf("the wrong instance or a secret in %+v", x)
		}
	}
}

func TestAuditFlagsUPnPSecureModeOffOnlyWhenEnabled(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "upnpd")
	f.on("uci -q show upnpd", "upnpd.config=upnpd\nupnpd.config.enabled='1'\nupnpd.config.secure_mode='0'\n")
	if auditFindings(context.Background()).byID("upnp-insecure-mode") == nil {
		t.Error("secure mode off on an enabled daemon is not flagged")
	}
	f.on("uci -q show upnpd", "upnpd.config=upnpd\nupnpd.config.enabled='0'\nupnpd.config.secure_mode='0'\n")
	if auditFindings(context.Background()).byID("upnp-insecure-mode") != nil {
		t.Error("a disabled daemon is flagged")
	}
	f.on("uci -q show upnpd", "upnpd.config=upnpd\nupnpd.config.enabled='1'\n")
	if auditFindings(context.Background()).byID("upnp-insecure-mode") != nil {
		t.Error("the default (secure mode on) is flagged")
	}
}

func TestDoctorFlagsSQMWithFlowOffloading(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "sqm")
	f.on("uci -q show sqm", sqmUCI)
	f.on("uci -q show firewall", "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].flow_offloading='1'\n")
	if healthFindings(context.Background()).byID("sqm-offload") == nil {
		t.Error("sqm with flow offloading is not flagged")
	}
	f.on("uci -q show firewall", "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].flow_offloading='0'\n")
	if healthFindings(context.Background()).byID("sqm-offload") != nil {
		t.Error("offloading off is flagged")
	}
	f.on("uci -q show firewall", "firewall.@defaults[0]=defaults\nfirewall.@defaults[0].flow_offloading='1'\n")
	f.on("uci -q show sqm", strings.Replace(sqmUCI, "sqm.eth1.enabled='1'", "sqm.eth1.enabled='0'", 1))
	if healthFindings(context.Background()).byID("sqm-offload") != nil {
		t.Error("no enabled queue, yet flagged")
	}
}

func TestDoctorFlagsAStaleDDNSRecordAndCGNAT(t *testing.T) {
	f, root := ddnsRouter(t, "198.51.100.9")
	installAddonConfig(t, root, "ddns")
	if x := healthFindings(context.Background()).byID("ddns-stale"); x == nil || !strings.Contains(x.evidence, "registered 203.0.113.7, WAN 198.51.100.9") {
		t.Errorf("stale record: %+v", x)
	}
	f.on("ubus call network.interface.wan status", `{"ipv4-address":[{"address":"203.0.113.7"}]}`)
	if r := healthFindings(context.Background()); r.byID("ddns-stale") != nil || r.byID("ddns-cgnat") != nil {
		t.Errorf("matching addresses flagged: %v", findingIDs(r))
	}
	f.on("ubus call network.interface.wan status", `{"ipv4-address":[{"address":"100.72.1.2"}]}`)
	r := healthFindings(context.Background())
	if r.byID("ddns-cgnat") == nil || r.byID("ddns-stale") != nil {
		t.Errorf("cgnat: %v", findingIDs(r))
	}
}

func TestDoctorFlagsMwan3OfflineAndPolicyDown(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "mwan3")
	f.on(`ubus call mwan3 status {"section":"interfaces"}`, mwan3Interfaces)
	f.on(`ubus call mwan3 status {"section":"policies"}`, strings.Replace(mwan3PoliciesJSON, `"balanced":{"x":0},`, `"balanced":[{"interface":"wan","percent":50},{"interface":"wanb","percent":50}],`, 1))
	// Rules use balanced and wanb_only; wan_only is defined but unused, and is down all the same.
	f.on("uci -q show mwan3", "mwan3.r1=rule\nmwan3.r1.use_policy='balanced'\nmwan3.r2=rule\nmwan3.r2.use_policy='wanb_only'\n")
	r := healthFindings(context.Background())
	ids := findingIDs(r)
	if !strings.Contains(ids, "mwan3-iface-offline") || strings.Count(ids, "mwan3-policy-down") != 1 {
		t.Errorf("want wanb offline and only wanb_only down (balanced still has wan): %v", ids)
	}
	f.on("uci -q show mwan3", "mwan3.r1=rule\nmwan3.r1.use_policy='balanced'\n")
	if ids := findingIDs(healthFindings(context.Background())); strings.Contains(ids, "mwan3-policy-down") {
		t.Errorf("a policy no rule uses was flagged: %v", ids)
	}
}

// The stock mwan3 config on a real 24.10.8 install: wanb_only has no active member and is not used.
func TestDoctorIsQuietOnAStockMwan3(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "mwan3")
	f.on(`ubus call mwan3 status {"section":"interfaces"}`, captured(t, "mwan3", "02.txt"))
	f.on(`ubus call mwan3 status {"section":"policies"}`, captured(t, "mwan3", "03.txt"))
	f.on("uci -q show mwan3", captured(t, "mwan3", "01.txt"))
	if ids := findingIDs(healthFindings(context.Background())); strings.Contains(ids, "mwan3") {
		t.Errorf("findings on a stock mwan3: %v", ids)
	}
}

func TestAddonChecksAreQuietWhenTheAddonIsNotInstalled(t *testing.T) {
	wave1Router(t)
	for _, r := range []*findingsRun{healthFindings(context.Background()), auditFindings(context.Background())} {
		for _, x := range r.findings {
			if strings.HasPrefix(x.id, "ttyd") || strings.HasPrefix(x.id, "upnp-insecure") || strings.HasPrefix(x.id, "sqm") || strings.HasPrefix(x.id, "ddns") || strings.HasPrefix(x.id, "mwan3") {
				t.Errorf("%s without the add-on installed", x.id)
			}
		}
	}
}

func TestDoctorFlagsSQMAndQosifyOnOneInterface(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "sqm")
	installAddonConfig(t, root, "qosify")
	f.on("uci -q show sqm", "sqm.q=queue\nsqm.q.enabled='1'\nsqm.q.interface='wan'\n")
	f.on("uci -q show qosify", "qosify.w=interface\nqosify.w.name='wan'\n")
	if healthFindings(context.Background()).byID("sqm-qosify-both") == nil {
		t.Error("two shapers on wan not flagged")
	}
	f.on("uci -q show qosify", "qosify.w=interface\nqosify.w.name='wan'\nqosify.w.disabled='1'\n")
	if healthFindings(context.Background()).byID("sqm-qosify-both") != nil {
		t.Error("a disabled qosify interface is flagged")
	}
}

func TestDoctorFlagsUnboundAndDnsmasqOnPort53(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "unbound")
	f.on("ubus call rc list", `{"unbound":{"enabled":true,"running":false,"start":25,"stop":4}}`)
	f.on("uci -q show unbound", "unbound.ub_main=unbound\n")
	f.on("uci -q show dhcp", "dhcp.@dnsmasq[0]=dnsmasq\n")
	if healthFindings(context.Background()).byID("unbound-port-clash") == nil {
		t.Error("port clash not flagged")
	}
	f.on("uci -q show dhcp", "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].port='1053'\n")
	if healthFindings(context.Background()).byID("unbound-port-clash") != nil {
		t.Error("dnsmasq moved aside, yet flagged")
	}
}

func TestDoctorFlagsTwoDNSBlockers(t *testing.T) {
	f, _ := wave1Router(t)
	f.on("ubus call rc list", `{"adblock":{"enabled":true,"running":true,"start":30,"stop":4},"adblock-fast":{"enabled":true,"running":true,"start":50,"stop":4}}`)
	if healthFindings(context.Background()).byID("dns-two-blockers") == nil {
		t.Error("two blockers not flagged")
	}
	f.on("ubus call rc list", `{"adblock":{"enabled":true,"running":true,"start":30,"stop":4},"adblock-fast":{"enabled":false,"running":false,"start":50,"stop":4}}`)
	if healthFindings(context.Background()).byID("dns-two-blockers") != nil {
		t.Error("one enabled blocker flagged")
	}
}

func TestDoctorFlagsBrokenFilteringAndRouting(t *testing.T) {
	f, root := wave1Router(t)
	for _, n := range []string{"adblock", "adblock-fast", "banip", "https-dns-proxy", "pbr"} {
		installAddonConfig(t, root, n)
	}
	writeFixture(t, root, "var/run/adblock/adblock.runtime.json", `{"adblock_status":"error"}`)
	writeFixture(t, root, "var/run/banIP/banIP.runtime.json", `{"status":"enabled","wan_interfaces":[]}`)
	f.on("ubus call service list", `{"adblock-fast":{"instances":{"i":{"running":true,"data":{"errors":[{"code":"errorDownloadingList"}]}}}},"pbr":{"instances":{"i":{"running":true,"data":{"errors":[{"code":"errorNoGateway"}]}}}}}`)
	f.on("uci -q show https-dns-proxy", "https-dns-proxy.config=main\nhttps-dns-proxy.config.dnsmasq_config_update='-'\nhttps-dns-proxy.a=https-dns-proxy\nhttps-dns-proxy.a.listen_port='5053'\n")
	f.on("uci -q get dhcp.@dnsmasq[0].server", "9.9.9.9\n")
	r := healthFindings(context.Background())
	for _, id := range []string{"adblock-broken", "banip-no-wan", "hdp-bypassed", "pbr-errors"} {
		if r.byID(id) == nil {
			t.Errorf("%s not flagged", id)
		}
	}
	writeFixture(t, root, "var/run/adblock/adblock.runtime.json", `{"adblock_status":"enabled"}`)
	f.on("ubus call service list", `{"adblock-fast":{"instances":{"i":{"running":true,"data":{"errors":[]}}}},"pbr":{"instances":{"i":{"running":true,"data":{"errors":[]}}}}}`)
	writeFixture(t, root, "var/run/banIP/banIP.runtime.json", `{"status":"enabled","wan_interfaces":["wan"]}`)
	f.on("uci -q get dhcp.@dnsmasq[0].server", "127.0.0.1#5053\n")
	r = healthFindings(context.Background())
	for _, id := range []string{"adblock-broken", "banip-no-wan", "hdp-bypassed", "pbr-errors"} {
		if r.byID(id) != nil {
			t.Errorf("%s flagged on a healthy setup", id)
		}
	}
}

// On the GL-MT6000 /etc/config/mwan3 outlived the package: the config is there, the ubus object is not.
// That is not a fault to report and not a check that could not run.
func TestDoctorIgnoresMwan3WhenOnlyItsConfigIsLeftBehind(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "mwan3")
	f.fail(`ubus call mwan3 status`, "Command failed: Not found")
	r := healthFindings(context.Background())
	if ids := findingIDs(r); strings.Contains(ids, "mwan3") {
		t.Errorf("findings: %v", ids)
	}
	for _, n := range r.skipped {
		if strings.Contains(n, "mwan3") {
			t.Errorf("mwan3 reported as not checked: %q", n)
		}
	}
}

// /proc/interrupts of a 4-core router: the first line names the CPUs, IPIs and timers are per-CPU by
// design and must not count, and a device whose interrupts are spread must not trip the finding.
const irqSkewed = `           CPU0       CPU1       CPU2       CPU3       
 11:     500000     480000     470000     460000     GICv3  30 Level     arch_timer
 38:    1200000      10000       5000       3000     GICv3 229 Level     mt76-wmac
 39:     800000       2000       1000       1000     GICv3 105 Level     eth0
IPI0:     90000      90000      90000      90000       Rescheduling interrupts
`

func TestDoctorSuggestsIrqbalanceWhenOneCpuTakesTheDeviceInterrupts(t *testing.T) {
	f, root := wave1Router(t)
	writeFixture(t, root, "proc/interrupts", irqSkewed)
	f.on("ubus call rc list", `{}`)
	fd := healthFindings(context.Background()).byID("irq-one-cpu")
	if fd == nil || fd.sev != sevInfo || !strings.Contains(fd.msg, "CPU0 handles 98%") || !strings.Contains(fd.evidence, "irqbalance is not installed") {
		t.Fatalf("finding %+v", fd)
	}
	f.on("ubus call rc list", `{"irqbalance":{"enabled":false,"running":false,"start":11,"stop":89}}`)
	if fd := healthFindings(context.Background()).byID("irq-one-cpu"); fd == nil || !strings.Contains(fd.evidence, "installed but not running") {
		t.Errorf("installed but stopped: %+v", fd)
	}
	f.on("ubus call rc list", `{"irqbalance":{"enabled":true,"running":true,"start":11,"stop":89}}`)
	if healthFindings(context.Background()).byID("irq-one-cpu") != nil {
		t.Error("flagged with irqbalance running")
	}
}

func TestDoctorStaysQuietOnSpreadOrQuietOrSingleCoreInterrupts(t *testing.T) {
	f, root := wave1Router(t)
	f.on("ubus call rc list", `{}`)
	for name, text := range map[string]string{
		"spread": "           CPU0       CPU1\n 38:    600000     500000     GIC  eth0\n",
		"quiet":  "           CPU0       CPU1\n 38:      9000        100     GIC  eth0\n",
		"one":    "           CPU0\n 38:    900000     GIC  eth0\n",
		"timers": "           CPU0       CPU1\n 11:    900000          0     GIC  arch_timer\nIPI0:    900000          0       Rescheduling interrupts\n",
	} {
		writeFixture(t, root, "proc/interrupts", text)
		if healthFindings(context.Background()).byID("irq-one-cpu") != nil {
			t.Errorf("%s: flagged", name)
		}
	}
}
