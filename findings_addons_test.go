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
	r := healthFindings(context.Background())
	ids := findingIDs(r)
	if !strings.Contains(ids, "mwan3-iface-offline") || strings.Count(ids, "mwan3-policy-down") != 1 {
		t.Errorf("want wanb offline and only wanb_only down (balanced still has wan): %v", ids)
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
