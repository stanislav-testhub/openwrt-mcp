package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Findings from installed add-ons (ROADMAP 9.1, layer L5). Each check applies only when the
// add-on's config file exists, so a router without it sees nothing, and reads only what the
// add-on's adapter reads. Like every finding they are advice, not actions.

func addonInstalled(config string) bool {
	_, err := os.Stat(sysPath("/etc/config/" + config))
	return err == nil
}

func init() {
	for id, h := range map[string]findingHint{
		"ttyd-open":           {"service_list detail=ttyd shows each instance; bind it to the LAN with uci_apply (dry_run first) and set a credential, or remove it", docSecure},
		"upnp-insecure-mode":  {"set secure_mode back to 1 with uci_apply (dry_run first); service_list detail=miniupnpd lists the current mappings", docUPnP},
		"sqm-offload":         {"turn off flow offloading with uci_apply (dry_run first) or stop using sqm on this link; service_list detail=sqm shows the counters", ""},
		"ddns-stale":          {"service_list detail=ddns shows the registered and the WAN address; logread with pattern=ddns for the update error", ""},
		"ddns-cgnat":          {"the WAN address is shared by the provider: ask for a public address or use a tunnel (service_list detail=ddns shows the address)", ""},
		"mwan3-policy-down":   {"service_list detail=mwan3 shows each interface and its track IPs; logread with pattern=mwan3 for why tracking failed", ""},
		"mwan3-iface-offline": {"service_list detail=mwan3 shows its track IPs; net_diag action=ping tests the uplink itself", ""},
	} {
		findingHints[id] = h
	}
}

// ---------------------------------------------------------------- audit

func checkTTYD(sn *snapshot) ([]finding, error) {
	if !addonInstalled("ttyd") {
		return nil, nil
	}
	t, err := sn.getUCI("ttyd")
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, s := range t.sectionsOfType("ttyd") {
		if !uciFlag(t.get(s, "enable"), true) || t.get(s, "command") == "" {
			continue
		}
		if t.get(s, "credential") != "" || ttydRunsLogin(t.get(s, "command")) {
			continue
		}
		where, sev := "the interface "+clip(t.get(s, "interface"), 30), sevMedium
		if t.get(s, "interface") == "" {
			where, sev = "every interface", sevHigh
		}
		out = append(out, newFinding("ttyd-open", sev,
			"ttyd gives a shell with no login to anyone who reaches it on "+where,
			fmt.Sprintf("ttyd.%s: no credential, command %s", s, clip(strings.Fields(t.get(s, "command"))[0], 40))))
	}
	return out, nil
}

func checkUPnPSecureMode(sn *snapshot) ([]finding, error) {
	if !addonInstalled("upnpd") {
		return nil, nil
	}
	t, err := sn.getUCI("upnpd")
	if err != nil {
		return nil, err
	}
	for _, s := range t.sectionsOfType("upnpd") {
		if uciFlag(t.get(s, "enabled"), true) && !uciFlag(t.get(s, "secure_mode"), true) {
			return []finding{newFinding("upnp-insecure-mode", sevMedium,
				"UPnP secure mode is off: any LAN host can map ports to other hosts' addresses", "upnpd."+s+".secure_mode=0")}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------- doctor

func checkSQM(sn *snapshot) ([]finding, error) {
	if !addonInstalled("sqm") {
		return nil, nil
	}
	t, err := sn.getUCI("sqm")
	if err != nil {
		return nil, err
	}
	var on []string
	for _, s := range t.sectionsOfType("queue") {
		if uciFlag(t.get(s, "enabled"), false) {
			on = append(on, s)
		}
	}
	if len(on) == 0 {
		return nil, nil
	}
	fw, err := sn.getUCI("firewall")
	if err != nil {
		return nil, err
	}
	for _, d := range fw.sectionsOfType("defaults") {
		if uciFlag(fw.get(d, "flow_offloading"), false) {
			return []finding{newFinding("sqm-offload", sevMedium,
				"sqm is enabled but software flow offloading is on: offloaded flows bypass the shaper",
				fmt.Sprintf("firewall.%s.flow_offloading=1, sqm queue %s enabled", d, clip(on[0], 30)))}, nil
		}
	}
	return nil, nil
}

func checkDDNS(sn *snapshot) ([]finding, error) {
	if !addonInstalled("ddns") {
		return nil, nil
	}
	t, err := sn.getUCI("ddns")
	if err != nil {
		return nil, err
	}
	dir := runtimePath(t.get("global", "ddns_rundir"), ddnsRunDir)
	var out []finding
	for _, s := range t.sectionsOfType("service") {
		if !uciFlag(t.get(s, "enabled"), false) || !uciName.MatchString(s) {
			continue
		}
		iface := t.get(s, "ip_network")
		if iface == "" {
			iface = t.get(s, "interface")
		}
		wan := wanAddress(sn.ctx, iface, uciFlag(t.get(s, "use_ipv6"), false))
		if wan == "" {
			continue
		}
		if behindCGNAT(wan) {
			out = append(out, newFinding("ddns-cgnat", sevMedium,
				fmt.Sprintf("ddns %s: the WAN address is in 100.64.0.0/10, so the record cannot be reached from outside", clip(s, 30)), "network.interface."+iface+" address "+wan))
			continue
		}
		text, rerr := readSys(dir + "/" + s + ".ip")
		if rerr != nil {
			continue
		}
		if reg := strings.TrimSpace(text); validIP(reg) && reg != wan {
			out = append(out, newFinding("ddns-stale", sevMedium,
				fmt.Sprintf("ddns %s: the registered address differs from the WAN address", clip(s, 30)), fmt.Sprintf("registered %s, WAN %s", reg, wan)))
		}
	}
	return out, nil
}

func checkMwan3(sn *snapshot) ([]finding, error) {
	if !addonInstalled("mwan3") {
		return nil, nil
	}
	var ifs struct {
		Interfaces map[string]mwan3Iface `json:"interfaces"`
	}
	if err := runJSON(sn.ctx, &ifs, "ubus", "call", "mwan3", "status", `{"section":"interfaces"}`); err != nil {
		return nil, err
	}
	var pol struct {
		Policies struct {
			V4 map[string][]mwan3Member `json:"ipv4"`
		} `json:"policies"`
	}
	if err := runJSON(sn.ctx, &pol, "ubus", "call", "mwan3", "status", `{"section":"policies"}`); err != nil {
		return nil, err
	}
	var out []finding
	for _, n := range sortedKeys(ifs.Interfaces) {
		i := ifs.Interfaces[n]
		if i.Enabled && i.Status == "offline" {
			out = append(out, newFinding("mwan3-iface-offline", sevMedium, fmt.Sprintf("mwan3 interface %s is offline", clip(n, 30)),
				"mwan3 status: "+n+" "+i.Status+", tracking "+clip(i.Tracking, 20)+", score "+strconv.Itoa(i.Score)))
		}
	}
	names := make([]string, 0, len(pol.Policies.V4))
	for n := range pol.Policies.V4 {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		online := 0
		for _, m := range pol.Policies.V4[n] {
			if ifs.Interfaces[m.Interface].Status == "online" {
				online++
			}
		}
		if online == 0 {
			out = append(out, newFinding("mwan3-policy-down", sevHigh, fmt.Sprintf("no member of mwan3 policy %s is online", clip(n, 30)), "mwan3 status policies: "+n))
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- wave 2

func init() {
	for id, h := range map[string]findingHint{
		"sqm-qosify-both":    {"keep one shaper per interface: service_list detail=sqm and detail=qosify show both; turn one off with uci_apply (dry_run first)", ""},
		"unbound-port-clash": {"move dnsmasq off port 53 (dhcp_link dnsmasq in unbound's config does it) or give unbound another listen_port, with uci_apply (dry_run first); service_list detail=unbound shows the wiring", ""},
		"dns-two-blockers":   {"net_diag action=dns_path shows every blocker in the path; keep one and disable the other", ""},
	} {
		findingHints[id] = h
	}
}

func checkSQMQosify(sn *snapshot) ([]finding, error) {
	if !addonInstalled("sqm") || !addonInstalled("qosify") {
		return nil, nil
	}
	sq, err := sn.getUCI("sqm")
	if err != nil {
		return nil, err
	}
	qo, err := sn.getUCI("qosify")
	if err != nil {
		return nil, err
	}
	shaped := map[string]bool{}
	for _, s := range sq.sectionsOfType("queue") {
		if uciFlag(sq.get(s, "enabled"), false) && sq.get(s, "interface") != "" {
			shaped[sq.get(s, "interface")] = true
		}
	}
	var out []finding
	for _, s := range qo.sectionsOfType("interface") {
		n := pick(qo.get(s, "name") != "", qo.get(s, "name"), s)
		if !uciFlag(qo.get(s, "disabled"), false) && shaped[n] {
			out = append(out, newFinding("sqm-qosify-both", sevMedium,
				"sqm and qosify both shape "+clip(n, 20)+": the two queues fight over the same traffic",
				fmt.Sprintf("sqm queue on %s enabled, qosify interface %s enabled", clip(n, 20), clip(s, 30))))
		}
	}
	return out, nil
}

func checkUnboundPort(sn *snapshot) ([]finding, error) {
	if !addonInstalled("unbound") {
		return nil, nil
	}
	ub, err := sn.getUCI("unbound")
	if err != nil {
		return nil, err
	}
	rc, err := sn.getRC()
	if err != nil {
		return nil, err
	}
	if e, ok := rc["unbound"]; !ok || !e.Enabled {
		return nil, nil
	}
	if p := ub.get("ub_main", "listen_port"); p != "" && p != "53" {
		return nil, nil
	}
	if ub.get("ub_main", "dhcp_link") == "dnsmasq" {
		return nil, nil
	}
	dh, err := sn.getUCI("dhcp")
	if err != nil {
		return nil, err
	}
	for _, s := range dh.sectionsOfType("dnsmasq") {
		if p := dh.get(s, "port"); p == "" || p == "53" {
			return []finding{newFinding("unbound-port-clash", sevHigh,
				"unbound and dnsmasq both want port 53; one of them will fail to start",
				fmt.Sprintf("unbound listen_port 53, dhcp_link %s, dnsmasq port %s", pick(ub.get("ub_main", "dhcp_link") != "", clip(ub.get("ub_main", "dhcp_link"), 20), "none"), pick(p != "", p, "53 (default)")))}, nil
		}
	}
	return nil, nil
}

func checkDNSBlockers(sn *snapshot) ([]finding, error) {
	rc, err := sn.getRC()
	if err != nil {
		return nil, err
	}
	var on []string
	for _, b := range []string{"adblock", "adblock-fast", "simple-adblock"} {
		if e, ok := rc[b]; ok && e.Enabled {
			on = append(on, b)
		}
	}
	if len(on) < 2 {
		return nil, nil
	}
	return []finding{newFinding("dns-two-blockers", sevMedium,
		"more than one DNS blocker is enabled at boot: they rewrite the same dnsmasq files",
		strings.Join(on, ", ")+" enabled")}, nil
}
