package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"
)

// Wi-Fi roaming and captive portals (ROADMAP 9.5, last batch): usteer and DAWN steer clients between
// access points, openNDS is a captive portal. All three are status only. Client MAC addresses are not
// printed (counts instead), and keys (DAWN's shared key, openNDS's FAS key) are only reported as set.

const maxRoamNodes = 8

// jnum reads a number from a decoded JSON object (ok is false when absent or not a number).
func jnum(m map[string]any, key string) (float64, bool) {
	f, ok := m[key].(float64)
	return f, ok && !math.IsNaN(f)
}

func jbool(m map[string]any, key string) bool { b, _ := m[key].(bool); return b }

// ubusMap runs `ubus call OBJ METHOD` and decodes the reply as an object.
func ubusMap(ctx context.Context, obj, method string) (map[string]any, error) {
	var m map[string]any
	err := runJSON(ctx, &m, "ubus", "call", obj, method)
	return m, err
}

// ---------------------------------------------------------------- usteer

func readUsteer(ctx context.Context) string {
	lines := []string{running(ctx, "usteerd")}
	cfg, err := ubusMap(ctx, "usteer", "get_config")
	if err != nil {
		return strings.Join(append(lines, "usteer does not answer on ubus: "+clip(err.Error(), 120)), "\n")
	}
	lines = append(lines, usteerPolicy(cfg)...)
	if local, err := ubusMap(ctx, "usteer", "local_info"); err == nil {
		lines = append(lines, usteerNodes(local)...)
	}
	peers, perr := ubusMap(ctx, "usteer", "remote_hosts")
	clients, cerr := ubusMap(ctx, "usteer", "get_clients")
	var state []string
	if perr == nil {
		state = append(state, plural(len(peers), "other usteer host")+" seen")
	}
	if cerr == nil {
		state = append(state, plural(len(clients), "client")+" tracked")
	}
	if len(state) > 0 {
		lines = append(lines, strings.Join(state, ", "))
	}
	if perr == nil && len(peers) == 0 && !jbool(cfg, "local_mode") {
		lines = append(lines, "note: no other usteer host answers, so nothing is steered between access points; every AP needs usteer and the same network (option network)")
	}
	return strings.Join(lines, "\n")
}

// usteerPolicy turns the effective configuration (ubus get_config, defaults included) into which
// steering policies are active. A policy whose threshold is 0 is off.
func usteerPolicy(c map[string]any) []string {
	var on, off []string
	if iv, _ := jnum(c, "band_steering_interval"); iv > 0 {
		th, _ := jnum(c, "band_steering_threshold")
		snr, _ := jnum(c, "band_steering_min_snr")
		on = append(on, fmt.Sprintf("band steering every %.0f s (min signal %.0f, station delta %.0f)", iv/1000, snr, th))
	} else {
		off = append(off, "band steering")
	}
	if lb, _ := jnum(c, "load_balancing_threshold"); lb > 0 {
		on = append(on, fmt.Sprintf("load balancing at a difference of %.0f stations", lb))
	} else {
		off = append(off, "load balancing")
	}
	scan, _ := jnum(c, "roam_scan_snr")
	trig, _ := jnum(c, "roam_trigger_snr")
	if scan > 0 || trig > 0 {
		on = append(on, fmt.Sprintf("client roaming (scan below SNR %.0f, forced below %.0f)", scan, trig))
	} else {
		off = append(off, "client roaming")
	}
	if s, _ := jnum(c, "min_snr"); s > 0 {
		on = append(on, fmt.Sprintf("kick below SNR %.0f", s))
	} else {
		off = append(off, "minimum-SNR kick")
	}
	if jbool(c, "load_kick_enabled") {
		th, _ := jnum(c, "load_kick_threshold")
		on = append(on, fmt.Sprintf("kick on channel load above %.0f%%", th))
	}
	if jbool(c, "assoc_steering") {
		on = append(on, "association rejects")
	}
	lines := []string{"policies on: " + pick(len(on) > 0, strings.Join(on, "; "), "none")}
	if len(off) > 0 {
		lines = append(lines, "policies off: "+strings.Join(off, ", "))
	}
	if jbool(c, "local_mode") {
		lines = append(lines, "WARNING: local_mode is on, so this AP does not exchange state with others and cannot coordinate roaming")
	}
	if ifs, ok := c["interfaces"].([]any); ok && len(ifs) > 0 {
		var n []string
		for _, i := range ifs {
			if s, ok := i.(string); ok {
				n = append(n, clip(s, 20))
			}
		}
		lines = append(lines, "exchanges state over: "+strings.Join(n, ", "))
	}
	if ss, ok := c["ssid_list"].([]any); ok && len(ss) > 0 {
		lines = append(lines, fmt.Sprintf("steering limited to %s", plural(len(ss), "SSID")))
	} else {
		lines = append(lines, "steering applies to every SSID")
	}
	return lines
}

// usteerNodes lists the local access point interfaces usteer tracks, from whichever of the common
// fields are present.
func usteerNodes(local map[string]any) []string {
	if len(local) == 0 {
		return []string{"local nodes: none (no hostapd interface is up)"}
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("local nodes (%d):", len(local)))
	for i, name := range sortedKeys(local) {
		if i == maxRoamNodes {
			lines = append(lines, fmt.Sprintf("  ... %d more not shown", len(local)-maxRoamNodes))
			break
		}
		n, _ := local[name].(map[string]any)
		var f []string
		if s, ok := n["ssid"].(string); ok {
			f = append(f, fmt.Sprintf("ssid %q", clip(s, 32)))
		}
		if v, ok := jnum(n, "freq"); ok {
			f = append(f, fmt.Sprintf("%.0f MHz", v))
		}
		if v, ok := jnum(n, "n_assoc"); ok {
			f = append(f, plural(int(v), "client"))
		}
		if v, ok := jnum(n, "load"); ok {
			f = append(f, fmt.Sprintf("load %.0f%%", v))
		}
		lines = append(lines, "  "+clip(name, 24)+pick(len(f) > 0, ": "+strings.Join(f, ", "), ""))
	}
	return lines
}

// ---------------------------------------------------------------- DAWN

// firstSection is the name of the first section of a type, "" if there is none. `uci show` names
// an unnamed section @type[0], and tree.get takes the name as shown.
func firstSection(t *uciTree, typ string) string {
	if s := t.sectionsOfType(typ); len(s) > 0 {
		return s[0]
	}
	return ""
}

const dawnDefaultKey = "Niiiiiiiiiiiiick" // the key and IV the package ships with

var dawnNetworkOption = map[string]string{"0": "broadcast", "1": "multicast", "2": "TCP with umdns discovery", "3": "TCP"}

func readDAWN(ctx context.Context) string {
	lines := []string{running(ctx, "dawn")}
	if tree, err := uciShow(ctx, "dawn", false); err == nil {
		net := firstSection(tree, "network")
		opt := tree.get(net, "network_option")
		name, known := dawnNetworkOption[opt]
		if !known {
			name = "option " + clip(opt, 6)
		}
		lines = append(lines, "AP discovery: "+name)
		if uciFlag(tree.get(net, "use_symm_enc"), false) {
			w := "traffic between APs is encrypted"
			if tree.get(net, "shared_key") == dawnDefaultKey {
				w += " with the key the package ships with, which everyone knows: set your own shared_key and iv"
			}
			lines = append(lines, w)
		} else {
			lines = append(lines, "traffic between APs is not encrypted (use_symm_enc off)")
		}
		lines = append(lines, "kicking mode "+orDefault(clip(tree.get("global", "kicking"), 4), "(default)")+" (0 = off), station-count scoring "+pick(uciFlag(tree.get("global", "use_station_count"), false), "on", "off"))
	} else {
		lines = append(lines, "dawn config unreadable: "+clip(err.Error(), 120))
	}
	if out, err := run(ctx, defaultCmdTimeout, "ubus", "list", "hostapd.*"); err == nil {
		lines = append(lines, plural(len(strings.Fields(out)), "hostapd interface")+" on ubus")
	} else {
		lines = append(lines, "no hostapd interface on ubus: dawn has no access point to manage (Wi-Fi is down, or wpad is not running)")
	}
	for _, c := range []struct{ method, what string }{{"get_network", "network view"}, {"get_hearing_map", "hearing map"}} {
		if m, err := ubusMap(ctx, "dawn", c.method); err == nil {
			lines = append(lines, fmt.Sprintf("%s: %d %s", c.what, len(m), pick(len(m) == 1, "entry", "entries")))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- openNDS

func readOpenNDS(ctx context.Context) string {
	lines := []string{running(ctx, "opennds")}
	out, err := run(ctx, 10*time.Second, "ndsctl", "status")
	if err != nil {
		lines = append(lines, "ndsctl does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 120))
	} else {
		lines = append(lines, openNDSStatus(out)...)
	}
	if tree, terr := uciShow(ctx, "opennds", false); terr == nil {
		if secs := tree.sectionsOfType("opennds"); len(secs) > 0 {
			s := secs[0]
			lines = append(lines, "config: "+pick(uciFlag(tree.get(s, "enabled"), true), "enabled", "disabled")+", FAS key "+pick(tree.get(s, "faskey") != "", "set (not shown)", "not set"))
		}
	}
	return strings.Join(lines, "\n")
}

// openNDSStatus picks the useful lines out of `ndsctl status` (plain "Key: value" lines). The
// trusted MAC list, the walled garden and the client table are left out.
func openNDSStatus(out string) []string {
	kv := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, ": "); ok {
			if _, seen := kv[k]; !seen {
				kv[k] = strings.TrimSpace(v)
			}
		}
	}
	if kv["Version"] == "" && kv["Current clients"] == "" {
		return []string{"output not recognised: no version or client count in ndsctl status"}
	}
	var lines []string
	lines = append(lines, "version "+clip(kv["Version"], 20)+", up "+clip(kv["Uptime"], 20)+", managing "+clip(kv["Managed interface"], 20))
	lines = append(lines, "clients now: "+clip(kv["Current clients"], 8)+", authenticated since start: "+clip(kv["Client authentications since start"], 8))
	if fas := kv["FAS"]; fas != "" {
		lines = append(lines, "FAS: "+clip(fasSummary(fas), 100))
	}
	lines = append(lines, "idle timeout: preauthenticated "+clip(kv["Preauthenticated Client Idle Timeout"], 12)+", authenticated "+clip(kv["Authenticated Client Idle Timeout"], 12))
	if b := kv["Binauth Script"]; b != "" {
		lines = append(lines, "binauth script: "+clip(b, 60))
	}
	return lines
}

// fasSummary keeps the secure level and the host of the FAS URL; the path and query can carry a token.
func fasSummary(v string) string {
	level, url, ok := strings.Cut(v, ", URL: ")
	if !ok {
		return v
	}
	return level + ", host " + hostOnly(url)
}
