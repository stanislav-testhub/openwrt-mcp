package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Wave 2, second batch: strongSwan, cloudflared, frp (client and server) and the statistics
// collector. Tunnel tokens, setup keys, pre-shared keys and dashboard passwords are only ever
// reported as "set".

// ---------------------------------------------------------------- strongswan

func readStrongSwan(ctx context.Context) string {
	lines := []string{running(ctx, "charon")}
	out, err := run(ctx, 15*time.Second, "swanctl", "--list-sas")
	if err != nil {
		return strings.Join(append(lines, "swanctl does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 120)), "\n")
	}
	var sas []string
	ike, child := 0, 0
	cur := ""
	up := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		f := strings.Split(t, ", ")
		switch {
		case l != "" && l[0] != ' ' && len(f) >= 3 && strings.Contains(f[0], ": #"):
			name, _, _ := strings.Cut(f[0], ":")
			cur = clip(name, 32)
			up[name] = true
			if f[1] == "ESTABLISHED" {
				ike++
			}
			sas = append(sas, fmt.Sprintf("  %s: %s, %s", cur, clip(f[1], 14), clip(f[2], 8)))
		case strings.HasPrefix(t, "established ") && len(sas) > 0:
			sas[len(sas)-1] += ", up " + clip(strings.TrimPrefix(strings.SplitN(t, " ago", 2)[0], "established "), 20)
		case strings.Contains(t, ", INSTALLED") || strings.Contains(t, ", REKEYING"):
			if strings.Contains(t, ", INSTALLED") {
				child++
			}
			name, _, _ := strings.Cut(t, ":")
			sas = append(sas, fmt.Sprintf("    child %s: %s", clip(name, 32), clip(f[len(f)-3+0], 12)+" "+clip(f[len(f)-2], 12)))
		case (strings.HasPrefix(t, "in ") || strings.HasPrefix(t, "out ")) && len(f) >= 2 && len(sas) > 0:
			dir, _, _ := strings.Cut(t, " ")
			sas[len(sas)-1] += ", " + dir + " " + clip(strings.TrimSpace(strings.TrimSuffix(f[1], "bytes")), 14) + "B"
		}
	}
	lines = append(lines, fmt.Sprintf("IKE SAs established: %d", ike), fmt.Sprintf("child SAs installed: %d", child))
	if len(sas) > 0 {
		lines = append(lines, "SAs (peer names are chosen by the peer):")
		if len(sas) > 4*maxShown {
			sas = append(sas[:4*maxShown], "  ... more not shown")
		}
		lines = append(lines, sas...)
	}
	if conns, err := run(ctx, 15*time.Second, "swanctl", "--list-conns"); err == nil {
		var idle []string
		for _, l := range strings.Split(conns, "\n") {
			if name, rest, ok := strings.Cut(l, ": IKEv"); ok && l[0] != ' ' && rest != "" && !up[name] {
				idle = append(idle, clip(name, 32))
			}
		}
		if len(idle) > 0 {
			lines = append(lines, "configured but with no SA now: "+strings.Join(idle, ", "))
		}
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- cloudflared

func readCloudflared(ctx context.Context) string {
	lines := []string{running(ctx, "cloudflared")}
	tree, err := uciShow(ctx, "cloudflared", false)
	if err != nil {
		return strings.Join(append(lines, "cloudflared config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines,
		"enabled in config: "+pick(uciFlag(tree.get("config", "enabled"), false), "yes", "no"),
		"tunnel token: "+pick(tree.get("config", "token") != "", "set (not shown)", "not set"),
		"metrics address: "+pick(tree.get("config", "metrics") != "", clip(tree.get("config", "metrics"), 40), "not set"))
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- frp

func readFrpc(ctx context.Context) string {
	lines := []string{running(ctx, "frpc")}
	tree, err := uciShow(ctx, "frpc", false)
	if err != nil {
		return strings.Join(append(lines, "frpc config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	sec := frpCommon(tree)
	lines = append(lines,
		"server: "+pick(tree.get(sec, "server_addr") != "", hostOnly(tree.get(sec, "server_addr"))+":"+clip(tree.get(sec, "server_port"), 6), "not set"),
		"token: "+pick(tree.get(sec, "token") != "", "set (not shown)", "not set"))
	proxies := frpProxies(tree)
	lines = append(lines, fmt.Sprintf("proxies: %d", len(proxies)))
	for i, p := range proxies {
		if i == maxShown {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(proxies)-maxShown))
			break
		}
		// A proxy opens a local service to whoever reaches the server's remote port.
		parts := []string{clip(p, 30), clip(tree.get(p, "type"), 8)}
		if v := tree.get(p, "local_port"); v != "" {
			parts = append(parts, "local "+clip(tree.get(p, "local_ip"), 40)+":"+clip(v, 6))
		}
		if v := tree.get(p, "remote_port"); v != "" {
			parts = append(parts, "remote port "+clip(v, 6))
		}
		if v := tree.get(p, "custom_domains"); v != "" {
			parts = append(parts, "domain "+clip(v, 40))
		}
		lines = append(lines, "  "+strings.Join(parts, ", "))
	}
	return strings.Join(lines, "\n")
}

// frpCommon is the section the package writes as [common] (stock config: `config conf 'common'`);
// `main` is what an older note of ours assumed, kept as a fallback.
func frpCommon(t *uciTree) string {
	for _, s := range t.sectionsOfType("conf") {
		if s == "common" {
			return s
		}
	}
	return "main"
}

// frpProxies are the other `conf` sections: one proxy each.
func frpProxies(t *uciTree) []string {
	var out []string
	for _, s := range t.sectionsOfType("conf") {
		if s != "common" {
			out = append(out, s)
		}
	}
	return out
}

func readFrps(ctx context.Context) string {
	lines := []string{running(ctx, "frps")}
	tree, err := uciShow(ctx, "frps", false)
	if err != nil {
		return strings.Join(append(lines, "frps config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	sec := frpCommon(tree)
	lines = append(lines,
		"bind port: "+pick(tree.get(sec, "bind_port") != "", clip(tree.get(sec, "bind_port"), 6), "default"),
		"token: "+pick(tree.get(sec, "token") != "", "set (not shown)", "not set (any client may connect)"),
		"dashboard: "+pick(tree.get(sec, "dashboard_port") != "", "port "+clip(tree.get(sec, "dashboard_port"), 6)+", password "+pick(tree.get(sec, "dashboard_pwd") != "", "set", "not set"), "off"))
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- statistics (collectd)

func readStatistics(ctx context.Context) string {
	lines := []string{running(ctx, "collectd")}
	tree, err := uciShow(ctx, "luci_statistics", false)
	if err != nil {
		if _, rerr := readSys("/etc/config/luci_statistics"); errors.Is(rerr, os.ErrNotExist) {
			// collectd alone (no luci-app-statistics) is configured in /etc/collectd.conf.
			return strings.Join(append(lines, "no luci_statistics config: luci-app-statistics is not installed, so collectd uses /etc/collectd.conf (not read here)"), "\n")
		}
		return strings.Join(append(lines, "luci_statistics config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	dir := tree.get("collectd_rrdtool", "DataDir")
	if dir == "" {
		dir = "/tmp/rrd"
	}
	where := "on flash or disk"
	if inRAM(dir) {
		where = "in RAM, lost on reboot"
	}
	lines = append(lines, "data directory: "+clip(dir, 60)+", "+where)
	var plugins []string
	for sec := range tree.opt {
		if strings.HasPrefix(sec, "collectd_") && sec != "collectd_rrdtool" && uciFlag(tree.get(sec, "enable"), false) {
			plugins = append(plugins, strings.TrimPrefix(sec, "collectd_"))
		}
	}
	sortStrings(plugins)
	lines = append(lines, fmt.Sprintf("plugins enabled (%d): %s", len(plugins), clip(strings.Join(plugins, ", "), 200)))
	return strings.Join(lines, "\n")
}

func inRAM(dir string) bool {
	for _, p := range []string{"/tmp/", "/var/", "/dev/shm/", "/run/"} {
		if strings.HasPrefix(dir+"/", p) {
			return true
		}
	}
	return false
}
