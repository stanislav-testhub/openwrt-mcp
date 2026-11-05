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
	ike, child := 0, 0
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(l, "ESTABLISHED"):
			ike++
		case strings.Contains(l, "INSTALLED"):
			child++
		}
	}
	return strings.Join(append(lines, fmt.Sprintf("IKE SAs established: %d", ike), fmt.Sprintf("child SAs installed: %d", child)), "\n")
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
	lines = append(lines,
		"server: "+pick(tree.get("main", "server_addr") != "", hostOnly(tree.get("main", "server_addr"))+":"+clip(tree.get("main", "server_port"), 6), "not set"),
		"token: "+pick(tree.get("main", "token") != "", "set (not shown)", "not set"),
		fmt.Sprintf("proxies: %d", len(tree.sectionsOfType("conf"))))
	return strings.Join(lines, "\n")
}

func readFrps(ctx context.Context) string {
	lines := []string{running(ctx, "frps")}
	tree, err := uciShow(ctx, "frps", false)
	if err != nil {
		return strings.Join(append(lines, "frps config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines,
		"bind port: "+pick(tree.get("main", "bind_port") != "", clip(tree.get("main", "bind_port"), 6), "default"),
		"token: "+pick(tree.get("main", "token") != "", "set (not shown)", "not set (any client may connect)"),
		"dashboard: "+pick(tree.get("main", "dashboard_port") != "", "port "+clip(tree.get("main", "dashboard_port"), 6)+", password "+pick(tree.get("main", "dashboard_pwd") != "", "set", "not set"), "off"))
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
