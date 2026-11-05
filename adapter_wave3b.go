package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Wave 3, second batch: wifischedule, vnstat, hd-idle, keepalived, lldpd and nlbwmon. The
// first four read their UCI config; lldpd reads its neighbour table with one fixed command.
// Neighbour names are set by whoever owns the neighbouring device and are not printed.

func readWifiSchedule(ctx context.Context) string {
	lines := []string{"wifischedule: driven by cron entries it installs"}
	tree, err := uciShow(ctx, "wifi_schedule", false)
	if err != nil {
		return strings.Join(append(lines, "wifi_schedule config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines, "enabled in config: "+pick(uciFlag(tree.get("global", "enabled"), false), "yes", "no"))
	entries := tree.sectionsOfType("entry")
	lines = append(lines, fmt.Sprintf("schedules (%d):", len(entries)))
	for i, s := range entries {
		if i == maxShown {
			break
		}
		lines = append(lines, fmt.Sprintf("  %s: %s, days %s, on %s, off %s", clip(s, 30), pick(uciFlag(tree.get(s, "enabled"), false), "enabled", "disabled"),
			clip(strings.Join(tree.list(s, "daysofweek"), " "), 40), clip(tree.get(s, "starttime"), 8), clip(tree.get(s, "stoptime"), 8)))
	}
	return strings.Join(lines, "\n")
}

func readVnstat(ctx context.Context) string {
	lines := []string{running(ctx, "vnstatd")}
	tree, err := uciShow(ctx, "vnstat", false)
	if err != nil {
		return strings.Join(append(lines, "vnstat config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	var ifs []string
	for _, s := range tree.sectionsOfType("vnstat") {
		ifs = append(ifs, tree.list(s, "interface")...)
	}
	lines = append(lines, "tracked interfaces: "+pick(len(ifs) > 0, clip(strings.Join(ifs, ", "), 100), "none"))
	return strings.Join(lines, "\n")
}

func readHDIdle(ctx context.Context) string {
	lines := []string{running(ctx, "hd-idle")}
	tree, err := uciShow(ctx, "hd-idle", false)
	if err != nil {
		return strings.Join(append(lines, "hd-idle config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	for _, s := range tree.sectionsOfType("hd-idle") {
		disk := clip(tree.get(s, "disk"), 30)
		present := "present"
		name := strings.TrimPrefix(disk, "/dev/")
		switch {
		case disk == "":
			present = "no disk set"
		case !ifaceName.MatchString(name):
			present = "name not usable"
		default:
			if _, err := os.Stat(sysPath("/dev/" + name)); err != nil {
				present = "not present"
			}
		}
		lines = append(lines, fmt.Sprintf("  %s: %s, idle after %ss, %s", pick(disk != "", disk, "(none)"), pick(uciFlag(tree.get(s, "enabled"), false), "enabled", "disabled"),
			pick(tree.get(s, "idle_time_interval") != "", clip(tree.get(s, "idle_time_interval"), 8), "?"), present))
	}
	return strings.Join(lines, "\n")
}

func readKeepalived(ctx context.Context) string {
	lines := []string{running(ctx, "keepalived")}
	tree, err := uciShow(ctx, "keepalived", false)
	if err != nil {
		return strings.Join(append(lines, "keepalived config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	inst := tree.sectionsOfType("vrrp_instance")
	lines = append(lines, fmt.Sprintf("VRRP instances (%d):", len(inst)))
	for i, s := range inst {
		if i == maxShown {
			break
		}
		lines = append(lines, fmt.Sprintf("  %s: configured state %s, priority %s, interface %s, auth %s", clip(pick(tree.get(s, "name") != "", tree.get(s, "name"), s), 30),
			pick(tree.get(s, "state") != "", clip(tree.get(s, "state"), 10), "?"), pick(tree.get(s, "priority") != "", clip(tree.get(s, "priority"), 5), "?"),
			clip(tree.get(s, "interface"), 15), pick(tree.get(s, "auth_pass") != "", "set", "none")))
	}
	lines = append(lines, "the live master/backup state is not read here; logread with pattern=keepalived shows transitions")
	return strings.Join(lines, "\n")
}

func readLLDPD(ctx context.Context) string {
	lines := []string{running(ctx, "lldpd")}
	out, err := run(ctx, 15*time.Second, "lldpcli", "-f", "json", "show", "neighbors")
	if err != nil {
		return strings.Join(append(lines, "lldpcli does not answer: "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 100)), "\n")
	}
	var doc struct {
		LLDP struct {
			Interface json.RawMessage `json:"interface"`
		} `json:"lldp"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return strings.Join(append(lines, "neighbour output not recognised"), "\n")
	}
	// lldpcli prints an object keyed by port, or (newer versions) an array of such objects.
	var byPort map[string]json.RawMessage
	var list []map[string]json.RawMessage
	var ports []string
	if json.Unmarshal(doc.LLDP.Interface, &byPort) == nil {
		for k := range byPort {
			ports = append(ports, k)
		}
	} else if json.Unmarshal(doc.LLDP.Interface, &list) == nil {
		for _, m := range list {
			for k := range m {
				ports = append(ports, k)
			}
		}
	}
	sortStrings(ports)
	lines = append(lines, fmt.Sprintf("local ports with a neighbour (%d): %s", len(ports), clip(strings.Join(ports, ", "), 100)))
	return strings.Join(lines, "\n")
}

func readNlbwmon(ctx context.Context) string {
	lines := []string{running(ctx, "nlbwmon")}
	tree, err := uciShow(ctx, "nlbwmon", false)
	if err != nil {
		return strings.Join(append(lines, "nlbwmon config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	dir := nlbwDir(tree)
	where := "on flash or disk"
	if inRAM(dir) {
		where = "in RAM, lost on reboot"
	}
	lines = append(lines, "database: "+clip(dir, 60)+", "+where, "commit interval: "+pick(tree.get("@nlbwmon[0]", "commit_interval") != "", clip(tree.get("@nlbwmon[0]", "commit_interval"), 8), "24h"))
	return strings.Join(lines, "\n")
}

func nlbwDir(t *uciTree) string {
	if d := t.get("@nlbwmon[0]", "database_directory"); d != "" {
		return d
	}
	return "/var/lib/nlbwmon"
}
