package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// mwan3 balances or fails over between WAN interfaces. Its rpcd plugin (`ubus call mwan3
// status`) returns the tracking state per interface and the policies with their members, so
// no free-text `mwan3 status` output is parsed.

type mwan3Iface struct {
	Status   string `json:"status"`
	Enabled  bool   `json:"enabled"`
	Up       bool   `json:"up"`
	Tracking string `json:"tracking"`
	Online   int    `json:"online"`
	Score    int    `json:"score"`
	TrackIPs []struct {
		IP     string `json:"ip"`
		Status string `json:"status"`
	} `json:"track_ip"`
}

type mwan3Member struct {
	Interface string  `json:"interface"`
	Percent   float64 `json:"percent"`
}

func readMwan3(ctx context.Context) string {
	var ifs struct {
		Interfaces map[string]mwan3Iface `json:"interfaces"`
	}
	if err := runJSON(ctx, &ifs, "ubus", "call", "mwan3", "status", `{"section":"interfaces"}`); err != nil {
		return "mwan3 does not answer (is the mwan3 service running, and rpcd's mwan3 plugin installed?): " + clip(err.Error(), 160)
	}
	names := make([]string, 0, len(ifs.Interfaces))
	for n := range ifs.Interfaces {
		names = append(names, n)
	}
	sort.Strings(names)
	lines := []string{fmt.Sprintf("interfaces (%d):", len(names))}
	for _, n := range names {
		lines = append(lines, mwan3Line(n, ifs.Interfaces[n]))
	}
	var pol struct {
		Policies struct {
			V4 map[string][]mwan3Member `json:"ipv4"`
		} `json:"policies"`
	}
	if err := runJSON(ctx, &pol, "ubus", "call", "mwan3", "status", `{"section":"policies"}`); err != nil {
		return strings.Join(append(lines, "policies unreadable: "+clip(err.Error(), 120)), "\n")
	}
	return strings.Join(append(lines, mwan3Policies(pol.Policies.V4, ifs.Interfaces)...), "\n")
}

func mwan3Line(name string, i mwan3Iface) string {
	state := clip(i.Status, 20)
	if state == "" {
		state = "unknown"
	}
	parts := []string{state}
	if !i.Enabled {
		parts = append(parts, "disabled")
	}
	parts = append(parts, pick(i.Up, "link up", "link down"), "tracking "+clip(i.Tracking, 20))
	if n := len(i.TrackIPs); n > 0 {
		ok := 0
		for _, t := range i.TrackIPs {
			if t.Status == "up" {
				ok++
			}
		}
		parts = append(parts, fmt.Sprintf("%d of %d track IPs up", ok, n))
	}
	if i.Status == "online" && i.Online > 0 {
		parts = append(parts, "online for "+ageText(i.Online))
	}
	return "  " + clip(name, 40) + ": " + strings.Join(parts, ", ")
}

func mwan3Policies(pol map[string][]mwan3Member, ifs map[string]mwan3Iface) []string {
	names := make([]string, 0, len(pol))
	for n := range pol {
		names = append(names, n)
	}
	sort.Strings(names)
	lines := []string{fmt.Sprintf("policies (%d):", len(names))}
	for _, n := range names {
		var members []string
		online := 0
		for _, m := range pol[n] {
			members = append(members, fmt.Sprintf("%s %.0f%%", clip(m.Interface, 40), m.Percent))
			if ifs[m.Interface].Status == "online" {
				online++
			}
		}
		line := "  " + clip(n, 40) + ": " + strings.Join(members, ", ")
		if len(members) == 0 {
			line += "no active member"
		}
		if len(pol[n]) > 0 && online == 0 {
			line += "; WARNING: no member of this policy is online"
		}
		lines = append(lines, line)
	}
	return lines
}
