package main

import (
	"context"
	"fmt"
	"strings"
)

// client_access (roadmap 6.3) turns "stop this device reaching the internet" into the fw4 rules
// that do it, and runs them through the normal rollback-armed uci_apply.
//
// What it writes, for one device:
//
//	config rule 'mcpdev_aabbccddeeff_0'
//		option name 'mcp-block aa:bb:cc:dd:ee:ff'
//		option src 'lan'
//		option src_mac 'aa:bb:cc:dd:ee:ff'
//		option dest 'wan'
//		option target 'REJECT'
//		option start_time '22:00:00'   (schedule only)
//		option stop_time '23:59:59'
//		option weekdays 'Mon Fri'
//
// Every section it owns is named mcpdev_<12 hex digits>_<n>: the MAC is fixed width, so the prefix
// of one device can never match another's, and a re-run or an allow finds exactly its own rules
// and nothing else. A rule it did not write is never touched.
//
// The rule has a dest, so it filters forwarded traffic only: the device keeps its LAN, DHCP and
// DNS and can still reach the router. That is "internet off", not "unplugged".

type clientAccessIn struct {
	Action  string   `json:"action" jsonschema:"block | schedule (blocked from..until) | allow (remove this tool's rules)"`
	MAC     string   `json:"mac" jsonschema:"aa:bb:cc:dd:ee:ff, from network_clients"`
	Zone    string   `json:"zone,omitempty" jsonschema:"the device's firewall zone (default lan)"`
	From    string   `json:"from,omitempty" jsonschema:"schedule: HH:MM, router local time"`
	Until   string   `json:"until,omitempty" jsonschema:"schedule: HH:MM; earlier than from runs past midnight"`
	Days    []string `json:"days,omitempty" jsonschema:"schedule: mon..sun the window starts on (default all)"`
	DryRun  bool     `json:"dry_run,omitempty" jsonschema:"show the change, then revert"`
	Timeout int      `json:"timeout,omitempty" jsonschema:"rollback seconds (default 90, max 600)"`
}

var weekdays = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

func parseHHMM(s string) (string, error) {
	var h, m int
	if len(s) != 5 || s[2] != ':' {
		return "", invalid("bad time %q: use 24-hour HH:MM", s)
	}
	if _, err := fmt.Sscanf(s, "%02d:%02d", &h, &m); err != nil || h > 23 || m > 59 {
		return "", invalid("bad time %q: use 24-hour HH:MM", s)
	}
	return s + ":00", nil
}

func normMAC(s string) string { return strings.ToLower(s) }

func (in clientAccessIn) validate() error {
	if !isMAC(in.MAC) {
		return invalid("mac must look like aa:bb:cc:dd:ee:ff")
	}
	if b := normMAC(in.MAC); b == "00:00:00:00:00:00" || b == "ff:ff:ff:ff:ff:ff" || strings.ContainsAny(b[1:2], "13579bdf") {
		return invalid("%s is not a device address (zero, broadcast or multicast)", in.MAC)
	}
	if in.Zone != "" && !reUCIType.MatchString(in.Zone) {
		return invalid("bad zone name %q", in.Zone)
	}
	switch in.Action {
	case "block", "allow":
		if in.From != "" || in.Until != "" || len(in.Days) > 0 {
			return invalid("from, until and days belong to action=schedule")
		}
	case "schedule":
		if in.From == "" || in.Until == "" {
			return invalid("schedule needs from and until, e.g. from 22:00 until 06:00")
		}
		if in.From == in.Until {
			return invalid("from and until are the same time: the window is empty")
		}
		if _, err := parseHHMM(in.From); err != nil {
			return err
		}
		if _, err := parseHHMM(in.Until); err != nil {
			return err
		}
		for _, d := range in.Days {
			if dayIndex(d) < 0 {
				return invalid("bad day %q: use mon, tue, wed, thu, fri, sat, sun", d)
			}
		}
	default:
		return invalid("action must be block, schedule or allow")
	}
	return nil
}

func dayIndex(d string) int {
	for i, w := range weekdays {
		if strings.EqualFold(d, w) {
			return i
		}
	}
	return -1
}

func clientAccessScope(in clientAccessIn) []string { return []string{"client." + normMAC(in.MAC)} }

// accessPrefix is the section-name prefix of one device's rules.
func accessPrefix(mac string) string {
	return "mcpdev_" + strings.ReplaceAll(normMAC(mac), ":", "") + "_"
}

// accessChanges is the whole compile step, free of the router: the existing section names it
// should clear first, and the input, give the changes to apply. Golden-tested.
func accessChanges(in clientAccessIn, existing []string) ([]UCIChange, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	prefix := accessPrefix(in.MAC)
	var out []UCIChange
	for _, sec := range existing {
		// Exactly prefix + digits: nothing else is ours to delete.
		if n, ok := strings.CutPrefix(sec, prefix); ok && n != "" && strings.Trim(n, "0123456789") == "" {
			out = append(out, UCIChange{Config: "firewall", Section: sec, Delete: true})
		}
	}
	if in.Action == "allow" {
		if len(out) == 0 {
			return nil, notFound("no client_access rule for %s: nothing to allow", normMAC(in.MAC))
		}
		return out, nil
	}
	zone, dest := in.Zone, "wan"
	if zone == "" {
		zone = "lan"
	}
	type window struct {
		from, to string
		days     []string
	}
	wins := []window{{}}
	label := "mcp-block " + normMAC(in.MAC)
	if in.Action == "schedule" {
		from, _ := parseHHMM(in.From)
		until, _ := parseHHMM(in.Until)
		var days []string
		for _, d := range in.Days {
			days = append(days, weekdays[dayIndex(d)])
		}
		label = "mcp-schedule " + normMAC(in.MAC)
		if until > from {
			wins = []window{{from, until, days}}
		} else {
			// Past midnight: the evening part, and the morning part on the following days.
			var next []string
			for _, d := range days {
				next = append(next, weekdays[(dayIndex(d)+1)%7])
			}
			wins = []window{{from, "23:59:59", days}, {"00:00:00", until, next}}
		}
	}
	for i, w := range wins {
		sec := fmt.Sprintf("%s%d", prefix, i)
		out = append(out,
			UCIChange{Config: "firewall", Section: sec, Type: "rule"},
			UCIChange{Config: "firewall", Section: sec, Option: "name", Value: label},
			UCIChange{Config: "firewall", Section: sec, Option: "src", Value: zone},
			UCIChange{Config: "firewall", Section: sec, Option: "src_mac", Value: normMAC(in.MAC)},
			UCIChange{Config: "firewall", Section: sec, Option: "dest", Value: dest},
			UCIChange{Config: "firewall", Section: sec, Option: "target", Value: "REJECT"})
		if w.from != "" {
			out = append(out,
				UCIChange{Config: "firewall", Section: sec, Option: "start_time", Value: w.from},
				UCIChange{Config: "firewall", Section: sec, Option: "stop_time", Value: w.to})
		}
		if len(w.days) > 0 {
			out = append(out, UCIChange{Config: "firewall", Section: sec, Option: "weekdays", Value: strings.Join(w.days, " ")})
		}
	}
	return out, nil
}

func (s *Server) clientAccess(ctx context.Context, client string, in clientAccessIn) (string, string, error) {
	if err := in.validate(); err != nil {
		return "", "", err
	}
	t, err := uciShow(ctx, "firewall", false)
	if err != nil {
		return "", "", err
	}
	var existing []string
	for _, sec := range t.sectionsOfType("rule") {
		if strings.HasPrefix(sec, "mcpdev_") {
			existing = append(existing, sec)
		}
	}
	changes, err := accessChanges(in, existing)
	if err != nil {
		return "", "", err
	}
	return s.uciApply(ctx, client, uciApplyIn{Changes: changes, DryRun: in.DryRun, Timeout: in.Timeout})
}
