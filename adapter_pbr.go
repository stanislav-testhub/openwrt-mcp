package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// pbr (policy-based routing) steers chosen clients, domains or ports out of chosen interfaces
// with routing tables and fwmarks. It reports through procd service data: its gateways with
// their table, mark and priority, and error and warning codes. The policies' sources and
// destinations are the operator's own lists and are not printed; only their names and
// interfaces are.

const pbrMaxPolicies = 30

func readPBR(ctx context.Context) string {
	found, running, data := procdData(ctx, "pbr")
	var lines []string
	switch {
	case !found:
		lines = append(lines, "pbr: not registered with procd (stopped, or disabled)")
	case running:
		lines = append(lines, "pbr: service running")
	default:
		lines = append(lines, "pbr: registered, no running instance")
	}
	lines = append(lines, pbrGateways(data)...)
	if e := dataCodes(data, "errors"); len(e) > 0 {
		lines = append(lines, "errors: "+strings.Join(e, ", "))
	}
	if w := dataCodes(data, "warnings"); len(w) > 0 {
		lines = append(lines, "warnings: "+strings.Join(w, ", "))
	}
	if found {
		if out, err := run(ctx, defaultCmdTimeout, "ip", "-4", "rule", "show"); err == nil {
			lines = append(lines, pbrMwan3Warnings(out)...)
		}
	}
	tree, err := uciShow(ctx, "pbr", false)
	if err != nil {
		return strings.Join(append(lines, "pbr config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	var unknown map[string]bool // set only when pbr itself said a policy names an interface it has no gateway for
	if slices.Contains(dataCodes(data, "errors"), "errorPolicyUnknownInterface") {
		unknown = map[string]bool{"ignore": true}
		for _, g := range pbrGatewayNames(data) {
			unknown[g] = true
		}
	}
	return strings.Join(append(lines, pbrConfig(tree, unknown)...), "\n")
}

// pbrGatewayNames are the interfaces pbr built a routing table for.
func pbrGatewayNames(data map[string]json.RawMessage) []string {
	var gws []struct {
		Name string `json:"name"`
	}
	var names []string
	if raw, ok := data["gateways"]; ok && json.Unmarshal(raw, &gws) == nil {
		for _, g := range gws {
			names = append(names, g.Name)
		}
	}
	return names
}

func pbrGateways(data map[string]json.RawMessage) []string {
	var gws []struct {
		Name     string `json:"name"`
		Default  bool   `json:"default"`
		Action   string `json:"action"`
		Table    string `json:"table_id"`
		Mark     string `json:"mark"`
		Priority string `json:"priority"`
	}
	raw, ok := data["gateways"]
	if !ok || json.Unmarshal(raw, &gws) != nil || len(gws) == 0 {
		return nil
	}
	lines := []string{fmt.Sprintf("gateways (%d):", len(gws))}
	for _, g := range gws {
		lines = append(lines, fmt.Sprintf("  %s: table %s, mark %s, priority %s, %s%s", clip(g.Name, 40), clip(g.Table, 10), clip(g.Mark, 12), clip(g.Priority, 8),
			clip(g.Action, 20), pick(g.Default, ", default route", "")))
	}
	return lines
}

func pbrConfig(t *uciTree, known map[string]bool) []string {
	on := uciFlag(t.get("config", "enabled"), false)
	parts := []string{pick(on, "enabled", "disabled")}
	if v := clip(t.get("config", "resolver_set"), 30); v != "" {
		parts = append(parts, "resolver set "+v)
	}
	if v := clip(t.get("config", "fw_mask"), 12); v != "" {
		parts = append(parts, "fw mask "+v)
	}
	if uciFlag(t.get("config", "strict_enforcement"), true) {
		parts = append(parts, "strict enforcement")
	}
	lines := []string{"settings: " + strings.Join(parts, ", ")}
	pols := t.sectionsOfType("policy")
	if len(pols) == 0 {
		return append(lines, "policies (0)")
	}
	lines = append(lines, fmt.Sprintf("policies (%d):", len(pols)))
	for i, p := range pols {
		if i == pbrMaxPolicies {
			lines = append(lines, fmt.Sprintf("... %d more policies not shown", len(pols)-pbrMaxPolicies))
			break
		}
		name := clip(t.get(p, "name"), 40)
		if name == "" {
			name = clip(p, 40)
		}
		on := uciFlag(t.get(p, "enabled"), true)
		iface := t.get(p, "interface")
		note := ""
		if known != nil && on && iface != "" && !known[iface] {
			note = ", NOTE: pbr has no gateway for this interface, so the policy is not applied"
		}
		lines = append(lines, fmt.Sprintf("  %s: via %s%s%s", name, pick(iface != "", clip(iface, 30), "(no interface)"), pick(on, "", ", disabled"), note))
	}
	return lines
}

var (
	pbrTableRule   = regexp.MustCompile(`^(\d+):\s+from all fwmark \S+ lookup pbr_`)
	numTableRule   = regexp.MustCompile(`^(\d+):\s+from all fwmark (0x[0-9a-fA-F]+)(?:/(0x[0-9a-fA-F]+))? lookup (\d+)\s*$`)
	discardingRule = regexp.MustCompile(`^\d+:\s+from all fwmark \S+ (blackhole|unreachable)`)
)

// pbrMwan3Warnings: mwan3 and pbr both steer by fwmark, and the kernel takes the first matching
// rule. mwan3's rules (priorities 1001-3999, numbered tables, plus its blackhole and unreachable
// rules) come before pbr's at 29997 and up, so traffic mwan3 marks never reaches a pbr table.
// Seen on 25.12.6: a policy sending a client out of wan2 left through wan until mwan3 was stopped.
func pbrMwan3Warnings(rules string) []string {
	first, last := 0, 0 // lowest priority of a pbr table rule; highest priority of an mwan3-style rule before it
	discards := false
	var mine []int
	for _, l := range strings.Split(rules, "\n") {
		if m := pbrTableRule.FindStringSubmatch(l); m != nil {
			if n, _ := strconv.Atoi(m[1]); first == 0 || n < first {
				first = n
			}
		}
		if discardingRule.MatchString(l) {
			discards = true
		}
		if m := numTableRule.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			mine = append(mine, n)
		}
	}
	if first == 0 || !discards {
		return nil
	}
	for _, n := range mine {
		if n < first && n > last {
			last = n
		}
	}
	if last == 0 {
		return nil
	}
	return []string{fmt.Sprintf("WARNING: mwan3 is active too: its fwmark rules (priority up to %d) are checked before pbr's (from %d), so traffic mwan3 marks is routed by mwan3 and a pbr policy for it has no effect. Use one of the two, or give the traffic to mwan3 policies.", last, first)}
}
