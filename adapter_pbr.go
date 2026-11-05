package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
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
