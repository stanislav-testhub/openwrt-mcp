package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	return strings.Join(append(lines, pbrConfig(tree)...), "\n")
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

func pbrConfig(t *uciTree) []string {
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
		lines = append(lines, fmt.Sprintf("  %s: via %s%s", name, pick(t.get(p, "interface") != "", clip(t.get(p, "interface"), 30), "(no interface)"),
			pick(uciFlag(t.get(p, "enabled"), true), "", ", disabled")))
	}
	return lines
}
