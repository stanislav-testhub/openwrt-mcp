package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Query layer for the two routing add-ons (ROADMAP 9.1): "which of the operator's rules would
// steer this address, and where does that send it". It reads the uci rules only; it does not
// predict the kernel's decision (marks already set, the main table, VPN killswitches).

const maxRouteMatches = 10

// ipSpecMatch reports whether ip is selected by a uci address list (an option or list of
// addresses, CIDRs, `!`-negated entries, and for pbr/mwan3 also names, sets and MACs). unknown
// counts the entries that are not addresses: a lookup by IP cannot say whether those match.
func ipSpecMatch(values []string, ip net.IP) (match bool, unknown int) {
	var pos, neg []*net.IPNet
	for _, v := range values {
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
			negated := strings.HasPrefix(tok, "!")
			tok = strings.TrimPrefix(tok, "!")
			n := parseNet(tok)
			switch {
			case n == nil:
				unknown++
			case negated:
				neg = append(neg, n)
			default:
				pos = append(pos, n)
			}
		}
	}
	for _, n := range neg {
		if n.Contains(ip) {
			return false, unknown
		}
	}
	if len(pos) == 0 {
		return len(neg) > 0, unknown
	}
	for _, n := range pos {
		if n.Contains(ip) {
			return true, unknown
		}
	}
	return false, unknown
}

func parseNet(s string) *net.IPNet {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 128
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	return nil
}

func queryPBR(ctx context.Context, addr string) string {
	ip := net.ParseIP(addr)
	tree, err := uciShow(ctx, "pbr", false)
	if err != nil {
		return "pbr config unreadable: " + clip(err.Error(), 160)
	}
	var lines []string
	named := 0
	for _, p := range tree.sectionsOfType("policy") {
		srcOK, srcU := ipSpecMatch(tree.list(p, "src_addr"), ip)
		dstOK, dstU := ipSpecMatch(tree.list(p, "dest_addr"), ip)
		named += srcU + dstU
		var roles []string
		if srcOK {
			roles = append(roles, "src_addr")
		}
		if dstOK {
			roles = append(roles, "dest_addr")
		}
		if len(roles) == 0 {
			continue
		}
		if len(lines) == maxRouteMatches {
			lines = append(lines, "... more policies match, not shown")
			break
		}
		name := clip(tree.get(p, "name"), 40)
		if name == "" {
			name = clip(p, 40)
		}
		lines = append(lines, fmt.Sprintf("policy %s: %s contains %s, via %s%s%s", name, strings.Join(roles, " and "), addr,
			pick(tree.get(p, "interface") != "", clip(tree.get(p, "interface"), 30), "(no interface)"), policyScope(tree, p),
			pick(uciFlag(tree.get(p, "enabled"), true), "", ", disabled")))
	}
	if len(lines) == 0 {
		lines = append(lines, "no pbr policy lists "+addr+" in src_addr or dest_addr")
	}
	if named > 0 {
		lines = append(lines, fmt.Sprintf("not evaluated: %d policy entries that are names, sets or MACs, which an address lookup cannot match", named))
	}
	return strings.Join(lines, "\n")
}

func policyScope(t *uciTree, p string) string {
	var parts []string
	for _, k := range []string{"proto", "src_port", "dest_port"} {
		if v := clip(t.get(p, k), 30); v != "" {
			parts = append(parts, k+" "+v)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func queryMwan3(ctx context.Context, addr string) string {
	ip := net.ParseIP(addr)
	tree, err := uciShow(ctx, "mwan3", false)
	if err != nil {
		return "mwan3 config unreadable: " + clip(err.Error(), 160)
	}
	rules := tree.sectionsOfType("rule")
	var lines []string
	for _, role := range []struct{ key, label string }{{"dest_ip", "destination"}, {"src_ip", "source"}} {
		hit := ""
		for _, r := range rules {
			vals := tree.list(r, role.key)
			if len(vals) == 0 {
				continue
			}
			if ok, _ := ipSpecMatch(vals, ip); ok {
				hit = r
				break
			}
		}
		if hit == "" {
			continue
		}
		pol := clip(tree.get(hit, "use_policy"), 40)
		lines = append(lines, fmt.Sprintf("as %s: rule %s (%s %s%s) uses policy %s", role.label, clip(hit, 40), role.key, strings.Join(tree.list(hit, role.key), " "),
			ruleScope(tree, hit), pick(pol != "", pol, "(none)")))
		if pol != "" {
			if now := mwan3PolicyNow(ctx, pol); now != "" {
				lines = append(lines, "  members now: "+now)
			}
		}
	}
	if len(lines) == 0 {
		if hit := firstCatchAll(tree, rules); hit != "" {
			return fmt.Sprintf("no mwan3 rule names %s; the first rule without an address, %s, uses policy %s", addr, clip(hit, 40), clip(tree.get(hit, "use_policy"), 40))
		}
		return "no mwan3 rule names " + addr + " in dest_ip or src_ip; traffic not matched by a rule uses the main routing table"
	}
	if n := addresslessRules(tree, rules); n > 0 {
		lines = append(lines, fmt.Sprintf("not evaluated: %s without an address (port or protocol only), which could take this traffic first", plural(n, "rule")))
	}
	lines = append(lines, "rules are tried in file order; the first match per role is shown, ports and protocol are shown but not tested")
	return strings.Join(lines, "\n")
}

func ruleScope(t *uciTree, r string) string {
	var parts []string
	for _, k := range []string{"proto", "src_port", "dest_port", "sticky"} {
		if v := clip(t.get(r, k), 20); v != "" && !(k == "proto" && v == "all") && !(k == "sticky" && v == "0") {
			parts = append(parts, k+" "+v)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, ", ")
}

func firstCatchAll(t *uciTree, rules []string) string {
	for _, r := range rules {
		if len(t.list(r, "src_ip")) == 0 && len(t.list(r, "dest_ip")) == 0 && t.get(r, "ipset") == "" {
			return r
		}
	}
	return ""
}

// mwan3PolicyNow is the policy's members as mwan3 reports them, "" when it does not answer.
func mwan3PolicyNow(ctx context.Context, policy string) string {
	var pol struct {
		Policies struct {
			V4 map[string][]mwan3Member `json:"ipv4"`
		} `json:"policies"`
	}
	if err := runJSON(ctx, &pol, "ubus", "call", "mwan3", "status", `{"section":"policies"}`); err != nil {
		return ""
	}
	ms, ok := pol.Policies.V4[policy]
	if !ok {
		return ""
	}
	if len(ms) == 0 {
		return "none active"
	}
	var out []string
	for _, m := range ms {
		out = append(out, fmt.Sprintf("%s %.0f%%", clip(m.Interface, 40), m.Percent))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// addresslessRules counts the rules that select by port, protocol or ipset only.
func addresslessRules(t *uciTree, rules []string) int {
	n := 0
	for _, r := range rules {
		if len(t.list(r, "src_ip")) == 0 && len(t.list(r, "dest_ip")) == 0 {
			n++
		}
	}
	return n
}
