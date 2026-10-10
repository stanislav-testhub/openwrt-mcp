package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Cross-config references (ROADMAP 5.10): where a name is defined and which sections use it. A
// name is an interface, a firewall zone, a device, a radio, or an mwan3 member or policy. The
// search reads only the fields below, never an arbitrary value, so it cannot be used to look for
// a key or a password, and what it prints is the name the caller already gave.

// refSpec is one place a name lives. option "" means the section's own name (mwan3 names an
// interface section after the interface; a radio is the name of a wifi-device section).
type refSpec struct {
	config, typ, option, target string
	// alias: a value written "@lan" names the interface lan, not a device (netifd's alias interfaces).
	alias bool
}

// refDefs are the sections a name is defined by.
var refDefs = []refSpec{
	{config: "network", typ: "interface", target: "interface"},
	{config: "network", typ: "device", option: "name", target: "device"},
	{config: "firewall", typ: "zone", option: "name", target: "zone"},
	{config: "wireless", typ: "wifi-device", target: "radio"},
	{config: "mwan3", typ: "member", target: "member"},
	{config: "mwan3", typ: "policy", target: "policy"},
}

// refUses are the options that hold a name. A value may be a list or one space-separated option.
var refUses = []refSpec{
	{config: "network", typ: "interface", option: "device", target: "device", alias: true},
	{config: "network", typ: "interface", option: "ifname", target: "device", alias: true},
	{config: "network", typ: "interface", option: "tunlink", target: "interface"},
	{config: "network", typ: "device", option: "ports", target: "device"},
	{config: "network", typ: "device", option: "ifname", target: "device"},
	{config: "network", typ: "bridge-vlan", option: "device", target: "device"},
	{config: "network", typ: "route", option: "interface", target: "interface"},
	{config: "network", typ: "route6", option: "interface", target: "interface"},
	{config: "network", typ: "rule", option: "in", target: "interface"},
	{config: "network", typ: "rule", option: "out", target: "interface"},
	{config: "network", typ: "rule6", option: "in", target: "interface"},
	{config: "network", typ: "rule6", option: "out", target: "interface"},
	{config: "firewall", typ: "zone", option: "network", target: "interface"},
	{config: "firewall", typ: "zone", option: "device", target: "device"},
	{config: "firewall", typ: "rule", option: "src", target: "zone"},
	{config: "firewall", typ: "rule", option: "dest", target: "zone"},
	{config: "firewall", typ: "forwarding", option: "src", target: "zone"},
	{config: "firewall", typ: "forwarding", option: "dest", target: "zone"},
	{config: "firewall", typ: "redirect", option: "src", target: "zone"},
	{config: "firewall", typ: "redirect", option: "dest", target: "zone"},
	{config: "dhcp", typ: "dhcp", option: "interface", target: "interface"},
	{config: "dhcp", typ: "dnsmasq", option: "interface", target: "interface"},
	{config: "dhcp", typ: "dnsmasq", option: "notinterface", target: "interface"},
	{config: "wireless", typ: "wifi-iface", option: "network", target: "interface"},
	{config: "wireless", typ: "wifi-iface", option: "device", target: "radio"},
	{config: "wireless", typ: "wifi-vlan", option: "network", target: "interface"},
	{config: "sqm", typ: "queue", option: "interface", target: "device"},
	{config: "mwan3", typ: "interface", target: "interface"},
	{config: "mwan3", typ: "member", option: "interface", target: "interface"},
	{config: "mwan3", typ: "policy", option: "use_member", target: "member"},
	{config: "mwan3", typ: "rule", option: "use_policy", target: "policy"},
}

// refConfigs are the configs the search reads, in the order its hits come (within a config, in
// file order). Every config in the tables above must be listed here.
func refConfigs() []string {
	return []string{"network", "firewall", "dhcp", "wireless", "sqm", "mwan3"}
}

type refDef struct{ config, section, target string }

type refUse struct {
	config, section, typ, option, target string
	label                                string // the section's name option, if it has one
}

type refResult struct {
	defs []refDef
	uses []refUse
}

// findRefs looks for name in the parsed configs. A config that is not in trees is skipped.
func findRefs(trees map[string]*uciTree, name string) refResult {
	var r refResult
	for _, c := range refConfigs() {
		t := trees[c]
		if t == nil {
			continue
		}
		for _, sec := range t.order {
			for _, d := range refDefs {
				if d.config == c && d.typ == t.typ[sec] &&
					(d.option == "" && sec == name || d.option != "" && t.get(sec, d.option) == name) {
					r.defs = append(r.defs, refDef{c, sec, d.target})
				}
			}
			for _, u := range refUses {
				if u.config != c || u.typ != t.typ[sec] {
					continue
				}
				if target, ok := u.holds(t, sec, name); ok {
					r.uses = append(r.uses, refUse{c, sec, u.typ, u.option, target, t.get(sec, "name")})
				}
			}
		}
	}
	return r
}

// holds reports whether the field of this section names name, and what it names there.
func (u refSpec) holds(t *uciTree, sec, name string) (string, bool) {
	if u.option == "" {
		return u.target, sec == name
	}
	for _, v := range t.list(sec, u.option) {
		for _, w := range strings.Fields(v) {
			if u.alias && strings.HasPrefix(w, "@") {
				if w[1:] == name {
					return "interface", true
				}
			} else if w == name {
				return u.target, true
			}
		}
	}
	return "", false
}

// renderRefs prints what defines the name and what uses it. "defined as: nothing" is the
// answer to "does this exist?", so it is said in words.
func renderRefs(name string, r refResult, searched, absent []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "references to %q; searched %s", name, strings.Join(searched, ", "))
	if len(absent) > 0 {
		fmt.Fprintf(&b, "; not on this router: %s", strings.Join(absent, ", "))
	}
	b.WriteString("\n")
	if len(r.defs) == 0 {
		b.WriteString("defined as: nothing (no interface, zone, device, radio, member or policy has this name)\n")
	} else {
		fmt.Fprintf(&b, "defined as (%d):\n", len(r.defs))
		for _, d := range r.defs {
			fmt.Fprintf(&b, "  %s.%s: %s\n", d.config, d.section, d.target)
		}
	}
	if len(r.uses) == 0 {
		b.WriteString("used as: nowhere")
		return b.String()
	}
	fmt.Fprintf(&b, "used as (%d):\n", len(r.uses))
	for _, u := range r.uses {
		if u.option == "" {
			fmt.Fprintf(&b, "  %s.%s: %s\n", u.config, u.section, u.target)
			continue
		}
		what := u.typ
		if u.label != "" {
			what += fmt.Sprintf(" %q", u.label)
		}
		fmt.Fprintf(&b, "  %s.%s.%s: %s (%s)\n", u.config, u.section, u.option, u.target, what)
	}
	return strings.TrimRight(b.String(), "\n")
}

var reRefName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// uciRefs is uci_get with refs set. Its scope is "refs" whatever the name, so a grant on the
// configs it reads does not cover it.
func uciRefs(ctx context.Context, in uciGetIn) (string, string, error) {
	if in.Section != "" || in.Option != "" || in.History != "" {
		return "", "", invalid("refs searches every config: give no section, option or history (config only narrows the search)")
	}
	if !reRefName.MatchString(in.Refs) {
		return "", "", invalid("refs must be one name: letters, digits, '_', '-' and '.', at most 64 characters")
	}
	if in.Config != "" {
		if !reUCIConfig.MatchString(in.Config) {
			return "", "", invalid("bad config name")
		}
		if !contains(refConfigs(), in.Config) {
			return "", "", invalid("config %q holds no reference fields; refs searches %s", in.Config, strings.Join(refConfigs(), ", "))
		}
	}
	trees, searched, absent, err := loadRefTrees(ctx, in.Config, in.IDs)
	if err != nil {
		return "", "", err
	}
	if in.Config != "" && len(searched) == 0 {
		return "", "", notFound("no UCI config %q on this router", in.Config)
	}
	return renderRefs(in.Refs, findRefs(trees, in.Refs), searched, absent), "references to " + in.Refs, nil
}

// loadRefTrees reads the configs the search covers (only, when given). A config that is not
// installed is reported as absent; one that is installed and will not print is an error, because
// an empty answer would read as "nothing uses this".
func loadRefTrees(ctx context.Context, only string, ids bool) (trees map[string]*uciTree, searched, absent []string, err error) {
	trees = map[string]*uciTree{}
	for _, c := range refConfigs() {
		if only != "" && c != only {
			continue
		}
		if _, serr := os.Stat(filepath.Join(uciConfDir, c)); serr != nil {
			absent = append(absent, c)
			continue
		}
		t, err := uciShow(ctx, c, ids)
		if err != nil {
			return nil, nil, nil, err
		}
		trees[c] = t
		searched = append(searched, c)
	}
	return trees, searched, absent, nil
}
