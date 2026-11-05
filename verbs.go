package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Adapter verbs (ROADMAP 9.1, layer L3): `service_control name=<svc> action=<verb> [arg=<value>]`
// for the few operations an add-on offers beyond start/stop/reload. A verb is a fixed name with a
// risk class and an argument kind; its argv is built by code, and the argument is validated by its
// kind (and, for names, against the add-on's own config) before anything runs.
//
// Risk classes decide who may call it. `routine` verbs (refresh a list, remove one ban) are in the
// @operator preset. `disruptive` verbs (stop filtering, take an uplink down) are not: the preset
// lists verb scopes explicitly, so a disruptive one needs a grant that names it.

type adapterVerb struct {
	service, name string
	disruptive    bool
	arg           string // "" (none), "ip" or "iface"
	run           func(ctx context.Context, arg string) (string, error)
}

func initScript(service, verb string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, _ string) (string, error) {
		out, err := run(ctx, defaultCmdTimeout*6, "/etc/init.d/"+service, verb)
		return out, err
	}
}

var adapterVerbs = []adapterVerb{
	{"adblock", "refresh", false, "", initScript("adblock", "reload")},
	{"adblock", "suspend", true, "", initScript("adblock", "suspend")},
	{"adblock", "resume", true, "", initScript("adblock", "resume")},
	{"adblock-fast", "refresh", false, "", initScript("adblock-fast", "reload")},
	{"adblock-fast", "pause", true, "", initScript("adblock-fast", "pause")},
	{"adblock-fast", "resume", true, "", initScript("adblock-fast", "resume")},
	{"banip", "refresh", false, "", initScript("banip", "reload")},
	{"banip", "unban", false, "ip", banipUnban},
	{"mwan3", "ifup", true, "iface", mwan3Link("ifup")},
	{"mwan3", "ifdown", true, "iface", mwan3Link("ifdown")},
}

func verbFor(service, name string) (adapterVerb, bool) {
	for _, v := range adapterVerbs {
		if v.service == service && v.name == name {
			return v, true
		}
	}
	return adapterVerb{}, false
}

// routineVerbScopes are the service_control scopes of the routine verbs, for the @operator preset.
func routineVerbScopes() []string {
	var s []string
	for _, v := range adapterVerbs {
		if !v.disruptive {
			s = append(s, v.service+"."+v.name)
		}
	}
	sort.Strings(s)
	return s
}

func verbNames(service string) string {
	var n []string
	for _, v := range adapterVerbs {
		if v.service == service {
			n = append(n, v.name)
		}
	}
	return strings.Join(n, ", ")
}

// runVerb validates the argument by its kind and runs the verb.
func runVerb(ctx context.Context, v adapterVerb, arg string) (string, string, error) {
	switch v.arg {
	case "":
		if arg != "" {
			return "", "", invalid("%s %s takes no arg", v.service, v.name)
		}
	case "ip":
		clean, err := cleanQuery("ip", arg)
		if err != nil {
			return "", "", invalid("arg: %v", err)
		}
		arg = clean
	case "iface":
		if !uciName.MatchString(arg) {
			return "", "", invalid("arg must be an interface name as mwan3 knows it")
		}
	}
	out, err := v.run(ctx, arg)
	label := v.service + " " + v.name + pick(arg != "", " "+arg, "")
	if err != nil {
		return clip(out, 400), "", fmt.Errorf("%s: %w", label, err)
	}
	return label + ": done. " + clip(strings.TrimSpace(out), 400) + "\nCheck the result with service_list detail=" + v.service + ".", label, nil
}

// banipUnban deletes the address from every active set that holds it, then reads back. A feed
// refresh will put it back if a feed still lists it; the allowlist is the lasting answer.
func banipUnban(ctx context.Context, ip string) (string, error) {
	m, err := readRuntime(banipRuntime)
	if err != nil {
		return "", fmt.Errorf("banIP has not run since boot (no runtime file)")
	}
	hits, _, _ := banipSetsHolding(ctx, m, ip)
	if len(hits) == 0 {
		return "", fmt.Errorf("%s is not in any active banIP set, nothing to remove", ip)
	}
	for _, set := range hits {
		if _, err := run(ctx, defaultCmdTimeout, "nft", "delete", "element", "inet", "banIP", set, "{ "+ip+" }"); err != nil {
			return "", fmt.Errorf("removing %s from %s: %w", ip, set, err)
		}
	}
	if left, _, _ := banipSetsHolding(ctx, m, ip); len(left) > 0 {
		return "", fmt.Errorf("%s is still in %s after the delete", ip, strings.Join(left, ", "))
	}
	return "removed from " + strings.Join(hits, ", ") + ". The next feed refresh adds it back if a feed lists it.", nil
}

// mwan3Link brings an mwan3 interface up or down. The name must be an interface in mwan3's config.
func mwan3Link(verb string) func(context.Context, string) (string, error) {
	return func(ctx context.Context, iface string) (string, error) {
		t, err := uciShow(ctx, "mwan3", false)
		if err != nil {
			return "", fmt.Errorf("mwan3 config unreadable: %w", err)
		}
		known := false
		for _, s := range t.sectionsOfType("interface") {
			known = known || s == iface
		}
		if !known {
			return "", fmt.Errorf("%q is not an interface in the mwan3 config", iface)
		}
		return run(ctx, defaultCmdTimeout, "mwan3", verb, iface)
	}
}

// verbLine is the last line of a detail: what service_control can do for this add-on.
func verbLine(service string) string {
	var parts []string
	for _, v := range adapterVerbs {
		if v.service == service {
			p := v.name
			if v.arg != "" {
				p += " arg=" + v.arg
			}
			parts = append(parts, p+" ("+pick(v.disruptive, "disruptive, needs its own grant", "routine")+")")
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "\nservice_control verbs: " + strings.Join(parts, "; ")
}
