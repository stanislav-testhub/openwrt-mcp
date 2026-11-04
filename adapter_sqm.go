package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// sqm-scripts shapes a WAN link with cake or fq_codel. The config says what was asked for; the
// live counters from `tc -s qdisc` say whether it is in force and doing work. Software flow
// offloading moves established flows past the qdisc, so with it on the shaper sees little.

var (
	reTcSent    = regexp.MustCompile(`Sent (\d+) bytes (\d+) pkt \(dropped (\d+), overlimits (\d+)`)
	reTcBacklog = regexp.MustCompile(`backlog (\d+)b (\d+)p`)
	reTcQdisc   = regexp.MustCompile(`^qdisc (\S+) \S+ `)
)

const sqmMaxQueues = 8

func readSQM(ctx context.Context) string {
	tree, err := uciShow(ctx, "sqm", false)
	if err != nil {
		return "sqm config unreadable: " + clip(err.Error(), 160)
	}
	secs := tree.sectionsOfType("queue")
	if len(secs) == 0 {
		return "queues (0)"
	}
	lines := []string{fmt.Sprintf("queues (%d):", len(secs))}
	anyOn := false
	for i, s := range secs {
		if i == sqmMaxQueues {
			lines = append(lines, fmt.Sprintf("... %d more queues not shown", len(secs)-sqmMaxQueues))
			break
		}
		on := uciFlag(tree.get(s, "enabled"), false)
		anyOn = anyOn || on
		lines = append(lines, sqmQueue(ctx, tree, s, on)...)
	}
	if anyOn {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "firewall.@defaults[0].flow_offloading"); err == nil && strings.TrimSpace(out) == "1" {
			lines = append(lines, "WARNING: software flow offloading is on: offloaded flows bypass the shaper, so rates are not enforced for them")
		}
	}
	return strings.Join(lines, "\n")
}

func sqmQueue(ctx context.Context, t *uciTree, s string, on bool) []string {
	iface := t.get(s, "interface")
	script := clip(t.get(s, "script"), 30)
	if script == "" {
		script = "default script"
	}
	head := fmt.Sprintf("%s: %s, %s, down %s kbit/s, up %s kbit/s, %s %s", clip(s, 40), pick(on, "enabled", "disabled"), clip(iface, 15),
		clip(t.get(s, "download"), 10), clip(t.get(s, "upload"), 10), clip(t.get(s, "qdisc"), 20), script)
	if !on || !ifaceName.MatchString(iface) {
		return []string{head}
	}
	out := []string{head}
	// Egress is shaped on the interface itself, ingress on its ifb4 mirror device.
	for _, c := range []struct{ dev, label string }{{iface, "upload"}, {"ifb4" + iface, "download"}} {
		if len(c.dev) > 15 {
			continue
		}
		txt, err := run(ctx, defaultCmdTimeout, "tc", "-s", "qdisc", "show", "dev", c.dev)
		if err != nil {
			out = append(out, fmt.Sprintf("  %s (%s): no qdisc statistics", c.label, c.dev))
			continue
		}
		out = append(out, "  "+c.label+" ("+c.dev+"): "+sqmCounters(txt))
	}
	return out
}

// sqmCounters summarises the root qdisc of `tc -s qdisc show dev X`: its kind, packets sent,
// drops and backlog.
func sqmCounters(text string) string {
	kind, sent := "", ""
	for _, l := range strings.Split(text, "\n") {
		if m := reTcQdisc.FindStringSubmatch(l); m != nil && kind == "" {
			kind = clip(m[1], 20)
		}
		if m := reTcSent.FindStringSubmatch(l); m != nil && sent == "" {
			sent = fmt.Sprintf("%s packets, %s dropped", m[2], m[3])
		}
		if m := reTcBacklog.FindStringSubmatch(l); m != nil && sent != "" && !strings.Contains(sent, "backlog") {
			sent += ", backlog " + m[2] + " packets"
		}
	}
	if kind == "" || sent == "" {
		return "output not recognised"
	}
	return kind + ", " + sent
}
