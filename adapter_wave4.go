package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Wave 4 (best effort, ROADMAP 9.6): proxy and circumvention stacks from community feeds. They
// change fast and hold the most credentials (node links, subscription URLs, API secrets), so the
// adapters are status only: which processes run, whether the stack's nft table is loaded, a few
// fixed config flags, and how many nodes or subscriptions are configured. Names, links and
// secrets are never read into the output. Built from each project's documented layout, not run
// against the project; they are dropped rather than patched when upstream changes.

// reListenAddr is the shape of a listen address option (host:port, a bracketed IPv6 form): a value of
// another shape, a link or a path, is not printed.
var reListenAddr = regexp.MustCompile(`^[0-9A-Za-z._:\[\]-]{1,64}$`)

type stack struct {
	config  string      // UCI config name ("" if none is read)
	procs   []string    // process names that mean the stack runs
	tables  []string    // nft tables "family name" to look for
	chains  []string    // nft chains "family table chain" to look for (a stack that lives inside fw4)
	flags   [][3]string // section, option, label: printed as the raw short value
	counts  [][2]string // section type, label: how many such sections exist
	secrets [][3]string // section, option, label: printed as set / not set
	errLog  string      // the stack's own log: its last error lines explain why it stopped
}

// lastErrors returns the last "Error:" line of a stack's log and the last FATAL line before it, which
// carries the cause (homeproxy logs sing-box's refusal on its own line). Control characters are
// dropped; a log that is missing or has no such line adds nothing.
func lastErrors(path string) []string {
	text, err := readSys(path)
	if err != nil {
		return nil
	}
	var errLine, fatal string
	for _, l := range strings.Split(text, "\n") {
		l = strings.Map(func(r rune) rune {
			if r < ' ' && r != '\t' {
				return -1
			}
			return r
		}, l)
		if _, after, ok := strings.Cut(l, "Error: "); ok {
			errLine = after
		} else if _, after, ok := strings.Cut(l, "FATAL"); ok {
			if i := strings.Index(after, "] "); i >= 0 && i < 12 { // the colour codes and the "[0000]" time stamp
				after = after[i+2:]
			}
			fatal = strings.TrimSpace(after)
		}
	}
	var out []string
	if errLine != "" {
		out = append(out, "last error: "+clip(errLine, 120))
	}
	if fatal != "" {
		out = append(out, "sing-box said: "+clip(fatal, 200))
	}
	return out
}

func (st stack) read(ctx context.Context) string {
	var lines []string
	for _, p := range st.procs {
		lines = append(lines, running(ctx, p))
	}
	if st.errLog != "" {
		lines = append(lines, lastErrors(st.errLog)...)
	}
	for _, t := range st.tables {
		fam, name, _ := strings.Cut(t, " ")
		if _, err := run(ctx, defaultCmdTimeout, "nft", "list", "table", fam, name); err == nil {
			lines = append(lines, "nft table "+name+": loaded")
		} else {
			lines = append(lines, "nft table "+name+": not loaded")
		}
	}
	for _, c := range st.chains {
		f := strings.Fields(c)
		if len(f) != 3 {
			continue
		}
		if _, err := run(ctx, defaultCmdTimeout, "nft", "list", "chain", f[0], f[1], f[2]); err == nil {
			lines = append(lines, "nft chain "+f[2]+" in "+f[1]+": loaded")
		} else {
			lines = append(lines, "nft chain "+f[2]+" in "+f[1]+": not loaded")
		}
	}
	if st.config == "" {
		return strings.Join(lines, "\n")
	}
	tree, err := uciShow(ctx, st.config, false)
	if err != nil {
		return strings.Join(append(lines, st.config+" config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	for _, f := range st.flags {
		shape := reVersion
		if f[1] == "address" {
			shape = reListenAddr
		}
		if v := tree.get(f[0], f[1]); v != "" && shape.MatchString(v) {
			lines = append(lines, f[2]+": "+v)
		} else {
			lines = append(lines, f[2]+": not set")
		}
	}
	for _, c := range st.counts {
		lines = append(lines, fmt.Sprintf("%s: %d", c[1], len(tree.sectionsOfType(c[0]))))
	}
	for _, s := range st.secrets {
		lines = append(lines, s[2]+": "+pick(tree.get(s[0], s[1]) != "", "set (not shown)", "not set"))
	}
	return strings.Join(lines, "\n")
}

var wave4 = map[string]stack{
	"openclash":      {config: "openclash", procs: []string{"clash"}, flags: [][3]string{{"config", "enable", "enabled in config"}, {"config", "en_mode", "mode"}}, counts: [][2]string{{"config_subscribe", "subscriptions"}}, secrets: [][3]string{{"config", "dashboard_password", "dashboard secret"}}},
	"zapret":         {procs: []string{"nfqws", "tpws"}, tables: []string{"inet zapret"}},
	"v2raya":         {config: "v2raya", procs: []string{"v2raya"}, flags: [][3]string{{"config", "enabled", "enabled in config"}, {"config", "address", "API address"}}},
	"passwall":       {config: "passwall", procs: []string{"xray", "sing-box"}, tables: []string{"inet passwall"}, flags: [][3]string{{"@global[0]", "enabled", "enabled in config"}, {"@global[0]", "dns_mode", "DNS mode"}}, counts: [][2]string{{"nodes", "nodes"}, {"shunt_rules", "shunt rules"}}},
	"passwall2":      {config: "passwall2", procs: []string{"xray", "sing-box"}, tables: []string{"inet passwall2"}, flags: [][3]string{{"@global[0]", "enabled", "enabled in config"}, {"@global[0]", "remote_dns_protocol", "remote DNS protocol"}}, counts: [][2]string{{"nodes", "nodes"}, {"shunt_rules", "shunt rules"}}},
	"nikki":          {config: "nikki", procs: []string{"mihomo"}, tables: []string{"inet nikki"}, flags: [][3]string{{"config", "enabled", "enabled in config"}, {"proxy", "tcp_mode", "TCP mode"}}, counts: [][2]string{{"subscription", "subscriptions"}}},
	"youtubeUnblock": {config: "youtubeUnblock", procs: []string{"youtubeUnblock"}, chains: []string{"inet fw4 youtubeUnblock"}, flags: [][3]string{{"youtubeUnblock", "conf_strat", "config strategy"}, {"youtubeUnblock", "queue_num", "queue number"}, {"youtubeUnblock", "packet_mark", "packet mark"}}, counts: [][2]string{{"section", "sections"}}},
	"homeproxy":      {config: "homeproxy", procs: []string{"sing-box"}, errLog: "/var/run/homeproxy/homeproxy.log", flags: [][3]string{{"config", "routing_mode", "routing mode"}, {"dns", "dns_strategy", "DNS strategy"}}, counts: [][2]string{{"node", "nodes"}}},
}
