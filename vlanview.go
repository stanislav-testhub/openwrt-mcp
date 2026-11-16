package main

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

// uci_get view=vlan_matrix (ROADMAP 7.6): the bridge-vlan sections of /etc/config/network as a port by VLAN table,
// the shape a DSA switch is reasoned about in, with the mistakes that table makes visible listed under it.
//
// The flag syntax is the one OpenWrt documents for `list ports`: "lan1:t" is tagged, "lan1:u" untagged, a "*" marks
// the port's PVID (untagged ingress lands in that VLAN), and no flag means tagged. `option local` (default 1) says
// whether the bridge itself is a member, which is how the router's own address reaches a VLAN.

type vlanCell struct {
	untagged, pvid bool
}

func (c vlanCell) String() string {
	s := "T"
	if c.untagged {
		s = "U"
	}
	if c.pvid {
		s += "*"
	}
	return s
}

type vlanRow struct {
	id      int
	alias   string
	section string
	cells   map[string]vlanCell // port -> membership
	local   bool
}

func parseVLANPort(s string) (string, vlanCell) {
	port, flags, _ := strings.Cut(s, ":")
	return port, vlanCell{untagged: strings.Contains(flags, "u"), pvid: strings.Contains(flags, "*")}
}

// renderVLANMatrix builds the view from a parsed network config.
func renderVLANMatrix(t *uciTree) string {
	type bridge struct {
		rows  []*vlanRow
		ports []string // from the matching `device` section, in order
		known bool     // a `device` section names it
	}
	bridges := map[string]*bridge{}
	var names []string
	get := func(name string) *bridge {
		b := bridges[name]
		if b == nil {
			b = &bridge{}
			bridges[name] = b
			names = append(names, name)
		}
		return b
	}
	var warns []string
	first := func(sec, opt string) string {
		if v := t.opt[sec][opt]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	for _, sec := range t.order {
		if t.typ[sec] != "device" {
			continue
		}
		if name := first(sec, "name"); name != "" {
			b := get(name)
			b.known = true
			b.ports = append(b.ports, t.opt[sec]["ports"]...)
		}
	}
	for _, sec := range t.order {
		if t.typ[sec] != "bridge-vlan" {
			continue
		}
		dev := first(sec, "device")
		id, err := strconv.Atoi(first(sec, "vlan"))
		if dev == "" || err != nil || id < 1 || id > 4094 {
			warns = append(warns, sec+": needs option device and a vlan between 1 and 4094")
			continue
		}
		b := get(dev)
		row := &vlanRow{id: id, alias: first(sec, "alias"), section: sec, cells: map[string]vlanCell{}, local: first(sec, "local") != "0"}
		for _, p := range t.opt[sec]["ports"] {
			port, cell := parseVLANPort(p)
			if port == "" {
				continue
			}
			row.cells[port] = cell
		}
		b.rows = append(b.rows, row)
	}
	if len(names) == 0 || func() bool {
		for _, n := range names {
			if len(bridges[n].rows) > 0 {
				return false
			}
		}
		return true
	}() {
		return "no bridge-vlan sections in /etc/config/network: this router does not filter VLANs on a bridge (DSA).\n" +
			"A swconfig router keeps them in switch_vlan sections: uci_get config=network shows them."
	}

	var b strings.Builder
	sort.Strings(names)
	for _, name := range names {
		br := bridges[name]
		if len(br.rows) == 0 {
			continue
		}
		sort.SliceStable(br.rows, func(i, j int) bool { return br.rows[i].id < br.rows[j].id })
		// Columns: the bridge's own ports first, in config order, then any port only a VLAN names.
		cols := append([]string(nil), br.ports...)
		seen := map[string]bool{}
		for _, p := range cols {
			seen[p] = true
		}
		var extra []string
		for _, r := range br.rows {
			for p := range r.cells {
				if !seen[p] {
					seen[p] = true
					extra = append(extra, p)
				}
			}
		}
		sort.Strings(extra)
		cols = append(cols, extra...)
		if br.known {
			for _, p := range extra {
				warns = append(warns, name+": "+p+" is in a VLAN but is not a port of the bridge's device section")
			}
		} else {
			warns = append(warns, name+": no device section names this bridge, so its port list is only what the VLANs mention")
		}

		header := append([]string{"VLAN"}, cols...)
		header = append(header, "(bridge)")
		table := [][]string{header}
		pvids := map[string][]int{}
		ids := map[int]int{}
		for _, r := range br.rows {
			ids[r.id]++
			label := strconv.Itoa(r.id)
			if r.alias != "" {
				label += " " + r.alias
			}
			line := []string{label}
			for _, p := range cols {
				if c, ok := r.cells[p]; ok {
					line = append(line, c.String())
					if c.pvid {
						pvids[p] = append(pvids[p], r.id)
					}
				} else {
					line = append(line, "-")
				}
			}
			if r.local {
				line = append(line, "T")
			} else {
				line = append(line, "-")
			}
			table = append(table, line)
		}
		b.WriteString(name + "\n" + alignTable(table) + "\n")
		for id, n := range ids {
			if n > 1 {
				warns = append(warns, name+": VLAN "+strconv.Itoa(id)+" is defined in "+strconv.Itoa(n)+" bridge-vlan sections")
			}
		}
		for _, p := range cols {
			if len(pvids[p]) > 1 {
				var s []string
				for _, id := range pvids[p] {
					s = append(s, strconv.Itoa(id))
				}
				warns = append(warns, name+": "+p+" has a PVID in VLANs "+strings.Join(s, ", ")+"; a port has one")
			}
		}
	}
	b.WriteString("T tagged, U untagged, * PVID (untagged ingress lands here), - not a member; (bridge) is option local\n")
	sort.Strings(warns)
	for _, w := range warns {
		b.WriteString("warning: " + w + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// alignTable pads every column to its widest cell.
func alignTable(rows [][]string) string {
	w := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if len(c) > w[i] {
				w[i] = len(c)
			}
		}
	}
	var out []string
	for _, r := range rows {
		var cells []string
		for i, c := range r {
			cells = append(cells, c+strings.Repeat(" ", w[i]-len(c)))
		}
		out = append(out, strings.TrimRight(strings.Join(cells, "  "), " "))
	}
	return strings.Join(out, "\n")
}

func uciVLANView(ctx context.Context, in uciGetIn) (string, string, error) {
	if in.View != "vlan_matrix" {
		return "", "", invalid("unknown view %q: the only view is vlan_matrix", in.View)
	}
	if (in.Config != "" && in.Config != "network") || in.Section != "" || in.Option != "" || in.History != "" || in.Refs != "" {
		return "", "", invalid("view=vlan_matrix reads the network config as a whole: give no config other than network, and no section, option, history or refs")
	}
	t, err := uciShow(ctx, "network", false)
	if err != nil {
		return "", "", err
	}
	return renderVLANMatrix(t), "read network (vlan matrix)", nil
}
