package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The exposure view (ROADMAP 4.3 tail): the other findings each name one thing that is open; this
// one answers "what can the internet reach, all in one place". It crosses the sockets that listen
// on every address (/proc/net) with the firewall rules and port forwards that face the WAN zones.
// It reads only; custom nft rules outside UCI and what an ISP or upstream NAT blocks are not seen,
// and the output says so.

const maxExposureItems = 12

type listener struct {
	proto string
	port  int
}

// anyAddressListeners reads the TCP and UDP sockets bound to the wildcard address from /proc/net.
func anyAddressListeners() ([]listener, error) {
	seen := map[listener]bool{}
	var out []listener
	readAny := false
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp", "0A"},
		{"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp", "07"},
	} {
		text, err := readSys(f.file)
		if err != nil {
			continue
		}
		readAny = true
		for i, line := range strings.Split(text, "\n") {
			fl := strings.Fields(line)
			if i == 0 || len(fl) < 4 || fl[3] != f.state {
				continue
			}
			addr, port, ok := strings.Cut(fl[1], ":")
			if !ok || strings.Trim(addr, "0") != "" {
				continue
			}
			if f.proto == "udp" && strings.Trim(strings.ReplaceAll(fl[2], ":", ""), "0") != "" {
				continue // a connected UDP socket, not a listener
			}
			n, err := strconv.ParseUint(port, 16, 16)
			if err != nil || n == 0 {
				continue
			}
			l := listener{f.proto, int(n)}
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	if !readAny {
		return nil, fmt.Errorf("/proc/net is not readable")
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].port != out[j].port {
			return out[i].port < out[j].port
		}
		return out[i].proto < out[j].proto
	})
	return out, nil
}

// wanAccept is one firewall rule that accepts traffic from a WAN zone to the router itself.
type wanAccept struct {
	protos []string
	ports  []string // empty: every port
	only   string   // source restriction, if any
	name   string
}

func (a wanAccept) covers(l listener) bool {
	if !contains(a.protos, l.proto) {
		return false
	}
	if len(a.ports) == 0 {
		return true
	}
	_, ok := anyPortCovered(a.ports, []int{l.port})
	return ok
}

func checkExposure(sn *snapshot) ([]finding, error) {
	fw, err := sn.getUCI("firewall")
	if err != nil {
		return nil, err
	}
	listeners, lerr := anyAddressListeners()
	if lerr != nil {
		sn.limit("exposure: " + lerr.Error() + ", so the open sockets are not listed")
	}
	wan := wanZoneSet(sn, fw)
	fromWan := func(sec string) bool {
		for _, s := range splitAll(fw.list(sec, "src")) {
			if s == "*" || wan[s] {
				return true
			}
		}
		return false
	}

	defaults := ""
	if ds := fw.sectionsOfType("defaults"); len(ds) > 0 {
		defaults = ds[0]
	}
	var openZones []string
	for _, sec := range fw.sectionsOfType("zone") {
		name := fw.get(sec, "name")
		if !wan[name] {
			continue
		}
		v := fw.get(sec, "input")
		if v == "" && defaults != "" {
			v = fw.get(defaults, "input")
		}
		if strings.EqualFold(v, "ACCEPT") {
			openZones = append(openZones, name)
		}
	}

	var accepts []wanAccept
	var forwards []string
	for _, sec := range fw.sectionsOfType("rule") {
		if uciOff(fw.get(sec, "enabled")) || !strings.EqualFold(fw.get(sec, "target"), "ACCEPT") || !fromWan(sec) {
			continue
		}
		var protos []string
		raw := splitAll(fw.list(sec, "proto"))
		for _, p := range raw {
			switch strings.ToLower(p) {
			case "tcp", "udp":
				protos = append(protos, strings.ToLower(p))
			case "all", "tcpudp":
				protos = append(protos, "tcp", "udp")
			}
		}
		if len(raw) == 0 {
			protos = []string{"tcp", "udp"}
		}
		if len(protos) == 0 {
			continue // icmp, esp and the like
		}
		ports := splitAll(fw.list(sec, "dest_port"))
		name := orDefault(fw.get(sec, "name"), sec)
		only := orDefault(fw.get(sec, "src_ip"), fw.get(sec, "src_mac"))
		if dest := fw.get(sec, "dest"); dest != "" {
			forwards = append(forwards, fmt.Sprintf("%s %s to zone %s (rule %q)%s", strings.Join(protos, "+"),
				pick(len(ports) > 0, strings.Join(ports, ","), "any port"), dest, trunc(name, 40), pick(only != "", ", only from "+trunc(only, 40), "")))
			continue
		}
		accepts = append(accepts, wanAccept{protos, ports, only, name})
	}
	for _, sec := range fw.sectionsOfType("redirect") {
		if uciOff(fw.get(sec, "enabled")) || !fromWan(sec) {
			continue
		}
		if t := fw.get(sec, "target"); t != "" && !strings.EqualFold(t, "DNAT") {
			continue
		}
		forwards = append(forwards, fmt.Sprintf("%s %s -> %s:%s (forward %q)", orDefault(fw.get(sec, "proto"), "tcp+udp"),
			orDefault(fw.get(sec, "src_dport"), "any port"), orDefault(fw.get(sec, "dest_ip"), "the router"),
			orDefault(fw.get(sec, "dest_port"), fw.get(sec, "src_dport")), trunc(orDefault(fw.get(sec, "name"), sec), 40)))
	}

	var reachable, held []string
	for _, l := range listeners {
		label := fmt.Sprintf("%s/%d", l.proto, l.port)
		switch {
		case len(openZones) > 0:
			reachable = append(reachable, label+" (zone "+strings.Join(openZones, ",")+" accepts all input)")
			continue
		}
		hit := false
		for _, a := range accepts {
			if a.covers(l) {
				reachable = append(reachable, label+" (rule "+fmt.Sprintf("%q", trunc(a.name, 40))+pick(a.only != "", ", only from "+trunc(a.only, 40), "")+")")
				hit = true
				break
			}
		}
		if !hit {
			held = append(held, label)
		}
	}

	if len(reachable) == 0 && len(forwards) == 0 {
		return nil, nil // nothing to show: the audit stays quiet on a router that exposes nothing
	}
	sn.limit("exposure comes from the UCI firewall and the sockets listening on every address; custom nft rules, an upstream NAT or the ISP are not seen")
	sort.Strings(forwards)
	var parts []string
	if len(reachable) > 0 {
		parts = append(parts, fmt.Sprintf("%s on the router reachable from the internet", plural(len(reachable), "listening port")))
	}
	if len(forwards) > 0 {
		parts = append(parts, fmt.Sprintf("%s into the LAN", plural(len(forwards), "forward")))
	}
	msg := strings.Join(parts, "; ")
	var ev []string
	if len(reachable) > 0 {
		ev = append(ev, "reachable: "+capList(reachable))
	}
	if len(forwards) > 0 {
		ev = append(ev, "forwarded: "+capList(forwards))
	}
	if len(held) > 0 {
		ev = append(ev, "bound to every address but blocked by the firewall: "+capList(held))
	}
	if len(accepts) > 0 && len(listeners) > 0 {
		// A rule can accept a port nothing listens on now: it is not exposure today, but it is
		// the first thing a service started later would inherit.
		var idle []string
		for _, a := range accepts {
			used := false
			for _, l := range listeners {
				used = used || a.covers(l)
			}
			dhcpClient := len(a.ports) == 1 && (a.ports[0] == "68" || a.ports[0] == "546") // the stock rules; nothing listens on purpose
			if !used && len(a.ports) > 0 && !dhcpClient {
				idle = append(idle, strings.Join(a.protos, "+")+"/"+strings.Join(a.ports, ",")+" ("+trunc(a.name, 30)+")")
			}
		}
		if len(idle) > 0 {
			ev = append(ev, "accepted but nothing listens now: "+capList(idle))
		}
	}
	return []finding{newFinding("wan-exposure", sevInfo, msg, strings.Join(ev, "; "))}, nil
}

func capList(items []string) string {
	if len(items) <= maxExposureItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxExposureItems], ", ") + fmt.Sprintf(" and %d more", len(items)-maxExposureItems)
}
