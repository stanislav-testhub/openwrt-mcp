package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Which add-on owns which fwmark bits (ROADMAP 9.4, mark map). `ip rule` shows where a mark
// leads; the nftables rules show who writes it. This reads the terse ruleset (`nft -t list
// ruleset`, no set elements) and attributes each mark match and mark write to an add-on by the
// chain or table it sits in. mwan3 goes through iptables-nft, whose MARK target hides its value,
// so for it only the mask is known (from the `meta mark & MASK` matches in its chains).

type markUse struct {
	owner  string
	bits   uint64          // every bit this add-on matches or writes
	values map[uint64]bool // values it writes where nft shows them
	whole  bool            // writes the whole mark, not a masked part
}

var (
	reNFTTable   = lazyRegexp(`^table (\S+) (\S+) \{`)
	reNFTChain   = lazyRegexp(`^\s+chain (\S+) \{`)
	reMarkMatch  = lazyRegexp(`\bmeta mark & (0x[0-9a-fA-F]+) (?:==|!=) 0x[0-9a-fA-F]+`)
	reMarkSetOr  = lazyRegexp(`\bmeta mark set meta mark & (0x[0-9a-fA-F]+) \| (0x[0-9a-fA-F]+)`)
	reMarkSetRaw = lazyRegexp(`\bmeta mark set (0x[0-9a-fA-F]+)(?:\s|$)`) // counter and comment may follow
	reMarkAddRaw = lazyRegexp(`\bmeta mark set meta mark \| (0x[0-9a-fA-F]+)(?:\s|$)`)
	reMarkExact  = lazyRegexp(`\bmeta mark (0x[0-9a-fA-F]+)(?:\s|$)`)
)

// markOwner attributes a rule to an add-on from its table and chain names; "" means not a
// routing add-on (fw4 itself, banIP, flow offloading).
func markOwner(table, chain string) string {
	switch {
	case strings.HasPrefix(chain, "mwan3_"):
		return "mwan3"
	case strings.HasPrefix(chain, "pbr_"):
		return "pbr"
	case strings.HasPrefix(chain, "ts-"):
		return "tailscale"
	case strings.HasPrefix(chain, "podkop_"):
		return "podkop" // podkop_remark sits in fw4 itself
	}
	switch table {
	case "PodkopTable":
		return "podkop"
	case "passwall", "passwall2", "nikki", "zapret", "youtubeUnblock", "homeproxy", "openclash":
		return table
	}
	return ""
}

func hexU(s string) (uint64, bool) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
	return v, err == nil
}

func parseMarkOwners(ruleset string) []*markUse {
	byOwner := map[string]*markUse{}
	get := func(o string) *markUse {
		if byOwner[o] == nil {
			byOwner[o] = &markUse{owner: o, values: map[uint64]bool{}}
		}
		return byOwner[o]
	}
	table, chain := "", ""
	for _, l := range strings.Split(ruleset, "\n") {
		if g := reNFTTable.FindStringSubmatch(l); g != nil {
			table, chain = g[2], ""
			continue
		}
		if g := reNFTChain.FindStringSubmatch(l); g != nil {
			chain = g[1]
			continue
		}
		owner := markOwner(table, chain)
		if owner == "" {
			continue
		}
		for _, g := range reMarkMatch.FindAllStringSubmatch(l, -1) {
			if m, ok := hexU(g[1]); ok {
				get(owner).bits |= m
			}
		}
		for _, g := range reMarkExact.FindAllStringSubmatch(l, -1) {
			if m, ok := hexU(g[1]); ok {
				get(owner).bits |= m
			}
		}
		if g := reMarkAddRaw.FindStringSubmatch(l); g != nil {
			if v, ok := hexU(g[1]); ok {
				u := get(owner)
				u.bits |= v
				u.values[v] = true
			}
		} else if g := reMarkSetOr.FindStringSubmatch(l); g != nil {
			keep, ok1 := hexU(g[1])
			v, ok2 := hexU(g[2])
			if ok1 && ok2 {
				u := get(owner)
				u.bits |= ^keep & 0xffffffff
				u.values[v] = true
			}
		} else if g := reMarkSetRaw.FindStringSubmatch(l); g != nil {
			if v, ok := hexU(g[1]); ok {
				u := get(owner)
				u.bits |= v
				u.values[v] = true
				u.whole = true
			}
		}
	}
	var out []*markUse
	for _, u := range byOwner {
		if u.bits != 0 || len(u.values) > 0 {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].owner < out[j].owner })
	return out
}

func (u *markUse) describe() string {
	s := fmt.Sprintf("%s: bits 0x%x", u.owner, u.bits)
	if len(u.values) > 0 {
		var vs []string
		for v := range u.values {
			vs = append(vs, fmt.Sprintf("0x%x", v))
		}
		sort.Strings(vs)
		s += ", writes " + strings.Join(vs, " ")
	} else {
		s += ", value not visible (iptables-nft target)"
	}
	return s
}

// markConflicts: two add-ons writing the same value, bits that only partly overlap, and a
// whole-mark write beside another add-on. Identical masks with different values are fine and
// are not reported.
func markConflicts(us []*markUse) []string {
	var w []string
	for i := range us {
		for j := i + 1; j < len(us); j++ {
			a, b := us[i], us[j]
			if a.bits&b.bits == 0 {
				continue
			}
			var same []string
			for v := range a.values {
				if b.values[v] {
					same = append(same, fmt.Sprintf("0x%x", v))
				}
			}
			sort.Strings(same)
			switch {
			case len(same) > 0:
				w = append(w, fmt.Sprintf("%s and %s both write mark %s", a.owner, b.owner, strings.Join(same, ", ")))
			case a.bits != b.bits && mayCollide(a, b):
				w = append(w, fmt.Sprintf("%s (0x%x) and %s (0x%x) share bits 0x%x without sharing a mask", a.owner, a.bits, b.owner, b.bits, a.bits&b.bits))
			}
		}
	}
	if len(us) > 1 {
		for _, u := range us {
			if u.whole {
				w = append(w, u.owner+" sets the whole mark, which can wipe the bits another add-on set earlier in the packet's path (check the hook order if both see the same traffic)")
			}
		}
	}
	return w
}

// mayCollide is false only when both add-ons write values nft shows and, inside the bits they
// share, no value of one equals a value of the other. Otherwise (a hidden iptables-nft value) it
// cannot be ruled out.
func mayCollide(a, b *markUse) bool {
	if len(a.values) == 0 || len(b.values) == 0 {
		return true
	}
	inter := a.bits & b.bits
	for va := range a.values {
		for vb := range b.values {
			if va&inter == vb&inter {
				return true
			}
		}
	}
	return false
}

// ruleOwners names the add-ons whose bits contain an ip rule's mask (and whose written values
// include the mark, when nft shows them).
func ruleOwners(m markEntry, us []*markUse) string {
	var names []string
	for _, u := range us {
		if m.k&^u.bits != 0 {
			continue
		}
		if len(u.values) > 0 && !u.values[m.m] {
			continue
		}
		names = append(names, u.owner)
	}
	return strings.Join(names, " or ")
}
