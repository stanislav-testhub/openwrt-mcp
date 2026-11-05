package main

import (
	"context"
	"net"
	"regexp"
	"strings"
)

// Which nftables rule that writes a fwmark can catch one client (ROADMAP 9.4, path view). Built
// from the terse ruleset: every rule is read with its table and chain, the address and interface
// conditions are evaluated for the client and the target, and a rule in a chain reached only by
// `jump` or `goto` takes the verdict of its callers. Named sets are asked with `nft get element`.
// Ports, protocols and connection state are not evaluated, so a "yes" means "if the port and
// protocol fit".

var reNFTName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type nftRule struct {
	family, table, chain string
	text                 string
}

type verdict int

const (
	vNo verdict = iota
	vMaybe
	vYes
)

var (
	reNFTBase    = regexp.MustCompile(`^\s+type \S+ hook `)
	reNFTSetOpen = regexp.MustCompile(`^\s+(set|map|flowtable|counter|quota|limit) \S+ \{`)
	reAddrCond   = regexp.MustCompile(`\bip (saddr|daddr) (!= )?(\{[^}]*\}|@[A-Za-z0-9_.-]+|[0-9./]+)`)
	reIifCond    = regexp.MustCompile(`\biifname (!= )?(\{[^}]*\}|"[^"]*"|@[A-Za-z0-9_.-]+)`)
	reJump       = regexp.MustCompile(`\b(?:jump|goto) ([A-Za-z0-9_.-]+)\s*$`)
	reRuleNoise  = regexp.MustCompile(`\s*counter packets \d+ bytes \d+|\s*comment "[^"]*"`)
)

type nftModel struct {
	rules   []nftRule
	base    map[string]bool // "family table chain" of base chains
	callers map[string][]int
}

func chainKey(family, table, chain string) string { return family + " " + table + " " + chain }

func parseNFTRules(ruleset string) *nftModel {
	m := &nftModel{base: map[string]bool{}, callers: map[string][]int{}}
	family, table, chain, skip := "", "", "", 0
	for _, l := range strings.Split(ruleset, "\n") {
		if g := reNFTTable.FindStringSubmatch(l); g != nil {
			family, table, chain, skip = g[1], g[2], "", 0
			continue
		}
		if g := reNFTChain.FindStringSubmatch(l); g != nil {
			chain = g[1]
			continue
		}
		if reNFTSetOpen.MatchString(l) {
			skip = 1
			if strings.HasSuffix(strings.TrimSpace(l), "}") {
				skip = 0
			}
			continue
		}
		t := strings.TrimSpace(l)
		if skip > 0 {
			if t == "}" {
				skip = 0
			}
			continue
		}
		if chain == "" || t == "" || t == "}" || strings.HasPrefix(t, "policy ") {
			if t == "}" {
				chain = ""
			}
			continue
		}
		if reNFTBase.MatchString(l) {
			m.base[chainKey(family, table, chain)] = true
			continue
		}
		t = strings.TrimSpace(reRuleNoise.ReplaceAllString(t, ""))
		m.rules = append(m.rules, nftRule{family, table, chain, t})
		if g := reJump.FindStringSubmatch(t); g != nil {
			k := chainKey(family, table, g[1])
			m.callers[k] = append(m.callers[k], len(m.rules)-1)
		}
	}
	return m
}

func vAnd(a, b verdict) verdict {
	if a < b {
		return a
	}
	return b
}

type matcher struct {
	ctx         context.Context
	ip, dev     string
	target      string
	m           *nftModel
	sets        map[string]verdict
	lookups     int
	chainMemo   map[string]verdict
	chainActive map[string]bool
}

func (x *matcher) addrIn(family, table, spec, ip string) verdict {
	if strings.HasPrefix(spec, "@") {
		key := family + " " + table + " " + spec + " " + ip
		if v, ok := x.sets[key]; ok {
			return v
		}
		v := vMaybe
		if x.lookups < 12 && reNFTName.MatchString(table) && reNFTName.MatchString(spec[1:]) && net.ParseIP(ip) != nil {
			x.lookups++
			if _, err := run(x.ctx, defaultCmdTimeout, "nft", "get", "element", family, table, spec[1:], "{ "+ip+" }"); err == nil {
				v = vYes
			} else {
				v = vNo
			}
		}
		x.sets[key] = v
		return v
	}
	addr := net.ParseIP(ip)
	spec = strings.Trim(spec, "{} ")
	for _, tok := range strings.Split(spec, ",") {
		if n := parseNet(strings.TrimSpace(tok)); n != nil && addr != nil && n.Contains(addr) {
			return vYes
		}
	}
	return vNo
}

func (x *matcher) ifaceIn(spec string) verdict {
	if strings.HasPrefix(spec, "@") {
		return vMaybe
	}
	for _, tok := range strings.Split(strings.Trim(spec, "{} "), ",") {
		n := strings.Trim(strings.TrimSpace(tok), `"`)
		if n == x.dev || (strings.HasSuffix(n, "*") && strings.HasPrefix(x.dev, strings.TrimSuffix(n, "*"))) {
			return vYes
		}
	}
	return vNo
}

func flip(v verdict, neg bool) verdict {
	if !neg || v == vMaybe {
		return v
	}
	if v == vYes {
		return vNo
	}
	return vYes
}

// rule evaluates the conditions written in the rule and, through its chain, its callers.
func (x *matcher) rule(i int, depth int) verdict {
	r := x.m.rules[i]
	v := vYes
	for _, g := range reAddrCond.FindAllStringSubmatch(r.text, -1) {
		ip := x.ip
		if g[1] == "daddr" {
			ip = x.target
		}
		v = vAnd(v, flip(x.addrIn(r.family, r.table, g[3], ip), g[2] != ""))
	}
	for _, g := range reIifCond.FindAllStringSubmatch(r.text, -1) {
		v = vAnd(v, flip(x.ifaceIn(g[2]), g[1] != ""))
	}
	if v == vNo {
		return vNo
	}
	return vAnd(v, x.chain(chainKey(r.family, r.table, r.chain), depth))
}

// chain: a base chain, or one nothing jumps to, is reached; otherwise the best verdict of its callers.
func (x *matcher) chain(key string, depth int) verdict {
	if x.m.base[key] {
		return vYes
	}
	if v, ok := x.chainMemo[key]; ok {
		return v
	}
	cs := x.m.callers[key]
	if len(cs) == 0 {
		return vMaybe // not a base chain and nothing calls it in the listing
	}
	if depth > 5 || x.chainActive[key] {
		return vMaybe
	}
	x.chainActive[key] = true
	best := vNo
	for _, c := range cs {
		if v := x.rule(c, depth+1); v > best {
			best = v
		}
	}
	delete(x.chainActive, key)
	x.chainMemo[key] = best
	return best
}

// clientMarkRules lists the mark-writing rules of routing add-ons that can catch this client
// going to target: "yes" ones first, then those the listing cannot decide.
func clientMarkRules(ctx context.Context, ruleset, ip, dev, target string) (yes, maybe []string) {
	m := parseNFTRules(ruleset)
	x := &matcher{ctx: ctx, ip: ip, dev: dev, target: target, m: m, sets: map[string]verdict{}, chainMemo: map[string]verdict{}, chainActive: map[string]bool{}}
	for i, r := range m.rules {
		owner := markOwner(r.table, r.chain)
		if owner == "" || !strings.Contains(r.text, "meta mark set") {
			continue
		}
		v := x.rule(i, 0)
		if v == vNo {
			continue
		}
		text := sanitizeText(r.text)
		line := owner + ", chain " + r.chain + ": " + clip(text, 150)
		if v == vYes {
			yes = append(yes, line)
		} else {
			maybe = append(maybe, line)
		}
	}
	return yes, maybe
}
