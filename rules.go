package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Argument rules (ROADMAP 6.2). A scope glob limits which names a call touches; a rule limits
// which values it writes. Rules live in the policy config as `config rule 'name'` sections and
// only ever take permission away:
//
//	config rule 'ssh_keys_only'
//	    option path 'dropbear.*.PasswordAuth'      # glob over config.section.option
//	    option eq 'on'                             # mode 'deny' (default): refuse when this holds
//
//	config rule 'wifi_switch'
//	    option path 'wireless.*.disabled'
//	    option mode 'only'                         # refuse unless the value satisfies the predicate
//	    list in '0'
//	    list in '1'
//
//	config rule 'wan_input'
//	    option path 'firewall.*.input'
//	    option eq 'ACCEPT'
//	    list when '@type=zone'                     # the section must also look like this
//	    list when 'name=wan'
//
// Semantics, fixed up front because getting them wrong after release is expensive:
//   - Rules never grant. A change is refused when ANY rule refuses it (deny wins, no ordering, no
//     precedence). No grant lifts a rule, @all included; only editing the config does, and the
//     floor keeps agents from that.
//   - Inside one rule every condition must hold (AND): the path glob, every `when`, and every
//     value predicate given (eq, in, regex, exists). A rule is a conjunction; to say "or", write
//     two rules.
//   - mode deny: refuse when path and `when` match and the value predicate holds (no predicate:
//     any write of the path). mode only: refuse when path and `when` match and the value
//     predicate does not hold (a predicate is required). An `only` rule ignores deletes: removing
//     an option puts it back to its default and is not a value write.
//   - The value of set is Value, of add_list and del_list the element, of set_list each of
//     Values (one failing element refuses the call). A delete has no value and does not exist.
//   - `when` entries are `option=glob`, tested on the section as it will be: the same call's
//     changes first, else the live value from uci. `@type=` tests the section type.
//   - Only a change with an option is looked at; creating or deleting a whole section is not a
//     value write.
//   - A client glob (default *) and a tool list (uci_apply only, today) narrow who a rule
//     applies to.
// Rules govern uci_apply. They are not a boundary against a client that holds exec on a shell.

type argRule struct {
	Name   string
	Client string
	Path   string
	Mode   string // deny | only
	Eq     *string
	In     []string
	Regex  *regexp.Regexp
	Exists *bool
	When   []ruleWhen
	Why    string
}

type ruleWhen struct{ key, glob string }

func ruleFromSection(s uciSection) (*argRule, error) {
	r := &argRule{Name: s.Name, Client: orStar(s.Options["client"]), Path: s.Options["path"], Mode: s.Options["mode"], Why: s.Options["why"]}
	if r.Mode == "" {
		r.Mode = "deny"
	}
	if r.Mode != "deny" && r.Mode != "only" {
		return nil, fmt.Errorf("bad 'mode' %q: want deny or only", r.Mode)
	}
	if n := len(strings.Split(r.Path, ".")); r.Path == "" || n != 3 {
		return nil, fmt.Errorf("'path' must be a config.section.option glob, got %q", r.Path)
	}
	if v, ok := s.Options["eq"]; ok {
		r.Eq = &v
	}
	r.In = s.Lists["in"]
	if v := s.Options["in"]; v != "" {
		r.In = append(r.In, strings.Fields(v)...)
	}
	if v, ok := s.Options["regex"]; ok {
		re, err := regexp.Compile("^(?:" + v + ")$")
		if err != nil {
			return nil, fmt.Errorf("bad 'regex': %w", err)
		}
		r.Regex = re
	}
	if v, ok := s.Options["exists"]; ok {
		if v != "0" && v != "1" {
			return nil, fmt.Errorf("bad 'exists' %q: want 0 or 1", v)
		}
		b := v == "1"
		r.Exists = &b
	}
	for _, w := range s.Lists["when"] {
		k, g, ok := strings.Cut(w, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("bad 'when' %q: want option=glob", w)
		}
		r.When = append(r.When, ruleWhen{k, g})
	}
	if r.Mode == "only" && !r.hasPredicate() {
		return nil, fmt.Errorf("mode only needs a predicate (eq, in, regex or exists)")
	}
	return r, nil
}

func (r *argRule) hasPredicate() bool {
	return r.Eq != nil || len(r.In) > 0 || r.Regex != nil || r.Exists != nil
}

// holds is the value predicate: every given condition must be true (AND).
func (r *argRule) holds(v string, present bool) bool {
	if r.Eq != nil && v != *r.Eq {
		return false
	}
	if len(r.In) > 0 && !contains(r.In, v) {
		return false
	}
	if r.Regex != nil && !r.Regex.MatchString(v) {
		return false
	}
	if r.Exists != nil && *r.Exists != present {
		return false
	}
	return true
}

// ruleLookup reads a section's option (or "@type") as it will be, for `when`.
type ruleLookup func(config, section, key string) string

// refuses says why this rule refuses the one change, or "".
func (r *argRule) refuses(client string, c UCIChange, look ruleLookup) string {
	if c.Option == "" || !matchAny([]string{r.Client}, client) || !matchAny([]string{r.Path}, uciKey(c)) {
		return ""
	}
	op := c.op()
	var vals []string
	present := true
	switch op {
	case opSet, opAddList, opDelList:
		vals = []string{c.Value}
	case opSetList:
		vals = c.Values
	case opDelete:
		if r.Mode == "only" {
			return ""
		}
		vals, present = []string{""}, false
	default:
		return ""
	}
	for _, w := range r.When {
		if !matchAny([]string{w.glob}, look(c.Config, c.Section, w.key)) {
			return ""
		}
	}
	for _, v := range vals {
		holds := r.holds(v, present)
		if (r.Mode == "deny" && (holds || !r.hasPredicate())) || (r.Mode == "only" && !holds) {
			why := r.Why
			if why == "" {
				why = "set by the operator"
			}
			return fmt.Sprintf("denied by rule %q: %s = %q is not allowed (%s). No grant lifts a rule, @operator and @all included; the owner edits %s.",
				r.Name, uciKey(c), v, why, "/etc/config/openwrt-mcp")
		}
	}
	return ""
}

// ruleRefusal checks a uci_apply call against every rule: any refusing rule refuses the call.
func ruleRefusal(ctx context.Context, rules []*argRule, client string, in any) string {
	apply, ok := in.(uciApplyIn)
	if !ok || len(rules) == 0 {
		return ""
	}
	staged := map[string]string{} // config.section.option -> last value set in this call
	for _, c := range apply.Changes {
		switch c.op() {
		case opSet:
			staged[uciKey(c)] = c.Value
		case opCreate:
			staged[c.Config+"."+c.Section+".@type"] = c.Type
		}
	}
	look := func(config, section, key string) string {
		if v, ok := staged[config+"."+section+"."+key]; ok {
			return v
		}
		ref := config + "." + section
		if key != "@type" {
			ref += "." + key
		}
		out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "get", ref)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(out)
	}
	for _, c := range apply.Changes {
		for _, r := range rules {
			if why := r.refuses(client, c, look); why != "" {
				return why
			}
		}
	}
	return ""
}
