package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
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
//   - A client glob (default *) and `option tool` (uci_apply, ubus_call or exec; default uci_apply)
//     narrow who and what a rule applies to.
//
// ubus_call and exec rules use the same modes and predicates:
//
//	config rule 'no_reboot_ubus'
//	    option tool 'ubus_call'
//	    option path 'system.reboot'                # glob over object.method
//
//	config rule 'hostapd_only_status'
//	    option tool 'ubus_call'
//	    option path 'hostapd.*.del_client'
//	    option arg 'reason'                        # the call's top-level arg the predicate reads
//	    option mode 'only'
//	    list in '0'
//
//	config rule 'no_recursive_rm'
//	    option tool 'exec'
//	    option path 'rm'                           # glob over argv[0]: as given, cleaned, or its basename
//	    option regex '-[a-zA-Z]*[rR][a-zA-Z]*'     # judged against each later argv element in turn
//
// For ubus_call the value is the named arg (strings as they are, other JSON as compact JSON);
// without `arg` a deny rule refuses every call of the path and predicates are not allowed. An
// absent arg is judged as the empty value that does not exist, so an `only` rule refuses it
// unless it says `exists 0`. For exec the values are argv[1:], one at a time (one failing element
// refuses; a call with no arguments is not judged). `busybox APPLET ...` is also judged as
// APPLET, so a rule on `rm` is not stepped around by `busybox rm`. `when` is uci_apply only.
// Rules govern what the tools are asked to do. They are not a boundary against a client that
// holds exec on a shell: `sh -c` hides its words from any argv rule.

type argRule struct {
	Name   string
	Client string
	Tool   string // uci_apply | ubus_call | exec
	Path   string
	Arg    string // ubus_call: the top-level arg the predicate reads
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
	r := &argRule{Name: s.Name, Client: orStar(s.Options["client"]), Tool: s.Options["tool"], Path: s.Options["path"], Arg: s.Options["arg"], Mode: s.Options["mode"], Why: s.Options["why"]}
	if r.Tool == "" {
		r.Tool = "uci_apply"
	}
	if !contains([]string{"uci_apply", "ubus_call", "exec"}, r.Tool) {
		return nil, fmt.Errorf("bad 'tool' %q: want uci_apply, ubus_call or exec", r.Tool)
	}
	if r.Mode == "" {
		r.Mode = "deny"
	}
	if r.Mode != "deny" && r.Mode != "only" {
		return nil, fmt.Errorf("bad 'mode' %q: want deny or only", r.Mode)
	}
	if r.Tool == "uci_apply" {
		if n := len(strings.Split(r.Path, ".")); r.Path == "" || n != 3 {
			return nil, fmt.Errorf("'path' must be a config.section.option glob, got %q", r.Path)
		}
	} else if r.Path == "" {
		return nil, fmt.Errorf("'path' is needed: object.method for ubus_call, argv[0] for exec")
	}
	if r.Arg != "" && r.Tool != "ubus_call" {
		return nil, fmt.Errorf("'arg' is for tool ubus_call only")
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
	if r.Tool != "uci_apply" && len(r.When) > 0 {
		return nil, fmt.Errorf("'when' is for tool uci_apply only")
	}
	if r.Tool == "ubus_call" && r.hasPredicate() && r.Arg == "" {
		return nil, fmt.Errorf("a ubus_call predicate needs 'arg' to say which argument it reads")
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
	if r.Tool != "uci_apply" || c.Option == "" || !matchAny([]string{r.Client}, client) || !matchAny([]string{r.Path}, uciKey(c)) {
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
	return r.judge(uciKey(c), vals, present)
}

// judge applies the mode and predicate to the values of one matched call.
func (r *argRule) judge(label string, vals []string, present bool) string {
	for _, v := range vals {
		holds := r.holds(v, present)
		if (r.Mode == "deny" && (holds || !r.hasPredicate())) || (r.Mode == "only" && !holds) {
			why := r.Why
			if why == "" {
				why = "set by the operator"
			}
			return fmt.Sprintf("denied by rule %q: %s = %q is not allowed (%s). No grant lifts a rule, @operator and @all included; the owner edits %s.",
				r.Name, label, v, why, "/etc/config/openwrt-mcp")
		}
	}
	return ""
}

// refusesUbus judges one ubus_call against a ubus_call rule.
func (r *argRule) refusesUbus(client string, in ubusCallIn) string {
	key := in.Object + "." + in.Method
	if r.Tool != "ubus_call" || !matchAny([]string{r.Client}, client) || !matchAny([]string{r.Path}, key) {
		return ""
	}
	if r.Arg == "" {
		return r.judge(key, []string{""}, true) // a deny rule without a predicate: any call of the path
	}
	raw, present := in.Args[r.Arg]
	v := ""
	if present {
		if str, ok := raw.(string); ok {
			v = str
		} else if b, err := json.Marshal(raw); err == nil {
			v = string(b)
		}
	}
	return r.judge(key+" arg "+r.Arg, []string{v}, present)
}

// execForms are the (program names, arguments) pairs an exec call is judged as: argv[0] as
// given, cleaned and by basename; and for `busybox APPLET ...` the applet too.
func execForms(argv []string) (forms []struct {
	names []string
	args  []string
}) {
	if len(argv) == 0 {
		return nil
	}
	names := func(p string) []string {
		p = filepath.ToSlash(p)
		return []string{p, path.Clean(p), path.Base(p)}
	}
	forms = append(forms, struct {
		names []string
		args  []string
	}{names(argv[0]), argv[1:]})
	if path.Base(filepath.ToSlash(argv[0])) == "busybox" && len(argv) > 1 {
		forms = append(forms, struct {
			names []string
			args  []string
		}{names(argv[1]), argv[2:]})
	}
	return forms
}

// refusesExec judges one exec call against an exec rule.
func (r *argRule) refusesExec(client string, in execIn) string {
	if r.Tool != "exec" || !matchAny([]string{r.Client}, client) {
		return ""
	}
	for _, f := range execForms(in.Argv) {
		if !anyGlob(r.Path, f.names) {
			continue
		}
		if r.Mode == "deny" && !r.hasPredicate() {
			return r.judge(in.Argv[0], []string{""}, true)
		}
		if why := r.judge(f.names[2], f.args, true); why != "" {
			return why
		}
	}
	return ""
}

func anyGlob(glob string, names []string) bool {
	for _, n := range names {
		if matchAny([]string{glob}, n) {
			return true
		}
	}
	return false
}

// ruleRefusal checks a uci_apply call against every rule: any refusing rule refuses the call.
func ruleRefusal(ctx context.Context, rules []*argRule, client string, in any) string {
	if len(rules) == 0 {
		return ""
	}
	switch v := in.(type) {
	case ubusCallIn:
		for _, r := range rules {
			if why := r.refusesUbus(client, v); why != "" {
				return why
			}
		}
		return ""
	case execIn:
		for _, r := range rules {
			if why := r.refusesExec(client, v); why != "" {
				return why
			}
		}
		return ""
	}
	apply, ok := in.(uciApplyIn)
	if !ok {
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
