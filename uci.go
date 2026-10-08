package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------- change model

// UCIChange is one step of a uci_apply. What it does is Op; when Op is empty it is inferred
// from the other fields, so a caller that only knows the original set/create/delete shape
// keeps working:
//
//	type set                 -> create   uci set dhcp.pi=host
//	delete                   -> delete   uci delete dhcp.pi[.ip]
//	values set               -> set_list uci delete dhcp.x.server; uci add_list ... (each)
//	otherwise                -> set      uci set dhcp.pi.ip=192.168.0.141
//
// add_list / del_list must be named explicitly. They are what the original tool could not
// express at all: on OpenWrt a lot of real configuration is a list (dnsmasq servers, firewall
// protos and src_ip, network dns, wireguard allowed_ips), and `uci set` on a list option
// silently turns it into a single-valued option.
//
// Named sections rather than `uci add`: the caller picks the name, so later changes in the
// same batch can refer to it without knowing a generated id, and re-running the same apply
// is idempotent where `uci add` would append a duplicate every time.
type UCIChange struct {
	Op      string   `json:"op,omitempty" jsonschema:"set | create | delete | add_list | del_list | set_list. Optional: inferred from the other fields when omitted (type->create, delete->delete, values->set_list, else set)."`
	Config  string   `json:"config" jsonschema:"UCI config name, e.g. 'network'"`
	Section string   `json:"section" jsonschema:"section name, e.g. 'lan', 'pi' or '@rule[3]'"`
	Option  string   `json:"option,omitempty" jsonschema:"option name, e.g. 'ipaddr'. Omit when creating or deleting a whole section."`
	Type    string   `json:"type,omitempty" jsonschema:"section type, e.g. 'host' or 'rule'. With no option this CREATES the named section; put it before the changes that fill it in."`
	Value   string   `json:"value,omitempty" jsonschema:"new value for set, or the list element for add_list/del_list"`
	Values  []string `json:"values,omitempty" jsonschema:"replace a list option with exactly these elements (set_list)"`
	Delete  bool     `json:"delete,omitempty" jsonschema:"delete the option, or the whole section when option is omitted (same as op=delete)"`
}

const (
	opSet     = "set"
	opCreate  = "create"
	opDelete  = "delete"
	opAddList = "add_list"
	opDelList = "del_list"
	opSetList = "set_list"
)

func (c UCIChange) op() string {
	if c.Op != "" {
		return c.Op
	}
	switch {
	case c.Type != "":
		return opCreate
	case c.Delete:
		return opDelete
	case c.Values != nil:
		return opSetList
	}
	return opSet
}

// Names are validated against UCI's own grammar, not merely for emptiness. uci parses
// "config.section.option=value" out of one string, so a section containing '.' or '=' would
// make the key uci acts on differ from the scope string the policy was checked against.
var (
	reUCIConfig  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`) // not '-' first: it starts the uci key, so it would parse as an option
	reUCISection = regexp.MustCompile(`^([A-Za-z0-9_]+|@[A-Za-z0-9_-]+\[-?[0-9]+\])$`)
	reUCIOption  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	reUCIType    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func validValue(v string) error {
	if strings.ContainsAny(v, "\x00\n\r") {
		return fmt.Errorf("value contains a newline or NUL byte")
	}
	return nil
}

// validListElement is validValue for one list element: an empty one is never meaningful, so
// add_list, del_list and set_list all refuse it (set may still write an empty scalar).
func validListElement(v string) error {
	if v == "" {
		return invalid("a list element must not be empty")
	}
	return validValue(v)
}

func validateChange(c UCIChange) error {
	if c.Config == "" || c.Section == "" {
		return fmt.Errorf("each change needs at least a config and a section")
	}
	if !reUCIConfig.MatchString(c.Config) {
		return invalid("bad config name %q", c.Config)
	}
	if !reUCISection.MatchString(c.Section) {
		return invalid("bad section name %q: use a name like 'lan' or an index like '@rule[2]'", c.Section)
	}
	if c.Option != "" && !reUCIOption.MatchString(c.Option) {
		return invalid("bad option name %q", c.Option)
	}
	key := c.Config + "." + c.Section
	switch c.op() {
	case opCreate:
		if c.Option != "" {
			return fmt.Errorf("%s: type creates a section, so it cannot be combined with option", key)
		}
		if c.Delete {
			return fmt.Errorf("%s: type creates a section, so it cannot be combined with delete", key)
		}
		if !reUCIType.MatchString(c.Type) {
			return invalid("bad section type %q", c.Type)
		}
		if strings.HasPrefix(c.Section, "@") {
			return fmt.Errorf("%s: a created section needs a real name, not an index", key)
		}
	case opDelete:
		// option optional: without it the whole section goes.
	case opSet:
		if c.Option == "" {
			return fmt.Errorf("%s: needs an option to set, a type to create the section, "+
				"or delete to remove the whole section", key)
		}
		return validValue(c.Value)
	case opAddList, opDelList:
		if c.Option == "" || c.Value == "" {
			return fmt.Errorf("%s: %s needs an option and a value", key, c.op())
		}
		return validListElement(c.Value)
	case opSetList:
		if c.Option == "" || len(c.Values) == 0 {
			return fmt.Errorf("%s: set_list needs an option and at least one value (use delete to clear a list)", key)
		}
		for _, v := range c.Values {
			if err := validListElement(v); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	default:
		return invalid("%s: unknown op %q", key, c.Op)
	}
	return nil
}

// uciKey is the change's identity for error messages and policy scope: "config.section" for
// anything section-level, "config.section.option" otherwise. Creating a section is a
// different permission from setting an option in one, and the scope string says so.
func uciKey(c UCIChange) string {
	if c.Option == "" {
		return c.Config + "." + c.Section
	}
	return c.Config + "." + c.Section + "." + c.Option
}

// uciCmd is one uci invocation; mayFail marks a step whose failure is expected and harmless
// (clearing a list that does not exist yet).
type uciCmd struct {
	argv    []string
	mayFail bool
}

func uciCmds(c UCIChange) []uciCmd {
	key := uciKey(c)
	switch c.op() {
	case opCreate:
		return []uciCmd{{argv: []string{"uci", "set", key + "=" + c.Type}}}
	case opDelete:
		return []uciCmd{{argv: []string{"uci", "delete", key}}}
	case opAddList:
		return []uciCmd{{argv: []string{"uci", "add_list", key + "=" + c.Value}}}
	case opDelList:
		return []uciCmd{{argv: []string{"uci", "del_list", key + "=" + c.Value}}}
	case opSetList:
		out := []uciCmd{{argv: []string{"uci", "-q", "delete", key}, mayFail: true}}
		for _, v := range c.Values {
			out = append(out, uciCmd{argv: []string{"uci", "add_list", key + "=" + v}})
		}
		return out
	}
	return []uciCmd{{argv: []string{"uci", "set", key + "=" + c.Value}}}
}

// listHas reports whether the list option already holds value, staged edits included. libuci's
// add_list appends a duplicate rather than refusing, so add_list is skipped when this is true.
// An unreadable or missing option counts as "not there", so the add goes ahead.
func listHas(ctx context.Context, key, value string) bool {
	out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "show", key)
	if err != nil {
		return false
	}
	_, v, ok := strings.Cut(strings.TrimSpace(out), "=")
	return ok && contains(splitUCIValue(v), value)
}

// uciArgv is the single-command form, kept for the common case and its tests.
func uciArgv(c UCIChange) []string { return uciCmds(c)[0].argv }

// uciScopes derives the policy scopes for an apply. A scope of "dhcp.pi" (create the section)
// is a different permission from "dhcp.pi.ip" (set an option in it), and a policy must cover
// each on its own terms.
func uciScopes(in uciApplyIn) []string {
	if in.Restore != "" {
		// A restore replaces a whole config, so its scope is the whole-config key, like a whole-config read.
		if config, _, err := parseHistoryID(in.Restore); err == nil {
			return append([]string{config}, probeScopes(in.Probe)...)
		}
		return []string{in.Restore} // matches nothing but "*"; uci_apply then rejects it
	}
	var out []string
	for _, c := range in.Changes {
		out = append(out, uciKey(c))
	}
	return append(out, probeScopes(in.Probe)...)
}

// ---------------------------------------------------------------- uci_get

type uciGetIn struct {
	Config  string `json:"config" jsonschema:"UCI config to read, e.g. 'dhcp' or 'network'"`
	Section string `json:"section,omitempty" jsonschema:"section to narrow to, e.g. 'lan' or '@wifi-iface[0]'. Omit to read the whole config."`
	Option  string `json:"option,omitempty" jsonschema:"option to read a single value. Omit to read the whole section."`
	IDs     bool   `json:"ids,omitempty" jsonschema:"show anonymous sections by their stable internal id (cfgXXXXXX) instead of @type[n]; ids survive reordering, indexes do not"`

	History string `json:"history,omitempty" jsonschema:"'list' shows the kept past versions of the config (from before each confirmed change); 'diff:<id>' compares one with the current config. Whole config only: give no section or option"`
}

// uciGetScope is the read counterpart of uciScopes: a read is scoped with the same identity
// a write would use. A whole-config read addresses just "<config>", so it is covered by a
// "<config>" or "<config>*" grant but deliberately NOT by "<config>.*" -- reading every
// section of a config is a broader permission than reading one named section.
func uciGetScope(in uciGetIn) []string {
	key := in.Config
	if in.Section != "" {
		key += "." + in.Section
		if in.Option != "" {
			key += "." + in.Option
		}
	}
	return []string{key}
}

// uciGet reads current configuration with `uci show`, so an agent can inspect state before
// changing it without being handed exec (a root shell) or a broad ubus "uci.*" grant.
func uciGet(ctx context.Context, in uciGetIn) (string, string, error) {
	if in.Config == "" {
		return "", "", invalid("config is required")
	}
	if in.Option != "" && in.Section == "" {
		return "", "", fmt.Errorf("option requires a section")
	}
	if !reUCIConfig.MatchString(in.Config) ||
		(in.Section != "" && !reUCISection.MatchString(in.Section)) ||
		(in.Option != "" && !reUCIOption.MatchString(in.Option)) {
		return "", "", invalid("bad config/section/option name")
	}
	sel := strings.Join(uciGetScope(in), "")
	argv := []string{"uci", "show", sel}
	if in.IDs {
		argv = []string{"uci", "-X", "show", sel}
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if err == nil {
		// Always the whole config's revision, even for a narrowed read: it is what uci_apply compares.
		if rev, rerr := configRevision(in.Config); rerr == nil {
			out = strings.TrimRight(out, "\n") + "\n# revision of " + in.Config + ": " + rev
		}
	}
	return out, "read " + sel, err
}

// ---------------------------------------------------------------- `uci show` parsing

// uciTree is the parsed form of `uci show <config>`.
type uciTree struct {
	typ   map[string]string              // section -> type
	opt   map[string]map[string][]string // section -> option -> value(s)
	order []string                       // section names in file order
}

// parseUCIShow reads `uci show` output: "cfg.section=type" and "cfg.section.option=value"
// lines, where a value is one or more single-quoted words ('a' 'b' for a list, with an
// embedded quote written '\”). Unparseable lines are skipped rather than fatal -- a
// config with an odd line should not make a tool unusable.
func parseUCIShow(out string) *uciTree {
	t := &uciTree{typ: map[string]string{}, opt: map[string]map[string][]string{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.Index(line, "=")
		if line == "" || eq < 0 {
			continue
		}
		lhs, rhs := line[:eq], line[eq+1:]
		parts := strings.Split(lhs, ".")
		switch len(parts) {
		case 2: // cfg.section=type
			sec := parts[1]
			if _, seen := t.typ[sec]; !seen {
				t.order = append(t.order, sec)
			}
			t.typ[sec] = strings.Trim(rhs, "'")
		case 3: // cfg.section.option=value
			sec, opt := parts[1], parts[2]
			if t.opt[sec] == nil {
				t.opt[sec] = map[string][]string{}
			}
			t.opt[sec][opt] = splitUCIValue(rhs)
		}
	}
	return t
}

// splitUCIValue unquotes a `uci show` value: 'a' -> [a], 'a' 'b' -> [a b], 'it'\”s' -> [it's].
// An unquoted value (older uci printed some that way) comes back whole.
func splitUCIValue(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "'") {
		return []string{s}
	}
	var out []string
	var cur strings.Builder
	in, started := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			in = !in
			started = true
		case c == '\\' && !in && i+1 < len(s) && s[i+1] == '\'':
			cur.WriteByte('\'')
			i++
		case c == ' ' && !in:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

// get returns an option's value, or the first element of a list.
func (t *uciTree) get(sec, opt string) string {
	if v := t.opt[sec][opt]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (t *uciTree) list(sec, opt string) []string { return t.opt[sec][opt] }

// sectionsOfType returns section names of the given uci type, in file order.
func (t *uciTree) sectionsOfType(typ string) []string {
	var out []string
	for _, s := range t.order {
		if t.typ[s] == typ {
			out = append(out, s)
		}
	}
	return out
}

func uciShow(ctx context.Context, config string, ids bool) (*uciTree, error) {
	argv := []string{"uci", "-q", "show", config}
	if ids {
		argv = []string{"uci", "-q", "-X", "show", config}
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if err != nil {
		return nil, fmt.Errorf("uci show %s: %w %s", config, err, strings.TrimSpace(out))
	}
	return parseUCIShow(out), nil
}

// uncommitted reports staged-but-uncommitted uci changes for a config ("" for all). Every
// tool that commits must refuse to run on top of them: committing another session's half
// finished edit as a side effect would apply changes nobody asked for.
func uncommitted(ctx context.Context, config string) (string, error) {
	argv := []string{"uci", "changes"}
	if config != "" {
		argv = append(argv, config)
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	return strings.TrimSpace(out), err
}
