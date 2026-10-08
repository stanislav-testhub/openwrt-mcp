package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Verify after write (ROADMAP 4.9). A router can accept a write and not keep it: a commit that
// lost the race with another writer, a hot-add into an interface that was just restarted, a
// package manager that exited 0. The exit status says nothing about that, so each write path
// reads back what it changed, and a difference is NOT_APPLIED rather than a success the caller
// has no reason to doubt. A read-back that cannot run is not a failed write: the result says
// "Not verified" and why.

// ---------------------------------------------------------------- uci_apply

type wantKind int

const (
	wantAny   wantKind = iota // nothing certain about the whole option, only about some list elements
	wantUnset                 // the option must not exist
	wantValue                 // exactly this one value
	wantList                  // exactly this list, in this order
)

// optWant is what a run of changes to one option must leave behind. The last change decides,
// except that add_list and del_list adjust whatever an earlier set_list established.
type optWant struct {
	kind    wantKind
	value   string
	list    []string // wantList
	with    []string // wantAny: must be in the list
	without []string // wantAny: must not be
}

func (w *optWant) apply(c UCIChange) {
	switch c.op() {
	case opSet:
		if c.Value == "" { // uci reads an empty value as "no value"
			*w = optWant{kind: wantUnset}
		} else {
			*w = optWant{kind: wantValue, value: c.Value}
		}
	case opDelete:
		*w = optWant{kind: wantUnset}
	case opSetList:
		*w = optWant{kind: wantList, list: append([]string(nil), c.Values...)}
	case opAddList:
		switch w.kind {
		case wantList:
			if !contains(w.list, c.Value) {
				w.list = append(w.list, c.Value)
			}
		case wantUnset:
			*w = optWant{kind: wantList, list: []string{c.Value}}
		default:
			*w = optWant{kind: wantAny, with: appendUnique(w.with, c.Value), without: dropString(w.without, c.Value)}
		}
	case opDelList:
		switch w.kind {
		case wantList:
			if w.list = dropString(w.list, c.Value); len(w.list) == 0 {
				*w = optWant{kind: wantUnset} // uci removes a list option that loses its last element
			}
		case wantUnset:
		default:
			*w = optWant{kind: wantAny, with: dropString(w.with, c.Value), without: appendUnique(w.without, c.Value)}
		}
	}
}

func appendUnique(s []string, v string) []string {
	if contains(s, v) {
		return s
	}
	return append(s, v)
}

func dropString(s []string, v string) []string {
	var out []string
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

type secWant struct {
	config string
	typ    string // "" = not asserted
	gone   bool
	opts   map[string]*optWant
	order  []string // option names, in the order they were first touched
}

// quoted renders values the way `uci show` does. A secret option's value is never printed:
// this text goes to the operator and to the audit log.
func quoted(opt string, vals []string) string {
	switch {
	case len(vals) == 0:
		return "nothing"
	case isSecretOption(opt):
		return "a value (hidden)"
	}
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = "'" + v + "'"
	}
	return strings.Join(q, " ")
}

// reGeneratedName is the name libuci invents for an anonymous section (cfg + 6 hex digits). It
// comes from the section's place in the file, so it can differ after the commit.
var reGeneratedName = regexp.MustCompile(`^cfg[0-9a-f]{6}$`)

// expectationMismatches compares the tree `uci show` printed for one config with what changes
// (all of them for that config, in the order they were staged) must have left in it. Sections
// addressed by position (@rule[3]) or by a generated name are not compared, because an earlier
// delete or add in the same batch moves them; unchecked counts those changes.
func expectationMismatches(t *uciTree, changes []UCIChange) (mismatches []string, unchecked int) {
	secs := map[string]*secWant{}
	var order []string
	for _, c := range changes {
		if strings.HasPrefix(c.Section, "@") || reGeneratedName.MatchString(c.Section) {
			unchecked++
			continue
		}
		sw := secs[c.Section]
		if sw == nil {
			sw = &secWant{config: c.Config, opts: map[string]*optWant{}}
			secs[c.Section] = sw
			order = append(order, c.Section)
		}
		switch {
		case c.op() == opCreate:
			sw.gone, sw.typ = false, c.Type
		case c.op() == opDelete && c.Option == "":
			sw.gone, sw.typ, sw.opts, sw.order = true, "", map[string]*optWant{}, nil
		case sw.gone:
			// staging an option on a deleted section fails, so nothing is expected of it
		default:
			ow := sw.opts[c.Option]
			if ow == nil {
				ow = &optWant{}
				sw.opts[c.Option] = ow
				sw.order = append(sw.order, c.Option)
			}
			ow.apply(c)
		}
	}
	for _, name := range order {
		sw := secs[name]
		key := sw.config + "." + name
		there := t.typ[name] != "" || len(t.opt[name]) > 0
		switch {
		case sw.gone && there:
			mismatches = append(mismatches, key+": expected it deleted, but it is still there")
		case sw.typ != "" && t.typ[name] != sw.typ:
			found := "none"
			if t.typ[name] != "" {
				found = "'" + t.typ[name] + "'"
			}
			mismatches = append(mismatches, fmt.Sprintf("%s: expected a section of type '%s', found %s", key, sw.typ, found))
		}
		for _, opt := range sw.order {
			if m := sw.opts[opt].mismatch(opt, t.opt[name][opt]); m != "" {
				mismatches = append(mismatches, key+"."+opt+": "+m)
			}
		}
	}
	return mismatches, unchecked
}

// mismatch is "" when got is what w asks for, else what was expected and what was found.
func (w *optWant) mismatch(opt string, got []string) string {
	found := quoted(opt, got)
	switch w.kind {
	case wantUnset:
		if len(got) > 0 {
			return "expected it unset, found " + found
		}
	case wantValue:
		if len(got) != 1 || got[0] != w.value {
			if isSecretOption(opt) && len(got) > 0 {
				return "the value read back is not the one set (secret values are not shown)"
			}
			return fmt.Sprintf("expected '%s', found %s", w.value, found)
		}
	case wantList:
		if strings.Join(got, "\x00") != strings.Join(w.list, "\x00") {
			if isSecretOption(opt) && len(got) > 0 {
				return "the list read back is not the one set (secret values are not shown)"
			}
			return "expected the list " + quoted(opt, w.list) + ", found " + found
		}
	case wantAny:
		for _, v := range w.with {
			if !contains(got, v) {
				return fmt.Sprintf("expected %s in the list, found %s", quoted(opt, []string{v}), found)
			}
		}
		for _, v := range w.without {
			if contains(got, v) {
				return fmt.Sprintf("expected %s out of the list, found %s", quoted(opt, []string{v}), found)
			}
		}
	}
	return ""
}

// verifyApplied re-reads every config the changes touched, after the commit and before any
// reload, and compares. mismatches is empty when everything matched; report is the text for the
// result ("" when nothing could be compared or read).
func verifyApplied(ctx context.Context, names []string, changes []UCIChange) (mismatches []string, report string) {
	var read, notes []string
	compared := 0
	for _, name := range names {
		var mine []UCIChange
		for _, c := range changes {
			if c.Config == name {
				mine = append(mine, c)
			}
		}
		tree, err := uciShow(ctx, name, false)
		if err != nil {
			notes = append(notes, fmt.Sprintf("Not verified: could not re-read %s after commit (%v).", name, err))
			continue
		}
		mm, unchecked := expectationMismatches(tree, mine)
		mismatches = append(mismatches, mm...)
		read = append(read, name)
		compared += len(mine) - unchecked
	}
	var lines []string
	if len(read) > 0 && len(mismatches) == 0 {
		line := fmt.Sprintf("Verified: re-read %s after commit, %d of %d change(s) match.", strings.Join(read, ", "), compared, len(changes))
		if skipped := len(changes) - compared; skipped > 0 && len(notes) == 0 {
			line += fmt.Sprintf(" (%d on a section addressed by position are not compared.)", skipped)
		}
		lines = append(lines, line)
	}
	return mismatches, strings.Join(append(lines, notes...), "\n")
}

// ---------------------------------------------------------------- WireGuard

// wgPeerNow reads the network config and the interface back, and returns the tree and the
// peer with this public key (nil if neither shows it).
func wgPeerNow(ctx context.Context, iface, pub string) (*uciTree, *wgPeer, error) {
	t, _, peers, err := loadWG(ctx, iface)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range peers {
		if p.PubKey == pub {
			return t, p, nil
		}
	}
	return t, nil, nil
}

// ---------------------------------------------------------------- pkg_change

const apkWorld = "/etc/apk/world"

// verifyWorld checks /etc/apk/world after an add or a del: apk records the packages the
// operator asked for there, so it is where "installed on purpose" is decided. A world entry may
// carry a version constraint (name>=1.2) or a repository tag (name@testing); only the name counts.
func verifyWorld(action string, pkgs []string) (line string, err error) {
	if action != "add" && action != "del" {
		return "", nil
	}
	body, rerr := readSys(apkWorld)
	if rerr != nil {
		return fmt.Sprintf("Not verified: could not read %s (%v).", apkWorld, rerr), nil
	}
	in := map[string]bool{}
	for _, entry := range strings.Fields(body) {
		in[entry[:indexAny(entry, "<>=~@")]] = true // "!name" keeps its "!", so it never equals name
	}
	var wrong []string
	for _, p := range pkgs {
		if in[p] != (action == "add") {
			wrong = append(wrong, p)
		}
	}
	if len(wrong) > 0 {
		if action == "add" {
			return "", notApplied("apk add exited 0, but %s does not list %s", apkWorld, strings.Join(wrong, ", "))
		}
		return "", notApplied("apk del exited 0, but %s still lists %s", apkWorld, strings.Join(wrong, ", "))
	}
	if action == "add" {
		return fmt.Sprintf("Verified: %s lists %s.", apkWorld, strings.Join(pkgs, ", ")), nil
	}
	return fmt.Sprintf("Verified: %s no longer lists %s.", apkWorld, strings.Join(pkgs, ", ")), nil
}

// indexAny is strings.IndexAny, returning len(s) when none of chars is in s.
func indexAny(s, chars string) int {
	if i := strings.IndexAny(s, chars); i >= 0 {
		return i
	}
	return len(s)
}

// wgKeepNote tells the operator where the new client's key is after a failed hot-add.
func wgKeepNote(confPath, name string) string {
	if confPath != "" {
		return fmt.Sprintf(" The client's config is still in %s: run `openwrt-mcp wg-show '%s'` on the router.", confPath, name)
	}
	return " The key was not shown (reveal=true): remove the peer with wg_remove_client and create it again."
}
