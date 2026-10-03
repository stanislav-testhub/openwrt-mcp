package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// Output redaction (ROADMAP 1.1). The audit log has always hidden secrets; this does the same
// for what a tool returns, because a result lands in a model's context window, a transcript
// and whatever the client forwards.
//
// It is a mask over text, not a parser of UCI. Three shapes carry an option and its value:
//
//	wireless.wifinet0.key='v'        uci show, uci changes (with a - or + prefix, and += / -=)
//	\toption key 'v'  /  list key v  uci export, config files, unified-diff lines
//	{"key": "v"}                     ubus replies
//
// Anything whose option name is secret (the same rule as the audit log: isSecretOption) keeps
// its shape and loses its value. An empty value is left alone: it says "no password set",
// which is worth knowing and hides nothing.

type maskMode int

const (
	maskUCI       maskMode = iota + 1 // text that may carry UCI lines
	maskJSONReply                     // a ubus reply: JSON, perhaps followed by a notice
)

// maskedTools: tools whose result can carry UCI values, by how to mask them.
var maskedTools = map[string]maskMode{
	"uci_get":            maskUCI, // the point of the tool: `uci show`
	"uci_apply":          maskUCI, // the staged diff, and errors that echo someone else's staged edit
	"uci_confirm":        maskUCI, // can echo restore or staging errors
	"uci_rollback":       maskUCI,
	"pkg_config_diff":    maskUCI, // diffs of /etc/config/* against the package default
	"pkg_config_resolve": maskUCI,
	"system_status":      maskUCI, // lists staged uci changes
	"ubus_call":          maskJSONReply,
}

// rawTools: everything else, each with the reason it is returned as the router printed it.
// A tool must be in exactly one of the two maps; a test enforces it, so a new tool cannot
// quietly skip the decision.
var rawTools = map[string]string{
	"exec":             "a root shell by design: whoever was granted it can read any file anyway",
	"logread":          "free-form log lines; masking free text is guesswork, so it is sanitised and labelled untrusted instead",
	"firewall_show":    "nftables rules carry addresses and ports, not credentials",
	"net_diag":         "ping, traceroute, DNS and route output: no configuration values",
	"network_clients":  "host names, addresses and signal levels: no credentials",
	"service_list":     "service names and run state only",
	"service_control":  "the init script's own output; no configuration values are read or printed",
	"pkg_query":        "package names, versions and file ownership only",
	"pkg_change":       "apk's transaction output; no configuration values",
	"sysupgrade":       "prints a status or the path of a backup, never the contents of a file",
	"wg_list_clients":  "public keys, endpoints and handshake times only: the private halves are never read",
	"wg_new_client":    "exempt on purpose: handing the operator the new client's private key is the tool's job",
	"wg_remove_client": "a confirmation line only",
	"ubus_list":        "object and method names with argument types: introspection, no values",
	"mfa_unlock":       "returns an expiry time, never a secret",
}

// maskForTool applies the tool's rule to out. in is the typed tool input: a ubus reply to a
// `uci get` of one secret option is just {"value": "..."} and only the request names the option.
func maskForTool(tool string, in any, out string, extra []string, enabled bool) string {
	if !enabled || out == "" {
		return out
	}
	switch maskedTools[tool] {
	case maskUCI:
		return maskUCIText(out, extra)
	case maskJSONReply:
		valuesSecret := false
		if u, ok := in.(ubusCallIn); ok {
			if o, ok := u.Args["option"].(string); ok {
				valuesSecret = secretOptionNamed(o, extra)
			}
		}
		return maskJSONWith(out, extra, valuesSecret)
	}
	return out
}

func secretOptionNamed(name string, extra []string) bool {
	if isSecretOption(name) {
		return true
	}
	for _, e := range extra {
		if strings.EqualFold(e, name) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- UCI text

var (
	// option key 'v' | list key v | -\toption key 'v' (a diff line). The name may be quoted.
	reUCIDecl = regexp.MustCompile(`^([-+ ]?[ \t]*(?:option|list)[ \t]+)('[^']*'|"[^"]*"|[^\s'"]+)([ \t]+)(\S.*)$`)

	// pkg.section.option followed by =, += or -=. A segment is any run of characters but space,
	// dot, equals and quotes: UCI itself only prints letters, digits and underscores (and the
	// @type[n] of an anonymous section), but a secret must not escape because a name holds
	// something else, which is how a long fuzz run found `!pwd`. A segment may not end in '-' or
	// '+', so that `dns-='x'` reads as option dns with operator -=.
	// Needs three segments: pkg.section=type is a section, not an option.
	reUCIPath = regexp.MustCompile(`([^\s.='"]*[^\s.='"+-](?:\.[^\s.='"]*[^\s.='"+-]){2,})(\+=|-=|=)`)
)

const maskedValue = "'" + redacted + "'"

// maskUCIText masks the value of every secret option in s, whatever else s contains.
func maskUCIText(s string, extra []string) string {
	if !strings.ContainsAny(s, "=") && !strings.Contains(s, "option") && !strings.Contains(s, "list") {
		return s
	}
	lines := strings.Split(s, "\n")
	changed := false
	for i, l := range lines {
		cr := ""
		if strings.HasSuffix(l, "\r") {
			l, cr = l[:len(l)-1], "\r"
		}
		if m := maskUCILine(l, extra); m != l {
			lines[i], changed = m+cr, true
		}
	}
	if !changed {
		return s
	}
	return strings.Join(lines, "\n")
}

func emptyUCIValue(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || v == "''" || v == `""`
}

func maskUCILine(l string, extra []string) string {
	if m := reUCIDecl.FindStringSubmatch(l); m != nil {
		name := strings.Trim(m[2], `'"`)
		if secretOptionNamed(name, extra) && !emptyUCIValue(m[4]) {
			return m[1] + m[2] + m[3] + maskedValue
		}
		return l
	}
	var out strings.Builder
	last, changed := 0, false
	for _, loc := range reUCIPath.FindAllStringSubmatchIndex(l, -1) {
		if loc[0] < last {
			continue // inside a value already masked
		}
		path := l[loc[2]:loc[3]]
		opt := path[strings.LastIndex(path, ".")+1:]
		valStart := loc[1]
		if !secretOptionNamed(opt, extra) || emptyUCIValue(l[valStart:]) {
			continue
		}
		end := len(l) // a line that starts with the path owns the rest of it, however odd
		if strings.Trim(l[:loc[0]], " \t+") != "" {
			end = valStart + uciValueEnd(l[valStart:]) // mid-line: only the value
		}
		out.WriteString(l[last:valStart])
		out.WriteString(maskedValue)
		last, changed = end, true
	}
	if !changed {
		return l
	}
	out.WriteString(l[last:])
	return out.String()
}

// uciValueEnd returns the length of the value at the start of s: a run of single-quoted words
// ('a' 'b', with '\” for an embedded quote), or one unquoted word.
func uciValueEnd(s string) int {
	if !strings.HasPrefix(s, "'") {
		if i := strings.IndexAny(s, " \t"); i >= 0 {
			return i
		}
		return len(s)
	}
	i := 0
	for i < len(s) && s[i] == '\'' {
		j := strings.IndexByte(s[i+1:], '\'')
		if j < 0 {
			return len(s)
		}
		i += j + 2
		for strings.HasPrefix(s[i:], `\''`) { // '\'' inside a value
			k := strings.IndexByte(s[i+3:], '\'')
			if k < 0 {
				return len(s)
			}
			i += k + 4
		}
		if strings.HasPrefix(s[i:], " '") { // the next word of a list
			i++
		}
	}
	return i
}

// ---------------------------------------------------------------- JSON

func maskJSON(s string, extra []string) string { return maskJSONWith(s, extra, false) }

// maskJSONWith masks a JSON reply. valuesSecret says the request asked for a secret option, so
// every "value" and "values" is secret even though nothing in the reply names the option.
//
// Text that does not parse as JSON (ubus error text) gets the UCI treatment. Text after the
// JSON value (the pruning notice) is kept, and treated the same way. A reply with nothing to
// mask is returned byte for byte, so the common case is exactly what ubus printed.
func maskJSONWith(s string, extra []string, valuesSecret bool) string {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return maskUCIText(s, extra)
	}
	tail := s[dec.InputOffset():]
	m := &jsonMasker{extra: extra, valuesSecret: valuesSecret}
	v = m.walk(v)
	maskedTail := maskUCIText(tail, extra)
	if m.n == 0 {
		if maskedTail == tail {
			return s
		}
		return s[:len(s)-len(tail)] + maskedTail
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "\t")
	if err := enc.Encode(v); err != nil {
		return maskUCIText(s, extra)
	}
	lead := s[:len(s)-len(strings.TrimLeft(s, " \t\r\n"))]
	return lead + strings.TrimRight(b.String(), "\n") + maskedTail
}

type jsonMasker struct {
	extra        []string
	valuesSecret bool
	n            int
}

func (m *jsonMasker) hide(v any) (any, bool) {
	switch t := v.(type) {
	case nil:
		return v, false
	case string:
		if t == "" {
			return v, false
		}
	}
	m.n++
	return redacted, true
}

func (m *jsonMasker) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		sibling := m.valuesSecret
		if o, ok := t["option"].(string); ok && secretOptionNamed(o, m.extra) {
			sibling = true
		}
		for k, e := range t {
			if secretOptionNamed(k, m.extra) || (sibling && (k == "value" || k == "values")) {
				if hidden, ok := m.hide(e); ok {
					t[k] = hidden
					continue
				}
			}
			t[k] = m.walk(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = m.walk(e)
		}
		return t
	case string:
		if masked := maskUCIText(t, m.extra); masked != t {
			m.n++
			return masked
		}
	}
	return v
}
