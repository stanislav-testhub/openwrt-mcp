package main

import "strings"

// A reader for the small YAML subset AdGuard Home writes: nested mappings, block lists with
// "- " items, lists of mappings, flow lists on one line, plain and quoted scalars, comments. It
// answers by key path ("dns.port") and keeps nothing it was not asked for, which makes it safe
// against input it does not understand: that gives empty answers, not errors. It is not a YAML
// parser and is not used for anything but status text.

type miniYAML struct {
	vals  map[string]string              // "dns.port" -> "5354"
	lists map[string][]string            // "dns.bind_hosts" -> items (block or flow lists of scalars)
	maps  map[string][]map[string]string // "filters" -> one map per "- key: value" item
}

type yamlFrame struct {
	indent int
	key    string
}

func parseYAML(text string) *miniYAML {
	y := &miniYAML{vals: map[string]string{}, lists: map[string][]string{}, maps: map[string][]map[string]string{}}
	var stack []yamlFrame
	path := func() string {
		keys := make([]string, 0, len(stack))
		for _, f := range stack {
			keys = append(keys, f.key)
		}
		return strings.Join(keys, ".")
	}
	itemIndent := -1 // indent of the list item whose mapping is being read
	itemCol := -1    // column its own keys start at (after the "- ")
	var itemOwner string

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r \t")
		trim := strings.TrimLeft(line, " ")
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(trim)

		if trim == "-" || strings.HasPrefix(trim, "- ") {
			if itemIndent >= 0 && indent > itemIndent {
				continue // a list nested inside an item: not read
			}
			for len(stack) > 0 && stack[len(stack)-1].indent > indent {
				stack = stack[:len(stack)-1]
			}
			owner := path()
			item := strings.TrimSpace(strings.TrimPrefix(trim, "-"))
			key, val, isMap := splitYAMLKey(item)
			if isMap {
				y.maps[owner] = append(y.maps[owner], map[string]string{})
				itemIndent, itemOwner = indent, owner
				itemCol = indent + len(trim) - len(strings.TrimLeft(trim[1:], " "))
				if val = cleanYAMLScalar(val); key != "" {
					y.maps[owner][len(y.maps[owner])-1][key] = val
				}
			} else {
				itemIndent = -1
				y.lists[owner] = append(y.lists[owner], cleanYAMLScalar(item))
			}
			continue
		}

		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		key, val, isMap := splitYAMLKey(trim)
		if !isMap || key == "" {
			continue
		}
		if itemIndent >= 0 && indent > itemIndent {
			// A key inside a list item: only the item's own keys are kept, not nested ones.
			if ms := y.maps[itemOwner]; len(ms) > 0 && indent == itemCol {
				ms[len(ms)-1][key] = cleanYAMLScalar(val)
			}
			continue
		}
		itemIndent = -1
		full := path()
		if full != "" {
			full += "."
		}
		full += key
		switch {
		case val == "":
			stack = append(stack, yamlFrame{indent, key})
		case strings.HasPrefix(val, "["):
			y.lists[full] = flowYAMLList(val)
		default:
			y.vals[full] = cleanYAMLScalar(val)
		}
	}
	return y
}

func (y *miniYAML) val(path string) string                { return y.vals[path] }
func (y *miniYAML) list(path string) []string             { return append([]string(nil), y.lists[path]...) }
func (y *miniYAML) items(path string) []map[string]string { return y.maps[path] }

// flag reads a boolean; ok is false when the key is absent or not a plain true/false.
func (y *miniYAML) flag(path string) (value, ok bool) {
	switch strings.ToLower(y.vals[path]) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// splitYAMLKey splits "key: value" (value possibly empty). A line with no ": " and no trailing
// colon is not a mapping entry.
func splitYAMLKey(s string) (key, val string, ok bool) {
	if strings.HasSuffix(s, ":") {
		return strings.TrimSpace(s[:len(s)-1]), "", true
	}
	if i := strings.Index(s, ": "); i > 0 && !strings.HasPrefix(s, "'") && !strings.HasPrefix(s, `"`) {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), true
	}
	return "", "", false
}

// cleanYAMLScalar drops a trailing comment and one layer of matching quotes.
func cleanYAMLScalar(v string) string {
	v = strings.TrimSpace(stripYAMLComment(v))
	if n := len(v); n >= 2 {
		switch {
		case v[0] == '\'' && v[n-1] == '\'':
			return strings.ReplaceAll(v[1:n-1], "''", "'")
		case v[0] == '"' && v[n-1] == '"':
			return v[1 : n-1]
		}
	}
	return v
}

func stripYAMLComment(v string) string {
	var quote byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t'):
			return v[:i]
		}
	}
	return v
}

// flowYAMLList reads "[a, 'b']" on one line. An unterminated or empty list gives no items.
func flowYAMLList(v string) []string {
	v = strings.TrimSpace(stripYAMLComment(v))
	if !strings.HasPrefix(v, "[") || !strings.HasSuffix(v, "]") {
		return nil
	}
	var out []string
	var cur strings.Builder
	var quote byte
	flush := func() {
		if s := cleanYAMLScalar(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i := 1; i < len(v)-1; i++ {
		c := v[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == ',':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}
