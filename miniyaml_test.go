package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestMiniYAMLScalarsAndComments(t *testing.T) {
	y := parseYAML(strings.Join([]string{
		"# a comment",
		"top: plain",
		"hash_inside: b#c",
		"hash_comment: b # c",
		"quoted_hash: 'x # y'",
		`double: "q"`,
		"escaped: 'it''s'",
		"empty: ''",
		"block:",
		"  child: 1",
		"  deeper:",
		"    leaf: yes",
		"  sibling: 2",
		"after: 3",
		"windows: line\r",
		"",
	}, "\n"))
	for path, want := range map[string]string{
		"top": "plain", "hash_inside": "b#c", "hash_comment": "b", "quoted_hash": "x # y", "double": "q",
		"escaped": "it's", "empty": "", "block.child": "1", "block.deeper.leaf": "yes", "block.sibling": "2",
		"after": "3", "windows": "line",
	} {
		if got := y.val(path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
	if y.val("child") != "" || y.val("leaf") != "" {
		t.Error("a nested key was readable without its path")
	}
}

func TestMiniYAMLListsAndMaps(t *testing.T) {
	y := parseYAML(strings.Join([]string{
		"dns:",
		"  hosts:",
		"    - 127.0.0.1",
		"    - '::1'  # loopback",
		"  flow: [a, 'b, c', \"d\"]",
		"  none: []",
		"  same:",
		"  - x",
		"  - y",
		"  - 'rule: with a colon'",
		"  after: 1",
		"filters:",
		"  - enabled: true",
		"    url: https://example.org/a.txt",
		"    nested:",
		"      enabled: false",
		"  - name: second",
		"    enabled: false",
		"users:",
		"  - name: u",
		"    password: p",
		"clients:",
		"  - name: c",
		"    ids:",
		"      - aa:bb",
		"other: z",
	}, "\n"))
	// A list nested inside an item belongs to nobody we ask about.
	if got := y.list("clients"); len(got) != 0 {
		t.Errorf("a nested list leaked into its owner's list: %q", got)
	}
	if c := y.items("clients"); len(c) != 1 || c[0]["name"] != "c" {
		t.Errorf("clients = %q", c)
	}
	lists := map[string][]string{
		"dns.hosts": {"127.0.0.1", "::1"},
		"dns.flow":  {"a", "b, c", "d"},
		"dns.same":  {"x", "y", "rule: with a colon"},
	}
	for path, want := range lists {
		if got := y.list(path); !reflect.DeepEqual(got, want) {
			t.Errorf("list %s = %q, want %q", path, got, want)
		}
	}
	if got := y.list("dns.none"); len(got) != 0 {
		t.Errorf("an empty flow list = %q", got)
	}
	if y.val("dns.after") != "1" || y.val("other") != "z" {
		t.Errorf("a key after a list was lost: %q %q", y.val("dns.after"), y.val("other"))
	}
	filters := y.items("filters")
	if len(filters) != 2 || filters[0]["enabled"] != "true" || filters[0]["url"] != "https://example.org/a.txt" ||
		filters[1]["enabled"] != "false" || filters[1]["name"] != "second" {
		t.Errorf("filters = %q", filters)
	}
	// An item's own keys, not what is nested under them.
	if filters[0]["nested"] != "" {
		t.Errorf("a nested key leaked into its item: %q", filters[0])
	}
	if u := y.items("users"); len(u) != 1 || u[0]["name"] != "u" {
		t.Errorf("users = %q", u)
	}
}

func TestMiniYAMLFlag(t *testing.T) {
	y := parseYAML("a: true\nb: False\nc: yes\nd:\ne: 'true'\n")
	for key, want := range map[string][2]bool{"a": {true, true}, "b": {false, true}, "c": {false, false}, "d": {false, false}, "e": {true, true}, "missing": {false, false}} {
		if v, ok := y.flag(key); v != want[0] || ok != want[1] {
			t.Errorf("flag(%s) = %v,%v want %v,%v", key, v, ok, want[0], want[1])
		}
	}
}

func TestUpstreamLabel(t *testing.T) {
	for in, want := range map[string]string{
		"9.9.9.9":      "9.9.9.9",
		"1.1.1.1:5353": "1.1.1.1:5353",
		"https://dns.example.net/dns-query/token":      "https://dns.example.net",
		"https://dns.example.net:8443/q?x=1#frag":      "https://dns.example.net:8443",
		"tls://user:pass@dns.example.org:853":          "tls://dns.example.org:853",
		"tls://dns.example.net#192.0.2.53":             "tls://dns.example.net",
		"quic://dns.example.net":                       "quic://dns.example.net",
		"[/lan/]192.0.2.1":                             "[/lan/]192.0.2.1",
		"[/example.com/]https://dns.example.net/q?t=s": "[/example.com/]https://dns.example.net",
		"sdns://AgcAAAAAAAAA":                          "sdns://(stamp)",
		"[/example.com/]sdns://AgcAAAAAAAAA":           "[/example.com/]sdns://(stamp)",
		"  9.9.9.9  ":                                  "9.9.9.9",
		"[/unterminated":                               "[/unterminated",
	} {
		if got := upstreamLabel(in); got != want {
			t.Errorf("upstreamLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if got := upstreamLabel("https://" + strings.Repeat("h", 200)); len([]rune(got)) != 81 {
		t.Errorf("a 200-character host came out as %d runes", len([]rune(got)))
	}
}
