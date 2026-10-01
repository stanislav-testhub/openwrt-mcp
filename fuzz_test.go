package main

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fuzz targets. Each states a property an attacker's input must not break, and checks it
// against an oracle that is written out here rather than derived from the code under test.
// Their seed corpora run as ordinary tests in `go test ./...`; `go test -fuzz=FuzzName` explores.

// ---------------------------------------------------------------- parsers

func FuzzSplitUCIRoundTripsAnyQuotedValue(f *testing.F) {
	for _, s := range []string{"", "plain", "has space", "# not a comment", "tab\there", `dq"inside`, "trailing ", " leading", "é€😀", "a=b.c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if strings.ContainsAny(v, "'\n\r\x00") || !utf8.ValidString(v) {
			t.Skip() // a single quote ends the value; line breaks end the line
		}
		fields, ok := splitUCI("\toption key '" + v + "'")
		if !ok || len(fields) != 3 || fields[0] != "option" || fields[1] != "key" || fields[2] != v {
			t.Fatalf("value %q came back as %q", v, fields)
		}
	})
}

func FuzzParseUCIIsTotal(f *testing.F) {
	f.Add("config policy 'a'\n\toption client 'x'\n\tlist tools 'y'\n")
	f.Add("option orphan 'x'\nlist orphan 'y'\nconfig\nconfig a b c d\n")
	f.Add("'unterminated\n\"also\n#\n\n\t\n")
	f.Fuzz(func(t *testing.T, text string) {
		secs := parseOne(t, text)
		for _, s := range secs {
			if s.Options == nil || s.Lists == nil {
				t.Fatalf("a section without its maps would panic the first writer: %+v", s)
			}
		}
	})
}

// ---------------------------------------------------------------- the browser defence

var originShape = regexp.MustCompile(`^(?i:https?)://[^/@\\#?\s]+/?$`)

func FuzzLoopbackOriginAcceptsOnlyAPlainSchemeHostPort(f *testing.F) {
	for _, s := range []string{
		"http://localhost:8730", "https://127.0.0.1", "http://[::1]:80", "http://localhost:80@evil.example",
		"http://evil.example", "null", "", "http://127.0.0.1.evil.example", "http://localhost\\@evil.example",
		"http://localhost/@evil.example", "https://localhost:443#@evil.example", "http://LOCALHOST", "ftp://localhost",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, o string) {
		if !isLoopbackOrigin(o) {
			return
		}
		// Whatever is accepted must be scheme://host[:port] with nothing that could hide a
		// second host: no userinfo, backslash, fragment, query or whitespace.
		if !originShape.MatchString(o) {
			t.Fatalf("accepted %q, which is not a plain scheme://host[:port]", o)
		}
		host := o[strings.Index(o, "://")+3:]
		host = strings.TrimSuffix(host, "/")
		if i := strings.LastIndex(host, ":"); i > strings.LastIndex(host, "]") {
			host = host[:i]
		}
		host = strings.Trim(host, "[]")
		if !strings.EqualFold(host, "localhost") && !isLoopbackIP(host) {
			t.Fatalf("accepted %q, whose host %q is not loopback", o, host)
		}
	})
}

func isLoopbackIP(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// ---------------------------------------------------------------- authorized_keys line

var authorizedKeyShape = regexp.MustCompile(
	`^command="/usr/bin/openwrt-mcp stdio --client [A-Za-z0-9._-]{1,64}",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]{40,}( [^\x00-\x1f\x7f]*)?$`)

func FuzzAuthorizedKeyLineCannotCarryExtraOptions(f *testing.F) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFO0iuRsB94YVh5gQOh1bEhtC7nqAo8hVcErAVnqOLmD mcp"
	f.Add("claude-code", key)
	f.Add(`c",command="sh`, key)
	f.Add("c", key+"\ncommand=\"sh\" ssh-ed25519 AAAA")
	f.Add("c\n", key)
	f.Add("c", `ssh-ed25519 `+strings.Repeat("A", 60)+` comment" ,permitopen="x`)
	f.Fuzz(func(t *testing.T, client, key string) {
		line, err := authorizedKeyLine(client, key)
		if err != nil {
			return
		}
		// One line, one forced command, a fixed option set, then the key: nothing the caller
		// typed can add an option (a second command=, a from=, a permitopen=) or a second key.
		if !authorizedKeyShape.MatchString(line) {
			t.Fatalf("(%q, %q) produced a line outside the fixed shape:\n%q", client, key, line)
		}
	})
}

// ---------------------------------------------------------------- policy matching

func FuzzScopeMatchingIsLiteralUnlessThePolicyUsesWildcards(f *testing.F) {
	f.Add("dhcp.pi", "dhcp.pi")
	f.Add("firewall.@rule[3].*", "firewall.@rule[3].enabled")
	f.Add("a*", "ab")
	f.Add("[ab]", "a")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, glob, scope string) {
		_ = matchAny([]string{glob}, scope) // must not panic on any pattern
		if !matchAny([]string{"*"}, scope) {
			t.Fatalf("the catch-all grant does not cover %q", scope)
		}
		if !matchAny([]string{scope}, scope) {
			t.Fatalf("a grant equal to the scope %q does not cover it", scope)
		}
		// With no wildcard or escape in the glob, matching is plain equality, brackets included.
		if !strings.ContainsAny(glob, `*?\`) {
			if got := matchAny([]string{glob}, scope); got != (glob == scope) {
				t.Fatalf("literal glob %q vs scope %q matched=%v", glob, scope, got)
			}
		}
	})
}

// ---------------------------------------------------------------- output shaping

func FuzzPruneNeverGrowsAndStaysParseable(f *testing.F) {
	f.Add(uint8(40), uint8(28), uint16(8192), false)
	f.Add(uint8(17), uint8(1), uint16(8200), true)
	f.Add(uint8(200), uint8(60), uint16(100), false)
	f.Fuzz(func(t *testing.T, n, valueLen uint8, pad uint16, nested bool) {
		items := make([]any, int(n))
		for i := range items {
			items[i] = strings.Repeat("v", int(valueLen))
		}
		var doc any = map[string]any{"pad": strings.Repeat("p", int(pad)), "a": items}
		if nested {
			doc = map[string]any{"outer": []any{doc, doc}, "x": items}
		}
		b, _ := json.MarshalIndent(doc, "", "\t")
		in := string(b)
		out := pruneUbusJSON(in)
		if len(out) > len(in) {
			t.Fatalf("grew %d -> %d", len(in), len(out))
		}
		if out != in {
			body, _, ok := strings.Cut(out, "\n\n[pruned:")
			var v any
			if !ok || json.Unmarshal([]byte(body), &v) != nil {
				t.Fatalf("pruned output is not JSON followed by a notice:\n%.200s", out)
			}
		}
	})
}

func FuzzTextResultIsBoundedAndNeverSplitsACharacter(f *testing.F) {
	f.Add("short", uint32(0))
	f.Add("€", uint32(maxResultBytes/3+5))
	f.Add("😀", uint32(maxResultBytes/4+5))
	f.Fuzz(func(t *testing.T, unit string, repeat uint32) {
		if !utf8.ValidString(unit) || len(unit) == 0 || len(unit) > 8 || repeat > 100_000 {
			t.Skip()
		}
		in := strings.Repeat(unit, int(repeat))
		got := textResult(in).Content[0].(*mcp.TextContent).Text
		if !utf8.ValidString(got) {
			t.Fatalf("invalid UTF-8 for %d x %q", repeat, unit)
		}
		if len(got) > maxResultBytes+400 {
			t.Fatalf("%d bytes returned for a %d byte input", len(got), len(in))
		}
	})
}

func FuzzAuditRedactionHidesTheValueOfASecretOption(f *testing.F) {
	for _, o := range []string{"key", "KEY", "key1", "psk", "password", "private_key", "preshared_key", "wpa_psk", "ssid", "keyId", "ipaddr"} {
		f.Add(o)
	}
	f.Fuzz(func(t *testing.T, option string) {
		if strings.Contains(option, "LEAK-MARKER") || !utf8.ValidString(option) {
			t.Skip()
		}
		change := map[string]any{"config": "wireless", "section": "x", "option": option, "value": "LEAK-MARKER-1",
			"values": []any{"LEAK-MARKER-2"}}
		out, _ := json.Marshal(redact(map[string]any{"changes": []any{change}}))
		secret := isSecretKey(option) || regexp.MustCompile(`(?i)^key[0-9]*$`).MatchString(option)
		leaked := strings.Contains(string(out), "LEAK-MARKER")
		if secret && leaked {
			t.Fatalf("option %q is secret but its value reached the log: %s", option, out)
		}
		if !secret && !strings.Contains(string(out), "LEAK-MARKER-1") {
			t.Fatalf("option %q is not secret but its value was hidden: %s", option, out)
		}
	})
}

// ---------------------------------------------------------------- what reaches a program

// optionLike reports an argv element, past the program name, that begins with '-' and is not one
// of the flags the code itself passes.
func optionLike(argv []string) string {
	for _, e := range argv[1:] {
		if strings.HasPrefix(e, "-") && !optionFlags[e] {
			return e
		}
	}
	return ""
}

func FuzzNoCallerValueBecomesAnOptionOrEscapesItsSlot(f *testing.F) {
	f.Add("-x", "--help", "-f", "/tmp/x")
	f.Add("inet", "fw4", "forward_lan", "1.1.1.1")
	f.Add("ping", "-6", "wg0", "example.com")
	f.Add("a b", "a;b", "$(id)", "a\nb")
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		f := everythingFake(t)
		withFixtureRoot(t)
		ctx := context.Background()

		_, _, _ = netDiag(ctx, netDiagIn{Action: "ping", Target: a, Iface: b})
		_, _, _ = netDiag(ctx, netDiagIn{Action: "traceroute", Target: a, Iface: b})
		_, _, _ = netDiag(ctx, netDiagIn{Action: "nslookup", Target: a, Server: b})
		_, _, _ = netDiag(ctx, netDiagIn{Action: "route", Table: a})
		_, _, _ = firewallShow(ctx, firewallShowIn{View: "chain", Family: a, Table: b, Chain: c})
		_, _, _ = firewallShow(ctx, firewallShowIn{View: "table", Family: a, Table: b})
		_, _, _ = pkgQuery(ctx, pkgQueryIn{Action: "installed", Package: a})
		_, _, _ = pkgQuery(ctx, pkgQueryIn{Action: "info", Package: a})
		_, _, _ = pkgQuery(ctx, pkgQueryIn{Action: "owner", Path: a})
		_, _, _ = pkgChange(ctx, pkgChangeIn{Action: "add", Packages: []string{a, b}})
		_, _, _ = uciGet(ctx, uciGetIn{Config: a, Section: b, Option: c})
		_, _, _ = ubusCall(ctx, ubusCallIn{Object: a, Method: b})
		_, _, _ = sysupgradeTool(ctx, sysupgradeIn{Action: "test", Image: a})
		_, _, _ = serviceControl(ctx, serviceControlIn{Name: a, Action: b})

		for _, argv := range f.argvList() {
			if e := optionLike(argv); e != "" {
				t.Fatalf("%q reached the command %q as an option", e, strings.Join(argv, " "))
			}
		}
	})
}

var backupName = regexp.MustCompile(`^/tmp/backup-[A-Za-z0-9_-]+-\d{8}-\d{6}\.tar\.gz$`)

func FuzzSysupgradeNeverRunsAnythingThatFlashes(f *testing.F) {
	f.Add("test", "/tmp/fw.bin", "OpenWrt")
	f.Add("flash", "/tmp/fw.bin", "x")
	f.Add("test", "/tmp/../etc/passwd", "x")
	f.Add("backup", "", "../../etc/x; reboot")
	f.Add("test", "-T", "")
	f.Fuzz(func(t *testing.T, action, image, host string) {
		root := withFixtureRoot(t)
		r := newFakeRouter(t)
		r.on("uci -q get system.@system[0].hostname", host)
		r.on("sysupgrade -l", "files")
		r.on("sysupgrade -T", "")
		r.onFn("sysupgrade -k -b", func(argv []string, _ string) (string, error) {
			writeFixture(t, root, strings.TrimPrefix(argv[3], "/"), "archive")
			return "", nil
		})
		_, _, _ = sysupgradeTool(context.Background(), sysupgradeIn{Action: action, Image: image})

		for _, argv := range r.argvList() {
			if argv[0] != "sysupgrade" {
				continue
			}
			switch {
			case len(argv) == 2 && argv[1] == "-l":
			case len(argv) == 3 && argv[1] == "-T" && strings.HasPrefix(argv[2], "/tmp/") && !strings.Contains(argv[2], ".."):
			case len(argv) == 4 && argv[1] == "-k" && argv[2] == "-b" && backupName.MatchString(argv[3]):
			default:
				t.Fatalf("sysupgrade ran %q for action %q image %q host %q: not one of -l, -T <file in /tmp>, -k -b <archive in /tmp>",
					argv, action, image, host)
			}
		}
	})
}

func FuzzAValidatedUCIChangeAddressesExactlyTheKeyItWasScopedAs(f *testing.F) {
	f.Add("dhcp", "pi", "ip", "192.168.1.5", "", "")
	f.Add("wireless", "@wifi-iface[0]", "ssid", "Home", "", "set")
	f.Add("a.b", "c=d", "e", "f", "", "")
	f.Add("-x", "s", "o", "v", "", "")
	f.Add("network", "wg0", "addresses", "10.0.0.1/24", "", "add_list")
	f.Fuzz(func(t *testing.T, config, section, option, value, typ, op string) {
		c := UCIChange{Op: op, Config: config, Section: section, Option: option, Value: value, Type: typ}
		if validateChange(c) != nil {
			return
		}
		key := uciKey(c) // what the policy is checked against
		for _, cmd := range uciCmds(c) {
			if len(cmd.argv) == 0 || cmd.argv[0] != "uci" {
				t.Fatalf("not a uci command: %q", cmd.argv)
			}
			target := cmd.argv[len(cmd.argv)-1]
			acted, _, _ := strings.Cut(target, "=") // the part uci reads as the key
			if acted != key {
				t.Fatalf("policy was checked against %q but uci acts on %q (change %+v)", key, acted, c)
			}
			if strings.HasPrefix(target, "-") {
				t.Fatalf("the key %q would be read as an option", target)
			}
		}
		parts := strings.Split(key, ".")
		want := 2
		if option != "" {
			want = 3
		}
		if len(parts) != want || parts[0] != config || parts[1] != section {
			t.Fatalf("key %q does not split back into config %q, section %q (%+v)", key, config, section, c)
		}
	})
}
