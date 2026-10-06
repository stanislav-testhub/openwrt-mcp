package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ROADMAP 1.1: the audit log has always hidden secrets; tool results did not. A model that
// reads `uci_get wireless` was handed the Wi-Fi password, and from there it sits in a context
// window, a transcript, and whatever the client forwards. These tests pin what a caller can
// see. The list of secret option names below is written out here, from the roadmap, and is
// deliberately not read from the code: iterating the code's own table would pass the day
// someone deletes an entry from it.

var specSecretNames = []string{
	"key", "key1", "key2", "key3", "key4", "psk", "password", "sae_password", "passphrase",
	"private_key", "preshared_key", "token",
}

// extraSecretName is configured through `option redact_extra`; matched exactly, any case.
const extraSecretName = "Vendor_Blob"

func secretFor(name string) string { return "hunter2-" + strings.ToUpper(name) + "-Zq7" }

// The neighbours of a secret that must survive: not secret options, and a value that merely
// contains a secret-looking word (`encryption 'psk2'`).
var wirelessNeighbours = []string{"HomeNet", "psk2", "PUBKEYVALUE="}

func uciShowFor(name, secret string) string {
	return strings.Join([]string{
		"wireless.wifinet0=wifi-iface",
		"wireless.wifinet0.ssid='HomeNet'",
		"wireless.wifinet0.encryption='psk2'",
		"wireless.wifinet0.keyid='7'",
		"wireless.wifinet0.publickey='PUBKEYVALUE='",
		"wireless.wifinet0." + name + "='" + secret + "'",
		"",
	}, "\n")
}

func wirelessFile(name, secret string) string {
	return "config wifi-iface 'wifinet0'\n\toption ssid 'HomeNet'\n\toption encryption 'psk2'\n" +
		"\toption " + name + " '" + secret + "'\n\toption publickey 'PUBKEYVALUE='\n"
}

// redactServer is a server with every tool granted for client "c" and the extra secret name
// configured, over a fixture root holding /etc/config/wireless.
func redactServer(t *testing.T, serverOpts string) (*Server, *fakeRouter, string) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/wireless", wirelessFile("key", "old"))
	f := everythingFake(t)
	s := testServer(t, "config server\n\toption redact_extra 'vendor_blob'\n"+serverOpts+grantAll())
	return s, f, root
}

// fakeUCIShow renders simple config text the way `uci show` would: enough for the settings diff.
func fakeUCIShow(name, body string) string {
	var out []string
	sec := ""
	for _, l := range strings.Split(body, "\n") {
		f := strings.Fields(l)
		switch {
		case len(f) == 3 && f[0] == "config":
			sec = strings.Trim(f[2], "'")
			out = append(out, name+"."+sec+"="+f[1])
		case len(f) >= 3 && f[0] == "option":
			out = append(out, name+"."+sec+"."+f[1]+"="+strings.Join(f[2:], " "))
		}
	}
	return strings.Join(out, "\n")
}

// redactHistory is a server whose wireless history holds one old version (secret + "-old") and
// whose live file holds another (secret + "-live"), with uci show stood in by fakeUCIShow.
func redactHistory(t *testing.T, name, secret string) (*Server, string) {
	t.Helper()
	s, f, root := redactServer(t, "")
	f.onFn("uci -q -c", func(argv []string, _ string) (string, error) {
		b, err := os.ReadFile(filepath.Join(argv[3], "wireless"))
		return fakeUCIShow("wireless", string(b)), err
	})
	writeFixture(t, root, "etc/config/wireless", wirelessFile(name, secret+"-live"))
	s.saveHistory("wireless", []byte(wirelessFile(name, secret+"-old")), 0o644, "c", "test", "seed")
	return s, s.historyEntries("wireless")[0].id()
}

type readPath struct {
	name string
	run  func(t *testing.T, name, secret string) string
}

var readPaths = []readPath{
	{"uci_get", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("uci show wireless", uciShowFor(name, secret))
		out, _ := callText(t, connectClient(t, s, "c"), "uci_get", map[string]any{"config": "wireless"})
		return out
	}},
	{"uci_get one option", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("uci show wireless.wifinet0."+name, "wireless.wifinet0."+name+"='"+secret+"'\n")
		out, _ := callText(t, connectClient(t, s, "c"), "uci_get",
			map[string]any{"config": "wireless", "section": "wifinet0", "option": name})
		return out
	}},
	{"uci_apply dry run diff", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("uci set", "")
		f.on("uci revert", "")
		calls := 0
		f.onFn("uci changes", func([]string, string) (string, error) {
			calls++
			if calls == 1 {
				return "", nil // the "someone else's edit" check, before staging
			}
			return uciShowFor(name, secret), nil
		})
		out, _ := callText(t, connectClient(t, s, "c"), "uci_apply", map[string]any{"dry_run": true,
			"changes": []map[string]any{{"config": "wireless", "section": "wifinet0", "option": name, "value": secret}}})
		return out
	}},
	{"uci_apply refusal echoing someone else's staged edit", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("uci changes", uciShowFor(name, secret))
		out, isErr := callText(t, connectClient(t, s, "c"), "uci_apply", map[string]any{"dry_run": true,
			"changes": []map[string]any{{"config": "wireless", "section": "wifinet0", "option": "ssid", "value": "x"}}})
		if !isErr || !strings.Contains(out, "refusing to apply") {
			t.Fatalf("expected the refusal path, got isError=%v: %s", isErr, out)
		}
		return out
	}},
	{"pkg_config_diff line diff", func(t *testing.T, name, secret string) string {
		s, f, root := redactServer(t, "")
		f.fail("uci -q", "uci: cannot parse") // so the diff falls back to the raw lines
		writeFixture(t, root, "etc/config/wireless", wirelessFile(name, secret+"-live"))
		writeFixture(t, root, "etc/config/wireless.apk-new", wirelessFile(name, secret+"-new"))
		out, _ := callText(t, connectClient(t, s, "c"), "pkg_config_diff", map[string]any{"path": "/etc/config/wireless"})
		if !strings.Contains(out, "line diff") {
			t.Fatalf("expected the raw line diff:\n%s", out)
		}
		return out
	}},
	{"pkg_config_diff settings diff", func(t *testing.T, name, secret string) string {
		s, f, root := redactServer(t, "")
		f.onFn("uci -q -c", func(argv []string, _ string) (string, error) {
			// `uci -q -c <dir> -t <dir> show wireless`: render the copy it was given.
			b, err := os.ReadFile(filepath.Join(argv[3], "wireless"))
			return fakeUCIShow("wireless", string(b)), err
		})
		writeFixture(t, root, "etc/config/wireless", wirelessFile(name, secret+"-live"))
		writeFixture(t, root, "etc/config/wireless.apk-new", wirelessFile(name, secret+"-new"))
		out, _ := callText(t, connectClient(t, s, "c"), "pkg_config_diff", map[string]any{"path": "/etc/config/wireless"})
		if !strings.Contains(out, "settings diff via uci show") {
			t.Fatalf("expected the settings diff:\n%s", out)
		}
		return out
	}},
	{"uci_get history diff", func(t *testing.T, name, secret string) string {
		s, id := redactHistory(t, name, secret)
		out, _ := callText(t, connectClient(t, s, "c"), "uci_get", map[string]any{"config": "wireless", "history": "diff:" + id})
		if !strings.Contains(out, "before that change") {
			t.Fatalf("expected the history diff:\n%s", out)
		}
		return out
	}},
	{"uci_apply restore dry run diff", func(t *testing.T, name, secret string) string {
		s, id := redactHistory(t, name, secret)
		out, _ := callText(t, connectClient(t, s, "c"), "uci_apply", map[string]any{"restore": id, "dry_run": true})
		if !strings.Contains(out, "Restoring wireless would change") {
			t.Fatalf("expected the restore dry run:\n%s", out)
		}
		return out
	}},
	{"system_status uncommitted block", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("uci changes", uciShowFor(name, secret))
		out, _ := callText(t, connectClient(t, s, "c"), "system_status", map[string]any{})
		if !strings.Contains(out, "uncommitted uci changes") {
			t.Fatalf("status did not list the staged changes:\n%s", out)
		}
		return out
	}},
	{"ubus_call JSON", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("ubus call uci get", fmt.Sprintf(`{"values":{"wifinet0":{".type":"wifi-iface","ssid":"HomeNet",`+
			`"encryption":"psk2","publickey":"PUBKEYVALUE=",%q:%q}}}`, name, secret))
		out, _ := callText(t, connectClient(t, s, "c"), "ubus_call",
			map[string]any{"object": "uci", "method": "get", "args": map[string]any{"config": "wireless"}})
		return out
	}},
	{"ubus_call uci get of one option", func(t *testing.T, name, secret string) string {
		s, f, _ := redactServer(t, "")
		f.on("ubus call uci get", fmt.Sprintf(`{"value":%q}`, secret))
		out, _ := callText(t, connectClient(t, s, "c"), "ubus_call", map[string]any{"object": "uci", "method": "get",
			"args": map[string]any{"config": "wireless", "section": "wifinet0", "option": name}})
		return out
	}},
}

func TestEverySecretNameIsHiddenOnEveryReadPath(t *testing.T) {
	names := append(append([]string(nil), specSecretNames...), extraSecretName, "Key", "PSK")
	for _, rp := range readPaths {
		for _, name := range names {
			t.Run(rp.name+"/"+name, func(t *testing.T) {
				secret := secretFor(name)
				out := rp.run(t, name, secret)
				if strings.Contains(out, secret) {
					t.Errorf("the value of %q reached the caller:\n%s", name, out)
				}
				if !strings.Contains(out, "<redacted>") {
					t.Errorf("nothing was marked as redacted for %q:\n%s", name, out)
				}
				if strings.HasPrefix(rp.name, "ubus_call uci get of one") {
					return // the reply carries a single value and no neighbours
				}
				if strings.HasPrefix(rp.name, "uci_get one") {
					return
				}
				for _, want := range wirelessNeighbours {
					if !strings.Contains(out, want) {
						t.Errorf("masking %q also removed the neighbouring %q:\n%s", name, want, out)
					}
				}
			})
		}
	}
}

func TestNonSecretOptionsAreNotMasked(t *testing.T) {
	s, f, _ := redactServer(t, "")
	f.on("uci show wireless", strings.Join([]string{
		"wireless.w.ssid='HomeNet'", "wireless.w.keyid='7'", "wireless.w.publickey='AAA='",
		"wireless.w.encryption='sae-mixed'", "wireless.w.ieee80211w='2'", "wireless.w.network='lan'",
	}, "\n"))
	out, _ := callText(t, connectClient(t, s, "c"), "uci_get", map[string]any{"config": "wireless"})
	for _, want := range []string{"'HomeNet'", "keyid='7'", "'AAA='", "'sae-mixed'", "'2'", "'lan'"} {
		if !strings.Contains(out, want) {
			t.Errorf("a non-secret value was masked (%s missing):\n%s", want, out)
		}
	}
	if strings.Contains(out, "<redacted>") {
		t.Errorf("something was masked in an output with no secret:\n%s", out)
	}
}

func TestSecretNameDoesNotHideAnotherToolsOutput(t *testing.T) {
	// logread, exec and the rest are raw by decision (see the tool table); a line that looks
	// like a UCI secret in them is returned as is.
	s, f, _ := redactServer(t, "")
	f.on("logread", "daemon: wireless.w.key='from-the-log'\n")
	out, _ := callText(t, connectClient(t, s, "c"), "logread", map[string]any{})
	if !strings.Contains(out, "from-the-log") {
		t.Errorf("logread was masked although it is listed as raw:\n%s", out)
	}
}

// ---------------------------------------------------------------- the text and JSON maskers

func TestMaskUCITextLineShapes(t *testing.T) {
	const r = "<redacted>"
	for _, tc := range []struct{ in, want string }{
		// uci show / uci changes
		{"wireless.w.key='abc'", "wireless.w.key='" + r + "'"},
		{"wireless.w.KEY='abc'", "wireless.w.KEY='" + r + "'"},
		{"-wireless.w.key='abc'", "-wireless.w.key='" + r + "'"},
		{"+wireless.w.psk='a b c'", "+wireless.w.psk='" + r + "'"},
		{"wireless.w.key+='abc'", "wireless.w.key+='" + r + "'"},
		{"wireless.w.key-='abc'", "wireless.w.key-='" + r + "'"},
		{"wireless.@wifi-iface[0].key='abc'", "wireless.@wifi-iface[0].key='" + r + "'"},
		{`wireless.w.key='it'\''s'`, "wireless.w.key='" + r + "'"},
		{"wireless.w.key=abc", "wireless.w.key='" + r + "'"},
		{"wireless.w.password='a' 'b'", "wireless.w.password='" + r + "'"},
		{"network.wg0.private_key='abc='", "network.wg0.private_key='" + r + "'"},
		{"network.peer.preshared_key='abc='", "network.peer.preshared_key='" + r + "'"},
		{"wireless.w.sae_password='abc'", "wireless.w.sae_password='" + r + "'"},
		{"wireless.w.passphrase='abc'", "wireless.w.passphrase='" + r + "'"},
		{"x.y.token='abc'", "x.y.token='" + r + "'"},
		{"wireless.w.pwd='abc'", "wireless.w.pwd='" + r + "'"},
		// uci export / config files / unified-diff lines
		{"\toption key 'abc'", "\toption key '" + r + "'"},
		{"\toption key1 'abc'", "\toption key1 '" + r + "'"},
		{"\toption key abc", "\toption key '" + r + "'"},
		{"\toption 'key' 'abc'", "\toption 'key' '" + r + "'"},
		{"\tlist password 'abc'", "\tlist password '" + r + "'"},
		{"option psk 'abc'", "option psk '" + r + "'"},
		{"-\toption key 'abc'", "-\toption key '" + r + "'"},
		{"+\toption key 'abc'", "+\toption key '" + r + "'"},
		{" \toption key 'abc'", " \toption key '" + r + "'"},
		{"+\t\toption  private_key   'abc'", "+\t\toption  private_key   '" + r + "'"},
		// an error message that echoes a change: only the value goes, the sentence stays
		{"uci: bad value for wireless.w.key='abc def' (try again)", "uci: bad value for wireless.w.key='" + r + "' (try again)"},
		{"uci: bad value for wireless.w.key=abc rest", "uci: bad value for wireless.w.key='" + r + "' rest"},
		{`uci: bad wireless.w.key='it'\''s' end`, "uci: bad wireless.w.key='" + r + "' end"},
		{"uci: bad wireless.w.psk='a' 'b' end", "uci: bad wireless.w.psk='" + r + "' end"},
		// UCI only prints letters, digits and underscores in a name, but a secret must not escape
		// because a name holds anything else (a long fuzz run found "!pwd")
		{"wireless.w.!pwd='abc'", "wireless.w.!pwd='" + r + "'"},
		{"-wireless.w.x:psk+='abc'", "-wireless.w.x:psk+='" + r + "'"},
		{"uci: x wireless.w.$token='abc' end", "uci: x wireless.w.$token='" + r + "' end"},
		// two secrets in one message: each value goes, the words between them stay
		{"uci: x wireless.w.key='a b' and wireless.w.psk='c' done", "uci: x wireless.w.key='" + r + "' and wireless.w.psk='" + r + "' done"},
		{"uci: x wireless.w.key=abc wireless.w.psk=def", "uci: x wireless.w.key='" + r + "' wireless.w.psk='" + r + "'"},
		// a line that starts with a secret option owns the rest of the line, a second pair included
		{"wireless.w.key='a' wireless.w.psk='b'", "wireless.w.key='" + r + "'"},
		// a value whose quote is never closed is masked to the end of the line
		{"uci: bad wireless.w.key='abc def", "uci: bad wireless.w.key='" + r + "'"},
		{`uci: bad wireless.w.key='it'\''s`, "uci: bad wireless.w.key='" + r + "'"},
		// empty is not a secret: it says "no password set"
		{"wireless.w.key=''", "wireless.w.key=''"},
		{"wireless.w.key=", "wireless.w.key="},
		{"\toption key ''", "\toption key ''"},
		{"\toption psk \"\"", "\toption psk \"\""},
		// not secrets
		{"wireless.w.ssid='HomeNet'", "wireless.w.ssid='HomeNet'"},
		{"wireless.w.keyid='7'", "wireless.w.keyid='7'"},
		{"wireless.w.publickey='AAA='", "wireless.w.publickey='AAA='"},
		{"wireless.w.encryption='psk2'", "wireless.w.encryption='psk2'"},
		{"wireless.key=wifi-iface", "wireless.key=wifi-iface"},
		{"network.lan.dns+='1.1.1.1'", "network.lan.dns+='1.1.1.1'"},
		{"\toption ssid 'key'", "\toption ssid 'key'"},
		{"\toption encryption 'psk2'", "\toption encryption 'psk2'"},
		{"\toption keyid '7'", "\toption keyid '7'"},
		{"error: the key is wrong", "error: the key is wrong"},
		{"key=value", "key=value"},
		{"", ""},
	} {
		if got := maskUCIText(tc.in, nil); got != tc.want {
			t.Errorf("maskUCIText(%q)\n got  %q\n want %q", tc.in, got, tc.want)
		}
	}

	// Several lines at once, line endings kept.
	in := "wireless.w.ssid='A'\r\nwireless.w.key='k1'\r\n\toption psk 'k2'\n\n+wireless.w.token='k3'"
	want := "wireless.w.ssid='A'\r\nwireless.w.key='<redacted>'\r\n\toption psk '<redacted>'\n\n+wireless.w.token='<redacted>'"
	if got := maskUCIText(in, nil); got != want {
		t.Errorf("multi-line: got %q want %q", got, want)
	}

	// Extra names: exact, any case, and only when configured.
	line := "\toption vendor_blob 'x'"
	if got := maskUCIText(line, nil); got != line {
		t.Errorf("an unconfigured name was masked: %q", got)
	}
	if got := maskUCIText(line, []string{"Vendor_Blob"}); got != "\toption vendor_blob '<redacted>'" {
		t.Errorf("a configured name was not masked: %q", got)
	}
	if got := maskUCIText("\toption vendor_blob_2 'x'", []string{"vendor_blob"}); strings.Contains(got, "redacted") {
		t.Errorf("redact_extra matched by prefix, want an exact name: %q", got)
	}
}

func TestMaskJSON(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"secret keys at any depth",
			`{"a":{"key":"k","keyid":"id","list":[{"password":"p","ssid":"s"}]}}`,
			`{"a":{"key":"<redacted>","keyid":"id","list":[{"password":"<redacted>","ssid":"s"}]}}`},
		{"option and value siblings",
			`{"option":"key","value":"v","values":["a","b"]}`,
			`{"option":"key","value":"<redacted>","values":"<redacted>"}`},
		{"non-secret option keeps its value",
			`{"option":"ssid","value":"v"}`, `{"option":"ssid","value":"v"}`},
		{"a secret holding a structure is replaced whole",
			`{"psk":{"a":1,"b":[2]},"x":1}`, `{"psk":"<redacted>","x":1}`},
		{"numbers are not rounded",
			`{"id":12345678901234567890,"key":1,"f":1.50}`, `{"id":12345678901234567890,"key":"<redacted>","f":1.50}`},
		{"multi-line string leaf is masked as UCI text",
			`{"data":"config wifi-iface\n\toption key 'abc'\n\toption ssid 'x'\n"}`,
			`{"data":"config wifi-iface\n\toption key '<redacted>'\n\toption ssid 'x'\n"}`},
		{"empty secrets stay empty", `{"key":"","psk":null,"password":"x"}`, `{"key":"","psk":null,"password":"<redacted>"}`},
		{"html characters are not escaped",
			`{"key":"k","note":"a<b&c>d"}`, `{"key":"<redacted>","note":"a<b&c>d"}`},
	} {
		got := maskJSON(tc.in, nil)
		var a, b any
		if json.Unmarshal([]byte(got), &a) != nil || json.Unmarshal([]byte(tc.want), &b) != nil {
			t.Errorf("%s: not JSON\n got  %s\n want %s", tc.name, got, tc.want)
			continue
		}
		ga, _ := json.Marshal(a)
		gb, _ := json.Marshal(b)
		if string(ga) != string(gb) || strings.Contains(got, `\u003c`) {
			t.Errorf("%s:\n got  %s\n want %s", tc.name, got, tc.want)
		}
	}

	// Numbers keep their exact text: a counter above 2^53 must not come back rounded.
	if got := maskJSON(`{"id":12345678901234567890,"f":1.50,"key":"k"}`, nil); !strings.Contains(got, "12345678901234567890") || !strings.Contains(got, "1.50") {
		t.Errorf("numbers were rewritten: %s", got)
	}
	// Nothing to mask: byte for byte what ubus printed, indentation and key order included.
	same := "{\n\t\"zeta\": 1,\n\t\"alpha\": {\n\t\t\"ssid\": \"x\"\n\t}\n}"
	if got := maskJSON(same, nil); got != same {
		t.Errorf("untouched reply was rewritten:\n got  %q\n want %q", got, same)
	}
	// The pruning notice that follows a JSON reply, and ubus error text, survive.
	withNotice := `{"key":"k"}` + "\n\n[pruned: 3 array element(s) dropped]"
	if got := maskJSON(withNotice, nil); !strings.HasSuffix(got, "[pruned: 3 array element(s) dropped]") || strings.Contains(got, `"k"`) {
		t.Errorf("trailing notice mishandled: %q", got)
	}
	// A secret in the text after the JSON value is masked too, and the JSON is left alone.
	if got := maskJSON(`{"a":1}`+"\nwireless.w.key='x'", nil); !strings.HasPrefix(got, `{"a":1}`) || strings.Contains(got, "'x'") || !strings.Contains(got, "'<redacted>'") {
		t.Errorf("text after the JSON value was not masked: %q", got)
	}
	if got := maskJSON("Command failed: Not found", nil); got != "Command failed: Not found" {
		t.Errorf("plain error text changed: %q", got)
	}
	// Text that is not JSON still gets the UCI treatment: an error message echoing a change.
	if got := maskJSON("uci: bad value\nwireless.w.key='abc'", nil); strings.Contains(got, "abc") {
		t.Errorf("non-JSON text with a secret line was not masked: %q", got)
	}
	// An extra name applies to JSON keys as well.
	if got := maskJSON(`{"vendor_blob":"zzz","a":"b"}`, []string{"VENDOR_BLOB"}); strings.Contains(got, "zzz") || !strings.Contains(got, `"b"`) {
		t.Errorf("extra name ignored in JSON: %q", got)
	}
}

// The syntax of `uci changes` was captured from a real router (OpenWrt 25.12.5) by staging a
// dry run of every kind of change: add_list is `+=`, del_list is `-=`, a quote inside a value is
// written '\”, a set_list is one `+=` per element, and a delete is the bare path with a minus
// and no value. Only the option names differ from the capture: the probe names are swapped for
// secret ones, so the masker has something to hide.
const realUciChanges = `dhcp.lan.x_mcp_probe+='alpha'
dhcp.lan.x_mcp_probe+='beta'
dhcp.lan.x_mcp_probe-='beta'
dhcp.lan.x_mcp_probe2='it'\''s a value'
dhcp.lan.x_mcp_probe3+='one'
dhcp.lan.x_mcp_probe3+='two words'
dhcp.lan.x_mcp_probe5='temp'
-dhcp.lan.x_mcp_probe5`

func TestMaskUCITextOnTheSyntaxOfARealUciChanges(t *testing.T) {
	// Probe names are not secrets: the captured block must come back byte for byte.
	if got := maskUCIText(realUciChanges, nil); got != realUciChanges {
		t.Errorf("a block with no secret option was altered:\n%s", got)
	}

	renamed := strings.NewReplacer(
		"x_mcp_probe5", "token", "x_mcp_probe3", "password", "x_mcp_probe2", "psk", "x_mcp_probe", "key",
	).Replace(realUciChanges)
	const want = `dhcp.lan.key+='<redacted>'
dhcp.lan.key+='<redacted>'
dhcp.lan.key-='<redacted>'
dhcp.lan.psk='<redacted>'
dhcp.lan.password+='<redacted>'
dhcp.lan.password+='<redacted>'
dhcp.lan.token='<redacted>'
-dhcp.lan.token`
	if got := maskUCIText(renamed, nil); got != want {
		t.Errorf("real `uci changes` syntax with secret names:\n got\n%s\n want\n%s", got, want)
	}
	for _, leak := range []string{"alpha", "beta", "it'", "a value", "one", "two words", "temp"} {
		if strings.Contains(maskUCIText(renamed, nil), leak) {
			t.Errorf("%q survived the masking", leak)
		}
	}
}

// ---------------------------------------------------------------- the tool table

func TestEveryToolIsMaskedOrListedRawWithAReason(t *testing.T) {
	for _, name := range allToolNames {
		_, masked := maskedTools[name]
		reason, raw := rawTools[name]
		switch {
		case masked && raw:
			t.Errorf("%s is both masked and listed raw", name)
		case !masked && !raw:
			t.Errorf("%s has no output rule: add it to maskedTools or give rawTools a reason", name)
		case raw && len(strings.TrimSpace(reason)) < 15:
			t.Errorf("%s is raw without a real reason: %q", name, reason)
		}
	}
	for name := range maskedTools {
		if !contains(allToolNames, name) {
			t.Errorf("maskedTools names %q, which is not a tool", name)
		}
	}
	for name := range rawTools {
		if !contains(allToolNames, name) {
			t.Errorf("rawTools names %q, which is not a tool", name)
		}
	}
	// The roadmap's list, and the one deliberate exemption.
	for _, name := range []string{"uci_get", "uci_apply", "pkg_config_diff", "system_status", "ubus_call"} {
		if _, ok := maskedTools[name]; !ok {
			t.Errorf("%s must be masked", name)
		}
	}
	if _, ok := rawTools["wg_new_client"]; !ok {
		t.Error("wg_new_client prints the new client's private key by design and must be listed raw")
	}
}

func TestWgNewClientStillShowsItsKey(t *testing.T) {
	const out = "[Interface]\nPrivateKey = cHJpdmF0ZWtleS1mb3ItdGhlLXBob25lLTAwMDAwMDA=\nAddress = 10.0.0.2/32\n"
	if got := maskForTool("wg_new_client", struct{}{}, out, nil, true); got != out {
		t.Errorf("wg_new_client output was altered:\n%s", got)
	}
	// And the same text from a tool that is masked would not survive.
	if got := maskForTool("uci_get", struct{}{}, "network.wg0.private_key='cHJpdmF0ZQ=='", nil, true); strings.Contains(got, "cHJpdmF0ZQ") {
		t.Errorf("a masked tool leaked a private key: %s", got)
	}
}

// ---------------------------------------------------------------- opting out

// systemEvents returns the audit entries the daemon wrote about itself for one tool name.
func systemEvents(t *testing.T, path, tool string) []AuditEvent {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev AuditEvent
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Client == "<system>" && ev.Tool == tool {
			out = append(out, ev)
		}
	}
	return out
}

func TestRedactOutputOptOutReturnsRawAndLeavesAnAuditEvent(t *testing.T) {
	s, f, _ := redactServer(t, "\toption redact_output '0'\n")
	f.on("uci show wireless", uciShowFor("key", "plain-visible-pw"))
	out, _ := callText(t, connectClient(t, s, "c"), "uci_get", map[string]any{"config": "wireless"})
	if !strings.Contains(out, "plain-visible-pw") {
		t.Errorf("redact_output '0' did not return the raw output:\n%s", out)
	}
	b, _ := os.ReadFile(s.cfg().AuditPath)
	log := string(b)
	if ev := systemEvents(t, s.cfg().AuditPath, "redact_output"); len(ev) != 1 || !strings.Contains(ev[0].Summary, "DISABLED") {
		t.Errorf("starting with redaction off left no audit event:\n%s", log)
	}
	if strings.Contains(log, "plain-visible-pw") {
		t.Errorf("the audit log holds the secret:\n%s", log)
	}
}

func TestRedactOutputIsOnByDefaultAndFlippingItIsAudited(t *testing.T) {
	s, f, _ := redactServer(t, "")
	f.on("uci show wireless", uciShowFor("key", "default-hidden-pw"))
	cs := connectClient(t, s, "c")
	if out, _ := callText(t, cs, "uci_get", map[string]any{"config": "wireless"}); strings.Contains(out, "default-hidden-pw") {
		t.Fatalf("redaction is not on by default:\n%s", out)
	}
	b, _ := os.ReadFile(s.cfg().AuditPath)
	if ev := systemEvents(t, s.cfg().AuditPath, "redact_output"); len(ev) != 0 {
		t.Errorf("an audit event for a setting nobody changed:\n%s", b)
	}

	// An operator edits the config while the daemon runs.
	body, _ := os.ReadFile(s.configPath)
	if err := os.WriteFile(s.configPath, append(body, []byte("\nconfig server\n\toption redact_output '0'\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(5 * time.Second)
	_ = os.Chtimes(s.configPath, future, future)
	if out, _ := callText(t, cs, "uci_get", map[string]any{"config": "wireless"}); !strings.Contains(out, "default-hidden-pw") {
		t.Errorf("the new setting was not picked up:\n%s", out)
	}
	b, _ = os.ReadFile(filepath.Join(filepath.Dir(s.configPath), "audit.jsonl"))
	if ev := systemEvents(t, s.cfg().AuditPath, "redact_output"); len(ev) != 1 || !strings.Contains(ev[0].Summary, "DISABLED") {
		t.Errorf("switching redaction off was not audited:\n%s", b)
	}
}

func TestRedactOutputOptionsInConfig(t *testing.T) {
	dir := t.TempDir()
	for i, tc := range []struct {
		body      string
		wantOn    bool
		wantExtra string
	}{
		{"", true, ""},
		{"\toption redact_output '1'\n", true, ""},
		{"\toption redact_output '0'\n", false, ""},
		{"\toption redact_output 'off'\n", true, ""}, // only a literal 0 turns it off
		{"\toption redact_extra 'a  B'\n\tlist redact_extra 'c'\n", true, "a b c"},
	} {
		p := filepath.Join(dir, fmt.Sprintf("c%d", i))
		if err := os.WriteFile(p, []byte("config server\n"+tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RedactOutput != tc.wantOn || strings.Join(cfg.RedactExtra, " ") != tc.wantExtra {
			t.Errorf("case %d: got on=%v extra=%q, want on=%v extra=%q", i, cfg.RedactOutput, cfg.RedactExtra, tc.wantOn, tc.wantExtra)
		}
	}
}

// ---------------------------------------------------------------- generated configs

// genNames mixes names that are secrets with names that merely look like one. Which is which is
// decided by regexpSecret, the independent oracle at the bottom of this file, never by the
// masker's own table.
var genNames = []string{"key", "key1", "key3", "Key", "psk", "password", "sae_password", "passphrase", "private_key",
	"preshared_key", "token", "wpa_psk_file", "ssid", "keyid", "publickey", "encryption", "network", "mode",
	"ifname", "proto", "ipaddr", "description", "ieee80211w", "wpa_disable_eapol_key_retries", "keyfile", "monkey"}

var genTypes = []string{"wifi-iface", "interface", "peer", "host", "rule"}

func quoteUCI(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// genValue returns a unique marker and a value that contains it, with spaces, a quote, non-ASCII
// text or a hash sign, the things a real value has and a naive masker trips over.
func genValue(rng *rand.Rand, n int) (marker, raw string) {
	marker = fmt.Sprintf("V%dZ", n)
	switch rng.Intn(5) {
	case 0:
		return marker, marker
	case 1:
		return marker, "two words " + marker
	case 2:
		return marker, "it's " + marker
	case 3:
		return marker, "Café " + marker + " ホーム"
	}
	return marker, marker + " # not a comment"
}

type genDoc struct{ in, want string }

// genUCI builds one random config twice, as `uci show` prints it and as `uci export` does, with
// the exact text the masker must produce, and the markers split by whether their option is secret.
func genUCI(rng *rand.Rand) (show, export genDoc, secret, plain []string) {
	var showIn, showWant, expIn, expWant []string
	n := 0
	for i, nsec := 0, 1+rng.Intn(4); i < nsec; i++ {
		typ := genTypes[rng.Intn(len(genTypes))]
		var showName, head string
		if rng.Intn(2) == 0 {
			showName, head = fmt.Sprintf("wireless.sec%d", i), fmt.Sprintf("config %s 'sec%d'", typ, i)
		} else {
			showName, head = fmt.Sprintf("wireless.@%s[%d]", typ, i), "config "+typ
		}
		showIn, showWant = append(showIn, showName+"="+typ), append(showWant, showName+"="+typ)
		expIn, expWant = append(expIn, head), append(expWant, head)
		used := map[string]bool{}
		for k, nopt := 0, 1+rng.Intn(6); k < nopt; k++ {
			name := genNames[rng.Intn(len(genNames))]
			if used[name] {
				continue
			}
			used[name] = true
			isSecret, isList, elems := regexpSecret(name), rng.Intn(4) == 0, 1
			if isList {
				elems += rng.Intn(3)
			}
			var quoted []string
			for e := 0; e < elems; e++ {
				n++
				m, raw := genValue(rng, n)
				quoted = append(quoted, quoteUCI(raw))
				if isSecret {
					secret = append(secret, m)
				} else {
					plain = append(plain, m)
				}
			}
			line := showName + "." + name + "=" + strings.Join(quoted, " ")
			showIn = append(showIn, line)
			if isSecret {
				line = showName + "." + name + "='<redacted>'"
			}
			showWant = append(showWant, line)
			kw := "option"
			if isList {
				kw = "list"
			}
			for _, q := range quoted {
				in := "\t" + kw + " " + name + " " + q
				want := in
				if isSecret {
					want = "\t" + kw + " " + name + " '<redacted>'"
				}
				expIn, expWant = append(expIn, in), append(expWant, want)
			}
		}
	}
	show = genDoc{strings.Join(showIn, "\n"), strings.Join(showWant, "\n")}
	export = genDoc{strings.Join(expIn, "\n"), strings.Join(expWant, "\n")}
	return
}

func checkGeneratedConfig(t *testing.T, seed int64) {
	t.Helper()
	show, export, secret, plain := genUCI(rand.New(rand.NewSource(seed)))
	for name, d := range map[string]genDoc{"uci show": show, "uci export": export,
		"both in one text": {show.in + "\n" + export.in, show.want + "\n" + export.want}} {
		got := maskUCIText(d.in, nil)
		if got != d.want {
			t.Fatalf("seed %d, %s:\n--- input\n%s\n--- got\n%s\n--- want\n%s", seed, name, d.in, got, d.want)
		}
		for _, m := range secret {
			if strings.Contains(got, m) && strings.Contains(d.in, m) {
				t.Fatalf("seed %d, %s: the secret value %s survived", seed, name, m)
			}
		}
		for _, m := range plain {
			if strings.Contains(d.in, m) && !strings.Contains(got, m) {
				t.Fatalf("seed %d, %s: the plain value %s was hidden", seed, name, m)
			}
		}
	}
}

func TestMaskUCITextOnGeneratedConfigs(t *testing.T) {
	for seed := int64(0); seed < 400; seed++ {
		checkGeneratedConfig(t, seed)
	}
}

func FuzzMaskUCITextOnGeneratedConfigs(f *testing.F) {
	for _, s := range []int64{0, 1, 7, 42, 1 << 40} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, seed int64) { checkGeneratedConfig(t, seed) })
}

// ---------------------------------------------------------------- fuzz

func FuzzMaskUCITextHidesTheValueOfASecretOption(f *testing.F) {
	for _, n := range []string{"key", "key3", "psk", "password", "private_key", "ssid", "keyid", "encryption"} {
		f.Add(n, "p4ss w0rd")
		f.Add(n, "it's")
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if !utf8.ValidString(name) || !utf8.ValidString(value) || strings.ContainsAny(name+value, "\r\n\x00'\"\\ \t\f\v=.+-") ||
			name == "" || len(value) < 6 || strings.Contains(name, "LEAK") {
			t.Skip()
		}
		marker := "LEAK" + value // not a substring of anything the line shape itself contains
		secret := regexpSecret(name)
		for _, line := range []string{
			"cfg.sec." + name + "='" + marker + "'",
			"-cfg.sec." + name + "='" + marker + "'",
			"\toption " + name + " '" + marker + "'",
			"+\tlist " + name + " " + marker,
		} {
			got := maskUCIText(line, nil)
			if secret && strings.Contains(got, marker) {
				t.Fatalf("%q is a secret option but its value survived:\n in   %q\n out  %q", name, line, got)
			}
			if !secret && !strings.Contains(got, marker) {
				t.Fatalf("%q is not a secret option but its value was hidden:\n in   %q\n out  %q", name, line, got)
			}
		}
	})
}

// regexpSecret is the oracle: the roadmap's rule written out again, independently of the table.
func regexpSecret(name string) bool {
	l := strings.ToLower(name)
	for _, s := range []string{"password", "passwd", "secret", "token", "credential", "apikey", "api_key",
		"privatekey", "private_key", "passphrase", "psk", "wgkey", "encryption_key", "preshared", "pwd"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	if strings.HasPrefix(l, "key") {
		return strings.Trim(l[3:], "0123456789") == ""
	}
	return false
}

func FuzzMaskJSONHidesTheValueOfASecretKey(f *testing.F) {
	for _, n := range []string{"key", "key2", "psk", "password", "private_key", "ssid", "keyid", "publickey", "Token"} {
		f.Add(n, "p4ss w0rd")
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if !utf8.ValidString(name) || !utf8.ValidString(value) || len(value) < 6 || name == "" || strings.Contains(name, "LEAK") {
			t.Skip()
		}
		marker := "LEAK" + value
		for _, doc := range []any{
			map[string]any{name: marker},
			map[string]any{"outer": []any{map[string]any{name: marker, "other": "fine"}}},
		} {
			in, err := json.Marshal(doc)
			if err != nil {
				t.Skip()
			}
			got := maskJSON(string(in), nil)
			if !json.Valid([]byte(got)) {
				t.Fatalf("masking broke the JSON:\n in  %s\n out %s", in, got)
			}
			// The marker may be re-encoded differently (escapes), so look for it decoded.
			var back any
			_ = json.Unmarshal([]byte(got), &back)
			flat, _ := json.Marshal(back)
			secret := regexpSecret(name)
			if secret && strings.Contains(string(flat), "LEAK") {
				t.Fatalf("%q is a secret key but its value survived:\n in  %s\n out %s", name, in, got)
			}
			if !secret && !strings.Contains(string(flat), "LEAK") {
				t.Fatalf("%q is not a secret key but its value was hidden:\n in  %s\n out %s", name, in, got)
			}
		}
	})
}

// The audit log records err.Error(). An error that echoes a staged change would put the secret
// there even though the caller never saw it.
func TestAuditErrorFieldDoesNotHoldASecret(t *testing.T) {
	s, f, _ := redactServer(t, "")
	// The secret comes first: the audit field is cut at 240 bytes, so anything after the
	// refusal's own sentence would be cut off and the test would prove nothing.
	f.on("uci changes", "wireless.wifinet0.key='audit-error-secret'\nwireless.wifinet0.ssid='HomeNet'")
	cs := connectClient(t, s, "c")
	out, isErr := callText(t, cs, "uci_apply", map[string]any{"dry_run": true,
		"changes": []map[string]any{{"config": "wireless", "section": "wifinet0", "option": "ssid", "value": "x"}}})
	if !isErr || strings.Contains(out, "audit-error-secret") {
		t.Fatalf("setup: isError=%v\n%s", isErr, out)
	}
	b, err := os.ReadFile(s.cfg().AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "audit-error-secret") {
		t.Errorf("the audit log holds a secret echoed by an error:\n%s", b)
	}
	if !strings.Contains(string(b), "refusing to apply") {
		t.Errorf("the refusal itself is no longer audited:\n%s", b)
	}
}

// Matching secret names by substring is a documented over-reach (SECURITY.md, README): a file
// path called wpa_psk_file is masked along with the keys. The test pins that, so narrowing the
// rule is a decision made with the documentation, not a side effect; and it pins the other
// direction, that names which only look similar are not swallowed.
func TestSubstringMatchingOvermasksAsDocumented(t *testing.T) {
	const r = "<redacted>"
	for _, tc := range []struct{ in, want string }{
		{"wireless.w.wpa_psk_file='/etc/hostapd.psk'", "wireless.w.wpa_psk_file='" + r + "'"},
		{"\toption wpa_psk_file '/etc/hostapd.psk'", "\toption wpa_psk_file '" + r + "'"},
		{"wireless.w.sae_password_file='/etc/sae'", "wireless.w.sae_password_file='" + r + "'"},
		// Names that merely resemble secrets.
		{"wireless.w.keyfile='/etc/k'", "wireless.w.keyfile='/etc/k'"},
		{"wireless.w.monkey='x'", "wireless.w.monkey='x'"},
		{"wireless.w.turkey='x'", "wireless.w.turkey='x'"},
		{"wireless.w.key_mgmt='sae'", "wireless.w.key_mgmt='sae'"},
		{"wireless.w.keyid='3'", "wireless.w.keyid='3'"},
	} {
		if got := maskUCIText(tc.in, nil); got != tc.want {
			t.Errorf("maskUCIText(%q)\n got  %q\n want %q", tc.in, got, tc.want)
		}
	}
	if !isSecretOption("wpa_psk_file") || !isSecretOption("WPA_PSK_FILE") {
		t.Error("wpa_psk_file is no longer treated as secret; update SECURITY.md and README if that is intended")
	}
}

// Redaction can be switched off by the config and back on again. Both directions are audited,
// the second one matters as much as the first (it is the record that the exposure ended), and a
// reload that changes nothing about it records nothing.
func TestSwitchingRedactionBackOnIsAuditedAndTakesEffect(t *testing.T) {
	s, f, _ := redactServer(t, "\toption redact_output '0'\n")
	f.on("uci show wireless", uciShowFor("key", "flip-flop-secret"))
	cs := connectClient(t, s, "c")
	auditPath := s.cfg().AuditPath

	if out, _ := callText(t, cs, "uci_get", map[string]any{"config": "wireless"}); !strings.Contains(out, "flip-flop-secret") {
		t.Fatalf("setup: redaction was not off:\n%s", out)
	}
	if ev := systemEvents(t, auditPath, "redact_output"); len(ev) != 1 || !strings.Contains(ev[0].Summary, "DISABLED") {
		t.Fatalf("setup: want one DISABLED event at startup, got %+v", ev)
	}

	touches := 0
	rewrite := func(edit func(string) string) {
		t.Helper()
		touches++
		body, err := os.ReadFile(s.configPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.configPath, []byte(edit(string(body))), 0o600); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(time.Duration(5*touches) * time.Second)
		if err := os.Chtimes(s.configPath, future, future); err != nil {
			t.Fatal(err)
		}
	}

	// The operator turns it back on.
	rewrite(func(b string) string {
		if !strings.Contains(b, "option redact_output '0'") {
			t.Fatal("setup: the config does not hold the option to flip")
		}
		return strings.Replace(b, "option redact_output '0'", "option redact_output '1'", 1)
	})
	out, _ := callText(t, cs, "uci_get", map[string]any{"config": "wireless"})
	if strings.Contains(out, "flip-flop-secret") {
		t.Errorf("redaction was switched back on but the secret is still returned:\n%s", out)
	}
	ev := systemEvents(t, auditPath, "redact_output")
	if len(ev) != 2 || !strings.Contains(ev[1].Summary, "ENABLED") {
		t.Fatalf("want a second event saying ENABLED, got %+v", ev)
	}

	// A reload that leaves the setting alone is not an event.
	rewrite(func(b string) string { return b + "\n# an unrelated edit\n" })
	if out, _ := callText(t, cs, "uci_get", map[string]any{"config": "wireless"}); strings.Contains(out, "flip-flop-secret") {
		t.Errorf("an unrelated reload turned redaction off:\n%s", out)
	}
	if ev := systemEvents(t, auditPath, "redact_output"); len(ev) != 2 {
		t.Errorf("an unrelated config reload wrote a redact_output event: %+v", ev)
	}
}
