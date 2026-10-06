package main

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Contract tests: properties every tool must have, checked against the live tool list rather
// than against one tool's code. They encode the MCP server guidance (tool naming, annotations,
// described input schemas, errors reported inside the result, bounded output) and this repo's
// own rules from CONTRIBUTING.md (an annotation per tool, a place in a preset, a README row,
// no value that starts with '-' reaching an argv). A tool added later is held to all of them
// without anyone remembering to.

// goldenCalls is one valid call per tool shape. It doubles as the seed for the hostile-input
// test and as the proof that no tool is registered without ever being exercised.
var goldenCalls = []struct {
	tool string
	args map[string]any
}{
	{"ubus_list", map[string]any{"filter": "network.interface.lan"}},
	{"ubus_call", map[string]any{"object": "system", "method": "board", "args": map[string]any{"k": "v"}}},
	{"exec", map[string]any{"argv": []string{"ls", "/"}}},
	{"system_status", map[string]any{}},
	{"logread", map[string]any{"pattern": "x", "regex": "y", "lines": 5, "since_minutes": 5}},
	{"network_clients", map[string]any{"filter": "x"}},
	{"firewall_show", map[string]any{"view": "chain", "family": "inet", "table": "fw4", "chain": "forward_lan"}},
	{"firewall_show", map[string]any{"view": "table", "family": "inet", "table": "fw4"}},
	{"net_diag", map[string]any{"action": "ping", "target": "192.0.2.1", "iface": "wg0", "count": 2}},
	{"net_diag", map[string]any{"action": "traceroute", "target": "192.0.2.1", "iface": "wg0"}},
	{"net_diag", map[string]any{"action": "nslookup", "target": "example.com", "server": "9.9.9.9"}},
	{"net_diag", map[string]any{"action": "route", "table": "main"}},
	{"uci_get", map[string]any{"config": "dhcp", "section": "lan", "option": "ipaddr"}},
	{"uci_apply", map[string]any{"dry_run": true, "changes": []map[string]any{
		{"config": "dhcp", "section": "pi", "type": "host"},
		{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.0.2.5"},
		{"op": "add_list", "config": "dhcp", "section": "pi", "option": "tag", "value": "t"},
		{"op": "set_list", "config": "dhcp", "section": "pi", "option": "dns", "values": []string{"192.0.2.1"}},
	}}},
	{"uci_apply", map[string]any{"dry_run": true, "expected_revisions": map[string]any{"dhcp": "0123456789ab"},
		"changes": []map[string]any{{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.0.2.5"}}}},
	{"uci_apply", map[string]any{"dry_run": true, "force": true, "probe_wait": 3,
		"probe":   []map[string]any{{"kind": "ping", "target": "192.0.2.1"}, {"kind": "resolve", "target": "example.com", "server": "192.0.2.53"}},
		"changes": []map[string]any{{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.0.2.5"}}}},
	{"uci_apply", map[string]any{"dry_run": true, "restore": "dhcp:20261007-100000.001-abcdef12"}},
	{"uci_get", map[string]any{"config": "dhcp", "history": "list"}},
	{"uci_get", map[string]any{"config": "dhcp", "history": "diff:dhcp:20261007-100000.001-abcdef12"}},
	{"uci_confirm", map[string]any{"token": "abc"}},
	{"uci_rollback", map[string]any{"token": "abc"}},
	{"service_list", map[string]any{"filter": "dns"}},
	{"service_control", map[string]any{"name": "dnsmasq", "action": "restart", "wait": 2}},
	{"pkg_query", map[string]any{"action": "installed", "package": "luci-*"}},
	{"pkg_query", map[string]any{"action": "info", "package": "dnsmasq"}},
	{"pkg_query", map[string]any{"action": "owner", "path": "/usr/sbin/nft"}},
	{"pkg_change", map[string]any{"action": "add", "packages": []string{"tcpdump"}}},
	{"pkg_config_diff", map[string]any{"path": "/etc/config/dhcp"}},
	{"pkg_config_resolve", map[string]any{"path": "/etc/config/dhcp", "action": "keep_current"}},
	{"sysupgrade", map[string]any{"action": "test", "image": "/tmp/fw.bin"}},
	{"sysupgrade", map[string]any{"action": "backup"}},
	{"wg_list_clients", map[string]any{"iface": "wg0"}},
	{"wg_new_client", map[string]any{"name": "phone", "iface": "wg0", "endpoint": "vpn.example.com:51820",
		"dns": "192.0.2.1", "allowed_ips": "0.0.0.0/0"}},
	{"wg_remove_client", map[string]any{"iface": "wg0", "name": "phone"}},
	{"mfa_unlock", map[string]any{"code": "123456"}},
}

// everythingFake makes every program the tools might run succeed with empty-ish output, so a
// tool gets as far as building the command it would really run.
func everythingFake(t *testing.T) *fakeRouter {
	t.Helper()
	f := newFakeRouter(t)
	for p, out := range map[string]string{
		"ubus": "{}", "uci": "", "ip": "[]", "nft": "", "fw4": "", "logread": "", "date": "2026-01-01 00:00:00",
		"apk": "", "wg": "", "ping": "", "traceroute": "", "nslookup": "", "sysupgrade": "", "owut": "",
		"ls": "", "/sbin/reload_config": "",
	} {
		f.on(p, out)
	}
	return f
}

// grantAll is a policy letting client "c" call every tool on every scope, with a rate limit
// high enough for table-driven tests.
func grantAll() string {
	return policyFor("c", allToolNames, "*") + "\toption max_per_min '1000000'\n"
}

func listedTools(t *testing.T, cs *mcp.ClientSession) []*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Tools
}

// ---------------------------------------------------------------- naming, schemas, docs

func TestToolListFollowsMCPConventions(t *testing.T) {
	cs := connectClient(t, testServer(t, ""), "c")
	snake := regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)
	seen := map[string]bool{}
	for _, tl := range listedTools(t, cs) {
		if !snake.MatchString(tl.Name) {
			t.Errorf("tool name %q is not snake_case", tl.Name)
		}
		if seen[tl.Name] {
			t.Errorf("tool %q registered twice", tl.Name)
		}
		seen[tl.Name] = true
		if len(strings.TrimSpace(tl.Description)) < 30 {
			t.Errorf("%s: description %q is too thin for a model to choose the tool by", tl.Name, tl.Description)
		}
		b, _ := json.Marshal(tl.InputSchema)
		var schema map[string]any
		if err := json.Unmarshal(b, &schema); err != nil || schema["type"] != "object" {
			t.Errorf("%s: input schema is not an object schema: %s", tl.Name, b)
			continue
		}
		walkSchema(schema, tl.Name, func(path string, prop map[string]any) {
			if d, _ := prop["description"].(string); strings.TrimSpace(d) == "" {
				t.Errorf("%s: input property %s has no description", tl.Name, path)
			}
		})
	}
}

// walkSchema visits every named property, descending into array item schemas.
func walkSchema(s map[string]any, path string, visit func(path string, prop map[string]any)) {
	props, _ := s["properties"].(map[string]any)
	for name, v := range props {
		p, _ := v.(map[string]any)
		if p == nil {
			continue
		}
		visit(path+"."+name, p)
		if items, ok := p["items"].(map[string]any); ok {
			walkSchema(items, path+"."+name+"[]", visit)
		}
		walkSchema(p, path+"."+name, visit)
	}
}

// Every tool the server registers must have a golden call, so that adding a tool without
// extending the contract tests is itself a failing test.
func TestEveryToolHasAGoldenCall(t *testing.T) {
	have := map[string]bool{}
	for _, c := range goldenCalls {
		have[c.tool] = true
	}
	for _, name := range allToolNames {
		if !have[name] {
			t.Errorf("tool %s has no entry in goldenCalls: the contract tests never exercise it", name)
		}
	}
	for name := range have {
		if !validTool(name) {
			t.Errorf("goldenCalls names %s, which is not a registered tool", name)
		}
	}
}

// Every golden call must at least reach the tool and come back as a result, never as a
// protocol error: a model can read a tool error and correct itself; it cannot read a crash.
func TestEveryGoldenCallAnswersAsAToolResult(t *testing.T) {
	withFixtureRoot(t)
	everythingFake(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	for _, c := range goldenCalls {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if err != nil {
			t.Errorf("%s %v: protocol error instead of a tool result: %v", c.tool, c.args, err)
			continue
		}
		if len(res.Content) == 0 {
			t.Errorf("%s: empty result content", c.tool)
		}
	}
}

// README.md carries the tool table; CONTRIBUTING requires a row per tool. Doc and registry
// are two copies of one fact, so a test keeps them from drifting.
func TestREADMEToolTableMatchesTheRegistry(t *testing.T) {
	b, err := os.ReadFile("README.md")
	if err != nil {
		t.Skipf("README.md not readable from the test directory: %v", err)
	}
	doc := strings.ReplaceAll(string(b), "\r\n", "\n")
	i := strings.Index(doc, "\n## Tools\n")
	if i < 0 {
		t.Fatal("README has no '## Tools' section")
	}
	section := doc[i+1:]
	if j := strings.Index(section[3:], "\n## "); j >= 0 {
		section = section[:j+3]
	}
	listed := map[string]bool{}
	name := regexp.MustCompile("`([a-z][a-z0-9_]*)`")
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cell := strings.SplitN(line, "|", 3)[1]
		for _, m := range name.FindAllStringSubmatch(cell, -1) {
			listed[m[1]] = true
		}
	}
	for _, tool := range allToolNames {
		if !listed[tool] {
			t.Errorf("tool %s has no row in the README tool table", tool)
		}
	}
	for tool := range listed {
		if !validTool(tool) {
			t.Errorf("README documents a tool that does not exist: %s", tool)
		}
	}
}

// ---------------------------------------------------------------- annotations vs policy

func TestAnnotationsAgreeWithThePresets(t *testing.T) {
	cs := connectClient(t, testServer(t, ""), "c")
	unscopedReadonly := map[string]bool{}
	for _, b := range presets["readonly"] {
		if len(b.scopes) == 1 && b.scopes[0] == "*" {
			for _, tool := range b.tools {
				unscopedReadonly[tool] = true
			}
		}
	}
	for _, tl := range listedTools(t, cs) {
		a := tl.Annotations
		if a == nil {
			t.Errorf("%s has no annotations (CONTRIBUTING: annRead, annIdem or annDest)", tl.Name)
			continue
		}
		if a.ReadOnlyHint && a.DestructiveHint != nil && *a.DestructiveHint {
			t.Errorf("%s claims to be both read-only and destructive", tl.Name)
		}
		if unscopedReadonly[tl.Name] && !a.ReadOnlyHint {
			t.Errorf("%s is granted on every scope by @readonly but is not annotated read-only", tl.Name)
		}
		if a.ReadOnlyHint && !unscopedReadonly[tl.Name] && !ungatedTools[tl.Name] {
			t.Errorf("%s is read-only but missing from @readonly: a new read tool nobody can be granted", tl.Name)
		}
	}
}

func TestPresetsNestAndKeepTheDangerousToolsOut(t *testing.T) {
	grants := func(preset string) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, b := range presets[preset] {
			for _, tool := range b.tools {
				if out[tool] == nil {
					out[tool] = map[string]bool{}
				}
				for _, s := range b.scopes {
					out[tool][s] = true
				}
			}
		}
		return out
	}
	ro, op := grants("readonly"), grants("operator")
	for tool, scopes := range ro {
		for s := range scopes {
			if !op[tool][s] {
				t.Errorf("@operator lacks what @readonly grants: %s on %q", tool, s)
			}
		}
	}
	for _, p := range []map[string]map[string]bool{ro, op} {
		for _, never := range []string{"exec", "mfa_unlock"} {
			if _, ok := p[never]; ok {
				t.Errorf("a preset grants %s", never)
			}
		}
	}
	// Anything not in a preset needs a stated reason.
	reason := map[string]string{"exec": "a root shell", "ubus_list": "ungated introspection", "mfa_unlock": "ungated: it is how a factor is satisfied"}
	for _, tool := range allToolNames {
		if _, inOp := op[tool]; !inOp {
			if reason[tool] == "" {
				t.Errorf("%s is in no preset and has no documented reason", tool)
			}
		}
	}
}

// readOnlyCommand is the independent oracle for "this command cannot change the router":
// it lists the read-only forms outright instead of deriving them from the code under test.
func readOnlyCommand(a []string) bool {
	if len(a) == 0 {
		return false
	}
	switch a[0] {
	case "ubus":
		if len(a) >= 3 && a[1] == "-v" && a[2] == "list" {
			return true
		}
		return len(a) >= 4 && a[1] == "call" && matchAny(readonlyUbus, a[2]+"."+a[3])
	case "uci":
		for i := 1; i < len(a); i++ {
			switch a[i] {
			case "-q", "-X":
			case "-c", "-t":
				i++
			default:
				return a[i] == "show" || a[i] == "changes" || a[i] == "get"
			}
		}
		return false
	case "ip":
		return contains(a, "show")
	case "nft":
		return len(a) > 1 && a[1] == "list"
	case "fw4":
		return len(a) > 1 && (a[1] == "check" || (a[1] == "-q" && len(a) > 2 && a[2] == "print"))
	case "apk":
		return len(a) > 1 && contains([]string{"list", "search", "info", "policy", "audit"}, a[1])
	case "wg":
		return len(a) > 1 && a[1] == "show"
	case "logread", "date", "ping", "traceroute", "nslookup":
		return true
	}
	return false
}

func TestReadOnlyToolsOnlyIssueReadOnlyCommands(t *testing.T) {
	withFixtureRoot(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	readOnly := map[string]bool{}
	for _, tl := range listedTools(t, cs) {
		if tl.Annotations != nil && tl.Annotations.ReadOnlyHint {
			readOnly[tl.Name] = true
		}
	}
	if len(readOnly) < 8 {
		t.Fatalf("only %d tools are annotated read-only; the check below would prove little", len(readOnly))
	}
	for _, c := range goldenCalls {
		if !readOnly[c.tool] {
			continue
		}
		f := everythingFake(t)
		callText(t, cs, c.tool, c.args)
		for _, argv := range f.argvList() {
			if !readOnlyCommand(argv) {
				t.Errorf("%s is annotated read-only but ran %q", c.tool, strings.Join(argv, " "))
			}
		}
	}
}

// ---------------------------------------------------------------- hostile input

// optionFlags are the flags the code puts in argv itself. Anything else that begins with '-'
// in a command line came from a caller.
var optionFlags = map[string]bool{
	"-q": true, "-X": true, "-4": true, "-6": true, "-c": true, "-t": true, "-W": true, "-I": true, "-i": true,
	"-n": true, "-w": true, "-m": true, "-a": true, "-L": true, "-l": true, "-T": true, "-k": true, "-b": true,
	"-v": true, "-j": true, "--who-owns": true, "--upgradable": true, "--simulate": true, "--installed": true,
}

var hostileValues = []string{"-x", "--help", "-f", "--", "-", "-rf", "--version", "-q"}

// stringLeaves lists the path of every string in a decoded JSON value.
func stringLeaves(v any, path []any, out *[][]any) {
	switch t := v.(type) {
	case string:
		*out = append(*out, append([]any(nil), path...))
	case map[string]any:
		for k, e := range t {
			stringLeaves(e, append(path, k), out)
		}
	case []any:
		for i, e := range t {
			stringLeaves(e, append(path, i), out)
		}
	}
}

func setLeaf(v any, path []any, val string) {
	for i, p := range path {
		last := i == len(path)-1
		switch k := p.(type) {
		case string:
			m := v.(map[string]any)
			if last {
				m[k] = val
				return
			}
			v = m[k]
		case int:
			s := v.([]any)
			if last {
				s[k] = val
				return
			}
			v = s[k]
		}
	}
}

// A caller-controlled value that starts with '-' must never reach a program as an option.
// Every string field of every tool is replaced, one at a time, with option-looking values; the
// commands the tool then builds are inspected. exec is exempt: running a caller-named program
// with caller-chosen arguments is what it is for, and what scopes it.
func TestHostileValuesNeverReachArgvAsOptions(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/dhcp", "config dnsmasq\n")
	writeFixture(t, root, "etc/config/dhcp.apk-new", "config dnsmasq\n")
	cs := connectClient(t, testServer(t, grantAll()), "c")

	for _, c := range goldenCalls {
		if c.tool == "exec" {
			continue
		}
		raw, _ := json.Marshal(c.args)
		var template any
		_ = json.Unmarshal(raw, &template)
		var leaves [][]any
		stringLeaves(template, nil, &leaves)

		for _, leaf := range leaves {
			for _, hostile := range hostileValues {
				var args any
				_ = json.Unmarshal(raw, &args)
				setLeaf(args, leaf, hostile)
				f := everythingFake(t)
				callText(t, cs, c.tool, args.(map[string]any))
				for _, argv := range f.argvList() {
					for _, e := range argv[1:] {
						if strings.HasPrefix(e, "-") && !optionFlags[e] {
							t.Errorf("%s: setting %v to %q put %q into the command %q: a caller value can act as an option",
								c.tool, leaf, hostile, e, strings.Join(argv, " "))
						}
					}
				}
			}
		}
	}
}

// The same rule at the validators, where the failure is cheap to read.
func TestNamesThatFeedACommandRefuseALeadingDash(t *testing.T) {
	for name, re := range map[string]*regexp.Regexp{
		"nft name": reNftName, "uci config": reUCIConfig, "package": rePkgName, "package pattern": rePkgPattern,
		"net target": reNetTarget, "net name": reNetName, "uci section": reUCISection, "uci option": reUCIOption,
	} {
		for _, bad := range []string{"-x", "--help", "-", "-1"} {
			if re.MatchString(bad) {
				t.Errorf("%s accepts %q: it would reach a program's argv as an option", name, bad)
			}
		}
	}
	if err := validateChange(UCIChange{Config: "-x", Section: "s", Option: "o", Value: "v"}); err == nil {
		t.Error("validateChange accepts a config named like an option")
	}
	for _, in := range []ubusCallIn{{Object: "-s", Method: "x"}, {Object: "system", Method: "-x"}} {
		f := newFakeRouter(t)
		if _, _, err := ubusCall(context.Background(), in); err == nil {
			t.Errorf("ubus_call %+v accepted", in)
		}
		f.noCalls(t, "a ubus_call with an option-like name")
	}
}

// ---------------------------------------------------------------- errors, audit, bounds

func TestEveryCallIsAuditedExactlyOnceWithItsOutcome(t *testing.T) {
	withFixtureRoot(t)
	f := everythingFake(t)
	f.on("ls", "files")
	s := testServer(t, policyFor("c", []string{"exec", "logread"}, "ls"))
	cs := connectClient(t, s, "c")
	other := connectClient(t, s, "stranger")

	steps := []struct {
		name    string
		do      func()
		tool    string
		client  string
		outcome Outcome
	}{
		{"ok", func() { callText(t, cs, "exec", map[string]any{"argv": []string{"ls"}}) }, "exec", "c", OutcomeOK},
		{"scope miss", func() { callText(t, cs, "exec", map[string]any{"argv": []string{"cat"}}) }, "exec", "c", OutcomeDenied},
		{"no grant", func() { callText(t, other, "exec", map[string]any{"argv": []string{"ls"}}) }, "exec", "stranger", OutcomeDenied},
		{"tool error", func() { callText(t, cs, "exec", map[string]any{"argv": []string{}}) }, "exec", "c", OutcomeError},
		{"ungated", func() { callText(t, cs, "ubus_list", map[string]any{}) }, "ubus_list", "c", OutcomeOK},
	}
	for _, st := range steps {
		before := len(auditEvents(t, s))
		st.do()
		evs := auditEvents(t, s)
		if len(evs) != before+1 {
			t.Errorf("%s: %d audit events written, want exactly 1", st.name, len(evs)-before)
			continue
		}
		ev := evs[len(evs)-1]
		if ev.Tool != st.tool || ev.Client != st.client || ev.Outcome != st.outcome {
			t.Errorf("%s: audited as %s/%s/%s, want %s/%s/%s", st.name, ev.Client, ev.Tool, ev.Outcome, st.client, st.tool, st.outcome)
		}
	}
}

func TestOversizedOutputIsBoundedAllTheWayToTheClientAndTheAuditLog(t *testing.T) {
	f := newFakeRouter(t)
	f.on("big", strings.Repeat("0123456789", 100_000)) // 1 MB
	s := testServer(t, policyFor("c", []string{"exec"}, "big"))
	cs := connectClient(t, s, "c")

	out, isErr := callText(t, cs, "exec", map[string]any{"argv": []string{"big"}})
	if isErr {
		t.Fatal(out[:100])
	}
	if len(out) > maxResultBytes+500 || !strings.Contains(out, "TRUNCATED") {
		t.Errorf("a 1 MB result reached the model: %d bytes, truncation notice=%v", len(out), strings.Contains(out, "TRUNCATED"))
	}
	b, _ := os.ReadFile(s.cfg().AuditPath)
	if len(b) > 2000 {
		t.Errorf("the audit log recorded %d bytes for one call: tool OUTPUT must never be logged", len(b))
	}
	if strings.Contains(string(b), "0123456789") {
		t.Error("tool output reached the audit log")
	}
}

func TestBadArgumentsComeBackSoAModelCanCorrectThem(t *testing.T) {
	everythingFake(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"uci_get", map[string]any{}},                     // required field missing
		{"exec", map[string]any{"argv": "ls"}},            // wrong type
		{"net_diag", map[string]any{"action": 7}},         // wrong type
		{"service_control", map[string]any{"name": "x"}},  // missing action
		{"sysupgrade", map[string]any{"action": "flash"}}, // not an action
		{"pkg_query", map[string]any{"action": "installed", "package": []int{1}}},
	} {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		var msg string
		switch {
		case err != nil:
			msg = err.Error()
		case res.IsError:
			for _, ct := range res.Content {
				if tc, ok := ct.(*mcp.TextContent); ok {
					msg += tc.Text
				}
			}
		default:
			t.Errorf("%s %v succeeded", c.tool, c.args)
			continue
		}
		if strings.TrimSpace(msg) == "" || strings.Contains(msg, "panic") || strings.Contains(msg, "goroutine") {
			t.Errorf("%s %v: unhelpful or leaking error %q", c.tool, c.args, msg)
		}
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "no_such_tool"}); err == nil {
		t.Error("an unknown tool name did not fail")
	}
}

// ---------------------------------------------------------------- audit redaction

func TestAuditNeverRecordsASecretValueNamedByItsOption(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/wireless", "config wifi-iface 'x'\n")
	everythingFake(t)
	s := testServer(t, grantAll())
	cs := connectClient(t, s, "c")

	secrets := map[string]string{
		"hunter2-wifi": `{"config":"wireless","section":"x","option":"key","value":"hunter2-wifi"}`,
		"hunter2-psk":  `{"config":"wireless","section":"x","option":"psk","value":"hunter2-psk"}`,
		"hunter2-pw":   `{"config":"network","section":"x","option":"password","value":"hunter2-pw"}`,
		"hunter2-priv": `{"config":"network","section":"x","option":"private_key","value":"hunter2-priv"}`,
		"hunter2-pre":  `{"config":"network","section":"x","option":"preshared_key","value":"hunter2-pre"}`,
		"hunter2-list": `{"op":"set_list","config":"network","section":"x","option":"password","values":["hunter2-list"]}`,
	}
	writeFixture(t, root, "etc/config/network", "config interface 'x'\n")
	for want, change := range secrets {
		var ch map[string]any
		_ = json.Unmarshal([]byte(change), &ch)
		callText(t, cs, "uci_apply", map[string]any{"dry_run": true, "changes": []map[string]any{ch}})
		b, _ := os.ReadFile(s.cfg().AuditPath)
		if strings.Contains(string(b), want) {
			t.Errorf("the audit log holds the secret set via option %v", ch["option"])
		}
	}
	// Both directions: the log must still say WHICH option was set, and ordinary values stay.
	callText(t, cs, "uci_apply", map[string]any{"dry_run": true, "changes": []map[string]any{
		{"config": "wireless", "section": "x", "option": "ssid", "value": "visible-ssid"}}})
	b, _ := os.ReadFile(s.cfg().AuditPath)
	if !strings.Contains(string(b), "visible-ssid") || !strings.Contains(string(b), `"option":"ssid"`) {
		t.Errorf("redaction swallowed a non-secret value, making the log useless:\n%s", b)
	}
	if !strings.Contains(string(b), `"option":"key"`) {
		t.Error("the audit log no longer says which option was changed")
	}
}
