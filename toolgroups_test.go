package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func groupRows(t *testing.T, r *rpcdRig) map[string]toolRow {
	t.Helper()
	m := r.ok("tools", map[string]any{})
	out := map[string]toolRow{}
	for _, g := range m["groups"].([]any) {
		for _, x := range g.(map[string]any)["tools"].([]any) {
			row := x.(map[string]any)
			tr := toolRow{Name: row["name"].(string), Title: row["title"].(string), Badge: row["badge"].(string)}
			notes, _ := row["notes"].([]any)
			for _, n := range notes {
				tr.Notes = append(tr.Notes, n.(string))
			}
			out[tr.Name] = tr
		}
	}
	return out
}

func TestEveryToolHasExactlyOneGroup(t *testing.T) {
	var placed []string
	for _, g := range toolGroups {
		placed = append(placed, g.Tools...)
	}
	if !sameSet(placed, allToolNames) || len(placed) != len(allToolNames) {
		t.Errorf("the group table places %v, the registry has %v", placed, allToolNames)
	}
}

func TestAToolWithNoGroupIsAnErrorNotAMissingRow(t *testing.T) {
	tools, err := registryTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildToolGroups(tools); err != nil {
		t.Fatalf("the real registry must build: %v", err)
	}
	if _, err := buildToolGroups(tools[1:]); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("a group entry with no registered tool gave %v", err)
	}
	saved := toolGroups
	defer func() { toolGroups = saved }()
	toolGroups = toolGroups[1:] // the Diagnostics group is gone: its tools have no place
	if _, err := buildToolGroups(tools); err == nil || !strings.Contains(err.Error(), "no group") {
		t.Errorf("tools with no group gave %v", err)
	}
}

func TestBadgesAndNotesComeFromTheRegistry(t *testing.T) {
	rows := groupRows(t, newRig(t))
	want := map[string]struct {
		badge string
		notes []string
	}{
		"system_status": {badgeRead, nil}, "uci_get": {badgeRead, nil}, "pkg_query": {badgeRead, nil},
		"uci_apply": {badgeWrite, []string{"rollback"}}, "pkg_change": {badgeWrite, nil},
		"wg_new_client": {badgeWrite, []string{"keys"}}, "service_control": {badgeWrite, nil},
		"exec": {badgeShell, nil}, "ubus_call": {badgeShell, nil},
	}
	for name, w := range want {
		got, ok := rows[name]
		if !ok {
			t.Errorf("%s is not on the page", name)
			continue
		}
		if got.Badge != w.badge || !slices.Equal(got.Notes, w.notes) {
			t.Errorf("%s: badge %q notes %v, want %q %v", name, got.Badge, got.Notes, w.badge, w.notes)
		}
		if got.Title != toolTitles[name] {
			t.Errorf("%s: title %q, the registry says %q", name, got.Title, toolTitles[name])
		}
	}
	if len(rows) != len(allToolNames) {
		t.Errorf("%d rows for %d tools", len(rows), len(allToolNames))
	}
}

func TestUngatedToolsCannotBeGranted(t *testing.T) {
	r := newRig(t)
	for _, tool := range []string{"ubus_list", "mfa_unlock"} {
		r.fails("grant", map[string]any{"client": "c", "tool": tool}, "needs no grant")
	}
}

// ---- grant

func TestGrantWritesOneToolOnTheNamedScopeAndAudits(t *testing.T) {
	r := newRig(t)
	r.ok("grant", map[string]any{"client": "claude-code", "tool": "uci_apply", "scope": "wireless.*", "duration": "8h"})
	if !r.allowed("claude-code", "uci_apply", "wireless.radio0.disabled") {
		t.Error("the grant does not cover its scope")
	}
	if r.allowed("claude-code", "uci_apply", "network.lan.ipaddr") {
		t.Error("the grant covers a scope it did not name")
	}
	if r.allowed("claude-code", "pkg_change", "wireless.radio0.disabled") {
		t.Error("the grant covers another tool")
	}
	if !strings.Contains(r.audit(), `"tool":"grant"`) {
		t.Errorf("no audit record: %s", r.audit())
	}
}

func TestGrantDefaultsToEveryScopeForOneHourAndAllowsNeverOnlyHere(t *testing.T) {
	r := newRig(t)
	r.ok("grant", map[string]any{"client": "c1", "tool": "logread"})
	if !r.allowed("c1", "logread", "anything") {
		t.Error("an omitted scope should mean every scope")
	}
	r.ok("grant", map[string]any{"client": "c2", "tool": "logread", "duration": "never"})
	r.fails("grant", map[string]any{"client": "c3", "tool": "logread", "duration": "forever"}, "not offered")
	r.fails("grant", map[string]any{"client": "c3", "tool": "logread", "duration": "30d"}, "not offered")
}

func TestGrantRefusesWhatItCannotWriteAndChangesNothing(t *testing.T) {
	r := newRig(t)
	before, _ := os.ReadFile(r.env.configPath)
	for in, want := range map[string]string{
		`{"client":"bad name","tool":"logread"}`:        "bad client name",
		`{"client":"c","tool":"no_such_tool"}`:          "no tool",
		`{"client":"c","tool":"logread","scope":"a b"}`: "cannot be limited",
		`{"client":"c","tool":"logread","scope":"a'b"}`: "bad scope",
		`{"client":"c","tool":"logread","breadth":"x"}`: "bad arguments",
	} {
		var m map[string]any
		_ = m
		r.fails("grant", jsonAny(t, in), want)
	}
	after, _ := os.ReadFile(r.env.configPath)
	if string(before) != string(after) {
		t.Errorf("a refused grant changed the config:\n%s", after)
	}
}

func TestGrantOfARootShellNeedsConfirmation(t *testing.T) {
	r := newRig(t)
	for _, c := range []map[string]any{
		{"client": "c", "tool": "exec", "scope": "sh"},
		{"client": "c", "tool": "exec", "scope": "*"},
		{"client": "c", "tool": "ubus_call", "scope": "file.exec"},
	} {
		m := r.call("grant", c)
		if m["code"] != "needs_confirm" {
			t.Fatalf("%v gave %v, want needs_confirm", c, m)
		}
	}
	if r.allowed("c", "exec", "sh") {
		t.Error("an unconfirmed root-shell grant was written")
	}
	r.ok("grant", map[string]any{"client": "c", "tool": "exec", "scope": "sh", "confirm": true})
	if !r.allowed("c", "exec", "sh") {
		t.Error("the confirmed grant is missing")
	}
	// A harmless exec grant is not a shell and needs no confirmation.
	r.ok("grant", map[string]any{"client": "c", "tool": "exec", "scope": "uptime"})
}

// ---- the page and the server agree

var jsDeclare = regexp.MustCompile(`method:\s*'([a-z_]+)'`)

func TestThePageCallsOnlyMethodsThePluginHasAndTheACLGrants(t *testing.T) {
	b, err := os.ReadFile("files/www/luci-static/resources/view/openwrt-mcp/status.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "object: 'openwrt-mcp'") {
		t.Error("the page does not declare the ubus object")
	}
	if strings.Contains(src, "'require fs'") || strings.Contains(src, "fs.exec") {
		t.Error("the page still shells out: the exec ACL line is meant to go")
	}
	var known []string
	for _, m := range rpcdMethods {
		known = append(known, m.name)
	}
	used := map[string]bool{}
	for _, m := range jsDeclare.FindAllStringSubmatch(src, -1) {
		used[m[1]] = true
		if m[1] != "access" && !slices.Contains(known, m[1]) {
			t.Errorf("the page calls %q, which the plugin does not have", m[1])
		}
	}
	for _, m := range rpcdMethods {
		if !used[m.name] && m.name != "requests" { // status carries the requests
			t.Errorf("the plugin method %q is never called by the page", m.name)
		}
	}
}

func jsonAny(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestLuciPageSmoke runs the page against a stub of LuCI and a fake rpcd (testdata/luci). It needs
// node, which CI has; without it the page is only covered by the checks above.
func TestLuciPageSmoke(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/luci/page_smoke.mjs", "files/www/luci-static/resources/view/openwrt-mcp/status.js").CombinedOutput()
	if err != nil {
		t.Fatalf("the page smoke test failed:\n%s", out)
	}
}

func TestTheACLGrantsNoFileExec(t *testing.T) {
	b, err := os.ReadFile("files/usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"file"`) || strings.Contains(string(b), `"exec"`) {
		t.Error("the ACL grants file access: the page no longer shells out to openwrt-mcp")
	}
}

// ---- the Overview include (8.5)

const overviewInclude = "files/www/luci-static/resources/view/status/include/15_openwrt-mcp.js"

func TestOverviewIncludeCallsOnlyMethodsInTheACLAndIsInstalled(t *testing.T) {
	b, err := os.ReadFile(overviewInclude)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := os.ReadFile("files/usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range jsDeclare.FindAllStringSubmatch(string(b), -1) {
		if m[1] != "access" && !strings.Contains(string(acl), `"`+m[1]+`"`) {
			t.Errorf("the include calls %q, which no ACL group grants", m[1])
		}
	}
	// Every file the installer puts on the router must survive a sysupgrade and be removed by uninstall.
	path := strings.TrimPrefix(overviewInclude, "files")
	for _, f := range []string{"files/lib/upgrade/keep.d/openwrt-mcp", "install-router.sh", "install.sh", ".github/workflows/ci.yml"} {
		if c, err := os.ReadFile(f); err != nil || !strings.Contains(string(c), path) {
			t.Errorf("%s does not name %s", f, path)
		}
	}
}

func TestLuciOverviewSmoke(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	out, err := exec.Command(node, "testdata/luci/overview_smoke.mjs", overviewInclude).CombinedOutput()
	if err != nil {
		t.Fatalf("the overview smoke test failed:\n%s", out)
	}
}

// The Overview include is one file with no shared module, so the words a request is described in
// are repeated from the page. They must not drift: a request reads the same on both.
func TestOverviewIncludeSaysRequestsInTheWordsOfThePage(t *testing.T) {
	page, err := os.ReadFile("files/www/luci-static/resources/view/openwrt-mcp/status.js")
	if err != nil {
		t.Fatal(err)
	}
	inc, err := os.ReadFile(overviewInclude)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"VERBS", "READONLY_UBUS", "RISK", "RISK_OF_BADGE"} {
		re := regexp.MustCompile(`(?s)var ` + name + ` = [\[{].*?[\]}];`)
		a, b := re.Find(page), re.Find(inc)
		if a == nil || b == nil {
			t.Fatalf("%s is missing from the page or the include", name)
		}
		if string(a) != string(b) {
			t.Errorf("%s differs between the page and the include:\n%s\n---\n%s", name, a, b)
		}
	}
}

// ---- editing a grant (replace)

func TestARefusedReplacementKeepsTheOldGrant(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "c", "wg_list_clients", "wireguard.wgua", "1h"); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"wgua, tailscale", "wgua,tailscale,wg0", "wg'ua", "<iface>"} {
		r.fails("grant", map[string]any{"client": "c", "tool": "wg_list_clients", "scope": scope, "replace": true}, "bad scope")
		if !r.allowed("c", "wg_list_clients", "wireguard.wgua") {
			t.Fatalf("scope %q: the refused edit removed the old grant", scope)
		}
	}
}

// Several limits for one tool are space-separated, as on the CLI; a single grant covers each of them.
func TestAGrantTakesSeveralLimitsForOneTool(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "c", "uci_get", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	r.ok("grant", map[string]any{"client": "c", "tool": "uci_get", "scope": "wireless.*  network.*", "duration": "1h", "replace": true})
	for scope, want := range map[string]bool{"wireless.radio0": true, "network.lan": true, "firewall.zone": false} {
		if got := r.allowed("c", "uci_get", scope); got != want {
			t.Errorf("uci_get on %s: allowed=%v, want %v", scope, got, want)
		}
	}
	// A tool with nothing to limit by still takes only "*", however many names are given.
	r.fails("grant", map[string]any{"client": "c", "tool": "logread", "scope": "a b"}, "cannot be limited")
}

func TestAReplacementAskingForConfirmationKeepsTheOldGrant(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "c", "exec", "ls", "1h"); err != nil {
		t.Fatal(err)
	}
	m := r.call("grant", map[string]any{"client": "c", "tool": "exec", "scope": "sh", "replace": true})
	if m["code"] != "needs_confirm" {
		t.Fatalf("want needs_confirm, got %v", m)
	}
	if !r.allowed("c", "exec", "ls") {
		t.Error("asking for confirmation removed the old grant")
	}
}

func TestAReplacementSwapsTheToolsGrantAndLeavesOtherToolsAlone(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "c", "uci_get,wg_list_clients", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	r.ok("grant", map[string]any{"client": "c", "tool": "wg_list_clients", "scope": "wireguard.wgua", "duration": "8h", "replace": true})
	if r.allowed("c", "wg_list_clients", "wireguard.wg0") {
		t.Error("the old unlimited grant survived the replacement")
	}
	if !r.allowed("c", "wg_list_clients", "wireguard.wgua") {
		t.Error("the new limit was not written")
	}
	if !r.allowed("c", "uci_get", "network.lan") {
		t.Error("replacing one tool took another tool's grant with it")
	}
}

func TestAToolWithNothingToLimitByCannotBeGivenALimit(t *testing.T) {
	r := newRig(t)
	r.fails("grant", map[string]any{"client": "c", "tool": "logread", "scope": "network.*"}, "cannot be limited")
	r.ok("grant", map[string]any{"client": "c", "tool": "logread", "scope": "*"})
	sawUnscoped := map[string]bool{}
	for _, g := range r.ok("tools", nil)["groups"].([]any) {
		for _, tl := range g.(map[string]any)["tools"].([]any) {
			row := tl.(map[string]any)
			if row["unscoped"] == true {
				sawUnscoped[row["name"].(string)] = true
			}
		}
	}
	for name := range unscopedTools {
		if !sawUnscoped[name] {
			t.Errorf("%s is in unscopedTools but the Permissions tab is not told", name)
		}
	}
}
