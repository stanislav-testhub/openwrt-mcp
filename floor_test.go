package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Milestone 8.1. The deny floor refuses, whatever the grant, every call by which an agent could
// widen what an agent may do: reach the approval objects, edit the policy or the rpcd logins,
// or run the binary. The grant under test is `*` on `*`, which is what @all will be.

func floorClient(t *testing.T) (*Server, *fakeRouter, func(string, map[string]any) (string, bool)) {
	t.Helper()
	f := newFakeRouter(t)
	f.on("ubus call", "{}")
	f.on("uci", "ok")
	f.on("echo", "ok")
	s := testServer(t, policyFor("c", allToolNames, "*"))
	cs := connectClient(t, s, "c")
	return s, f, func(tool string, args map[string]any) (string, bool) { return callText(t, cs, tool, args) }
}

type floorCase struct {
	name string
	tool string
	args map[string]any
}

func ubusCase(name, object, method string, args map[string]any) floorCase {
	in := map[string]any{"object": object, "method": method}
	if args != nil {
		in["args"] = args
	}
	return floorCase{name, "ubus_call", in}
}

func execCase(name string, argv ...string) floorCase {
	a := make([]any, len(argv))
	for i, v := range argv {
		a[i] = v
	}
	return floorCase{name, "exec", map[string]any{"argv": a}}
}

func floorRefused() []floorCase {
	cfg := func(c string) map[string]any { return map[string]any{"config": c, "section": "x"} }
	return []floorCase{
		// ubus objects an agent must never reach
		ubusCase("approval object decide", "openwrt-mcp", "decide", map[string]any{"id": "7f3a9c01"}),
		ubusCase("approval object read", "openwrt-mcp", "status", nil),
		ubusCase("object name in another case", "OpenWrt-MCP", "decide", nil),
		ubusCase("session list", "session", "list", nil),
		ubusCase("session create", "session", "create", nil),
		ubusCase("file exec", "file", "exec", map[string]any{"command": "/bin/sh"}),
		ubusCase("file write", "file", "write", map[string]any{"path": "/etc/config/rpcd"}),
		ubusCase("rpc-sys password", "rpc-sys", "password_set", nil),
		// uci writes to the two protected configs, every write method
		ubusCase("uci set policy", "uci", "set", cfg("openwrt-mcp")),
		ubusCase("uci add policy", "uci", "add", cfg("openwrt-mcp")),
		ubusCase("uci delete rpcd", "uci", "delete", cfg("rpcd")),
		ubusCase("uci rename rpcd", "uci", "rename", cfg("rpcd")),
		ubusCase("uci order rpcd", "uci", "order", cfg("rpcd")),
		ubusCase("uci commit policy", "uci", "commit", map[string]any{"config": "openwrt-mcp"}),
		ubusCase("uci revert rpcd", "uci", "revert", map[string]any{"config": "rpcd"}),
		ubusCase("uci set, config not a string", "uci", "set", map[string]any{"config": []any{"rpcd"}}),
		// the binary, its rpcd plugin, and the files that hold grants
		execCase("binary by name", "openwrt-mcp", "allow", "c", "@operator", "1h"),
		execCase("binary by path", "/usr/bin/openwrt-mcp", "allow", "c", "@operator", "1h"),
		execCase("binary by dotted path", "/usr/bin/../bin/openwrt-mcp", "status"),
		execCase("rpcd plugin", "/usr/libexec/rpcd/openwrt-mcp", "call", "decide"),
		execCase("rpcd plugin as an argument", "cat", "/usr/libexec/rpcd/openwrt-mcp"),
		execCase("uci set policy", "uci", "set", "openwrt-mcp.@policy[0].tools=exec"),
		execCase("uci commit rpcd", "uci", "commit", "rpcd"),
		execCase("uci add rpcd", "uci", "add", "rpcd", "login"),
		execCase("uci show rpcd", "uci", "show", "rpcd"),
		execCase("copy over the policy", "cp", "/tmp/p", "/etc/config/openwrt-mcp"),
		execCase("dd over rpcd", "dd", "if=/tmp/p", "of=/etc/config/rpcd"),
		execCase("copy of the binary", "cp", "/usr/bin/openwrt-mcp", "/tmp/m"),
		execCase("dotted path to rpcd", "cp", "/tmp/p", "/etc/config/x/../rpcd"),
		execCase("hook directory", "cp", "/tmp/h", "/etc/openwrt-mcp/hooks.d/x"),
		execCase("request state", "rm", "/var/run/openwrt-mcp/requests.json"),
	}
}

func floorAllowed() []floorCase {
	return []floorCase{
		ubusCase("uci set elsewhere", "uci", "set", map[string]any{"config": "network", "section": "x"}),
		ubusCase("uci get rpcd", "uci", "get", map[string]any{"config": "rpcd"}),
		ubusCase("uci changes", "uci", "changes", nil),
		ubusCase("system board", "system", "board", nil),
		ubusCase("a lookalike object", "openwrt-mcp2", "x", nil),
		execCase("uci show network", "uci", "show", "network"),
		execCase("echo", "echo", "hello"),
	}
}

func TestFloorRefusesEveryWritePathUnderAFullGrant(t *testing.T) {
	_, f, call := floorClient(t)
	for _, c := range floorRefused() {
		out, isErr := call(c.tool, c.args)
		if !isErr || !strings.Contains(out, "deny floor") || !strings.Contains(out, "[code: POLICY_DENIED]") {
			t.Errorf("%s: want a deny-floor refusal, got err=%v %q", c.name, isErr, out)
		}
	}
	if got := f.allCalls(); got != "" {
		t.Errorf("a refused call reached the router:\n%s", got)
	}
}

// The floor is narrow: everything it does not name still follows the grant.
func TestFloorLeavesOtherCallsToThePolicy(t *testing.T) {
	_, _, call := floorClient(t)
	for _, c := range floorAllowed() {
		if out, isErr := call(c.tool, c.args); isErr {
			t.Errorf("%s: refused: %s", c.name, out)
		}
	}
}

func TestFloorRefusalIsAudited(t *testing.T) {
	s, _, call := floorClient(t)
	call("ubus_call", map[string]any{"object": "openwrt-mcp", "method": "decide"})
	if got := auditErrorFor(t, s, "ubus_call", OutcomeDenied); !strings.Contains(got, "deny floor") {
		t.Errorf("audit error %q", got)
	}
}

// A symlink named something else still runs the binary.
func TestFloorFollowsASymlinkToTheBinary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "openwrt-mcp")
	link := filepath.Join(dir, "harmless")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("path semantics differ")
	}
	_, f, call := floorClient(t)
	if out, isErr := call("exec", map[string]any{"argv": []any{link, "status"}}); !isErr || !strings.Contains(out, "deny floor") {
		t.Errorf("symlink to the binary ran: %q", out)
	}
	if f.allCalls() != "" {
		t.Errorf("reached the router: %s", f.allCalls())
	}
}

// The rpcd config holds the LuCI logins. A client that can edit it can add a login and approve
// itself in the browser, so uci_apply, restore and pkg_config_resolve refuse it like the policy.
func TestPolicyGuardCoversTheRpcdConfig(t *testing.T) {
	s := testServer(t, "")
	ctx := context.Background()
	for _, dir := range []string{"/etc/config", filepath.Dir(s.configPath)} {
		old := uciConfDir
		uciConfDir = dir
		_, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: []UCIChange{
			{Config: "rpcd", Section: "l", Type: "login"},
		}, DryRun: true})
		uciConfDir = old
		if err != errPolicyFile {
			t.Errorf("uci_apply on rpcd, uciConfDir=%s: %v, want errPolicyFile", dir, err)
		}
	}
}

func TestRestoreAndResolveRefuseTheRpcdConfig(t *testing.T) {
	f := newFakeRouter(t)
	_ = f
	root := withFixtureRoot(t)
	s := testServer(t, "")
	ctx := context.Background()
	s.saveHistory("rpcd", []byte("config login\n"), 0o600, "c", "test", "seed")
	id := s.historyEntries("rpcd")[0].id()
	if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: id}); err != errPolicyFile {
		t.Errorf("restore of rpcd: %v, want errPolicyFile", err)
	}
	writeFixture(t, root, "etc/config/rpcd", "config login\n")
	writeFixture(t, root, "etc/config/rpcd.apk-new", "config login\n\toption password 'x'\n")
	if _, _, err := s.pkgConfigResolve(ctx, "c", pkgConfigResolveIn{Path: "/etc/config/rpcd", Action: "use_new"}); err != errPolicyFile {
		t.Errorf("use_new on rpcd: %v, want errPolicyFile", err)
	}
	if b, _ := os.ReadFile(root + "/etc/config/rpcd"); string(b) != "config login\n" {
		t.Errorf("the rpcd config was replaced: %q", b)
	}
}

// Adding or dropping a floor entry is a decision: this test makes it be written down.
func TestFloorEntriesArePinned(t *testing.T) {
	if got := strings.Join(floorUbusObjects, ","); got != "openwrt-mcp,session,file,rpc-sys" {
		t.Errorf("floorUbusObjects = %s", got)
	}
	if got := strings.Join(floorConfigs, ","); got != "openwrt-mcp,rpcd" {
		t.Errorf("floorConfigs = %s", got)
	}
	if got := strings.Join(floorUciWriteMethods, ","); got != "set,add,delete,rename,order,commit,revert" {
		t.Errorf("floorUciWriteMethods = %s", got)
	}
	if got := strings.Join(floorPaths, ","); got != "etc/config/openwrt-mcp,etc/config/rpcd,etc/openwrt-mcp,usr/bin/openwrt-mcp,usr/libexec/rpcd/openwrt-mcp,var/run/openwrt-mcp" {
		t.Errorf("floorPaths = %s", got)
	}
}
