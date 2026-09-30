package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectClient runs a real MCP client against the per-client server over an in-memory
// transport, so these tests go through the SDK's schema handling and the policy wrapper
// exactly as a remote client would.
func connectClient(t *testing.T, s *Server, client string) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.serverFor(client).Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

func TestEveryToolIsRegisteredAndListed(t *testing.T) {
	s := testServer(t, "")
	cs := connectClient(t, s, "c")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, tl := range res.Tools {
		got = append(got, tl.Name)
		if tl.InputSchema == nil {
			t.Errorf("%s has no input schema", tl.Name)
		}
	}
	want := append([]string(nil), allToolNames...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("registered tools differ from allToolNames:\n got %v\nwant %v", got, want)
	}
	if cs.InitializeResult().Instructions == "" {
		t.Error("server instructions not sent")
	}
}

func TestDenialIsActionableAndNothingRuns(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, "")
	cs := connectClient(t, s, "claude-code")
	out, isErr := callText(t, cs, "system_status", nil)
	if !isErr || !strings.Contains(out, "openwrt-mcp allow claude-code system_status") {
		t.Errorf("denial not actionable: %s", out)
	}
	if f.allCalls() != "" {
		t.Errorf("a denied tool still ran commands:\n%s", f.allCalls())
	}
}

func TestReadonlyPresetAllowsReadsAndRefusesWrites(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"m"}`)
	f.on("uci changes", "")
	f.on("ubus call system info", "{}")

	dir := t.TempDir()
	cfg := filepath.Join(dir, "cfg")
	if err := os.WriteFile(cfg, []byte("config server\n\toption socket ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocks, _ := expandPreset("@readonly")
	for _, b := range blocks {
		if err := appendPolicy(cfg, "c", strings.Join(b.tools, ","), strings.Join(b.scopes, " "), "never"); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewServer(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	cs := connectClient(t, s, "c")

	if out, isErr := callText(t, cs, "system_status", nil); isErr {
		t.Errorf("readonly cannot read status: %s", out)
	}
	if out, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "system", "method": "board"}); isErr {
		t.Errorf("readonly cannot call system.board: %s", out)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"ubus_call", map[string]any{"object": "session", "method": "list"}}, // LuCI session ids
		{"ubus_call", map[string]any{"object": "system", "method": "reboot"}},
		{"ubus_call", map[string]any{"object": "network.interface.lan", "method": "down"}},
		{"uci_apply", map[string]any{"changes": []map[string]any{{"config": "dhcp", "section": "x", "type": "host"}}}},
		{"exec", map[string]any{"argv": []string{"reboot"}}},
		{"pkg_change", map[string]any{"action": "add", "packages": []string{"x"}}},
		{"sysupgrade", map[string]any{"action": "backup"}},
	} {
		if out, isErr := callText(t, cs, tc.tool, tc.args); !isErr || !strings.Contains(out, "denied") {
			t.Errorf("readonly allowed %s %v: %s", tc.tool, tc.args, out)
		}
	}
}

// The stdio bridge path: a handshake line naming the client, then plain MCP. Driven over a
// net.Pipe so it runs anywhere.
func TestBridgeHandshakeThenMCP(t *testing.T) {
	s := testServer(t, "")
	srvSide, cliSide := net.Pipe()
	go s.handleBridge(srvSide)
	defer cliSide.Close()
	_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))

	w := bufio.NewWriter(cliSide)
	w.WriteString(`{"client":"claude-code","origin":"ssh from 192.168.1.10"}` + "\n")
	w.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n")
	w.Flush()

	line, err := bufio.NewReader(cliSide).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Result struct {
			ServerInfo struct{ Name string } `json:"serverInfo"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(line), &resp) != nil || resp.Result.ServerInfo.Name != "openwrt-mcp" {
		t.Fatalf("no initialize response over the bridge: %s", line)
	}
	b, _ := os.ReadFile(s.cfg().AuditPath)
	if !strings.Contains(string(b), "stdio session opened via ssh from 192.168.1.10") {
		t.Errorf("bridge session not audited:\n%s", b)
	}
}

func TestBridgeRejectsABadHandshake(t *testing.T) {
	s := testServer(t, "")
	for _, hello := range []string{"not json\n", `{"client":"../etc"}` + "\n", `{"client":""}` + "\n"} {
		srvSide, cliSide := net.Pipe()
		go s.handleBridge(srvSide)
		_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))
		cliSide.Write([]byte(hello))
		line, _ := bufio.NewReader(cliSide).ReadString('\n')
		if !strings.Contains(line, "bad bridge handshake") {
			t.Errorf("handshake %q accepted: %q", hello, line)
		}
		cliSide.Close()
	}
}
