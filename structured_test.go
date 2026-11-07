package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func callRaw(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func TestWGListClientsReturnsRowsAsDataAndKeepsTheText(t *testing.T) {
	wgFake(t, 0)
	res := callRaw(t, connectClient(t, testServer(t, grantAll()), "c"), "wg_list_clients", map[string]any{})
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("%+v", res)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "ALLOWED IPS") {
		t.Errorf("the text table is gone:\n%s", text)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var got struct {
		Interface string `json:"interface"`
		PublicKey string `json:"public_key"`
		Peers     []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
			Endpoint  string `json:"endpoint"`
			Rx        int64  `json:"rx_bytes"`
			InKernel  bool   `json:"in_kernel"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if got.Interface != "wg0" || got.PublicKey != "SERVERPUB=" || len(got.Peers) != 3 {
		t.Fatalf("structured content: %s", b)
	}
	found := false
	for _, p := range got.Peers {
		if p.Name == "tablet" && p.Endpoint == "203.0.113.9:5555" && p.Rx == 2048 && p.InKernel && p.PublicKey != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("the tablet peer is not in the data: %s", b)
	}
	if strings.Contains(string(b), "SERVERPRIV") {
		t.Error("a private key reached structured content")
	}
}

func TestNetworkClientsReturnsRowsAsDataAndMatchesTheTextPage(t *testing.T) {
	f := everythingFake(t)
	root := withFixtureRoot(t)
	writeFixture(t, root, "tmp/dhcp.leases", "0 aa:bb:cc:00:00:50 192.168.1.50 laptop *\n0 aa:bb:cc:00:00:51 192.168.1.51 ignore‮me *\n")
	f.on("ip -j neigh show", "[]")
	res := callRaw(t, connectClient(t, testServer(t, grantAll()), "c"), "network_clients", map[string]any{"filter": "laptop"})
	text := res.Content[0].(*mcp.TextContent).Text
	b, _ := json.Marshal(res.StructuredContent)
	var got struct {
		Total   int `json:"total"`
		Clients []struct {
			MAC  string   `json:"mac"`
			IPs  []string `json:"ips"`
			Host string   `json:"host"`
		} `json:"clients"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if got.Total != 1 || len(got.Clients) != 1 || got.Clients[0].Host != "laptop" || got.Clients[0].IPs[0] != "192.168.1.50" {
		t.Fatalf("data: %s\ntext:\n%s", b, text)
	}
	if !strings.Contains(text, "laptop") || strings.Contains(text, "ignore") {
		t.Errorf("text and data disagree:\n%s", text)
	}
}

// Errors carry no structured content, and a tool without a schema never does.
func TestStructuredContentOnlyOnSuccessAndOnlyForDeclaredTools(t *testing.T) {
	newFakeRouter(t)
	cs := connectClient(t, testServer(t, grantAll()), "c")
	res := callRaw(t, cs, "wg_list_clients", map[string]any{"iface": "nope"})
	if res.StructuredContent != nil {
		t.Errorf("an error result has structured content: %v", res.StructuredContent)
	}
	for name := range outputSchemas {
		if !validTool(name) {
			t.Errorf("outputSchemas names unknown tool %q", name)
		}
	}
	for _, tl := range listedTools(t, cs) {
		if _, ok := outputSchemas[tl.Name]; ok != (tl.OutputSchema != nil) {
			t.Errorf("%s: outputSchema listed=%v declared=%v", tl.Name, tl.OutputSchema != nil, ok)
		}
	}
}

func TestSystemStatusAndServiceListReturnDataAndKeepTheText(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"Box","board_name":"box","kernel":"6.12.1","hostname":"rtr","release":{"description":"OpenWrt 25.12.6"}}`)
	f.on("ubus call system info", `{"uptime":3600,"load":[65536,32768,0],"memory":{"total":536870912,"available":268435456},"root":{"total":1024,"avail":512},"tmp":{"total":2048,"avail":1024}}`)
	f.on("ubus call network.wireless status", `{"radio0":{"up":true,"interfaces":[{"ifname":"wlan0","config":{"ssid":"Home","mode":"ap"}}]}}`)
	f.on("ubus call rc list", `{"dropbear":{"start":19,"stop":50,"enabled":true,"running":true},"ttyd":{"start":99,"stop":10,"enabled":false,"running":false}}`)
	cs := connectClient(t, testServer(t, grantAll()), "c")

	res := callRaw(t, cs, "system_status", map[string]any{})
	if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "uptime 1h0m0s") {
		t.Fatalf("text: %+v", res)
	}
	var st struct {
		Board     struct{ Model, Hostname string }
		UptimeS   int64 `json:"uptime_s"`
		Load      []float64
		MemoryMiB struct{ Total, Free int64 } `json:"memory_mib"`
		Radios    []struct {
			Name  string
			SSIDs []struct{ SSID string }
		}
		Outstanding []string
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	if st.Board.Model != "Box" || st.UptimeS != 3600 || st.Load[0] != 1 || st.MemoryMiB.Total != 512 || st.MemoryMiB.Free != 256 ||
		len(st.Radios) != 1 || st.Radios[0].SSIDs[0].SSID != "Home" || st.Outstanding == nil {
		t.Errorf("system_status data: %s", b)
	}

	res = callRaw(t, cs, "service_list", map[string]any{"filter": "d"})
	b, _ = json.Marshal(res.StructuredContent)
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "dropbear") || !strings.Contains(string(b), `"enabled":true,"name":"dropbear","running":true,"start":19,"stop":50`) {
		t.Errorf("service_list: %s", b)
	}

	// doctor stays text only
	res = callRaw(t, cs, "system_status", map[string]any{"mode": "doctor"})
	if res.StructuredContent != nil {
		t.Errorf("doctor returned structured content: %v", res.StructuredContent)
	}
}

// pkg_query installed and upgradable return a list in structuredContent as well; the other
// actions are free text and stay text only.
func TestPkgQueryListsReturnDataAndKeepTheText(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("apk list --installed", "dnsmasq-full-2.91-r1 x86_64 {feeds/base/dnsmasq} (GPL-2.0) [installed]\nluci-26.270.72870~a24d1f2 noarch {feeds/luci/luci} (Apache-2.0) [upgradable from: luci-26.268.1-r2]\n")
	f.on("apk list --upgradable", "luci-26.270.72870~a24d1f2 noarch {feeds/luci/luci} (Apache-2.0) [upgradable from: luci-26.268.1-r2]\n")
	f.on("apk info", "x\n")
	cs := connectClient(t, testServer(t, grantAll()), "c")
	res := callRaw(t, cs, "pkg_query", map[string]any{"action": "installed"})
	if res.IsError {
		t.Fatalf("%+v", res)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "dnsmasq-full-2.91-r1") || !strings.Contains(txt, "(2 packages)") {
		t.Errorf("text: %s", txt)
	}
	b, _ := json.Marshal(res.StructuredContent)
	wantAll(t, string(b), `"total":2`, `"name":"dnsmasq-full"`, `"version":"2.91-r1"`, `"name":"luci"`, `"upgradable_from":"luci-26.268.1-r2"`)
	if res := callRaw(t, cs, "pkg_query", map[string]any{"action": "info", "package": "dnsmasq"}); res.StructuredContent != nil {
		t.Errorf("a free-text action returned data: %v", res.StructuredContent)
	}
}

// A secret the text masker hides must be hidden in structuredContent too: for uci_get, logread and
// exec the data is parsed from the masked text, never from the raw output.
func TestStructuredFromMaskedTextHidesSecrets(t *testing.T) {
	f := newFakeRouter(t)
	f.on("uci show wireless", "wireless.wlan0=wifi-iface\nwireless.wlan0.ssid='home'\nwireless.wlan0.key='hunter2-secret'\n")
	f.on("logread", "Tue Sep 30 10:00:00 2026 daemon.info proc[1]: hello\nnot a syslog line\n")
	cs := connectClient(t, testServer(t, grantAll()), "c")
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "uci_get", Arguments: map[string]any{"config": "wireless"}})
	if err != nil || res.IsError {
		t.Fatalf("uci_get: %v %+v", err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if strings.Contains(string(b), "hunter2") {
		t.Fatalf("secret in structuredContent: %s", b)
	}
	if !strings.Contains(string(b), `"wireless.wlan0.ssid"`) || !strings.Contains(string(b), `"home"`) {
		t.Errorf("ssid entry missing: %s", b)
	}
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "logread", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("logread: %v %+v", err, res)
	}
	b, _ = json.Marshal(res.StructuredContent)
	if !strings.Contains(string(b), `"level":"daemon.info"`) || !strings.Contains(string(b), `"text":"not a syslog line"`) {
		t.Errorf("log lines: %s", b)
	}
}

// rawSession talks JSON-RPC lines to a server over a pipe, so a test can negotiate any protocol
// version (the SDK's own client always asks for the newest).
func rawSession(t *testing.T, s *Server, version string) func(method, params string) map[string]any {
	t.Helper()
	cli, srv := net.Pipe()
	ss, err := s.serverFor("c").Connect(context.Background(), &mcp.IOTransport{Reader: srv, Writer: srv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close(); ss.Close() })
	br := bufio.NewReader(cli)
	id := 0
	call := func(method, params string) map[string]any {
		id++
		fmt.Fprintf(cli, `{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`+"\n", id, method, params)
		line, err := br.ReadBytes('\n')
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("%s: %v: %s", method, err, line)
		}
		return m
	}
	call("initialize", `{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"t","version":"0"}}`)
	fmt.Fprintln(cli, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return call
}

// 10.9: a client that did not negotiate structured output (protocol before 2025-06-18) gets the
// text alone: no outputSchema in tools/list and no structuredContent in the result.
func TestStructuredOutputGoesOnlyToClientsThatNegotiateIt(t *testing.T) {
	wgFake(t, 0)
	for _, c := range []struct {
		version string
		want    bool
	}{{"2024-11-05", false}, {"2025-03-26", false}, {"2025-06-18", true}, {"2025-11-25", true}} {
		call := rawSession(t, testServer(t, grantAll()), c.version)
		list := call("tools/list", `{}`)
		schemas := 0
		for _, tl := range list["result"].(map[string]any)["tools"].([]any) {
			if _, ok := tl.(map[string]any)["outputSchema"]; ok {
				schemas++
			}
		}
		res := call("tools/call", `{"name":"wg_list_clients","arguments":{}}`)["result"].(map[string]any)
		_, hasData := res["structuredContent"]
		if (schemas > 0) != c.want || hasData != c.want {
			t.Errorf("%s: outputSchemas=%d structuredContent=%v, want present=%v", c.version, schemas, hasData, c.want)
		}
		if text := res["content"].([]any)[0].(map[string]any)["text"].(string); !strings.Contains(text, "ALLOWED IPS") {
			t.Errorf("%s: the text table is missing:\n%s", c.version, text)
		}
	}
}
