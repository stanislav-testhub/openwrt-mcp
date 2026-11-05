package main

import (
	"context"
	"encoding/json"
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
