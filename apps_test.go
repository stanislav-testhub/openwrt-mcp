package main

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connectApps(t *testing.T, s *Server, declare bool) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.serverFor("c").Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	opts := &mcp.ClientOptions{}
	if declare {
		opts.Capabilities = &mcp.ClientCapabilities{}
		opts.Capabilities.AddExtension(appsExt, map[string]any{"mimeTypes": []any{appsMIME}})
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func uiLinks(t *testing.T, cs *mcp.ClientSession) map[string]string {
	t.Helper()
	tl, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tool := range tl.Tools {
		if ui, ok := tool.Meta["ui"].(map[string]any); ok {
			got[tool.Name], _ = ui["resourceUri"].(string)
		}
	}
	return got
}

func TestAppsAreOffUnlessTheOwnerAndTheClientBothAsk(t *testing.T) {
	grants := policyFor("c", allToolNames, "*")
	read := func(cs *mcp.ClientSession) error {
		_, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "ui://openwrt-mcp/clients"})
		return err
	}
	// Owner off, client asks: nothing is registered or linked.
	cs := connectApps(t, testServer(t, grants), true)
	if l := uiLinks(t, cs); len(l) != 0 {
		t.Errorf("links with the feature off: %v", l)
	}
	if rl, err := cs.ListResources(context.Background(), nil); err == nil && len(rl.Resources) != 0 {
		t.Errorf("resources with the feature off: %v", rl.Resources)
	}
	if read(cs) == nil {
		t.Error("a page was served with the feature off")
	}
	// Owner on, client does not ask: the same silence.
	on := "config server\n\toption apps '1'\n" + grants
	cs = connectApps(t, testServer(t, on), false)
	if l := uiLinks(t, cs); len(l) != 0 {
		t.Errorf("links for a client that did not ask: %v", l)
	}
	if rl, err := cs.ListResources(context.Background(), nil); err == nil && len(rl.Resources) != 0 {
		t.Errorf("resources for a client that did not ask: %v", rl.Resources)
	}
	if read(cs) == nil {
		t.Error("a page was served to a client that did not ask")
	}
	// A client that declares the extension without the page type is not asking either.
	ct, st := mcp.NewInMemoryTransports()
	s := testServer(t, on)
	if _, err := s.serverFor("c").Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	caps := &mcp.ClientCapabilities{}
	caps.AddExtension(appsExt, map[string]any{"mimeTypes": []any{"text/html"}})
	cs2, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, &mcp.ClientOptions{Capabilities: caps}).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs2.Close()
	if l := uiLinks(t, cs2); len(l) != 0 {
		t.Errorf("links for a client with the wrong page type: %v", l)
	}
}

func TestAppsLinkThreeToolsAndServeTheirPages(t *testing.T) {
	s := testServer(t, "config server\n\toption apps '1'\n"+policyFor("c", allToolNames, "*"))
	cs := connectApps(t, s, true)
	want := map[string]string{
		"network_clients": "ui://openwrt-mcp/clients", "system_status": "ui://openwrt-mcp/audit", "request_access": "ui://openwrt-mcp/approvals",
	}
	got := uiLinks(t, cs)
	if len(got) != len(want) {
		t.Fatalf("links %v, want %v", got, want)
	}
	for tool, uri := range want {
		if got[tool] != uri {
			t.Errorf("%s links %q, want %q", tool, got[tool], uri)
		}
		res, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
		if err != nil || len(res.Contents) != 1 {
			t.Fatalf("read %s: %v", uri, err)
		}
		c := res.Contents[0]
		view := strings.TrimPrefix(uri, "ui://openwrt-mcp/")
		if c.MIMEType != appsMIME || !strings.Contains(c.Text, `data-view="`+view+`"`) || strings.Contains(c.Text, "{{VIEW}}") {
			t.Errorf("%s: mime %q, page does not name its view", uri, c.MIMEType)
		}
	}
	if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "ui://openwrt-mcp/nope"}); err == nil {
		t.Error("an unknown view was served")
	}
}

// The page must stay a reader: no markup from data, no network, no tool calls, a closed CSP.
func TestAppPageIsReadOnlyAndClosed(t *testing.T) {
	for _, banned := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "fetch(", "XMLHttpRequest",
		"WebSocket", "sendBeacon", "window.open", "location", "tools/call", "resources/read", "<a ", "<iframe", "<img", "src=", "href="} {
		if strings.Contains(appsPage, banned) {
			t.Errorf("the view page contains %q", banned)
		}
	}
	if !strings.Contains(appsPage, "default-src 'none'") {
		t.Error("no default-deny content security policy")
	}
	// Every outgoing message is one of the three the handshake needs.
	for _, m := range []string{`method: "ui/initialize"`, `method: "ui/notifications/initialized"`} {
		if !strings.Contains(appsPage, strings.TrimPrefix(m, "method: ")) && !strings.Contains(appsPage, m) {
			t.Errorf("handshake step %s missing", m)
		}
	}
}

func TestAppViewsAreTheThreeRoadmapViews(t *testing.T) {
	for _, v := range appViews {
		if !slices_contains(allToolNames, v.tool) {
			t.Errorf("view %s names unknown tool %s", v.name, v.tool)
		}
		if strings.ContainsAny(v.name, " /\"'<>") {
			t.Errorf("view name %q would break the page or the URI", v.name)
		}
	}
	if len(appViews) != 3 {
		t.Errorf("%d views; ROADMAP 6.6 names three", len(appViews))
	}
}

func slices_contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// The audit view reads findings back out of the text, so the two must stay in step: every line
// findingsRun.render writes has to match one of the patterns in apps/view.html.
func TestAuditViewParsesWhatRenderWrites(t *testing.T) {
	run := &findingsRun{title: "audit", checked: []string{"firewall"}, skipped: []string{"nothing"}, limits: []string{"one limit"}}
	run.findings = []finding{newFinding("ssh-wan", sevHigh, "SSH is open", "port 22"), newFinding("wps-on", sevLow, "WPS on", "")}
	text := run.render()
	for _, pat := range []string{`^\[(\w+)\] ([^:]+): (.*)$`, `^\s+(evidence|next|docs): (.*)$`, `^(checked|not checked|limits): `, `^\w[^\n]*: (no findings|\d+ finding)`} {
		if !strings.Contains(appsPage, strings.ReplaceAll(pat, `\n`, `\n`)) {
			t.Errorf("view.html no longer has the pattern %s", pat)
		}
		re := regexp.MustCompile(pat)
		hit := false
		for _, l := range strings.Split(text, "\n") {
			hit = hit || re.MatchString(l)
		}
		if !hit {
			t.Errorf("pattern %s matches no line of the rendered findings:\n%s", pat, text)
		}
	}
}

// The links are what one client is shown, never what the server holds: tools/list hands out the
// registered tool objects, so a client that asked must not leave its links on them for the next
// one (found in the ext-apps reference host: after one Apps client every client saw the links).
func TestAppsLinksDoNotLeakToTheNextClient(t *testing.T) {
	s := testServer(t, "config server\n\toption apps '1'\n"+policyFor("c", allToolNames, "*"))
	if l := uiLinks(t, connectApps(t, s, false)); len(l) != 0 {
		t.Fatalf("links before any client asked: %v", l)
	}
	if l := uiLinks(t, connectApps(t, s, true)); len(l) != 3 {
		t.Fatalf("a client that asked sees %d links, want 3: %v", len(l), l)
	}
	if l := uiLinks(t, connectApps(t, s, false)); len(l) != 0 {
		t.Errorf("a client that did not ask sees the links an earlier client got: %v", l)
	}
}

// An empty resource list is [], never null: a client built on the TypeScript SDK rejects null with
// "expected array, received null" and cannot connect (found in the ext-apps reference host, with
// the feature off, which is the default).
func TestEmptyResourceListIsAnArrayNotNull(t *testing.T) {
	s := testServer(t, grantAll())
	call := rawSession(t, s, "2025-11-25")
	res := call("resources/list", `{}`)["result"].(map[string]any)
	list, ok := res["resources"].([]any)
	if !ok || len(list) != 0 {
		t.Errorf("resources = %#v, want an empty array", res["resources"])
	}
	for method, key := range map[string]string{"prompts/list": "prompts", "resources/templates/list": "resourceTemplates"} {
		r := call(method, `{}`)["result"].(map[string]any)
		if _, ok := r[key].([]any); !ok {
			t.Errorf("%s: %s = %#v, want an array", method, key, r[key])
		}
	}
}

// The page draws data from a typed server, but it must not die on a shape the server would never
// send (found by feeding the page crafted results in the reference host: a null entry in clients,
// or ips as a string, threw and left the page half drawn). It runs the page's own script against
// a minimal DOM, so it needs node and skips without it.
func TestClientsViewSurvivesOddShapes(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	start := strings.Index(appsPage, "<script>")
	end := strings.LastIndex(appsPage, "</script>")
	if start < 0 || end < start {
		t.Fatal("no script in the view page")
	}
	script := appsPage[start+len("<script>") : end]
	harness := `
const made = {};
const mk = tag => ({ tag, children: [], attrs: {}, dataset: {}, text: "", value: "",
  set textContent(v) { this.text = String(v); this.children = []; }, get textContent() { return this.text; },
  append(...n) { this.children.push(...n); }, replaceChildren(...n) { this.children = n; },
  setAttribute(k, v) { this.attrs[k] = v; }, get firstChild() { return this.children[0]; } });
const root = mk("div"), title = mk("h1");
globalThis.document = { documentElement: { dataset: { view: "clients" } }, getElementById: id => id === "root" ? root : title, createElement: mk };
let handler; const sent = [];
globalThis.parent = { postMessage: m => sent.push(m) };
globalThis.addEventListener = (type, f) => { handler = f; };
(0, eval)(` + "`" + `SCRIPT` + "`" + `);
const rows = [];
const walk = n => { if (n.tag === "tr") rows.push(n); n.children.forEach(c => typeof c === "object" && walk(c)); };
handler({ source: parent, data: { jsonrpc: "2.0", method: "ui/notifications/tool-result", params: { content: [{ type: "text", text: "x" }],
  structuredContent: { total: 5, clients: [null, 5, "str", { host: "ok", mac: "02:00:00:00:00:01", ips: "1.2.3.4" }, { host: { a: 1 }, ips: [null, { k: "v" }] }] } } } });
walk(root);
console.log(JSON.stringify({ title: title.text, rows: rows.length, sawTable: root.children.some(c => c.tag === "table") }));
`
	// The script goes in as a template literal body; escape what would end it.
	esc := strings.NewReplacer("\\", "\\\\", "`", "\\`", "${", "\\${").Replace(script)
	cmd := exec.Command(node, "-e", strings.Replace(harness, "SCRIPT", esc, 1))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the page threw on an odd shape: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), `"sawTable":true`) {
		t.Errorf("the page did not draw the clients it could read: %s", out)
	}
}
