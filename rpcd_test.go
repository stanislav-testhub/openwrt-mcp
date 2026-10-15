package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The rpcd plugin is a separate process from the daemon, so these tests drive it the way rpcd does:
// `list`, and `call <method>` with JSON on stdin and JSON on stdout, against files in a temp dir.

type rpcdRig struct {
	t   *testing.T
	env rpcdEnv
	rs  *RequestStore // a daemon's view of the same mirror
}

const rigConfig = "config server\n\toption audit '%AUDIT%'\n\toption request_wait '30'\n"

func newRig(t *testing.T) *rpcdRig {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openwrt-mcp")
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(cfg, []byte(strings.Replace(rigConfig, "%AUDIT%", audit, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	req := filepath.Join(dir, "run", "requests.json")
	return &rpcdRig{t: t,
		env: rpcdEnv{configPath: cfg, statePath: dir, requestsPath: req, now: time.Now},
		rs:  NewRequestStore(req, nil)}
}

// call runs one method through the plugin protocol and returns the decoded reply.
func (r *rpcdRig) call(method string, in any) map[string]any {
	r.t.Helper()
	var out bytes.Buffer
	body, _ := json.Marshal(in)
	if code := runRpcd(r.env, []string{"call", method}, bytes.NewReader(body), &out); code != 0 {
		r.t.Fatalf("%s exited %d: %s", method, code, out.String())
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		r.t.Fatalf("%s printed %q, not a JSON object: %v", method, out.String(), err)
	}
	return m
}

func (r *rpcdRig) ok(method string, in any) map[string]any {
	r.t.Helper()
	m := r.call(method, in)
	if e, bad := m["error"]; bad {
		r.t.Fatalf("%s failed: %v", method, e)
	}
	return m
}

func (r *rpcdRig) fails(method string, in any, want string) {
	r.t.Helper()
	m := r.call(method, in)
	e, _ := m["error"].(string)
	if e == "" || !strings.Contains(e, want) {
		r.t.Fatalf("%s gave %v, want an error containing %q", method, m, want)
	}
}

func (r *rpcdRig) open(client, tool, scope string) Request {
	r.t.Helper()
	req, ok := r.rs.Open(time.Now(), 10*time.Minute, client, tool, scope, map[string]any{"scope": scope})
	if !ok {
		r.t.Fatal("request refused")
	}
	return req
}

func (r *rpcdRig) config() *Config {
	r.t.Helper()
	c, err := LoadConfig(r.env.configPath)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rpcdRig) allowed(client, tool, scope string) bool {
	return func() bool {
		p, _ := r.config().AuthorisePolicy(client, tool, []string{scope}, time.Now())
		return p != nil
	}()
}

func (r *rpcdRig) audit() string {
	b, _ := os.ReadFile(filepath.Join(r.env.statePath, "audit.jsonl"))
	return string(b)
}

func stateOf(t *testing.T, m map[string]any, id string) string {
	t.Helper()
	list, _ := m["requests"].([]any)
	for _, x := range list {
		if row := x.(map[string]any); row["id"] == id {
			return row["state"].(string)
		}
	}
	return "absent"
}

// ---- the protocol

func TestListNamesEveryMethodAndMatchesTheACLFile(t *testing.T) {
	var out bytes.Buffer
	if code := runRpcd(rpcdEnv{}, []string{"list"}, strings.NewReader(""), &out); code != 0 {
		t.Fatalf("list exited %d", code)
	}
	var sigs map[string]map[string]string
	if err := json.Unmarshal(out.Bytes(), &sigs); err != nil {
		t.Fatalf("list printed %q: %v", out.String(), err)
	}

	b, err := os.ReadFile("files/usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var acl map[string]struct {
		Read  struct{ Ubus map[string][]string } `json:"read"`
		Write struct{ Ubus map[string][]string } `json:"write"`
	}
	if err := json.Unmarshal(b, &acl); err != nil {
		t.Fatal(err)
	}
	read := acl["luci-app-openwrt-mcp"].Read.Ubus["openwrt-mcp"]
	write := acl["luci-app-openwrt-mcp-write"].Write.Ubus["openwrt-mcp"]
	if len(acl["luci-app-openwrt-mcp"].Write.Ubus) != 0 {
		t.Error("the read group grants write methods: a read-only LuCI user could approve")
	}
	if len(acl["luci-app-openwrt-mcp-write"].Read.Ubus) != 0 {
		t.Error("the write group also grants read methods; it should add to the read group, not repeat it")
	}

	var all, wantRead, wantWrite []string
	for name := range sigs {
		all = append(all, name)
	}
	for _, m := range rpcdMethods {
		if m.write {
			wantWrite = append(wantWrite, m.name)
		} else {
			wantRead = append(wantRead, m.name)
		}
	}
	if !sameSet(all, append(slices.Clone(wantRead), wantWrite...)) {
		t.Errorf("list names %v, the method table has %v and %v", all, wantRead, wantWrite)
	}
	if !sameSet(read, wantRead) {
		t.Errorf("ACL read methods %v, want %v", read, wantRead)
	}
	if !sameSet(write, wantWrite) {
		t.Errorf("ACL write methods %v, want %v", write, wantWrite)
	}
	for _, w := range []string{"decide", "revoke", "revoke_tools", "grant_preset", "set_settings"} {
		if !slices.Contains(write, w) {
			t.Errorf("%s is not behind the write ACL", w)
		}
	}
}

func TestAnUnknownMethodAndBadInputAreErrorsNotCrashes(t *testing.T) {
	r := newRig(t)
	r.fails("no_such_method", map[string]any{}, "unknown method")
	var out bytes.Buffer
	if code := runRpcd(r.env, []string{"call", "decide"}, strings.NewReader("{not json"), &out); code != 0 || !strings.Contains(out.String(), `"error"`) {
		t.Errorf("bad JSON gave exit %d and %q, want an error object", code, out.String())
	}
	out.Reset()
	if code := runRpcd(r.env, []string{"call"}, strings.NewReader(""), &out); code == 0 {
		t.Error("call with no method succeeded")
	}
	if code := runRpcd(r.env, []string{"frobnicate"}, strings.NewReader(""), &out); code == 0 {
		t.Error("an unknown subcommand succeeded")
	}
}

// rpcd puts the caller's session id into the arguments of every call to a plugin as
// "ubus_rpc_session"; a method that rejects it as an unknown field fails every call from LuCI.
func TestEveryMethodAcceptsTheSessionFieldRpcdAdds(t *testing.T) {
	r := newRig(t)
	for _, m := range rpcdMethods {
		got := r.call(m.name, map[string]any{"ubus_rpc_session": "0123456789abcdef"})
		if e, _ := got["error"].(string); strings.Contains(e, "unknown field") {
			t.Errorf("%s refused the session field: %s", m.name, e)
		}
	}
	r.fails("decide", map[string]any{"ubus_rpc_session": "x", "breath": "family"}, "unknown field")
}

// ---- reading

func TestRequestsListsOpenRequestsWithTheirFacts(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "wireless.radio0.disabled")
	m := r.ok("requests", map[string]any{})
	list := m["requests"].([]any)
	if len(list) != 1 {
		t.Fatalf("%d requests, want 1: %v", len(list), m)
	}
	row := list[0].(map[string]any)
	for k, want := range map[string]string{"id": q.ID, "client": "claude", "tool": "uci_apply",
		"scope": "wireless.radio0.disabled", "state": "open"} {
		if row[k] != want {
			t.Errorf("%s = %v, want %s", k, row[k], want)
		}
	}
}

func TestRequestsShowsAnUnansweredRequestPastItsTimeAsExpired(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	r.env.now = func() time.Time { return time.Now().Add(time.Hour) }
	if got := stateOf(t, r.ok("requests", nil), q.ID); got != "expired" {
		t.Errorf("state %s, want expired", got)
	}
}

func TestRequestsNoticesAGrantTheCLIWroteAndSettlesTheRequest(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.lan.start")
	if err := appendPolicy(r.env.configPath, "claude", "uci_apply", "dhcp.*", "1h"); err != nil {
		t.Fatal(err)
	}
	if got := stateOf(t, r.ok("requests", nil), q.ID); got != "allowed" {
		t.Fatalf("state %s, want allowed: a covered request must not stay open until its ttl", got)
	}
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow"}, "already allowed")
	if n := len(r.config().Policies); n != 1 {
		t.Errorf("%d grants, want the CLI's one: Allow on a covered request wrote another", n)
	}
}

func TestStatusCarriesTheDaemonReportAndTheOpenRequests(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "claude", "uci_get", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	q := r.open("claude", "uci_apply", "dhcp.*")
	m := r.ok("status", map[string]any{})
	for _, k := range []string{"version", "policies", "clients", "audit", "requests"} {
		if _, ok := m[k]; !ok {
			t.Errorf("status has no %q", k)
		}
	}
	if stateOf(t, m, q.ID) != "open" {
		t.Errorf("status does not list the open request %s", q.ID)
	}
	pol := m["policies"].([]any)[0].(map[string]any)
	if pol["client"] != "claude" || pol["index"] != float64(0) {
		t.Errorf("policy row %v, want client claude, index 0 (revoke addresses blocks by it)", pol)
	}
}

// ---- deciding

func TestAllowWritesTheNarrowestGrantAndSettlesTheRequest(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "wireless.radio1.disabled")
	if r.allowed("claude", "uci_apply", "wireless.radio1.disabled") {
		t.Fatal("granted before anyone decided")
	}
	m := r.ok("decide", map[string]any{"id": q.ID, "decision": "allow"})
	if m["state"] != "allowed" {
		t.Errorf("reply %v, want state allowed", m)
	}
	if !r.allowed("claude", "uci_apply", "wireless.radio1.disabled") {
		t.Error("the call is still refused after Allow")
	}
	if r.allowed("claude", "uci_apply", "wireless.radio0.disabled") || r.allowed("claude", "uci_get", "wireless.radio1.disabled") ||
		r.allowed("other", "uci_apply", "wireless.radio1.disabled") {
		t.Error("the default grant is wider than the one scope on the one tool for the one client")
	}
	p := r.config().Policies[0]
	if d := time.Until(p.Expires); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("default duration gave expiry in %v, want 1 hour", d)
	}
	got, _ := r.rs.Get(q.ID, time.Now())
	if got.State != reqAllowed || got.Decider != "luci" {
		t.Errorf("the daemon sees %+v, want allowed by luci", got)
	}
	if a := r.audit(); !strings.Contains(a, `"decide"`) || !strings.Contains(a, q.ID) || !strings.Contains(a, "luci") {
		t.Errorf("audit lacks the decision, its id and its actor:\n%s", a)
	}
}

func TestADecisionIsConsumedOnce(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	r.ok("decide", map[string]any{"id": q.ID, "decision": "allow"})
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow"}, "already allowed")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "deny"}, "already allowed")
	if n := len(r.config().Policies); n != 1 {
		t.Errorf("%d grants after a repeated Allow, want 1", n)
	}
}

func TestConcurrentDecisionsOnOneRequestGrantExactlyOnce(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out bytes.Buffer
			body, _ := json.Marshal(map[string]any{"id": q.ID, "decision": "allow"})
			runRpcd(r.env, []string{"call", "decide"}, bytes.NewReader(body), &out)
			if !strings.Contains(out.String(), `"error"`) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 || len(r.config().Policies) != 1 {
		t.Errorf("%d decisions won and %d grants exist, want 1 and 1", won.Load(), len(r.config().Policies))
	}
}

func TestDenyWritesNoGrantAndTheDaemonSeesTheRefusal(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "exec", "sh")
	r.ok("decide", map[string]any{"id": q.ID, "decision": "deny"})
	if len(r.config().Policies) != 0 {
		t.Error("Deny wrote a grant")
	}
	// The held call polls the store; the plugin ran in another process, so the store must take
	// the answer from the mirror file.
	if got, _ := r.rs.Get(q.ID, time.Now()); got.State != reqDenied {
		t.Errorf("the daemon's store holds %q after the plugin denied the request", got.State)
	}
}

func TestADaemonSaveDoesNotEraseADecisionTheStoreHasNotSeenYet(t *testing.T) {
	r := newRig(t)
	a := r.open("claude", "uci_apply", "dhcp.*")
	r.ok("decide", map[string]any{"id": a.ID, "decision": "deny"})
	r.open("claude", "uci_apply", "network.*") // the daemon saves the mirror again
	if got := stateOf(t, r.ok("requests", nil), a.ID); got != "denied" {
		t.Errorf("request %s is %s after the daemon saved, want denied: the daemon overwrote the decision", a.ID, got)
	}
}

func TestDecideRefusesWhatItCannotDoAndChangesNothing(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	r.fails("decide", map[string]any{"id": "ffffffff", "decision": "allow"}, "no request")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "maybe"}, "decision")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow", "duration": "never"}, "duration")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow", "duration": "30d"}, "duration")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow", "breadth": "everything"}, "breadth")
	if len(r.config().Policies) != 0 {
		t.Error("a refused decision left a grant behind")
	}
	if got, _ := r.rs.Get(q.ID, time.Now()); got.State != reqOpen {
		t.Errorf("a refused decision left the request %s", got.State)
	}
}

func TestDecideRefusesAnExpiredRequest(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	r.env.now = func() time.Time { return time.Now().Add(time.Hour) }
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow"}, "expired")
	if len(r.config().Policies) != 0 {
		t.Error("an expired request was granted")
	}
}

func TestBreadthWidensOnlyAsFarAsChosen(t *testing.T) {
	cases := []struct {
		breadth       string
		scope         string
		coversSibling bool // dhcp.lan.start's family
		coversAny     bool // another scope entirely
		otherTool     bool
	}{
		{"exact", "dhcp.lan.start", false, false, false},
		{"family", "dhcp.lan.start", true, false, false},
		{"tool", "dhcp.lan.start", true, true, false},
	}
	for _, c := range cases {
		t.Run(c.breadth, func(t *testing.T) {
			r := newRig(t)
			q := r.open("claude", "uci_apply", c.scope)
			r.ok("decide", map[string]any{"id": q.ID, "decision": "allow", "breadth": c.breadth})
			if !r.allowed("claude", "uci_apply", c.scope) {
				t.Fatal("the request's own call is not covered")
			}
			if got := r.allowed("claude", "uci_apply", "dhcp.wan.leasetime"); got != c.coversSibling {
				t.Errorf("sibling in the same family covered = %v, want %v", got, c.coversSibling)
			}
			if got := r.allowed("claude", "uci_apply", "firewall.zone1.name"); got != c.coversAny {
				t.Errorf("unrelated scope covered = %v, want %v", got, c.coversAny)
			}
			if r.allowed("claude", "exec", "sh") || r.allowed("claude", "uci_get", c.scope) {
				t.Error("the grant covers another tool")
			}
		})
	}
}

func TestAScopeWithNoFamilyStaysExactAtFamilyBreadth(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "sysupgrade", "backup")
	r.ok("decide", map[string]any{"id": q.ID, "decision": "allow", "breadth": "family"})
	if r.allowed("claude", "sysupgrade", "flash") || r.allowed("claude", "sysupgrade", "anything") {
		t.Error("a scope with no dot became a wildcard at family breadth")
	}
}

func TestOperatorBreadthGrantsThePresetAndOnlyForToolsItHolds(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.lan.start")
	r.ok("decide", map[string]any{"id": q.ID, "decision": "allow", "breadth": "operator"})
	for _, tool := range []string{"uci_apply", "uci_get", "service_control"} {
		if !r.allowed("claude", tool, "dhcp.lan.start") {
			t.Errorf("%s is not covered by the operator preset grant", tool)
		}
	}
	if r.allowed("claude", "exec", "sh") {
		t.Error("the operator preset covers exec")
	}

	e := r.open("claude", "exec", "sh")
	r.fails("decide", map[string]any{"id": e.ID, "decision": "allow", "breadth": "operator"}, "exec")
	if got, _ := r.rs.Get(e.ID, time.Now()); got.State != reqOpen {
		t.Errorf("a decision that could not release the call closed its request (%s)", got.State)
	}
}

func TestARootShellGrantNeedsAnExplicitConfirmation(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "exec", "sh")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow"}, "root shell")
	if len(r.config().Policies) != 0 {
		t.Fatal("a shell-equivalent grant was written without confirmation")
	}
	if got, _ := r.rs.Get(q.ID, time.Now()); got.State != reqOpen {
		t.Errorf("the refused decision closed the request (%s)", got.State)
	}
	r.ok("decide", map[string]any{"id": q.ID, "decision": "allow", "confirm": true})
	if !r.allowed("claude", "exec", "sh") {
		t.Error("the confirmed grant does not cover the call")
	}
}

// ---- revoking and presets

func TestRevokeRemovesOneBlockByIndexOrEverythingForTheClient(t *testing.T) {
	r := newRig(t)
	for _, tool := range []string{"uci_get", "logread", "firewall_show"} {
		if err := appendPolicy(r.env.configPath, "claude", tool, "*", "1h"); err != nil {
			t.Fatal(err)
		}
	}
	if err := appendPolicy(r.env.configPath, "other", "uci_get", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	if got := r.ok("revoke", map[string]any{"client": "claude", "index": 1})["removed"]; got != float64(1) {
		t.Fatalf("removed %v, want 1", got)
	}
	if r.allowed("claude", "logread", "x") || !r.allowed("claude", "uci_get", "x") || !r.allowed("claude", "firewall_show", "x") {
		t.Error("index 1 removed the wrong block")
	}
	if got := r.ok("revoke", map[string]any{"client": "claude", "all": true})["removed"]; got != float64(2) {
		t.Errorf("removed %v, want the two that remain", got)
	}
	if !r.allowed("other", "uci_get", "x") {
		t.Error("revoking claude removed another client's grant")
	}
	if !strings.Contains(r.audit(), `"revoke"`) {
		t.Error("audit lacks the revoke")
	}
}

func TestRevokeNeedsExactlyOneOfIndexAndAll(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "claude", "uci_get", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	r.fails("revoke", map[string]any{"client": "claude"}, "index")
	r.fails("revoke", map[string]any{"client": "claude", "index": 0, "all": true}, "index")
	r.fails("revoke", map[string]any{"client": "claude", "index": 5}, "no grant")
	r.fails("revoke", map[string]any{"client": "claude", "index": -1}, "no grant")
	if len(r.config().Policies) != 1 {
		t.Error("a refused revoke removed something")
	}
}

func TestGrantPresetWritesTheCLIsBlocksAndRefusesWhatTheCLIWould(t *testing.T) {
	r := newRig(t)
	r.ok("grant_preset", map[string]any{"client": "claude", "preset": "readonly", "duration": "8h"})
	if !r.allowed("claude", "uci_get", "network.lan.ipaddr") || r.allowed("claude", "uci_apply", "network.lan.ipaddr") {
		t.Error("the readonly preset grants the wrong tools")
	}
	want, _ := expandPreset("@readonly")
	if got := len(r.config().Policies); got != len(want) {
		t.Errorf("%d blocks, want the preset's %d", got, len(want))
	}
	r.fails("grant_preset", map[string]any{"client": "claude", "preset": "all", "duration": "1h"}, "preset")
	r.fails("grant_preset", map[string]any{"client": "claude", "preset": "admin", "duration": "1h"}, "preset")
	r.fails("grant_preset", map[string]any{"client": "bad name!", "preset": "readonly", "duration": "1h"}, "client")
	r.fails("grant_preset", map[string]any{"client": "claude", "preset": "readonly", "duration": "forever"}, "duration")
	before := len(r.config().Policies)
	r.fails("grant_preset", map[string]any{"client": "claude", "preset": "readonly", "duration": "30d"}, "duration")
	if len(r.config().Policies) != before {
		t.Error("a duration the page does not offer was granted")
	}
	r.ok("grant_preset", map[string]any{"client": "claude", "preset": "operator", "duration": "never"})
	if !strings.Contains(r.audit(), `"grant_preset"`) {
		t.Error("audit lacks the preset grant")
	}
}

// ---- settings

func TestSettingsRoundTripAndKeepTheRestOfTheFile(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "claude", "uci_get", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	m := r.ok("settings", nil)
	if m["request_wait"] != float64(30) || m["request_ttl"] != float64(600) {
		t.Errorf("settings %v, want wait 30 and the default ttl 600", m)
	}
	r.ok("set_settings", map[string]any{"request_wait": 90, "request_ttl": 1800})
	m = r.ok("settings", nil)
	if m["request_wait"] != float64(90) || m["request_ttl"] != float64(1800) {
		t.Errorf("settings %v after the change", m)
	}
	c := r.config()
	if c.RequestWait != 90*time.Second || c.RequestTTL != 30*time.Minute {
		t.Errorf("the daemon would read wait %v ttl %v", c.RequestWait, c.RequestTTL)
	}
	if len(c.Policies) != 1 || !strings.Contains(r.audit(), `"set_settings"`) {
		t.Error("the change lost a grant or was not audited")
	}
	b, _ := os.ReadFile(r.env.configPath)
	if strings.Count(string(b), "option request_wait") != 1 {
		t.Errorf("request_wait written %d times:\n%s", strings.Count(string(b), "option request_wait"), b)
	}
	r.ok("set_settings", map[string]any{"request_wait": 0})
	if got := r.ok("settings", nil)["request_wait"]; got != float64(0) {
		t.Errorf("request_wait %v, want 0 (off)", got)
	}
	if got := r.ok("settings", nil)["request_ttl"]; got != float64(1800) {
		t.Errorf("an omitted field changed: request_ttl %v", got)
	}
}

func TestSettingsRefuseOutOfRangeValuesWithoutWriting(t *testing.T) {
	r := newRig(t)
	before, _ := os.ReadFile(r.env.configPath)
	r.fails("set_settings", map[string]any{"request_wait": 601}, "request_wait")
	r.fails("set_settings", map[string]any{"request_wait": -1}, "request_wait")
	r.fails("set_settings", map[string]any{"request_ttl": 59}, "request_ttl")
	r.fails("set_settings", map[string]any{"request_ttl": 86401}, "request_ttl")
	r.fails("set_settings", map[string]any{}, "nothing")
	r.fails("set_settings", map[string]any{"request_wait": 10, "request_ttl": 5}, "request_ttl")
	after, _ := os.ReadFile(r.env.configPath)
	if !bytes.Equal(before, after) {
		t.Errorf("a refused change edited the config:\n%s", after)
	}
}

func TestSetServerOptionAddsTheOptionWhenTheFileHasNone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg")
	os.WriteFile(p, []byte("# comment\nconfig server 'main'\n\toption listen '127.0.0.1:8730'\n\nconfig policy\n\toption client 'a'\n\tlist tools 'uci_get'\n"), 0o600)
	if err := setServerOption(p, "request_wait", "45"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	secs := parseUCI(bufio.NewScanner(strings.NewReader(string(b))))
	if secs[0].Options["request_wait"] != "45" || secs[0].Options["listen"] != "127.0.0.1:8730" || secs[1].Options["client"] != "a" {
		t.Errorf("sections %v from\n%s", secs, b)
	}
	os.WriteFile(p, []byte("config policy\n\toption client 'a'\n\tlist tools 'uci_get'\n"), 0o600)
	if err := setServerOption(p, "request_wait", "45"); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil || c.RequestWait != 45*time.Second || len(c.Policies) != 1 {
		t.Errorf("config with no server section: %+v, %v", c, err)
	}
}

// ---- the lock

func TestAStaleMirrorLockIsBrokenButAFreshOneIsRespected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "requests.json")
	lock := p + ".lock"
	os.WriteFile(lock, nil, 0o600)
	old := time.Now().Add(-time.Minute)
	os.Chtimes(lock, old, old)
	unlock, err := lockMirror(p)
	if err != nil {
		t.Fatalf("a lock left by a crashed process blocked the plugin: %v", err)
	}
	if _, err := os.Stat(lock); err != nil {
		t.Error("the lock file is not held")
	}
	unlock()
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Error("unlock left the file")
	}
}

func TestAMisspelledOrExtraFieldIsRefusedNotIgnored(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "uci_apply", "dhcp.*")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow", "breath": "tool"}, "breath")
	if len(r.config().Policies) != 0 {
		t.Error("a decision with an unknown field still wrote a grant")
	}
}

func TestAScopeWithSpacesCannotBeGrantedExactly(t *testing.T) {
	r := newRig(t)
	q := r.open("claude", "exec", "git status")
	r.fails("decide", map[string]any{"id": q.ID, "decision": "allow", "confirm": true}, "space")
	if len(r.config().Policies) != 0 {
		t.Error("a scope with a space was written; the config would hold two scopes, neither the one asked for")
	}
}

// The store re-reads the mirror only when its size or time changed. A plugin write that leaves both
// as the store last saw them must still survive the store's next save.
func TestADecisionTheStoreCannotSeeByStatIsStillKeptAtSaveTime(t *testing.T) {
	r := newRig(t)
	a := r.open("claude", "uci_apply", "dhcp.*")
	r.ok("decide", map[string]any{"id": a.ID, "decision": "deny"})
	r.rs.mu.Lock()
	r.rs.noteMirrorLocked() // the store believes the file is as it left it
	r.rs.mu.Unlock()
	r.open("claude", "uci_apply", "network.*")
	if got := stateOf(t, r.ok("requests", nil), a.ID); got != "denied" {
		t.Errorf("request %s is %s after the daemon saved, want denied", a.ID, got)
	}
}

// ---- revoking single tools out of a block

func TestRevokeToolsTakesNamedToolsOutOfAMixedBlockAndKeepsTheRest(t *testing.T) {
	r := newRig(t)
	// What a preset writes: one block that holds several abilities at once.
	if err := appendPolicy(r.env.configPath, "claude", "uci_get,logread,uci_apply", "*", "8h"); err != nil {
		t.Fatal(err)
	}
	if err := appendPolicy(r.env.configPath, "claude", "ubus_call", "system.board system.info", "1h"); err != nil {
		t.Fatal(err)
	}
	if err := appendPolicy(r.env.configPath, "other", "logread", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	got := r.ok("revoke_tools", map[string]any{"client": "claude", "tools": []string{"logread", "ubus_call"}})
	if got["removed"] != float64(2) {
		t.Fatalf("removed %v, want the two named tools", got["removed"])
	}
	if r.allowed("claude", "logread", "x") || r.allowed("claude", "ubus_call", "system.board") {
		t.Error("a named tool is still granted")
	}
	if !r.allowed("claude", "uci_get", "x") || !r.allowed("claude", "uci_apply", "x") {
		t.Error("the tools that were not named lost their grant")
	}
	if !r.allowed("other", "logread", "x") {
		t.Error("another client lost its grant")
	}
	ps := r.config().Policies
	if len(ps) != 2 {
		t.Fatalf("%d blocks left, want the mixed block (now two tools) and the other client's: the emptied block must go", len(ps))
	}
	var kept *Policy
	for i := range ps {
		if ps[i].Client == "claude" {
			kept = ps[i]
		}
	}
	if kept == nil || kept.Expires.IsZero() || !sameSet(kept.Scopes, []string{"*"}) || !kept.Enabled {
		t.Errorf("the block kept is %+v: its scopes, expiry and enabled flag must survive the edit", kept)
	}
	if !strings.Contains(r.audit(), `"revoke_tools"`) {
		t.Error("audit lacks the revoke")
	}
}

func TestRevokeToolsRefusesWhatItCannotDoAndChangesNothing(t *testing.T) {
	r := newRig(t)
	if err := appendPolicy(r.env.configPath, "claude", "uci_get,logread", "*", "1h"); err != nil {
		t.Fatal(err)
	}
	r.fails("revoke_tools", map[string]any{"client": "claude", "tools": []string{}}, "tools")
	r.fails("revoke_tools", map[string]any{"client": "claude", "tools": []string{"no_such_tool"}}, "no tool")
	r.fails("revoke_tools", map[string]any{"client": "bad name", "tools": []string{"logread"}}, "client")
	r.fails("revoke_tools", map[string]any{"client": "claude", "tools": []string{"firewall_show"}}, "no grant")
	if !r.allowed("claude", "logread", "x") || !r.allowed("claude", "uci_get", "x") {
		t.Error("a refused call changed the grants")
	}
}
