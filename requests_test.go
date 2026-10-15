package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Servers built by any test would otherwise write the request mirror under /var/run on the
// workstation (C:\var\run on Windows).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "openwrt-mcp-requests")
	if err != nil {
		panic(err)
	}
	requestsPath = filepath.Join(dir, "requests.json")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const ttl10 = 10 * time.Minute

func newStore(t *testing.T) (*RequestStore, *[]AuditEvent) {
	t.Helper()
	var mu sync.Mutex
	var events []AuditEvent
	rs := NewRequestStore(filepath.Join(t.TempDir(), "run", "requests.json"), func(e AuditEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	return rs, &events
}

func eventsOf(events *[]AuditEvent, tool string) int {
	n := 0
	for _, e := range *events {
		if e.Tool == tool {
			n++
		}
	}
	return n
}

// ---- the record

func TestARequestHoldsTheFactsTheDaemonDerived(t *testing.T) {
	rs, events := newStore(t)
	args := map[string]any{"config": "wireless", "section": "x", "password": "hunter2"}
	r, ok := rs.Open(t0, ttl10, "claude", "uci_apply", "wireless.x.key", args)
	if !ok {
		t.Fatal("a first request was refused")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(r.ID) {
		t.Errorf("id %q, want 8 hex characters", r.ID)
	}
	if r.Client != "claude" || r.Tool != "uci_apply" || r.Scope != "wireless.x.key" || r.State != reqOpen {
		t.Errorf("request %+v: wrong client, tool, scope or state", r)
	}
	if !r.Created.Equal(t0) || !r.Expires.Equal(t0.Add(ttl10)) {
		t.Errorf("created %v, expires %v; want %v and %v later", r.Created, r.Expires, t0, ttl10)
	}
	if strings.Contains(r.Args, "hunter2") || !strings.Contains(r.Args, redacted) || !strings.Contains(r.Args, "wireless") {
		t.Errorf("args %q: want the audit log's redaction (secret hidden, rest kept)", r.Args)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(r.ArgsHash) {
		t.Errorf("args_hash %q, want a SHA-256 in hex", r.ArgsHash)
	}
	if eventsOf(events, "request") != 1 {
		t.Errorf("audit events %+v, want exactly one 'request' event", *events)
	}
}

func TestTheArgumentHashIgnoresKeyOrderAndSeparatesDifferentCalls(t *testing.T) {
	rs, _ := newStore(t)
	a, _ := rs.Open(t0, ttl10, "c", "exec", "a", map[string]any{"x": 1, "y": 2})
	b, _ := rs.Open(t0, ttl10, "c", "exec", "b", map[string]any{"y": 2, "x": 1})
	c, _ := rs.Open(t0, ttl10, "c", "exec", "c", map[string]any{"x": 1, "y": 3})
	if a.ArgsHash != b.ArgsHash {
		t.Error("the same arguments in another key order hash differently")
	}
	if a.ArgsHash == c.ArgsHash {
		t.Error("different arguments hash the same")
	}
}

func TestStoredArgumentsAreCappedAtFiveHundredTwelveBytes(t *testing.T) {
	rs, _ := newStore(t)
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", map[string]any{"argv": strings.Repeat("a", 4000)})
	// The cap plus the ellipsis truncate() adds.
	if len(r.Args) > requestArgsMax+len("…") {
		t.Errorf("args are %d bytes, want at most %d", len(r.Args), requestArgsMax)
	}
}

// ---- dedupe and caps

func TestARepeatedDenialReusesTheOpenRequest(t *testing.T) {
	rs, events := newStore(t)
	a, _ := rs.Open(t0, ttl10, "c", "uci_apply", "wireless.*", nil)
	b, ok := rs.Open(t0.Add(time.Minute), ttl10, "c", "uci_apply", "wireless.*", nil)
	if !ok || a.ID != b.ID {
		t.Fatalf("same client, tool and scope gave %q then %q, want one request", a.ID, b.ID)
	}
	if !b.LastSeen.Equal(t0.Add(time.Minute)) {
		t.Errorf("last_seen %v, want it moved to the second denial", b.LastSeen)
	}
	if !b.Expires.Equal(a.Expires) {
		t.Errorf("a repeat moved the expiry to %v: a client could keep a request open for ever", b.Expires)
	}
	if len(rs.List(t0)) != 1 || eventsOf(events, "request") != 1 {
		t.Errorf("%d requests, %d request events; want 1 and 1", len(rs.List(t0)), eventsOf(events, "request"))
	}
	for name, other := range map[string][3]string{
		"client": {"d", "uci_apply", "wireless.*"}, "tool": {"c", "exec", "wireless.*"}, "scope": {"c", "uci_apply", "network.*"},
	} {
		if r, _ := rs.Open(t0, ttl10, other[0], other[1], other[2], nil); r.ID == a.ID {
			t.Errorf("a different %s was folded into the first request", name)
		}
	}
}

func TestAClientHoldsAtMostFiveOpenRequests(t *testing.T) {
	rs, _ := newStore(t)
	for i := 0; i < maxOpenPerClient; i++ {
		if _, ok := rs.Open(t0, ttl10, "c", "exec", fmt.Sprint("s", i), nil); !ok {
			t.Fatalf("request %d of %d refused", i+1, maxOpenPerClient)
		}
	}
	if _, ok := rs.Open(t0, ttl10, "c", "exec", "one-too-many", nil); ok {
		t.Error("a sixth open request was accepted")
	}
	if _, ok := rs.Open(t0, ttl10, "c", "exec", "s0", nil); !ok {
		t.Error("a repeat of an open request was refused at the cap: it adds nothing")
	}
	if _, ok := rs.Open(t0, ttl10, "other", "exec", "s0", nil); !ok {
		t.Error("one client at its cap blocked another client")
	}
}

func TestAtMostFiftyRequestsAreOpenInAll(t *testing.T) {
	rs, _ := newStore(t)
	for i := 0; i < maxOpenTotal; i++ {
		if _, ok := rs.Open(t0, ttl10, fmt.Sprint("c", i/2), "exec", fmt.Sprint("s", i), nil); !ok {
			t.Fatalf("request %d of %d refused", i+1, maxOpenTotal)
		}
	}
	if _, ok := rs.Open(t0, ttl10, "fresh", "exec", "x", nil); ok {
		t.Errorf("request %d was accepted", maxOpenTotal+1)
	}
}

func TestDecidedAndExpiredRequestsFreeTheirPlaceUnderTheCaps(t *testing.T) {
	rs, _ := newStore(t)
	ids := make([]string, 0, maxOpenPerClient)
	for i := 0; i < maxOpenPerClient; i++ {
		r, _ := rs.Open(t0, ttl10, "c", "exec", fmt.Sprint("s", i), nil)
		ids = append(ids, r.ID)
	}
	if _, err := rs.Decide(ids[0], false, "luci", t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Open(t0, ttl10, "c", "exec", "new1", nil); !ok {
		t.Error("a denied request still counts as open")
	}
	later := t0.Add(ttl10 + time.Second)
	if _, ok := rs.Open(later, ttl10, "c", "exec", "new2", nil); !ok {
		t.Error("expired requests still count as open")
	}
}

func TestACallerCannotOpenRequestsFasterThanTheRateLimit(t *testing.T) {
	rs, _ := newStore(t)
	made := 0
	for i := 0; i < 3*requestRatePerMin; i++ {
		r, ok := rs.Open(t0, ttl10, "c", "exec", fmt.Sprint("s", i), nil)
		if !ok {
			continue
		}
		made++
		// Closing each request keeps the open cap out of the way: only the rate limit is measured.
		if _, err := rs.Decide(r.ID, false, "luci", t0); err != nil {
			t.Fatal(err)
		}
	}
	if made != requestRatePerMin {
		t.Errorf("%d requests in one minute, want the limit of %d", made, requestRatePerMin)
	}
	if _, ok := rs.Open(t0.Add(61*time.Second), ttl10, "c", "exec", "later", nil); !ok {
		t.Error("the limit did not lift after a minute")
	}
}

// ---- decisions and expiry

func TestADecisionIsAppliedOnceAndThenRefused(t *testing.T) {
	rs, events := newStore(t)
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(allow bool) {
			defer wg.Done()
			_, err := rs.Decide(r.ID, allow, fmt.Sprint("actor-", allow), t0)
			errs <- err
		}(i%2 == 0)
	}
	wg.Wait()
	close(errs)
	won := 0
	for err := range errs {
		if err == nil {
			won++
		} else if !strings.Contains(err.Error(), "already") {
			t.Errorf("a refused decision says %q, want it to say the request was already decided", err)
		}
	}
	if won != 1 {
		t.Errorf("%d concurrent decisions succeeded, want exactly 1", won)
	}
	if eventsOf(events, "decide") != 1 {
		t.Errorf("%d decide events, want 1", eventsOf(events, "decide"))
	}
	got, _ := rs.Get(r.ID, t0)
	if got.State != reqAllowed && got.State != reqDenied {
		t.Errorf("state %q after a decision", got.State)
	}
}

func TestADecisionNamesWhoMadeItAndWhatTheyChose(t *testing.T) {
	rs, events := newStore(t)
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	got, err := rs.Decide(r.ID, true, "luci:root", t0.Add(time.Minute))
	if err != nil || got.State != reqAllowed {
		t.Fatalf("decide: %+v, %v", got, err)
	}
	last := (*events)[len(*events)-1]
	if last.Tool != "decide" || last.Client != "c" || !strings.Contains(last.Summary, "luci:root") || !strings.Contains(last.Summary, "allowed") {
		t.Errorf("audit event %+v, want the actor and the decision", last)
	}
}

func TestACallAfterADecisionOpensAFreshRequest(t *testing.T) {
	rs, _ := newStore(t)
	first, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	if _, err := rs.Decide(first.ID, false, "luci", t0); err != nil {
		t.Fatal(err)
	}
	again, ok := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	if !ok || again.ID == first.ID || again.State != reqOpen {
		t.Errorf("after a denial the same call got %+v, want a new open request", again)
	}
	later := t0.Add(ttl10 + time.Second)
	third, ok := rs.Open(later, ttl10, "c", "exec", "x", nil)
	if !ok || third.ID == again.ID || third.State != reqOpen {
		t.Errorf("after an expiry the same call got %+v, want a new open request", third)
	}
}

func TestDecidingAnUnknownOrExpiredRequestFails(t *testing.T) {
	rs, _ := newStore(t)
	if _, err := rs.Decide("deadbeef", true, "luci", t0); err == nil {
		t.Error("an unknown id was accepted")
	}
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	if _, err := rs.Decide(r.ID, true, "luci", t0.Add(ttl10+time.Second)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("deciding an expired request: %v, want an error saying it expired", err)
	}
}

func TestAnOpenRequestExpiresOnceAndIsAudited(t *testing.T) {
	rs, events := newStore(t)
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	if got, _ := rs.Get(r.ID, t0.Add(ttl10-time.Second)); got.State != reqOpen {
		t.Errorf("state %q just before the expiry, want open", got.State)
	}
	for i := 0; i < 3; i++ {
		got, ok := rs.Get(r.ID, t0.Add(ttl10+time.Second))
		if !ok || got.State != reqExpired {
			t.Fatalf("state %q after the expiry, want expired", got.State)
		}
	}
	if eventsOf(events, "expire") != 1 {
		t.Errorf("%d expire events, want 1", eventsOf(events, "expire"))
	}
}

func TestClosedRequestsAreForgottenAfterAWhile(t *testing.T) {
	rs, _ := newStore(t)
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", nil)
	if _, err := rs.Decide(r.ID, false, "luci", t0); err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Get(r.ID, t0.Add(time.Minute)); !ok {
		t.Error("a decision vanished at once: a held call would never learn of it")
	}
	if _, ok := rs.Get(r.ID, t0.Add(requestKeepClosed+time.Second)); ok {
		t.Error("a decided request is kept for ever")
	}
}

// ---- the mirror the rpcd plugin reads

func TestRequestsAreMirroredToAPrivateFileOnEveryChange(t *testing.T) {
	rs, _ := newStore(t)
	read := func() []Request {
		t.Helper()
		b, err := os.ReadFile(rs.path)
		if err != nil {
			t.Fatalf("mirror not written: %v", err)
		}
		var f struct {
			Requests []Request `json:"requests"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("mirror is not JSON: %v\n%s", err, b)
		}
		return f.Requests
	}
	r, _ := rs.Open(t0, ttl10, "c", "exec", "x", map[string]any{"token": "s3cret"})
	if got := read(); len(got) != 1 || got[0].ID != r.ID || got[0].State != reqOpen {
		t.Errorf("mirror after open: %+v", got)
	}
	if b, _ := os.ReadFile(rs.path); strings.Contains(string(b), "s3cret") {
		t.Error("the mirror holds a secret from the arguments")
	}
	if _, err := rs.Decide(r.ID, true, "luci", t0); err != nil {
		t.Fatal(err)
	}
	if got := read(); got[0].State != reqAllowed {
		t.Errorf("mirror after decide: %+v", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(rs.path); st.Mode().Perm() != 0o600 {
			t.Errorf("mirror mode %v, want 0600", st.Mode().Perm())
		}
	}
	if left, _ := filepath.Glob(rs.path + ".*"); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestAMirrorThatCannotBeWrittenDoesNotBreakTheStore(t *testing.T) {
	rs, _ := newStore(t)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rs.path = filepath.Join(blocker, "sub", "requests.json") // a directory cannot be made under a file
	if _, ok := rs.Open(t0, ttl10, "c", "exec", "x", nil); !ok {
		t.Error("a mirror failure refused the request")
	}
}

// ---- the denial path of a tool call

// callEvents is the audit log without the request lifecycle events: one per tool call.
func callEvents(t *testing.T, s *Server) []AuditEvent {
	t.Helper()
	var out []AuditEvent
	for _, ev := range auditEvents(t, s) {
		if ev.Tool != "request" && ev.Tool != "decide" && ev.Tool != "expire" {
			out = append(out, ev)
		}
	}
	return out
}

func uciGrant(client string) string { return policyFor(client, []string{"uci_get"}, "network") }

var uciGetCall = map[string]any{"config": "wireless"}

func (s *Server) openRequests(t *testing.T) []Request {
	t.Helper()
	var open []Request
	for _, r := range s.requests.List(time.Now()) {
		if r.State == reqOpen {
			open = append(open, r)
		}
	}
	return open
}

// grant appends a policy to the live config and moves its mtime on, so the daemon reloads it.
func grant(t *testing.T, s *Server, policy string) {
	t.Helper()
	b, err := os.ReadFile(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.configPath, append(b, []byte("\n"+policy)...), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Duration(time.Now().UnixNano()%1000+2) * time.Second)
	if err := os.Chtimes(s.configPath, future, future); err != nil {
		t.Fatal(err)
	}
}

func fastPoll(t *testing.T) {
	t.Helper()
	old := requestPoll
	requestPoll = 5 * time.Millisecond
	t.Cleanup(func() { requestPoll = old })
}

func TestADeniedCallOpensARequestAndSaysWhereToApproveIt(t *testing.T) {
	s := testServer(t, uciGrant("c"))
	out, isErr := callText(t, connectClient(t, s, "c"), "uci_get", uciGetCall)
	open := s.openRequests(t)
	if !isErr || len(open) != 1 {
		t.Fatalf("error %v, %d open requests; want a denial and one request", isErr, len(open))
	}
	r := open[0]
	if r.Client != "c" || r.Tool != "uci_get" || r.Scope != "wireless" {
		t.Errorf("request %+v, want the failed call's client, tool and scope", r)
	}
	for _, want := range []string{"request " + r.ID, "LuCI", "grant it: openwrt-mcp allow c uci_get 'wireless' 60m", "[code: POLICY_DENIED"} {
		if !strings.Contains(out, want) {
			t.Errorf("denial lacks %q:\n%s", want, out)
		}
	}
	if eventsOf(auditEventsPtr(t, s), "request") != 1 {
		t.Errorf("audit %+v, want one request event", auditEvents(t, s))
	}
}

func auditEventsPtr(t *testing.T, s *Server) *[]AuditEvent {
	evs := auditEvents(t, s)
	return &evs
}

func TestTheSameDeniedCallTwiceIsOneRequest(t *testing.T) {
	s := testServer(t, uciGrant("c"))
	cs := connectClient(t, s, "c")
	a, _ := callText(t, cs, "uci_get", uciGetCall)
	b, _ := callText(t, cs, "uci_get", uciGetCall)
	if open := s.openRequests(t); len(open) != 1 || !strings.Contains(a, open[0].ID) || !strings.Contains(b, open[0].ID) {
		t.Errorf("open %+v; want one request named in both denials:\n%s\n---\n%s", open, a, b)
	}
}

func TestAFloorRefusalNeverOpensARequest(t *testing.T) {
	s := testServer(t, policyFor("c", []string{"ubus_call"}, "*"))
	callText(t, connectClient(t, s, "c"), "ubus_call", map[string]any{"object": "openwrt-mcp", "method": "decide"})
	if open := s.openRequests(t); len(open) != 0 {
		t.Errorf("a call the floor refuses opened %+v: no approval can lift the floor", open)
	}
}

func TestARateLimitedCallOpensNoRequest(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call system board", boardJSON)
	s := testServer(t, policyFor("c", []string{"ubus_call"}, "system.board")+"\toption max_per_min '1'\n")
	cs := connectClient(t, s, "c")
	callText(t, cs, "ubus_call", boardCall)
	out, isErr := callText(t, cs, "ubus_call", boardCall)
	if !isErr || !strings.Contains(out, "rate limit") {
		t.Fatalf("second call: %q, want the rate limit", out)
	}
	if open := s.openRequests(t); len(open) != 0 {
		t.Errorf("a rate limit opened %+v: more access is not what it lacks", open)
	}
}

func TestACallAtTheRequestCapIsDeniedAsBeforeWithNoNewRequest(t *testing.T) {
	s := testServer(t, uciGrant("c"))
	for i := 0; i < maxOpenPerClient; i++ {
		s.requests.Open(time.Now(), ttl10, "c", "uci_get", fmt.Sprint("other", i), nil)
	}
	out, isErr := callText(t, connectClient(t, s, "c"), "uci_get", uciGetCall)
	if !isErr || !strings.Contains(out, "grant it:") || strings.Contains(out, "LuCI") {
		t.Errorf("denial at the cap: %q, want today's text without an approve line", out)
	}
	if n := len(s.openRequests(t)); n != maxOpenPerClient {
		t.Errorf("%d open requests, want the %d already there", n, maxOpenPerClient)
	}
}

// ---- held calls

func heldServer(t *testing.T) (*Server, *fakeRouter) {
	t.Helper()
	fastPoll(t)
	f := newFakeRouter(t)
	f.on("uci show wireless", "wireless.radio0=wifi-device")
	return testServer(t, "\toption request_wait '5'\n"+uciGrant("c")), f
}

func waitForOpenRequest(t *testing.T, s *Server) Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if open := s.openRequests(t); len(open) > 0 {
			return open[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no request was opened")
	return Request{}
}

type callResult struct {
	text  string
	isErr bool
}

func callAsync(t *testing.T, cs *mcp.ClientSession, ctx context.Context, name string, args map[string]any) <-chan callResult {
	ch := make(chan callResult, 1)
	go func() {
		res, err := cs.CallTool(ctx, callParams(name, args))
		if err != nil {
			ch <- callResult{text: "CALL ERROR " + err.Error(), isErr: true}
			return
		}
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text + "\n")
			}
		}
		ch <- callResult{b.String(), res.IsError}
	}()
	return ch
}

func expectPending(t *testing.T, ch <-chan callResult, what string) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("%s: the call returned instead of waiting: %q", what, r.text)
	case <-time.After(100 * time.Millisecond):
	}
}

func expectResult(t *testing.T, ch <-chan callResult, what string) callResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: the call never returned", what)
		return callResult{}
	}
}

func TestAHeldCallRunsWhenAGrantArrives(t *testing.T) {
	setInflight(t, 1, 100*time.Millisecond) // the hold and the run must share one slot, and give it back
	s, f := heldServer(t)
	res := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	expectPending(t, res, "no grant yet")
	if f.ran("uci") {
		t.Fatal("the tool ran before it was approved")
	}
	req := waitForOpenRequest(t, s)

	grant(t, s, policyFor("c", []string{"uci_get"}, "wireless"))
	r := expectResult(t, res, "after the grant")
	if r.isErr || !strings.Contains(r.text, "wireless.radio0") {
		t.Errorf("held call after the grant: %+v, want the tool's output", r)
	}
	if !strings.Contains(r.text, "approved after") || !strings.Contains(r.text, req.ID) {
		t.Errorf("result %q does not say it waited for approval and under which request", r.text)
	}
	if got, _ := s.requests.Get(req.ID, time.Now()); got.State != reqAllowed {
		t.Errorf("request state %q after the call ran, want allowed", got.State)
	}
	if out, isErr := callText(t, connectClient(t, s, "c"), "uci_get", uciGetCall); isErr {
		t.Errorf("a call after the approved one finished: %q, want its slot back", out)
	}
}

func TestAHeldCallEndsWhenTheRequestIsDenied(t *testing.T) {
	s, f := heldServer(t)
	res := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	req := waitForOpenRequest(t, s)
	if _, err := s.requests.Decide(req.ID, false, "luci", time.Now()); err != nil {
		t.Fatal(err)
	}
	r := expectResult(t, res, "after a denial")
	if !r.isErr || !strings.Contains(r.text, "denied by the operator") || !strings.Contains(r.text, "[code: POLICY_DENIED") {
		t.Errorf("held call after a denial: %+v", r)
	}
	if f.ran("uci") {
		t.Error("a denied call ran")
	}
}

func TestAHeldCallThatIsNeverAnsweredGivesUpWithTheRequestId(t *testing.T) {
	setInflight(t, 1, 100*time.Millisecond)
	fastPoll(t)
	newFakeRouter(t).on("uci show wireless", "wireless.radio0=wifi-device")
	s := testServer(t, "\toption request_wait '1'\n"+uciGrant("c"))
	started := time.Now()
	r := expectResult(t, callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall), "no answer")
	if took := time.Since(started); took < 900*time.Millisecond {
		t.Errorf("returned after %v, want it to wait out the 1 s", took)
	}
	req := s.openRequests(t)
	if !r.isErr || len(req) != 1 || !strings.Contains(r.text, req[0].ID) || !strings.Contains(r.text, "grant it:") {
		t.Errorf("timeout result %+v with open requests %+v, want POLICY_DENIED naming the request and the CLI line", r, req)
	}
	// "a retry after approval works": the request is still there to approve.
	if len(req) != 1 || req[0].State != reqOpen {
		t.Errorf("the request did not stay open after the wait ended: %+v", req)
	}
	grant(t, s, policyFor("c", []string{"uci_get"}, "wireless"))
	if out, isErr := callText(t, connectClient(t, s, "c"), "uci_get", uciGetCall); isErr {
		t.Errorf("a call after a wait that ended: %q, want the slot back", out)
	}
}

func TestACancelledHeldCallLeavesAndReleasesItsSlot(t *testing.T) {
	setInflight(t, 1, 100*time.Millisecond)
	s, _ := heldServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	res := callAsync(t, connectClient(t, s, "c"), ctx, "uci_get", uciGetCall)
	waitForOpenRequest(t, s)
	cancel()
	expectResult(t, res, "after cancel")

	// The one slot is free again: a call that needs no approval runs.
	grant(t, s, policyFor("c", []string{"ubus_call"}, "system.board"))
	f := newFakeRouter(t)
	f.on("ubus call system board", boardJSON)
	if out, isErr := callText(t, connectClient(t, s, "c"), "ubus_call", boardCall); isErr {
		t.Errorf("a call after the cancel: %q, want the slot back", out)
	}
	if n := len(s.openRequests(t)); n != 1 {
		t.Errorf("%d open requests after the cancel, want the request to stay for a retry", n)
	}
}

func TestAHeldCallCountsAgainstTheInFlightLimit(t *testing.T) {
	setInflight(t, 1, 100*time.Millisecond)
	s, _ := heldServer(t)
	grant(t, s, policyFor("c", []string{"ubus_call"}, "system.board"))
	f := newFakeRouter(t)
	f.on("ubus call system board", boardJSON)

	res := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	waitForOpenRequest(t, s)
	out, isErr := callText(t, connectClient(t, s, "c"), "ubus_call", boardCall)
	if !isErr || !strings.Contains(out, "busy") {
		t.Errorf("a call while the only slot is held: %q, want busy", out)
	}
	req := s.openRequests(t)[0]
	if _, err := s.requests.Decide(req.ID, false, "luci", time.Now()); err != nil {
		t.Fatal(err)
	}
	expectResult(t, res, "after a denial")
}

func TestHoldingDoesNotTakeASlotWhenWaitingIsOff(t *testing.T) {
	setInflight(t, 1, 100*time.Millisecond)
	s := testServer(t, uciGrant("c")+policyFor("c", []string{"ubus_call"}, "system.board"))
	b := newBlockingRunner(t)
	wait := fillSlots(t, s, b, 1)
	out, isErr := callText(t, connectClient(t, s, "c"), "uci_get", uciGetCall)
	if !isErr || strings.Contains(out, "busy") {
		t.Errorf("a denied call with waiting off: %q, want today's denial, not a queue for a slot", out)
	}
	close(b.release)
	wait()
}

func TestIdenticalHeldCallsShareOneRequestAndAreReleasedTogether(t *testing.T) {
	s, _ := heldServer(t)
	a := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	b := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	waitForOpenRequest(t, s)
	time.Sleep(50 * time.Millisecond)
	if n := len(s.openRequests(t)); n != 1 {
		t.Fatalf("%d open requests for two identical calls, want 1", n)
	}
	grant(t, s, policyFor("c", []string{"uci_get"}, "wireless"))
	for name, ch := range map[string]<-chan callResult{"first": a, "second": b} {
		if r := expectResult(t, ch, name); r.isErr {
			t.Errorf("%s held call: %+v, want it to run", name, r)
		}
	}
}

func TestAnApprovedCallStillNeedsItsSecondFactor(t *testing.T) {
	s, f := heldServer(t)
	res := callAsync(t, connectClient(t, s, "c"), context.Background(), "uci_get", uciGetCall)
	waitForOpenRequest(t, s)
	grant(t, s, policyFor("c", []string{"uci_get"}, "wireless")+"\tlist mfa_tools 'uci_get'\n")
	r := expectResult(t, res, "after the grant")
	if !r.isErr || !strings.Contains(r.text, "second factor") || f.ran("uci") {
		t.Errorf("approved call on an MFA tool: %+v (ran %v), want the MFA refusal", r, f.ran("uci"))
	}
}

// ---- configuration

func TestRequestOptionsAreReadAndClamped(t *testing.T) {
	load := func(opts string) *Config {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c")
		os.WriteFile(p, []byte("config server\n"+opts), 0o600)
		c, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for _, c := range []struct {
		opts string
		wait time.Duration
		ttl  time.Duration
	}{
		{"", 0, defaultRequestTTL},
		{"\toption request_wait '60'\n\toption request_ttl '30m'\n", 60 * time.Second, 30 * time.Minute},
		{"\toption request_wait '9999'\n\toption request_ttl '90d'\n", maxRequestWait, maxRequestTTL},
		{"\toption request_wait '-5'\n\toption request_ttl '1s'\n", 0, minRequestTTL},
		{"\toption request_wait 'soon'\n\toption request_ttl 'later'\n", 0, defaultRequestTTL},
	} {
		got := load(c.opts)
		if got.RequestWait != c.wait || got.RequestTTL != c.ttl {
			t.Errorf("%q: wait %v ttl %v, want %v and %v", c.opts, got.RequestWait, got.RequestTTL, c.wait, c.ttl)
		}
	}
}
