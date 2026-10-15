package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Milestone 8.8. The push hook is an optional channel: off after install, and when on it sends the
// request (redacted) to the ubus event and to each runnable script in hooks.d, once per new request.

// Windows has no Unix modes, so addHook records each mode and hookModeOf reads it back by name.
var hookModes = map[string]fs.FileMode{}

func pushServer(t *testing.T, on string) (*Server, *fakeRouter, string) {
	t.Helper()
	s := testServer(t, "") // before the fixture root, which would re-root its state paths
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus send", "")
	oldMode := hookModeOf
	hookModeOf = func(fi fs.FileInfo) fs.FileMode { return hookModes[fi.Name()] }
	t.Cleanup(func() { hookModeOf = oldMode; clear(hookModes) })
	if on != "" {
		b, _ := os.ReadFile(s.configPath)
		if err := os.WriteFile(s.configPath, append(b, []byte("\n"+on)...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(root, "etc", "openwrt-mcp", "hooks.d")
	return s, f, dir
}

// quiet drops the daemon's own trigger, so a test calls pushRequest itself, once.
func quiet(s *Server) { s.requests.onNew = nil }

func addHook(t *testing.T, f *fakeRouter, dir, name string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
	hookModes[name] = mode
	f.on(p, "")
	return p
}

const pushOn = "config server\n\toption push_hook '1'\n"

func TestHookModeRefusesWhatARootProcessMustNotRun(t *testing.T) {
	for _, c := range []struct {
		mode fs.FileMode
		ok   bool
	}{
		{0o755, true}, {0o700, true}, {0o750, true},
		{0o644, false},                                 // not executable
		{0o775, false}, {0o757, false}, {0o777, false}, // writable by group or others
		{0o755 | fs.ModeDir, false}, {0o755 | fs.ModeSymlink, false},
	} {
		if got := hookModeOK(c.mode); got != c.ok {
			t.Errorf("hookModeOK(%v) = %v, want %v", c.mode, got, c.ok)
		}
	}
}

func TestPushHookIsOffByDefault(t *testing.T) {
	s, f, dir := pushServer(t, "")
	addHook(t, f, dir, "10-notify", 0o755)
	quiet(s)
	s.pushRequest(Request{ID: "x"}) // an off channel sends nothing
	if got := f.allCalls(); strings.Contains(got, "ubus send") || strings.Contains(got, "10-notify") {
		t.Errorf("push hook ran while off:\n%s", got)
	}
}

func TestPushHookSendsEventAndRunsHooksInOrderWithRedactedJSON(t *testing.T) {
	s, f, dir := pushServer(t, pushOn)
	quiet(s)
	b := addHook(t, f, dir, "20-b", 0o755)
	a := addHook(t, f, dir, "10-a", 0o700)
	addHook(t, f, dir, "30-writable", 0o777)
	addHook(t, f, dir, "40-plain", 0o644)
	addHook(t, f, dir, ".hidden", 0o755)
	addHook(t, f, dir, "50-edit~", 0o755)
	r, _ := s.requests.Open(time.Now(), time.Minute, "claude-code", "uci_apply", "wireless.*",
		map[string]any{"password": "hunter2-secret", "path": "wireless.x"})
	s.pushRequest(r)

	calls := f.allCalls()
	if !(strings.Index(calls, a) >= 0 && strings.Index(calls, a) < strings.Index(calls, b)) {
		t.Errorf("hooks did not run in name order:\n%s", calls)
	}
	for _, bad := range []string{"30-writable", "40-plain", ".hidden", "50-edit~"} {
		if strings.Contains(calls, bad) {
			t.Errorf("ran %s:\n%s", bad, calls)
		}
	}
	if !strings.Contains(calls, "ubus send openwrt-mcp.request ") {
		t.Errorf("no ubus event:\n%s", calls)
	}
	var payloads int
	for i, argv := range f.argvList() {
		if len(argv) == 0 || argv[0] != a {
			continue
		}
		payloads++
		var p pushPayload
		if err := json.Unmarshal([]byte(f.stdinOf(i)), &p); err != nil {
			t.Fatalf("stdin is not the request JSON: %v", err)
		}
		if p.ID != r.ID || p.Client != "claude-code" || p.Tool != "uci_apply" || p.Scope != "wireless.*" || p.Event != "request" {
			t.Errorf("payload = %+v", p)
		}
		if strings.Contains(f.stdinOf(i), "hunter2-secret") {
			t.Errorf("a secret reached the hook: %s", f.stdinOf(i))
		}
	}
	if payloads != 1 {
		t.Errorf("hook ran %d times, want 1", payloads)
	}
	for _, argv := range f.argvList() {
		if strings.Contains(strings.Join(argv, " "), "hunter2-secret") {
			t.Errorf("a secret reached argv: %v", argv)
		}
	}
	audit, _ := os.ReadFile(s.cfg().AuditPath)
	if !strings.Contains(string(audit), `"push_hook"`) || !strings.Contains(string(audit), "2 hook(s) run") ||
		!strings.Contains(string(audit), "30-writable") {
		t.Errorf("audit lacks the push summary, with the skipped hook named:\n%s", audit)
	}
}

func TestPushHookFiresOncePerRequestNotPerRepeatedCall(t *testing.T) {
	s, _, _ := pushServer(t, pushOn)
	var n int
	s.requests.onNew = func(r Request) { n++ }
	for range 3 {
		s.requests.Open(time.Now(), time.Minute, "claude-code", "uci_apply", "wireless.*", nil)
	}
	s.requests.Open(time.Now(), time.Minute, "claude-code", "uci_apply", "dhcp.*", nil)
	if n != 2 {
		t.Errorf("onNew fired %d times for 2 distinct requests", n)
	}
}

func TestAFailingHookIsAnAuditLineNotAnError(t *testing.T) {
	s, f, dir := pushServer(t, pushOn)
	quiet(s)
	bad := addHook(t, f, dir, "10-broken", 0o755)
	f.fail(bad, "")
	f.fail("ubus send", "")
	addHook(t, f, dir, "20-fine", 0o755)
	r, _ := s.requests.Open(time.Now(), time.Minute, "claude-code", "uci_apply", "wireless.*", nil)
	s.pushRequest(r)
	audit, _ := os.ReadFile(s.cfg().AuditPath)
	if !strings.Contains(string(audit), "failed: ubus send, 10-broken") || !strings.Contains(f.allCalls(), "20-fine") {
		t.Errorf("a failure should be audited and later hooks still run:\n%s\n%s", audit, f.allCalls())
	}
}

func TestPushChannelListedOffWithNotice(t *testing.T) {
	var c channel
	for _, x := range channels {
		if x.Name == "push" {
			c = x
		}
	}
	if c.Name == "" || c.option != "push_hook" || !strings.Contains(c.Harm, "root") || !strings.Contains(c.Harm, "third-party") {
		t.Errorf("push channel = %+v", c)
	}
}

// The wiring itself: a refused call opens a request, and the daemon pushes it without being asked.
func TestANewRequestTriggersThePushWithoutHelp(t *testing.T) {
	s, f, dir := pushServer(t, pushOn)
	h := addHook(t, f, dir, "10-notify", 0o755)
	s.requests.Open(time.Now(), time.Minute, "claude-code", "uci_apply", "wireless.*", nil)
	for deadline := time.Now().Add(5 * time.Second); !f.ran(h) && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !f.ran(h) {
		t.Errorf("the hook did not run:\n%s", f.allCalls())
	}
}

func (f *fakeRouter) stdinOf(i int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stdins[i]
}
