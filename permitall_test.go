package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Milestone 8.6. Permit all is every gated tool on every scope for at most 24 hours, written the
// same way from the CLI and from LuCI, and loud wherever it shows.

func (r *rpcdRig) permitAll(client, duration string) {
	r.t.Helper()
	r.ok("permit_all", map[string]any{"client": client, "duration": duration, "confirm": true})
}

func TestPermitAllNeedsTheConfirmAndWritesNothingWithout(t *testing.T) {
	r := newRig(t)
	m := r.call("permit_all", map[string]any{"client": "claude", "duration": "1h"})
	if m["code"] != "needs_confirm" || !strings.Contains(m["error"].(string), "anything root can") {
		t.Fatalf("got %v, want needs_confirm with the warning", m)
	}
	if len(r.config().Policies) != 0 {
		t.Error("an unconfirmed permit all wrote a grant")
	}
	r.permitAll("claude", "1h")
	for _, c := range []struct{ tool, scope string }{{"exec", "sh"}, {"uci_apply", "network.lan.ipaddr"}, {"sysupgrade", "backup"}, {"ubus_call", "file.exec"}} {
		if !r.allowed("claude", c.tool, c.scope) {
			t.Errorf("permit all does not cover %s on %s", c.tool, c.scope)
		}
	}
	if r.allowed("other", "exec", "sh") {
		t.Error("permit all reached another client")
	}
	if !strings.Contains(r.audit(), `"permit_all"`) {
		t.Error("audit lacks the permit all")
	}
}

func TestPermitAllRefusesNeverAndAnythingOver24Hours(t *testing.T) {
	r := newRig(t)
	for _, d := range []string{"never", "25h", "48h", "7d", "1d", "forever", "-1h", "0s"} {
		r.fails("permit_all", map[string]any{"client": "claude", "duration": d, "confirm": true}, "duration")
	}
	if len(r.config().Policies) != 0 {
		t.Error("a refused duration still wrote a grant")
	}
	r.permitAll("claude", "24h")
	if rows := activePermitAll(r.config(), time.Now()); len(rows) != 1 || rows[0].Client != "claude" {
		t.Errorf("active rows %v", rows)
	}
	// The default is an hour, not "never".
	r2 := newRig(t)
	r2.ok("permit_all", map[string]any{"client": "claude", "confirm": true})
	exp := r2.config().Policies[0].Expires
	if d := time.Until(exp); d < 50*time.Minute || d > 61*time.Minute {
		t.Errorf("the default lasts %v, want about 1h", d)
	}
}

func TestCheckPermitAllDurationBoundary(t *testing.T) {
	for d, ok := range map[string]bool{"24h": true, "1440m": true, "1d": true, "15m": true, "24h1s": false, "25h": false, "2d": false, "never": false, "": false, "0": false} {
		if err := checkPermitAllDuration(d); (err == nil) != ok {
			t.Errorf("%q: err=%v, want ok=%v", d, err, ok)
		}
	}
}

func TestEndPermitAllRemovesOnlyPermitAllBlocks(t *testing.T) {
	r := newRig(t)
	r.ok("grant_preset", map[string]any{"client": "claude", "preset": "operator", "duration": "8h"})
	r.permitAll("claude", "1h")
	r.permitAll("other", "1h")
	before := len(r.config().Policies)
	m := r.ok("end_permit_all", map[string]any{"client": "claude"})
	if m["removed"] != float64(1) {
		t.Errorf("removed %v, want 1", m["removed"])
	}
	if got := len(r.config().Policies); got != before-1 {
		t.Errorf("%d blocks left, want %d", got, before-1)
	}
	if r.allowed("claude", "exec", "sh") {
		t.Error("claude still has exec after End now")
	}
	if !r.allowed("claude", "uci_apply", "network.lan.ipaddr") {
		t.Error("End now took the operator grant with it")
	}
	if !r.allowed("other", "exec", "sh") {
		t.Error("End now ended another client's permit all")
	}
	r.fails("end_permit_all", map[string]any{"client": "claude"}, "no permit-all")
	r.fails("end_permit_all", map[string]any{}, "client")
}

func TestPermitAllIsRefusedForAClientWithASecondFactorAndNotAPreset(t *testing.T) {
	r := newRig(t)
	ms, err := LoadMFA(mfaPath(r.env.statePath))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ms.Enrol("claude", "x", "router"); err != nil {
		t.Fatal(err)
	}
	r.fails("permit_all", map[string]any{"client": "claude", "duration": "1h", "confirm": true}, "second factor")
	if len(r.config().Policies) != 0 {
		t.Error("a refused permit all wrote a grant")
	}
	// No other rpcd method hands out @all.
	r.fails("grant_preset", map[string]any{"client": "other", "preset": "all", "duration": "1h"}, "preset")
}

func TestPermitAllShapeIsWhatTheBannerFollows(t *testing.T) {
	all := permitAllBlocks()[0].tools
	for name, tc := range map[string]struct {
		tools  []string
		scopes []string
		want   bool
	}{
		"every gated tool on *":    {all, []string{"*"}, true},
		"with ubus_list too":       {allToolNames, []string{"*"}, true},
		"one tool missing":         {all[1:], []string{"*"}, false},
		"narrow scope":             {all, []string{"wireless.*"}, false},
		"the operator preset":      {presets["operator"][0].tools, []string{"*"}, false},
		"extra scope beside the *": {all, []string{"wireless.*", "*"}, true},
	} {
		if got := (&Policy{Tools: tc.tools, Scopes: tc.scopes}).permitsAll(); got != tc.want {
			t.Errorf("%s: permitsAll=%v, want %v", name, got, tc.want)
		}
	}
}

func TestStatusAndSystemStatusReportAPermitAll(t *testing.T) {
	r := newRig(t)
	r.permitAll("claude", "4h")
	m := r.ok("status", map[string]any{})
	rows, _ := m["permit_all"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["client"] != "claude" || rows[0].(map[string]any)["expires"] == "" {
		t.Errorf("status permit_all = %v", m["permit_all"])
	}
	r.ok("end_permit_all", map[string]any{"client": "claude"})
	if m := r.ok("status", map[string]any{}); len(m["permit_all"].([]any)) != 0 {
		t.Errorf("an ended permit all still reported: %v", m["permit_all"])
	}

	withFixtureRoot(t)
	s := testServer(t, policyFor("c", permitAllBlocks()[0].tools, "*"))
	out, _, _ := s.systemStatus(t.Context(), systemStatusIn{})
	if !strings.Contains(out, "PERMIT ALL") || !strings.Contains(out, `"c"`) {
		t.Errorf("system_status does not say so:\n%s", out)
	}
	quiet := testServer(t, policyFor("c", presets["operator"][0].tools, "*"))
	if out, _, _ := quiet.systemStatus(t.Context(), systemStatusIn{}); strings.Contains(out, "PERMIT ALL") {
		t.Errorf("system_status cried wolf:\n%s", out)
	}
}

func TestCallsUnderPermitAllAreMarkedInTheAuditAndTheFloorStillHolds(t *testing.T) {
	f := newFakeRouter(t)
	f.on("uci", "ok")
	f.on("ubus call", "{}")
	s := testServer(t, policyFor("c", permitAllBlocks()[0].tools, "*")+
		policyFor("narrow", []string{"uci_get"}, "*"))
	call := func(client, tool string, args map[string]any) (string, bool) {
		return callText(t, connectClient(t, s, client), tool, args)
	}
	call("c", "uci_get", map[string]any{"config": "network"})
	call("narrow", "uci_get", map[string]any{"config": "network"})
	if out, isErr := call("c", "ubus_call", map[string]any{"object": "openwrt-mcp", "method": "decide"}); !isErr || !strings.Contains(out, "deny floor") {
		t.Errorf("the floor did not hold under permit all: %q", out)
	}
	var via, plain int
	for _, ev := range auditEvents(t, s) {
		if ev.Tool != "uci_get" {
			continue
		}
		switch {
		case ev.Client == "c" && ev.Via == "permit-all":
			via++
		case ev.Client == "narrow" && ev.Via == "":
			plain++
		}
	}
	if via != 1 || plain != 1 {
		t.Errorf("marked %d permit-all and %d ordinary calls, want 1 and 1", via, plain)
	}
}

func TestCLIAllowAllNeedsShellEquivalentAndCapsTheDuration(t *testing.T) {
	c := newCLI(t)
	c.fails("--shell-equivalent", "allow", "claude-code", "@all", "1h")
	c.fails("capped", "allow", "claude-code", "@all", "48h", "--shell-equivalent")
	c.fails("never", "allow", "claude-code", "@all", "never", "--shell-equivalent")
	if _, err := LoadConfig(c.config); err == nil {
		if cfg, _ := LoadConfig(c.config); len(cfg.Policies) != 0 {
			t.Fatal("a refused @all wrote a grant")
		}
	}
	c.ok("allow", "claude-code", "@all", "1h", "--shell-equivalent")
	cfg, err := LoadConfig(c.config)
	if err != nil || len(cfg.Policies) != 1 || !cfg.Policies[0].permitsAll() || cfg.Policies[0].Expires.IsZero() {
		t.Fatalf("the CLI wrote %v, %v", cfg.Policies, err)
	}
	// LuCI's End now removes what the CLI wrote.
	r := &rpcdRig{t: t, env: rpcdEnv{configPath: c.config, statePath: c.state, requestsPath: filepath.Join(c.state, "requests.json"), now: time.Now}}
	r.ok("end_permit_all", map[string]any{"client": "claude-code"})
	if cfg, _ := LoadConfig(c.config); len(cfg.Policies) != 0 {
		t.Error("End now left the CLI's grant behind")
	}
}

func TestActivePermitAllIgnoresExpiredAndDisabledGrantsAndReportsTheLongest(t *testing.T) {
	now := time.Now()
	all := permitAllBlocks()[0]
	pol := func(client string, exp time.Duration, enabled bool) *Policy {
		p := &Policy{Client: client, Tools: all.tools, Scopes: all.scopes, Enabled: enabled}
		if exp != 0 {
			p.Expires = now.Add(exp)
		}
		return p
	}
	cfg := &Config{Policies: []*Policy{
		pol("expired", -time.Minute, true),
		pol("disabled", time.Hour, false),
		pol("short", time.Hour, true), pol("short", 2*time.Hour, true),
		pol("forever", 0, true),
	}}
	got := map[string]string{}
	for _, r := range activePermitAll(cfg, now) {
		got[r.Client] = r.Expires
	}
	if len(got) != 2 || got["short"] != now.Add(2*time.Hour).Format(time.RFC3339) || got["forever"] != "" {
		t.Errorf("active = %v, want only short (the later expiry) and forever (no end)", got)
	}
	if _, bad := got["expired"]; bad {
		t.Error("an expired permit all still shows")
	}
}
