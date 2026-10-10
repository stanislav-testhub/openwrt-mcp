package main

import (
	"bufio"
	"context"
	"net"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A session profile narrows what one connection may use: --toolset limits the catalogue to named
// groups, --read-only limits it to what the @readonly preset grants. Both only ever remove, and
// both are enforced when a tool is called, not just when the catalogue is listed, because a client
// that never saw a tool can still name it.

// The expected sets below are written out from the design, not read back from the code under test.
var (
	wantToolsetTools = map[string][]string{
		"diag":   {"logread", "network_clients", "firewall_show", "net_diag", "service_list", "ubus_list", "ubus_call"},
		"config": {"uci_get", "uci_apply", "uci_confirm", "uci_rollback", "service_control"},
		"pkg":    {"pkg_query", "pkg_change", "pkg_config_diff", "pkg_config_resolve", "sysupgrade"},
		"wg":     {"wg_list_clients", "wg_new_client", "wg_remove_client"},
	}
	wantCoreTools         = []string{"system_status", "mfa_unlock"} // listed whatever toolsets are selected
	wantUnrestrictedTools = []string{"exec"}                        // in no toolset: only a session that selects none has it
	// What the @readonly preset grants, plus ubus_list (introspection, ungated).
	wantReadOnlyTools = []string{"system_status", "logread", "network_clients", "firewall_show", "service_list",
		"pkg_query", "pkg_config_diff", "wg_list_clients", "uci_get", "ubus_call", "net_diag", "sysupgrade", "ubus_list"}
)

func sortedCopy(s ...[]string) []string {
	var out []string
	for _, x := range s {
		out = append(out, x...)
	}
	sort.Strings(out)
	return out
}

func TestToolsetTablePartitionsEveryTool(t *testing.T) {
	if !slices.Equal(sortedCopy(toolsetNames), sortedCopy(keysOf(wantToolsetTools))) || len(toolsetTools) != len(toolsetNames) {
		t.Fatalf("toolsetTools has %v, the grammar allows %v", keysOf(toolsetTools), toolsetNames)
	}
	for name, want := range wantToolsetTools {
		if got := sortedCopy(toolsetTools[name]); !slices.Equal(got, sortedCopy(want)) {
			t.Errorf("toolset %s = %v, want %v", name, got, sortedCopy(want))
		}
	}
	if got := sortedCopy(coreTools); !slices.Equal(got, sortedCopy(wantCoreTools)) {
		t.Errorf("core = %v, want %v", got, sortedCopy(wantCoreTools))
	}
	if got := sortedCopy(unrestrictedTools); !slices.Equal(got, sortedCopy(wantUnrestrictedTools)) {
		t.Errorf("unrestricted-only = %v, want %v", got, sortedCopy(wantUnrestrictedTools))
	}
	// Every registered tool has exactly one home, so adding a tool fails here until it is classified.
	var all []string
	for _, ts := range toolsetNames {
		all = append(all, toolsetTools[ts]...)
	}
	all = append(all, coreTools...)
	all = append(all, unrestrictedTools...)
	if got, want := sortedCopy(all), sortedCopy(allToolNames); !slices.Equal(got, want) {
		t.Errorf("toolsets + core + unrestricted = %v, registered tools = %v", got, want)
	}
}

func keysOf(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// connectProfile is connectClient with a session profile on the context given to Connect, which is
// exactly how handleBridge opens a session.
func connectProfile(t *testing.T, s *Server, client string, p sessionProfile) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ctx := withProfile(context.Background(), p)
	ss, err := s.serverFor(client).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func listedNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	var out []string
	for _, tl := range listedTools(t, cs) {
		out = append(out, tl.Name)
	}
	sort.Strings(out)
	return out
}

func TestSessionCatalogueFollowsItsProfile(t *testing.T) {
	s := testServer(t, "")
	for _, c := range []struct {
		name string
		p    sessionProfile
		want []string
	}{
		{"no profile lists everything", sessionProfile{}, allToolNames},
		{"one toolset plus core", sessionProfile{Toolsets: []string{"diag"}}, sortedCopy(wantToolsetTools["diag"], wantCoreTools)},
		{"two toolsets plus core", sessionProfile{Toolsets: []string{"config", "pkg"}},
			sortedCopy(wantToolsetTools["config"], wantToolsetTools["pkg"], wantCoreTools)},
		{"every toolset still leaves exec out", sessionProfile{Toolsets: []string{"diag", "config", "pkg", "wg"}},
			sortedCopy(wantToolsetTools["diag"], wantToolsetTools["config"], wantToolsetTools["pkg"], wantToolsetTools["wg"], wantCoreTools)},
		{"read-only", sessionProfile{ReadOnly: true}, sortedCopy(wantReadOnlyTools)},
		{"read-only within a toolset is the intersection", sessionProfile{ReadOnly: true, Toolsets: []string{"diag"}},
			[]string{"firewall_show", "logread", "net_diag", "network_clients", "service_list", "system_status", "ubus_call", "ubus_list"}},
	} {
		want := sortedCopy(c.want)
		if got := listedNames(t, connectProfile(t, s, "c", c.p)); !slices.Equal(got, want) {
			t.Errorf("%s:\n got %v\nwant %v", c.name, got, want)
		}
	}
}

func fullGrants(client string) string { return policyFor(client, allToolNames, "*") }

func deniedAudit(t *testing.T, s *Server, tool string) []AuditEvent {
	t.Helper()
	var out []AuditEvent
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == tool && ev.Outcome == OutcomeDenied {
			out = append(out, ev)
		}
	}
	return out
}

func TestToolsetSessionRefusesToolsOutsideItAndRunsNothing(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, fullGrants("c")) // the client holds every grant: the session profile is what refuses
	cs := connectProfile(t, s, "c", sessionProfile{Toolsets: []string{"diag"}})
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"uci_get", map[string]any{"config": "network"}},
		{"exec", map[string]any{"argv": []string{"reboot"}}},
		{"pkg_change", map[string]any{"action": "add", "packages": []string{"x"}}},
		{"wg_list_clients", map[string]any{}},
	} {
		out, isErr := callText(t, cs, c.tool, c.args)
		if !isErr || !strings.Contains(out, "not available in this session") {
			t.Errorf("%s: %q, want a refusal naming the session", c.tool, out)
		}
		if !strings.HasSuffix(out, "\n[code: POLICY_DENIED]") {
			t.Errorf("%s: a toolset refusal does not end with the POLICY_DENIED code: %q", c.tool, out)
		}
		if len(deniedAudit(t, s, c.tool)) != 1 {
			t.Errorf("%s: refusal not audited as DENIED: %+v", c.tool, deniedAudit(t, s, c.tool))
		}
	}
	if calls := f.allCalls(); calls != "" {
		t.Errorf("a refused tool still ran commands:\n%s", calls)
	}
}

func TestToolsetSessionStillServesItsOwnTools(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus -v list", "'network' @a1b2c3d4\n\t\"status\":{}\n'system' @e5f6a7b8\n\t\"board\":{}")
	s := testServer(t, fullGrants("c"))
	cs := connectProfile(t, s, "c", sessionProfile{Toolsets: []string{"diag"}})
	if out, isErr := callText(t, cs, "ubus_list", nil); isErr || !strings.Contains(out, "network") {
		t.Errorf("ubus_list in its own toolset: %q (error %v)", out, isErr)
	}
}

func TestReadOnlySessionOverridesGrantsAndRunsNothing(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, fullGrants("c")) // even a client granted exec and uci_apply is held to read-only
	cs := connectProfile(t, s, "c", sessionProfile{ReadOnly: true})
	for _, c := range []struct {
		name, tool string
		args       map[string]any
	}{
		{"change config", "uci_apply", map[string]any{"changes": []map[string]any{{"config": "dhcp", "section": "x", "type": "host"}}}},
		{"run a command", "exec", map[string]any{"argv": []string{"reboot"}}},
		{"install", "pkg_change", map[string]any{"action": "add", "packages": []string{"x"}}},
		{"sysupgrade backup is outside the readonly scopes", "sysupgrade", map[string]any{"action": "backup"}},
		{"ubus method that is not on the read list", "ubus_call", map[string]any{"object": "system", "method": "reboot"}},
		{"unlock MFA", "mfa_unlock", map[string]any{"code": "123456"}},
		{"confirm a pending change", "uci_confirm", map[string]any{"token": "x"}},
	} {
		out, isErr := callText(t, cs, c.tool, c.args)
		if !isErr || !strings.Contains(out, "read-only") {
			t.Errorf("%s (%s): %q, want a read-only refusal", c.name, c.tool, out)
		}
		if !strings.HasSuffix(out, "\n[code: POLICY_DENIED]") {
			t.Errorf("%s (%s): a read-only refusal does not end with the POLICY_DENIED code: %q", c.name, c.tool, out)
		}
		if len(deniedAudit(t, s, c.tool)) != 1 {
			t.Errorf("%s (%s): refusal not audited as DENIED", c.name, c.tool)
		}
	}
	if calls := f.allCalls(); calls != "" {
		t.Errorf("a refused tool still ran commands:\n%s", calls)
	}
}

func TestReadOnlySessionStillReads(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	f.on("ubus call system board", `{"model":"m"}`)
	s := testServer(t, fullGrants("c"))
	cs := connectProfile(t, s, "c", sessionProfile{ReadOnly: true})
	if out, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "system", "method": "board"}); isErr {
		t.Errorf("a ubus method on the read list was refused: %s", out)
	}
	f.on("ubus -v list", "'network' @a1b2c3d4\n\t\"status\":{}")
	if out, isErr := callText(t, cs, "ubus_list", nil); isErr {
		t.Errorf("ubus_list (introspection, no grant needed) was refused: %s", out)
	}
}

// Read-only narrows what the client holds; it is not a grant. A client with nothing gets nothing,
// and the denial is the ordinary one that says how to grant.
func TestReadOnlySessionDoesNotGrantAnything(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, "")
	cs := connectProfile(t, s, "c", sessionProfile{ReadOnly: true})
	out, isErr := callText(t, cs, "system_status", nil)
	if !isErr || !strings.Contains(out, "openwrt-mcp allow c system_status") {
		t.Errorf("read-only session without a grant: %q", out)
	}
}

func TestSessionsOfOneClientKeepTheirOwnProfiles(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, fullGrants("c"))
	plain := connectProfile(t, s, "c", sessionProfile{})
	narrow := connectProfile(t, s, "c", sessionProfile{ReadOnly: true})
	other := connectProfile(t, s, "c", sessionProfile{Toolsets: []string{"wg"}})
	args := map[string]any{"argv": []string{"true"}}
	// Interleaved: the server is shared, the profile must not leak between connections.
	for i := 0; i < 2; i++ {
		if out, _ := callText(t, narrow, "exec", args); !strings.Contains(out, "read-only") {
			t.Fatalf("read-only session ran exec: %q", out)
		}
		if out, _ := callText(t, plain, "exec", args); strings.Contains(out, "read-only") || strings.Contains(out, "not available") {
			t.Fatalf("the unrestricted session inherited a narrower profile: %q", out)
		}
		if out, _ := callText(t, other, "exec", args); !strings.Contains(out, "not available in this session") {
			t.Fatalf("toolset session ran exec: %q", out)
		}
	}
}

func TestBridgeCommandSelectsTheSessionProfile(t *testing.T) {
	for _, c := range []struct {
		command string
		want    []string
		audit   string
	}{
		{"--toolset wg", sortedCopy(wantToolsetTools["wg"], wantCoreTools), "toolsets wg"},
		{"--read-only", sortedCopy(wantReadOnlyTools), "read-only"},
		{"", sortedCopy(allToolNames), ""},
	} {
		s := testServer(t, "")
		srvSide, cliSide := net.Pipe()
		go s.handleBridge(srvSide)
		_ = cliSide.SetDeadline(time.Now().Add(5 * time.Second))
		w := bufio.NewWriter(cliSide)
		w.WriteString(`{"client":"c","origin":"ssh from 192.0.2.7","command":` + jsonString(c.command) + "}\n")
		w.Flush()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil).
			Connect(context.Background(), &mcp.IOTransport{Reader: cliSide, Writer: cliSide}, nil)
		if err != nil {
			t.Fatalf("%q: %v", c.command, err)
		}
		if got := listedNames(t, cs); !slices.Equal(got, c.want) {
			t.Errorf("%q:\n got %v\nwant %v", c.command, got, c.want)
		}
		_ = cs.Close()
		cliSide.Close()
		var opened string
		for _, ev := range auditEvents(t, s) {
			if ev.Tool == "session" && strings.HasPrefix(ev.Summary, stdioOpened) {
				opened = ev.Summary
			}
		}
		if !strings.Contains(opened, "ssh from 192.0.2.7") || !strings.Contains(opened, c.audit) {
			t.Errorf("%q: session audit %q, want the origin and %q", c.command, opened, c.audit)
		}
	}
}
