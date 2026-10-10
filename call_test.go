package main

import (
	"context"
	"io"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// `openwrt-mcp call` is another transport, not another code path: the daemon runs the call through
// an in-memory MCP client against the same per-client server, with the session profile on the
// context. These tests drive it the way sshd does, through runBridge with SSH_ORIGINAL_COMMAND.

const boardJSON = `{"model":"TestBox","release":{"version":"25.12.5"}}`

var boardArgs = `{"object":"system","method":"board"}`

// runCallCLI runs the bridge as the forced command would, with stdin left open (a call must not
// wait for it), and returns what it printed and how it ended.
func runCallCLI(t *testing.T, s *Server, client, command string) (stdout, stderr string, err error) {
	t.Helper()
	sock := listenTestSocket(t, s)
	_, stdoutR := swapStdio(t)
	errR, errW, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	oldErr := os.Stderr
	os.Stderr = errW
	t.Cleanup(func() { os.Stderr = oldErr; errR.Close(); errW.Close() })
	t.Setenv("SSH_ORIGINAL_COMMAND", command)
	t.Setenv("SSH_CLIENT", "192.0.2.7 51234 22")

	done := make(chan error, 1)
	go func() { done <- runBridge(sock, client) }()
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%q: runBridge did not return", command)
	}
	_ = os.Stdout.Close() // the write ends, so the readers see EOF
	_ = os.Stderr.Close()
	o, _ := io.ReadAll(stdoutR)
	e, _ := io.ReadAll(errR)
	return string(o), string(e), err
}

func boardServer(t *testing.T) (*Server, *fakeRouter) {
	t.Helper()
	f := newFakeRouter(t)
	f.on("ubus call system board", boardJSON)
	return testServer(t, policyFor("c", []string{"ubus_call"}, "system.board")), f
}

func TestCallRunsAToolThroughTheDaemon(t *testing.T) {
	s, f := boardServer(t)
	out, errOut, err := runCallCLI(t, s, "c", "call ubus_call "+boardArgs)
	if err != nil || errOut != "" || !strings.Contains(out, "TestBox") {
		t.Fatalf("stdout %q, stderr %q, err %v; want the board on stdout and nothing else", out, errOut, err)
	}
	if !f.ran("ubus call system board") {
		t.Errorf("the tool never ran: %q", f.allCalls())
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output does not end with a line end: %q", out)
	}
}

// Same tool, same arguments, once over stdio and once over call: the audit record of the call
// itself must be identical, so an operator reading the log cannot tell the transports apart except
// by the session line.
func TestCallAndStdioLeaveTheSameToolAuditRecord(t *testing.T) {
	toolEvents := func(s *Server) []AuditEvent {
		var out []AuditEvent
		for _, ev := range auditEvents(t, s) {
			if ev.Tool == "session" {
				continue
			}
			ev.Time, ev.Duration = "", 0
			out = append(out, ev)
		}
		return out
	}
	sCall, _ := boardServer(t)
	if _, _, err := runCallCLI(t, sCall, "c", "call ubus_call "+boardArgs); err != nil {
		t.Fatal(err)
	}
	sStdio, _ := boardServer(t)
	cs := connectClient(t, sStdio, "c")
	if out, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "system", "method": "board"}); isErr {
		t.Fatalf("stdio call failed: %s", out)
	}
	got, want := toolEvents(sCall), toolEvents(sStdio)
	if len(want) != 1 || !reflect.DeepEqual(got, want) {
		t.Errorf("audit differs between transports:\n call  %+v\n stdio %+v", got, want)
	}
	var session string
	for _, ev := range auditEvents(t, sCall) {
		if ev.Tool == "session" {
			session = ev.Summary
		}
	}
	if !strings.Contains(session, "call") || !strings.Contains(session, "192.0.2.7") {
		t.Errorf("session line %q should say it was a call and from where", session)
	}
}

func TestCallDenialGoesToStderrWithTheAllowLine(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, "")
	out, errOut, err := runCallCLI(t, s, "c", "call system_status")
	if err != errCallFailed || out != "" || !strings.Contains(errOut, "openwrt-mcp allow c system_status") {
		t.Errorf("stdout %q, stderr %q, err %v; want the allow line on stderr and a failed call", out, errOut, err)
	}
	if f.allCalls() != "" {
		t.Errorf("a denied call still ran commands:\n%s", f.allCalls())
	}
}

func TestCallIsHeldToTheSessionProfile(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, fullGrants("c"))
	for _, c := range []struct{ command, want string }{
		{`--read-only call uci_apply {"changes":[{"config":"dhcp","section":"x","type":"host"}]}`, "read-only"},
		{`--read-only call exec {"argv":["reboot"]}`, "read-only"},
		{`--toolset wg call logread`, "not available in this session"},
		{`--toolset diag call exec {"argv":["reboot"]}`, "not available in this session"},
	} {
		out, errOut, err := runCallCLI(t, s, "c", c.command)
		if err != errCallFailed || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: stdout %q, stderr %q, err %v; want a failed call mentioning %q", c.command, out, errOut, err, c.want)
		}
	}
	if f.allCalls() != "" {
		t.Errorf("a refused call still ran commands:\n%s", f.allCalls())
	}
}

func TestCallListAndHelp(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, "")
	lineNames := func(out string) []string {
		var names []string
		for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
			names = append(names, strings.Fields(l)[0])
		}
		sort.Strings(names)
		return names
	}

	out, errOut, err := runCallCLI(t, s, "c", "call --list")
	if err != nil || errOut != "" {
		t.Fatalf("--list: stderr %q, err %v", errOut, err)
	}
	if got, want := lineNames(out), sortedCopy(allToolNames); !reflect.DeepEqual(got, want) {
		t.Errorf("--list names:\n got %v\nwant %v", got, want)
	}

	out, _, err = runCallCLI(t, s, "c", "--toolset wg --read-only call --list")
	if err != nil || !reflect.DeepEqual(lineNames(out), []string{"system_status", "wg_list_clients"}) {
		t.Errorf("--list under a profile = %q (err %v), want only what the profile allows", out, err)
	}

	out, errOut, err = runCallCLI(t, s, "c", "call uci_get --help")
	if err != nil || errOut != "" || !strings.Contains(out, "uci_get") || !strings.Contains(out, `"properties"`) || !strings.Contains(out, `"config"`) {
		t.Errorf("--help: stdout %q, stderr %q, err %v; want the name and the argument schema", out, errOut, err)
	}

	// Help about a tool the session does not have is the same refusal as calling it.
	_, errOut, err = runCallCLI(t, s, "c", "--toolset diag call exec --help")
	if err != errCallFailed || !strings.Contains(errOut, "exec") || !strings.Contains(errOut, "--list") {
		t.Errorf("--help outside the profile: stderr %q, err %v", errOut, err)
	}
}

func TestCallReportsAnUnknownToolAndBadArguments(t *testing.T) {
	newFakeRouter(t)
	s := testServer(t, fullGrants("c"))
	for _, c := range []struct{ command, want string }{
		{"call nosuchtool", "nosuchtool"},
		{`call ubus_call {"object":5}`, "object"},
	} {
		out, errOut, err := runCallCLI(t, s, "c", c.command)
		if err != errCallFailed || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: stdout %q, stderr %q, err %v; want a failed call mentioning %q", c.command, out, errOut, err, c.want)
		}
	}
}

// If the caller disappears (ssh dropped, the agent gave up) the tool call is cancelled instead of
// running on with nobody to hear the answer.
func TestCallIsCancelledWhenTheCallerGoesAway(t *testing.T) {
	newFakeRouter(t)
	started := make(chan struct{}, 1)
	ended := make(chan error, 1)
	cmdRunner = func(ctx context.Context, _ *string, _ []string) (string, string, error) {
		started <- struct{}{}
		<-ctx.Done()
		ended <- ctx.Err()
		return "", "", ctx.Err()
	}
	s := testServer(t, policyFor("c", []string{"ubus_call"}, "system.board"))
	srvSide, cliSide := net.Pipe()
	go s.handleBridge(srvSide)
	hello := `{"client":"c","command":` + jsonString("call ubus_call "+boardArgs) + "}\n"
	if _, err := io.WriteString(cliSide, hello); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the tool never started")
	}
	cliSide.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the tool kept running after the caller went away")
	}
	// The handler records the cancelled call after the command ends; let it finish before the
	// test's temp directory goes away.
	auditErrorFor(t, s, "ubus_call", OutcomeError)
}

// Hardware, 2026-10-10: a `call` the grammar refused came back as a raw JSON-RPC line on stdout and
// "daemon closed the connection" on stderr, because the bridge only knew it was a call once the
// grammar had accepted it. The refusal is text for the person at the shell, like any other.
func TestCallRefusedByTheGrammarPrintsPlainTextToStderr(t *testing.T) {
	for _, c := range []struct{ command, want string }{
		{"--toolset bogus call --list", "bad toolset"},
		{"--read-only --read-only call --list", "option given twice"},
		{"call uci_get {bad json", "must be one JSON object"},
	} {
		s := testServer(t, "")
		out, errOut, err := runCallCLI(t, s, "c", c.command)
		if err != errCallFailed || out != "" || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: err=%v stdout=%q stderr=%q, want a plain %q on stderr", c.command, err, out, errOut, c.want)
		}
		if strings.Contains(errOut, "jsonrpc") || strings.Contains(errOut, "daemon closed") {
			t.Errorf("%q: stderr is protocol noise: %q", c.command, errOut)
		}
	}
}
