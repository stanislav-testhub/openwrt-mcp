package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A session ends for reasons the operator wants to know: the client went away, the router
// restarted under it, the link broke. These tests pin how the bridge waits for a daemon that is
// still starting, and how the daemon records the end of a session so `status` can say why.

// Tests that call runBridge against an absent daemon would otherwise wait the full production
// bound; the ones about waiting set their own.
func init() { dialRetryFor = 0 }

func shortRetry(t *testing.T, forHowLong time.Duration) {
	t.Helper()
	oldFor, oldEvery := dialRetryFor, dialRetryEvery
	dialRetryFor, dialRetryEvery = forHowLong, 10*time.Millisecond
	t.Cleanup(func() { dialRetryFor, dialRetryEvery = oldFor, oldEvery })
}

// ---------------------------------------------------------------- the bridge waits for the daemon

func TestBridgeWaitsForADaemonThatIsStillStarting(t *testing.T) {
	shortRetry(t, 10*time.Second)
	s, f := boardServer(t)
	sock := shortSocketPath(t)
	_, stdoutR := swapStdio(t)
	t.Setenv("SSH_ORIGINAL_COMMAND", "call ubus_call "+boardArgs)
	t.Setenv("SSH_CLIENT", "192.0.2.7 51234 22")

	done := make(chan error, 1)
	go func() { done <- runBridge(sock, "c") }()

	// The router has booted and sshd answers, but the daemon is not listening yet.
	select {
	case err := <-done:
		t.Fatalf("runBridge gave up while the daemon was still starting: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	ln, err := s.listenSocket(sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	go s.serveSocket(ln)
	t.Cleanup(func() { ln.Close() })

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runBridge: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge never connected to the daemon that came up")
	}
	_ = os.Stdout.Close()
	out, _ := io.ReadAll(stdoutR)
	if !strings.Contains(string(out), "TestBox") || !f.ran("ubus call system board") {
		t.Errorf("the call did not run once the daemon was up: stdout %q", out)
	}
}

// After a crash or a kill the socket file is still there but nobody answers on it.
func TestBridgeWaitsOutAStaleSocketFile(t *testing.T) {
	shortRetry(t, 10*time.Second)
	s, _ := boardServer(t)
	sock := shortSocketPath(t)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	old, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Skipf("no stale socket file to test with: %v", err)
	}
	_, stdoutR := swapStdio(t)
	t.Setenv("SSH_ORIGINAL_COMMAND", "call ubus_call "+boardArgs)

	done := make(chan error, 1)
	go func() { done <- runBridge(sock, "c") }()
	time.Sleep(150 * time.Millisecond)
	ln, err := s.listenSocket(sock) // removes the stale file, as the restarted daemon does
	if err != nil {
		t.Fatal(err)
	}
	go s.serveSocket(ln)
	t.Cleanup(func() { ln.Close() })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runBridge: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge never connected")
	}
	_ = os.Stdout.Close()
	if out, _ := io.ReadAll(stdoutR); !strings.Contains(string(out), "TestBox") {
		t.Errorf("stdout %q", out)
	}
}

func TestBridgeGivesUpAfterTheBoundAndSaysHowLongItWaited(t *testing.T) {
	shortRetry(t, 300*time.Millisecond)
	absent := filepath.Join(t.TempDir(), "absent.sock")
	start := time.Now()
	res := make(chan error, 1)
	go func() { res <- runBridge(absent, "c") }()
	var err error
	select {
	case err = <-res:
	case <-time.After(10 * time.Second):
		t.Fatal("runBridge is still waiting for the daemon long past its 300ms bound")
	}
	took := time.Since(start)
	if err == nil {
		t.Fatal("runBridge succeeded with no daemon")
	}
	for _, want := range []string{"daemon not reachable", "after waiting 300ms", "/etc/init.d/openwrt-mcp start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if took < 300*time.Millisecond {
		t.Errorf("gave up after %v, before the 300ms bound", took)
	}
	if took > 5*time.Second {
		t.Errorf("kept waiting for %v past a 300ms bound", took)
	}
}

func TestBridgeRefusesBadInputBeforeWaitingForTheDaemon(t *testing.T) {
	shortRetry(t, 10*time.Second)
	absent := filepath.Join(t.TempDir(), "absent.sock")
	start := time.Now()
	if err := runBridge(absent, "../etc"); err == nil || !strings.Contains(err.Error(), "bad client name") {
		t.Errorf("bad client name: %v", err)
	}
	t.Setenv("SSH_ORIGINAL_COMMAND", strings.Repeat("x", entryMaxLen+1))
	if err := runBridge(absent, "c"); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("oversized command: %v", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("input the daemon would never accept still waited %v for the daemon", took)
	}
}

// `connect doctor` runs the real bridge over ssh (ConnectTimeout=10). If the bridge may wait
// longer than doctor does, a stopped daemon is reported as a timeout instead of by name.
func TestDoctorOutlastsTheBridgeWait(t *testing.T) {
	const sshConnect = 10 * time.Second
	if need := sshConnect + defaultDialRetryFor + time.Second; doctorTimeout < need {
		t.Errorf("doctorTimeout = %v, below the %v a stopped daemon can take to be reported", doctorTimeout, need)
	}
}

// ---------------------------------------------------------------- the daemon records how a session ended

func TestSessionClosedSummary(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		err  error
		want string
	}{
		{5*time.Minute + 2*time.Second, nil, "stdio session closed after 5m2s: client closed the connection"},
		{3*time.Minute + 2400*time.Millisecond, io.EOF, "stdio session closed after 3m2s: client closed the connection"},
		{90 * time.Millisecond, nil, "stdio session closed after 0s: client closed the connection"},
		{time.Hour + 30*time.Minute, io.ErrClosedPipe, "stdio session closed after 1h30m0s: client closed the connection"},
		{time.Second, net.ErrClosed, "stdio session closed after 1s: client closed the connection"},
		{2 * time.Second, errors.New("read: connection reset by peer"), "stdio session closed after 2s: connection error: read: connection reset by peer"},
	} {
		if got := sessionClosedSummary(c.d, c.err); got != c.want {
			t.Errorf("sessionClosedSummary(%v, %v)\n got %q\nwant %q", c.d, c.err, got, c.want)
		}
	}
}

// sessionEvents returns the summaries of the session audit lines, in order.
func sessionEvents(t *testing.T, s *Server) []AuditEvent {
	t.Helper()
	var out []AuditEvent
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "session" {
			out = append(out, ev)
		}
	}
	return out
}

func runSession(t *testing.T, s *Server, conn func(srvSide net.Conn) net.Conn, client func(c net.Conn)) {
	t.Helper()
	srvSide, cli := net.Pipe()
	done := make(chan struct{})
	go func() { s.handleBridge(conn(srvSide)); close(done) }()
	client(cli)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the session never ended")
	}
}

func TestAClientThatHangsUpIsRecordedAsClosed(t *testing.T) {
	s := testServer(t, "")
	runSession(t, s, func(c net.Conn) net.Conn { return c }, func(c net.Conn) {
		io.WriteString(c, `{"client":"c","origin":"ssh from 192.0.2.7"}`+"\n")
		time.Sleep(60 * time.Millisecond)
		c.Close()
	})
	evs := sessionEvents(t, s)
	if len(evs) != 2 {
		t.Fatalf("session events = %+v, want opened then closed", evs)
	}
	if !strings.HasPrefix(evs[0].Summary, "stdio session opened via ssh from 192.0.2.7") {
		t.Errorf("first event %q", evs[0].Summary)
	}
	closed := evs[1]
	if closed.Client != "c" || closed.Outcome != OutcomeOK ||
		!strings.HasPrefix(closed.Summary, "stdio session closed after ") ||
		!strings.HasSuffix(closed.Summary, ": client closed the connection") {
		t.Errorf("closing event = %+v", closed)
	}
	if closed.Duration < 50 || closed.Duration > 5000 {
		t.Errorf("closing event duration_ms = %d, want about the 60ms the session lasted", closed.Duration)
	}
}

type brokenConn struct {
	net.Conn
	r io.Reader
}

func (b brokenConn) Read(p []byte) (int, error) { return b.r.Read(p) }

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func TestALinkThatBreaksIsRecordedWithItsError(t *testing.T) {
	s := testServer(t, "")
	hello := `{"client":"c","origin":"ssh from 192.0.2.7"}` + "\n"
	runSession(t, s,
		func(c net.Conn) net.Conn {
			return brokenConn{c, io.MultiReader(strings.NewReader(hello), failingReader{errors.New("connection reset by peer")})}
		},
		func(c net.Conn) { go io.Copy(io.Discard, c); t.Cleanup(func() { c.Close() }) })
	evs := sessionEvents(t, s)
	if len(evs) != 2 {
		t.Fatalf("session events = %+v", evs)
	}
	if got := evs[1].Summary; !strings.Contains(got, "stdio session closed after ") ||
		!strings.Contains(got, ": connection error: ") || !strings.Contains(got, "connection reset by peer") {
		t.Errorf("closing summary %q should carry the error", got)
	}
}

// A call is not a session: it has no close line, so it cannot look like a disconnect.
func TestACallLeavesNoClosedLine(t *testing.T) {
	s, _ := boardServer(t)
	if _, _, err := runCallCLI(t, s, "c", "call ubus_call "+boardArgs); err != nil {
		t.Fatal(err)
	}
	for _, ev := range sessionEvents(t, s) {
		if strings.Contains(ev.Summary, "closed") {
			t.Errorf("a call recorded %q", ev.Summary)
		}
	}
}

func TestServeRecordsThatTheDaemonStarted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	s := testServer(t, "config server\n\toption listen '"+addr+"'\n")
	go s.Serve()

	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, ev := range auditEvents(t, s) {
			if ev.Tool == "daemon" {
				if ev.Outcome != OutcomeOK || ev.Summary != "daemon started "+version {
					t.Errorf("start event = %+v, want OK %q", ev, "daemon started "+version)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon started and wrote nothing to the audit log")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------- status: the last disconnect

func evLine(t *testing.T, e AuditEvent) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func opened(tm, client string) AuditEvent {
	return AuditEvent{Time: tm, Client: client, Tool: "session", Outcome: OutcomeOK, Summary: "stdio session opened via ssh from 192.0.2.7"}
}
func closedBy(tm, client, reason string) AuditEvent {
	return AuditEvent{Time: tm, Client: client, Tool: "session", Outcome: OutcomeOK, Summary: "stdio session closed after 4m1s: " + reason}
}
func calledVia(tm, client string) AuditEvent {
	return AuditEvent{Time: tm, Client: client, Tool: "session", Outcome: OutcomeOK, Summary: "call via ssh from 192.0.2.7"}
}
func started(tm string) AuditEvent {
	return AuditEvent{Time: tm, Client: "<daemon>", Tool: "daemon", Outcome: OutcomeOK, Summary: "daemon started 1.5.0"}
}
func toolRan(tm, client string) AuditEvent {
	return AuditEvent{Time: tm, Client: client, Tool: "ubus_call", Scope: "system.board", Outcome: OutcomeOK}
}

const (
	byClient = "client closed the connection"
	byBoot   = "the daemon restarted (router reboot, upgrade or crash)"
)

func TestLastDisconnect(t *testing.T) {
	const (
		t1 = "2026-10-05T10:00:00Z"
		t2 = "2026-10-05T10:05:00Z"
		t3 = "2026-10-05T10:09:00Z"
		t4 = "2026-10-12T05:00:41Z"
		t5 = "2026-10-12T05:03:00Z"
		t6 = "2026-10-12T05:09:00Z"
	)
	for _, c := range []struct {
		name string
		log  []AuditEvent
		want *disconnectRow
	}{
		{"an empty log has none", nil, nil},
		{"only tool calls", []AuditEvent{toolRan(t1, "a"), toolRan(t2, "a")}, nil},
		{"a client hangs up",
			[]AuditEvent{opened(t1, "a"), toolRan(t2, "a"), closedBy(t3, "a", byClient)},
			&disconnectRow{Time: t3, Client: "a", Reason: byClient}},
		{"the latest close wins",
			[]AuditEvent{opened(t1, "a"), closedBy(t2, "a", byClient), opened(t3, "b"), closedBy(t4, "b", "connection error: read: i/o timeout")},
			&disconnectRow{Time: t4, Client: "b", Reason: "connection error: read: i/o timeout"}},
		{"a restart cuts the sessions that were open",
			[]AuditEvent{opened(t1, "a"), toolRan(t2, "a"), started(t4)},
			&disconnectRow{Time: t4, Client: "a", Reason: byBoot}},
		{"a restart names every client it cut, sorted",
			[]AuditEvent{opened(t1, "codex"), opened(t2, "zed"), opened(t2, "claude-code"), opened(t3, "aider"), started(t4)},
			&disconnectRow{Time: t4, Client: "aider, claude-code, codex, zed", Reason: byBoot}},
		{"a client that already left was not cut by the restart",
			[]AuditEvent{opened(t1, "a"), opened(t1, "b"), closedBy(t2, "a", byClient), started(t4)},
			&disconnectRow{Time: t4, Client: "b", Reason: byBoot}},
		{"a restart with nobody connected disconnects nobody",
			[]AuditEvent{opened(t1, "a"), closedBy(t2, "a", byClient), started(t4)},
			&disconnectRow{Time: t2, Client: "a", Reason: byClient}},
		{"two sessions of one client, one left, one cut",
			[]AuditEvent{opened(t1, "a"), opened(t2, "a"), closedBy(t3, "a", byClient), started(t4)},
			&disconnectRow{Time: t4, Client: "a", Reason: byBoot}},
		{"a session that ends after the restart is the later disconnect",
			[]AuditEvent{opened(t1, "a"), started(t4), opened(t5, "a"), closedBy(t6, "a", byClient)},
			&disconnectRow{Time: t6, Client: "a", Reason: byClient}},
		{"a second start cuts nothing more",
			[]AuditEvent{opened(t1, "a"), started(t4), started(t5)},
			&disconnectRow{Time: t4, Client: "a", Reason: byBoot}},
		{"a close whose open was rotated away does not hide a later open session",
			[]AuditEvent{closedBy(t1, "a", byClient), opened(t2, "a"), started(t4)},
			&disconnectRow{Time: t4, Client: "a", Reason: byBoot}},
		{"calls are not sessions",
			[]AuditEvent{calledVia(t1, "a"), started(t4)},
			nil},
	} {
		var lines []string
		for _, e := range c.log {
			lines = append(lines, evLine(t, e))
		}
		// Damaged lines between the events must not stop the scan.
		body := strings.Join(lines, "\nnot json at all\n") + "\nnot json at all\n"
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := lastDisconnect(p); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
	if got := lastDisconnect(filepath.Join(t.TempDir(), "absent.jsonl")); got != nil {
		t.Errorf("no audit file: %+v", got)
	}
}

func TestStatusReportsTheLastDisconnect(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config server\n\toption listen '127.0.0.1:9'\n\toption audit '"+dir+"/audit.jsonl'\n")
	statusFile(t, dir, "audit.jsonl", strings.Join([]string{
		evLine(t, opened("2026-10-12T04:00:00Z", "claude-code")),
		evLine(t, started("2026-10-12T05:00:41Z")),
	}, "\n")+"\n")

	var rep statusReport
	out := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 20, true, false); err != nil {
			t.Fatal(err)
		}
	})
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	want := &disconnectRow{Time: "2026-10-12T05:00:41Z", Client: "claude-code", Reason: byBoot}
	if !reflect.DeepEqual(rep.LastDisconnect, want) {
		t.Errorf("last_disconnect = %+v, want %+v", rep.LastDisconnect, want)
	}
	if !strings.Contains(out, `"last_disconnect"`) || !strings.Contains(out, `"reason"`) {
		t.Errorf("JSON keys: %s", out)
	}

	text := captureStdout(t, func() {
		if err := runStatus(cfg, dir, 20, false, false); err != nil {
			t.Fatal(err)
		}
	})
	line := "last disconnect: 2026-10-12T05:00:41Z claude-code: " + byBoot
	if !strings.Contains(text, line+"\n") {
		t.Errorf("text status lacks %q:\n%s", line, text)
	}
}

func TestStatusSaysNothingAboutDisconnectsWhenThereWereNone(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config server\n\toption listen '127.0.0.1:9'\n\toption audit '"+dir+"/audit.jsonl'\n")
	statusFile(t, dir, "audit.jsonl", evLine(t, toolRan("2026-10-12T04:00:00Z", "a"))+"\n")
	out := captureStdout(t, func() { _ = runStatus(cfg, dir, 20, true, false) })
	if strings.Contains(out, "last_disconnect") {
		t.Errorf("JSON carries a last_disconnect with nothing to report: %s", out)
	}
	text := captureStdout(t, func() { _ = runStatus(cfg, dir, 20, false, false) })
	if strings.Contains(text, "last disconnect") {
		t.Errorf("text status invents a disconnect:\n%s", text)
	}
}

// What status prints comes from a log file; a reason with control bytes must not reach a terminal.
func TestStatusStripsControlBytesFromTheDisconnectReason(t *testing.T) {
	dir := t.TempDir()
	cfg := statusFile(t, dir, "config", "config server\n\toption listen '127.0.0.1:9'\n\toption audit '"+dir+"/audit.jsonl'\n")
	statusFile(t, dir, "audit.jsonl", strings.Join([]string{
		`{"time":"2026-10-12T04:00:00Z","client":"a\u001b[2J","tool":"session","outcome":"OK","summary":"stdio session opened via ssh from 192.0.2.7"}`,
		`{"time":"2026-10-12T04:01:00Z","client":"a\u001b[2J","tool":"session","outcome":"OK","summary":"stdio session closed after 1m0s: connection error: \u001b[31mboom\u0007"}`,
	}, "\n")+"\n")
	text := captureStdout(t, func() { _ = runStatus(cfg, dir, 20, false, false) })
	if strings.ContainsAny(text, "\x1b\x07") {
		t.Errorf("control bytes reached the terminal: %q", text)
	}
	if !strings.Contains(text, "last disconnect: 2026-10-12T04:01:00Z a") || !strings.Contains(text, "connection error: ") {
		t.Errorf("reason lost:\n%s", text)
	}
}

// A call made while the daemon is still starting ends in a TIMEOUT with a retry hint (ROADMAP 5.6),
// so a script or a model can tell "not up yet" from "refused" without reading prose. The code
// belongs to that one failure: a bridge that was refused for another reason carries none.
func TestTheBridgeThatCannotReachTheDaemonEndsWithATimeoutCodeAndARetryHint(t *testing.T) {
	c := newCLI(t)
	sock := filepath.ToSlash(filepath.Join(filepath.Dir(c.config), "absent.sock"))
	if err := os.WriteFile(c.config, []byte("config server\n\toption socket '"+sock+"'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lastLine := func(s string) string {
		lines := strings.Split(strings.TrimSpace(s), "\n")
		return lines[len(lines)-1]
	}
	for _, tc := range []struct{ name, entry string }{
		{"an MCP session", ""},
		{"a call", "call system_status {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SSH_ORIGINAL_COMMAND", tc.entry)
			out, errs, code := c.run("stdio", "--client", "claude-code")
			if code == 0 || out != "" {
				t.Fatalf("exit %d, stdout %q: want a failure with nothing on stdout", code, out)
			}
			if !strings.Contains(errs, "daemon not reachable") {
				t.Errorf("the prose that says what happened is gone:\n%s", errs)
			}
			last := lastLine(errs)
			if !strings.HasPrefix(last, "[code: TIMEOUT; next: ") || !strings.Contains(last, "starting") || !strings.Contains(last, "retry") {
				t.Errorf("the last line is %q, want the TIMEOUT code with a retry hint", last)
			}
			if strings.Count(errs, "[code:") != 1 {
				t.Errorf("one code line expected:\n%s", errs)
			}
		})
	}

	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	_, errs, code := c.run("stdio", "--client", "../etc")
	if code == 0 || !strings.Contains(errs, "bad client name") || strings.Contains(errs, "[code:") {
		t.Errorf("a refused client name is not a start-up wait: exit %d\n%s", code, errs)
	}
}
