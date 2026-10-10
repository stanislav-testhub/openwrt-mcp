package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A call is bounded three ways: the client can cancel it (the tool's child process dies), every tool
// has a deadline above the longest wait the tool makes itself, and only so many calls run at once.
// The deadline and the cap are what keep a small router answering when something hangs.

// What each tool's own commands can wait for, from the code: an exec timeout is capped at 300 s,
// pkg_change runs apk update (2 min) then the change (5 min), pkg_query updates (2 min) then reads
// (1 min), service_control waits up to 60 s after a 2 min command and a 30 s read, traceroute is
// cut at 90 s, the WireGuard writers wait up to 60 s for the reload and twice 8 s for netifd. A deadline
// at or under these would cut a legitimate call short.
var toolWaitFloors = map[string]time.Duration{
	"exec": 300 * time.Second, "pkg_change": 7 * time.Minute, "pkg_query": 3 * time.Minute,
	"service_control": 3 * time.Minute, "sysupgrade": 2 * time.Minute, "net_diag": 90 * time.Second,
	"uci_apply": 3 * time.Minute, "wg_new_client": 90 * time.Second, "wg_remove_client": 90 * time.Second,
}

func TestToolDeadlinesExceedWhatEachToolWaitsFor(t *testing.T) {
	for _, name := range allToolNames {
		d := deadlineFor(name)
		if d < time.Minute || d > 10*time.Minute {
			t.Errorf("%s: deadline %s, want between 1 and 10 minutes", name, d)
		}
		if floor, ok := toolWaitFloors[name]; ok && d <= floor {
			t.Errorf("%s: deadline %s does not exceed the %s the tool itself may wait", name, d, floor)
		}
	}
}

// blockingRunner replaces the router's commands with one that waits for the call's context or an
// explicit release, and counts how many are running.
type blockingRunner struct {
	mu        sync.Mutex
	running   int
	started   chan struct{}
	release   chan struct{}
	cancelled chan struct{}
}

func newBlockingRunner(t *testing.T) *blockingRunner {
	t.Helper()
	newFakeRouter(t)
	b := &blockingRunner{started: make(chan struct{}, 32), release: make(chan struct{}), cancelled: make(chan struct{}, 32)}
	cmdRunner = func(ctx context.Context, _ *string, _ []string) (string, string, error) {
		b.mu.Lock()
		b.running++
		b.mu.Unlock()
		b.started <- struct{}{}
		defer func() { b.mu.Lock(); b.running--; b.mu.Unlock() }()
		select {
		case <-b.release:
			return `{"model":"m"}`, "", nil
		case <-ctx.Done():
			b.cancelled <- struct{}{}
			return "", "", ctx.Err()
		}
	}
	return b
}

func (b *blockingRunner) count() int { b.mu.Lock(); defer b.mu.Unlock(); return b.running }

func awaitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for: %s", what)
	}
}

func boardPolicy() string { return policyFor("c", []string{"ubus_call"}, "system.board") }

var boardCall = map[string]any{"object": "system", "method": "board"}

func TestAHungToolIsStoppedAtItsDeadlineAndSaysSo(t *testing.T) {
	b := newBlockingRunner(t)
	old, had := toolDeadline["ubus_call"]
	toolDeadline["ubus_call"] = 200 * time.Millisecond
	t.Cleanup(func() {
		if had {
			toolDeadline["ubus_call"] = old
		} else {
			delete(toolDeadline, "ubus_call")
		}
	})
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")

	start := time.Now()
	out, isErr := callText(t, cs, "ubus_call", boardCall)
	if !isErr || !strings.Contains(out, "limit") || !strings.Contains(out, "200ms") {
		t.Fatalf("hung call: %q (error %v), want an error naming the tool's limit", out, isErr)
	}
	if !strings.HasSuffix(out, "\n[code: TIMEOUT; next: retry once, then narrow the request]") {
		t.Errorf("a deadline hit does not end with the TIMEOUT code: %q", out)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the call returned after %s, the deadline is 200ms", took)
	}
	awaitSignal(t, b.cancelled, "the tool's command to be cancelled at the deadline")
	var logged []AuditEvent
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "ubus_call" {
			logged = append(logged, ev)
		}
	}
	if len(logged) != 1 || logged[0].Outcome != OutcomeError || !strings.Contains(logged[0].Error, "limit") {
		t.Errorf("audit = %+v, want one ERROR that names the limit", logged)
	}
}

func TestACallTheClientCancelsStopsItsCommand(t *testing.T) {
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = cs.CallTool(ctx, callParams("ubus_call", boardCall))
		close(done)
	}()
	awaitSignal(t, b.started, "the command to start")
	cancel()
	awaitSignal(t, b.cancelled, "the command to be cancelled after the client cancelled")
	awaitSignal(t, done, "the client's call to return")
	for i := 0; b.count() != 0; i++ {
		if i > 100 {
			t.Fatalf("%d commands still running after the cancel", b.count())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The handler records the call after the command ends; let it, or it writes into a removed directory.
	auditErrorFor(t, s, "ubus_call", OutcomeError)
}

// ---- how many calls run at once

func setInflight(t *testing.T, limit int, wait time.Duration) {
	t.Helper()
	oldLimit, oldWait := inflightLimit, inflightWait
	inflightLimit, inflightWait = limit, wait
	t.Cleanup(func() { inflightLimit, inflightWait = oldLimit, oldWait })
}

// fillSlots starts n board calls that stay running until the runner's release is closed.
func fillSlots(t *testing.T, s *Server, b *blockingRunner, n int) (wait func()) {
	t.Helper()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		cs := connectClient(t, s, "c")
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cs.CallTool(context.Background(), callParams("ubus_call", boardCall))
		}()
		awaitSignal(t, b.started, "a call to take a slot")
	}
	return wg.Wait
}

func TestTooManyCallsAtOnceWaitForASlotThenRefuseAsBusy(t *testing.T) {
	setInflight(t, 2, 150*time.Millisecond)
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	wait := fillSlots(t, s, b, 2)

	out, isErr := callText(t, connectClient(t, s, "c"), "ubus_call", boardCall)
	if !isErr || !strings.Contains(out, "busy") {
		t.Errorf("third call with both slots taken: %q (error %v), want a busy refusal", out, isErr)
	}
	if !strings.HasSuffix(out, "\n[code: TIMEOUT; next: retry once, then narrow the request]") {
		t.Errorf("a busy refusal does not end with the TIMEOUT code: %q", out)
	}
	if n := b.count(); n != 2 {
		t.Errorf("%d commands running, want the 2 that hold the slots", n)
	}
	if len(deniedAudit(t, s, "ubus_call")) != 1 {
		t.Errorf("the busy refusal was not audited as DENIED: %+v", auditEvents(t, s))
	}

	close(b.release)
	wait()
	// The slots came back.
	if out, isErr := callText(t, connectClient(t, s, "c"), "ubus_call", boardCall); isErr {
		t.Errorf("a call after the slots were freed: %q", out)
	}
}

func TestACallWaitsForASlotAndRunsWhenOneFrees(t *testing.T) {
	setInflight(t, 2, 5*time.Second)
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	wait := fillSlots(t, s, b, 2)

	result := make(chan string, 1)
	cs := connectClient(t, s, "c")
	go func() {
		out, isErr := callText(t, cs, "ubus_call", boardCall)
		if isErr {
			out = "ERROR " + out
		}
		result <- out
	}()
	select {
	case out := <-result:
		t.Fatalf("the third call did not wait for a slot: %q", out)
	case <-time.After(200 * time.Millisecond):
	}
	close(b.release)
	select {
	case out := <-result:
		if strings.HasPrefix(out, "ERROR") {
			t.Errorf("the queued call failed once a slot freed: %s", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the queued call never ran")
	}
	wait()
}

// The tools that end a rollback window or unlock the others must never queue behind slow work: a
// full router is exactly when a pending change needs confirming or rolling back.
func TestFullSlotsNeverBlockTheSafetyTools(t *testing.T) {
	setInflight(t, 1, 150*time.Millisecond)
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy()+policyFor("c", []string{"uci_rollback", "uci_confirm", "mfa_unlock"}, "*"))
	wait := fillSlots(t, s, b, 1)
	cs := connectClient(t, s, "c")
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"uci_rollback", map[string]any{"token": "none"}},
		{"uci_confirm", map[string]any{"token": "none"}},
		{"mfa_unlock", map[string]any{"code": "000000"}},
	} {
		if out, _ := callText(t, cs, c.tool, c.args); strings.Contains(out, "busy") {
			t.Errorf("%s was refused as busy: %q", c.tool, out)
		}
	}
	close(b.release)
	wait()
}

// A refused call never held a slot, so a client that is denied gets the denial it would always get.
func TestADeniedCallDoesNotTakeOrWaitForASlot(t *testing.T) {
	setInflight(t, 1, 2*time.Second)
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	wait := fillSlots(t, s, b, 1)
	start := time.Now()
	out, isErr := callText(t, connectClient(t, s, "c"), "system_status", nil) // not granted
	if !isErr || !strings.Contains(out, "openwrt-mcp allow c system_status") {
		t.Errorf("denied call: %q (error %v), want the ordinary denial", out, isErr)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("a denied call waited %s for a slot", took)
	}
	close(b.release)
	wait()
}

func callParams(name string, args map[string]any) *mcp.CallToolParams {
	return &mcp.CallToolParams{Name: name, Arguments: args}
}

func auditErrorFor(t *testing.T, s *Server, tool string, outcome Outcome) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, ev := range auditEvents(t, s) {
			if ev.Tool == tool && ev.Outcome == outcome {
				return ev.Error
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestACallCancelledWhileWaitingForASlotGivesUpItsPlace(t *testing.T) {
	setInflight(t, 1, 30*time.Second)
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	wait := fillSlots(t, s, b, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cs := connectClient(t, s, "c")
	go func() { _, _ = cs.CallTool(ctx, callParams("ubus_call", boardCall)) }()
	time.Sleep(100 * time.Millisecond) // it is queued by now
	cancel()
	if got := auditErrorFor(t, s, "ubus_call", OutcomeDenied); !strings.Contains(got, "cancelled while waiting") {
		t.Errorf("queued call after a cancel: audit error %q, want it to say it stopped waiting", got)
	}
	if n := b.count(); n != 1 {
		t.Errorf("%d commands running, want only the one that holds the slot", n)
	}
	close(b.release)
	wait()
}

func TestAClientCancelIsRecordedAsSuch(t *testing.T) {
	b := newBlockingRunner(t)
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, _ = cs.CallTool(ctx, callParams("ubus_call", boardCall)) }()
	awaitSignal(t, b.started, "the command to start")
	cancel()
	if got := auditErrorFor(t, s, "ubus_call", OutcomeError); !strings.Contains(got, "cancelled by the client") {
		t.Errorf("audit error %q, want it to say the client cancelled", got)
	}
}

// run() has its own timeout; when the caller's deadline is earlier it must report how long the
// command really ran, not the timeout it never reached.
func TestRunReportsHowLongItRanWhenTheCallersDeadlineCameFirst(t *testing.T) {
	newBlockingRunner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := run(ctx, 30*time.Second, "sleep", "60")
	if err == nil || !strings.Contains(err.Error(), "timed out after ") || strings.Contains(err.Error(), "30s") {
		t.Errorf("err = %v, want a timeout that names about 100ms, not the 30s the command never reached", err)
	}
}
