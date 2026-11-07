package main

import (
	"strings"
	"testing"
	"time"
)

// request_access opens every request at once and does not wait, so a client that runs its calls
// one after another still shows the owner all of them together.
func TestRequestAccessOpensAllRequestsAtOnceWithoutWaiting(t *testing.T) {
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")
	start := time.Now()
	out, isErr := callText(t, cs, "request_access", map[string]any{"wants": []string{
		"uci_apply wireless.radio1.channel wireless.radio1.htmode", "pkg_change add.usteer", "service_control usteer.restart"}})
	if isErr {
		t.Fatalf("request_access failed: %s", out)
	}
	if time.Since(start) > time.Second {
		t.Errorf("request_access waited %s; it must return at once", time.Since(start))
	}
	if !strings.Contains(out, "3 of 3 requests are waiting") {
		t.Errorf("want three waiting requests: %s", out)
	}
	open := 0
	for _, r := range s.requests.List(time.Now()) {
		if r.State == reqOpen && r.Client == "c" {
			open++
		}
	}
	if open != 3 {
		t.Errorf("%d open requests, want 3", open)
	}
	// The real call finds its request already there instead of opening a second one.
	before := len(s.requests.List(time.Now()))
	callText(t, cs, "service_control", map[string]any{"name": "usteer", "action": "restart"})
	if after := len(s.requests.List(time.Now())); after != before {
		t.Errorf("the real call opened another request (%d, was %d)", after, before)
	}
}

func TestRequestAccessSkipsWhatIsAlreadyAllowedAndGrantsNothing(t *testing.T) {
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")
	out, _ := callText(t, cs, "request_access", map[string]any{"wants": []string{"ubus_call system.board", "exec /bin/sh"}})
	if !strings.Contains(out, "ubus_call system.board: already allowed") || !strings.Contains(out, "1 of 2 requests are waiting") {
		t.Errorf("an allowed call must not open a request: %s", out)
	}
	if res, isErr := callText(t, cs, "exec", map[string]any{"argv": []string{"/bin/sh"}}); !isErr || !strings.Contains(res, "denied") {
		t.Errorf("asking must not grant: %s", res)
	}
}

func TestRequestAccessRefusesWhatIsNotARealWant(t *testing.T) {
	s := testServer(t, boardPolicy())
	cs := connectClient(t, s, "c")
	for _, w := range [][]string{
		{}, {"mfa_unlock"}, {"no_such_tool x"}, {"uci_apply <b>x</b>"},
		{"uci_apply a", "uci_apply b", "uci_apply c", "uci_apply d", "uci_apply e", "uci_apply f", "uci_apply g", "uci_apply h", "uci_apply i"},
	} {
		if out, isErr := callText(t, cs, "request_access", map[string]any{"wants": w}); !isErr {
			t.Errorf("wants %q was accepted: %s", w, out)
		}
	}
	for _, r := range s.requests.List(time.Now()) {
		t.Errorf("a refused call opened request %s", r.ID)
	}
}
