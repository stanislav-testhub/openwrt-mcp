package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func progressClient(t *testing.T, s *Server, got *[]string, mu *sync.Mutex) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := s.serverFor("c").Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			mu.Lock()
			*got = append(*got, r.Params.Message)
			mu.Unlock()
		}})
	cs, err := c.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func slowTraceroute(f *fakeRouter) {
	f.onFn("traceroute", func([]string, string) (string, error) {
		time.Sleep(120 * time.Millisecond)
		return "1  192.0.2.1  1 ms\n", nil
	})
}

func TestLongCallsSendProgressWhenTheClientAsksForIt(t *testing.T) {
	old := progressEvery
	progressEvery = 20 * time.Millisecond
	t.Cleanup(func() { progressEvery = old })
	f := newFakeRouter(t)
	slowTraceroute(f)
	var got []string
	var mu sync.Mutex
	cs := progressClient(t, testServer(t, grantAll()), &got, &mu)

	params := &mcp.CallToolParams{Name: "net_diag", Arguments: map[string]any{"action": "traceroute", "target": "192.0.2.1"}}
	params.SetProgressToken("tok-1")
	if _, err := cs.CallTool(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	n := len(got)
	first := ""
	if n > 0 {
		first = got[0]
	}
	mu.Unlock()
	if n < 2 || !strings.HasPrefix(first, "net_diag traceroute: still running after") {
		t.Fatalf("progress messages: %v", got)
	}
	// Nothing more arrives once the call has returned.
	time.Sleep(80 * time.Millisecond)
	mu.Lock()
	after := len(got)
	mu.Unlock()
	if after != n {
		t.Errorf("%d notifications after the call ended", after-n)
	}
}

func TestProgressIsOnlyForLongCallsWithAToken(t *testing.T) {
	old := progressEvery
	progressEvery = 20 * time.Millisecond
	t.Cleanup(func() { progressEvery = old })
	f := newFakeRouter(t)
	slowTraceroute(f)
	f.onFn("ping", func([]string, string) (string, error) {
		time.Sleep(100 * time.Millisecond)
		return "ok\n", nil
	})
	var got []string
	var mu sync.Mutex
	cs := progressClient(t, testServer(t, grantAll()), &got, &mu)

	// No token: a traceroute sends nothing.
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "net_diag", Arguments: map[string]any{"action": "traceroute", "target": "192.0.2.1"}}); err != nil {
		t.Fatal(err)
	}
	// A token on a call that is not long: nothing either.
	p := &mcp.CallToolParams{Name: "net_diag", Arguments: map[string]any{"action": "ping", "target": "192.0.2.1"}}
	p.SetProgressToken("tok-2")
	if _, err := cs.CallTool(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 0 {
		t.Errorf("unexpected progress: %v", got)
	}
}

func TestLongRunningNamesExactlyTheDocumentedCalls(t *testing.T) {
	yes := []any{pkgChangeIn{Action: "add", Commit: true}, sysupgradeIn{Action: "test"}, sysupgradeIn{Action: "check"},
		netDiagIn{Action: "traceroute"}, netDiagIn{Action: "throughput"}, netDiagIn{Action: "capture"}}
	no := []any{pkgChangeIn{Action: "add"}, sysupgradeIn{Action: "list"}, sysupgradeIn{Action: "backup"}, netDiagIn{Action: "ping"}, uciGetIn{}}
	for _, in := range yes {
		if longRunning("", in) == "" {
			t.Errorf("%#v has no heartbeat", in)
		}
	}
	for _, in := range no {
		if longRunning("", in) != "" {
			t.Errorf("%#v has a heartbeat", in)
		}
	}
}
