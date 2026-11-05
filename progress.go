package main

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Progress for long operations (ROADMAP 5.8). A client that sends a progressToken with a call
// gets a notification every progressEvery while the operation runs: pkg_change with commit=true,
// sysupgrade test and check, and net_diag traceroute, throughput and capture. None of these
// reports a real percentage, so the notification says how long it has been running and carries
// no total. A call without a token, and every other call, sends nothing.

var progressEvery = 5 * time.Second

// longRunning names the call a heartbeat is worth sending for, or "".
func longRunning(tool string, in any) string {
	switch v := in.(type) {
	case pkgChangeIn:
		if v.Commit {
			return "pkg_change " + v.Action
		}
	case sysupgradeIn:
		if v.Action == "test" || v.Action == "check" {
			return "sysupgrade " + v.Action
		}
	case netDiagIn:
		switch v.Action {
		case "traceroute", "throughput", "capture":
			return "net_diag " + v.Action
		}
	}
	return ""
}

// startProgress begins the heartbeat for a call and returns the function that ends it. It is a
// no-op when the client sent no progress token, or the call is not a long one.
func startProgress(ctx context.Context, req *mcp.CallToolRequest, tool string, in any) (stop func()) {
	label := longRunning(tool, in)
	if label == "" || req == nil || req.Session == nil || req.Params == nil || req.Params.GetProgressToken() == nil {
		return func() {}
	}
	token := req.Params.GetProgressToken()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(done)
		t := time.NewTicker(progressEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				el := time.Since(started).Round(time.Second)
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: token,
					Progress:      el.Seconds(),
					Message:       fmt.Sprintf("%s: still running after %s", label, el),
				})
			}
		}
	}()
	return func() { cancel(); <-done }
}
