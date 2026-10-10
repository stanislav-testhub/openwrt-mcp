package main

import (
	"context"
	"fmt"
	"time"
)

// How long a call may run and how many may run at once. On a router with a small CPU and little
// RAM, one hung command or a burst of parallel calls from an agent must not leave the box unable to
// answer the next request. Cancelling a call kills its child process (exec.CommandContext), so
// the deadline and the client's own cancel both end up at the same place: the context.

// toolDeadline is the most one call of a tool may take, queueing for a slot excluded. Each value
// sits above the longest wait the tool makes itself (an exec timeout is capped at 300 s, pkg_change
// runs apk update for 2 min then the change for 5, ...; TestToolDeadlinesExceedWhatEachToolWaitsFor
// pins those floors), so a legitimate call is never cut short and a stuck one is.
var toolDeadline = map[string]time.Duration{
	"exec":            6 * time.Minute,
	"pkg_change":      8 * time.Minute,
	"pkg_query":       4 * time.Minute,
	"uci_apply":       6 * time.Minute,
	"service_control": 5 * time.Minute,
	"sysupgrade":      3 * time.Minute,
}

const defaultToolDeadline = 2 * time.Minute

func deadlineFor(tool string) time.Duration {
	if d := toolDeadline[tool]; d > 0 {
		return d
	}
	return defaultToolDeadline
}

var (
	// inflightLimit is how many tool calls run at once across every client. A further call waits up
	// to inflightWait for a slot and is then refused as busy. Variables so tests need not run
	// eight real calls.
	inflightLimit = 8
	inflightWait  = 30 * time.Second
)

// slotExempt tools never queue. A rollback window ends in uci_confirm or uci_rollback, and a full
// router is exactly when a pending change needs one of them; mfa_unlock is how the other tools
// are unlocked at all. All three are quick.
var slotExempt = map[string]bool{"uci_confirm": true, "uci_rollback": true, "mfa_unlock": true}

// acquireSlot takes one of the server's slots, waiting up to inflightWait. It returns the function
// that gives the slot back, or a refusal text when none came free (or the caller gave up first).
func (s *Server) acquireSlot(ctx context.Context) (release func(), refusal string) {
	free := func() { <-s.slots }
	select {
	case s.slots <- struct{}{}:
		return free, ""
	default:
	}
	timer := time.NewTimer(inflightWait)
	defer timer.Stop()
	select {
	case s.slots <- struct{}{}:
		return free, ""
	case <-timer.C:
		return nil, fmt.Sprintf("busy: %d calls are already running on this router (the limit); try again in a few seconds", cap(s.slots))
	case <-ctx.Done():
		return nil, "cancelled while waiting for a free slot"
	}
}
