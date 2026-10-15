package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Push hook (docs/luci-approvals.md, 8.8): when a call opens a new approval request, the daemon
// sends the ubus event openwrt-mcp.request and runs every executable in hooksDir with the request
// as JSON on stdin. The notification only says that something is waiting; approving stays in
// LuCI. Off until the owner switches the channel on.

const (
	hooksDir      = "/etc/openwrt-mcp/hooks.d"
	pushHookEvent = "openwrt-mcp.request"
	pushHookLimit = 10 * time.Second
)

// pushPayload is what a hook receives. Args are the redacted text the audit log holds.
type pushPayload struct {
	Event   string    `json:"event"`
	ID      string    `json:"id"`
	Client  string    `json:"client"`
	Tool    string    `json:"tool"`
	Scope   string    `json:"scope"`
	Args    string    `json:"args"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}

// hookModeOK: a hook runs as root, so it must be executable and not writable by group or others.
func hookModeOK(m fs.FileMode) bool { return m.IsRegular() && m&0o111 != 0 && m&0o022 == 0 }

// hookModeOf reads a file's mode; a variable only so tests on a filesystem without Unix modes
// can supply them.
var hookModeOf = func(fi fs.FileInfo) fs.FileMode { return fi.Mode() }

// hookScripts lists the runnable files of dir in name order. Dotfiles and editor backups are
// skipped, as are files whose mode fails hookModeOK; skipped names are returned so the audit
// line says why a hook did not run.
func hookScripts(dir string) (run, skipped []string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || strings.HasSuffix(n, "~") {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, n)) // follows a symlink to its target's mode
		if err != nil || !hookModeOK(hookModeOf(fi)) {
			skipped = append(skipped, n)
			continue
		}
		run = append(run, filepath.Join(dir, n))
	}
	return run, skipped
}

// pushRequest is called, once, for each newly opened request. It never blocks the call that
// opened it and never returns an error: a broken hook is an audit line, not a failed tool call.
func (s *Server) pushRequest(r Request) {
	if !s.cfg().PushHook {
		return
	}
	s.pushMu.Lock() // one batch at a time: a burst of requests must not become a burst of processes
	defer s.pushMu.Unlock()
	body, _ := json.Marshal(pushPayload{Event: "request", ID: r.ID, Client: r.Client, Tool: r.Tool,
		Scope: r.Scope, Args: r.Args, Created: r.Created, Expires: r.Expires})
	scripts, skipped := hookScripts(sysPath(hooksDir))

	exec := func(stdin *string, argv ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), pushHookLimit)
		defer cancel()
		_, _, err := cmdRunner(ctx, stdin, argv)
		return err
	}
	var failed []string
	if err := exec(nil, "ubus", "send", pushHookEvent, string(body)); err != nil {
		failed = append(failed, "ubus send")
	}
	in := string(body)
	for _, path := range scripts {
		if err := exec(&in, path); err != nil {
			failed = append(failed, filepath.Base(path))
		}
	}
	sum := fmt.Sprintf("request %s: event sent, %d hook(s) run", r.ID, len(scripts))
	if len(failed) > 0 {
		sum += ", failed: " + strings.Join(failed, ", ")
	}
	if len(skipped) > 0 {
		sum += ", skipped (not executable or writable by others): " + strings.Join(skipped, ", ")
	}
	s.audit.Record(AuditEvent{Time: nowISO(), Client: r.Client, Tool: "push_hook", Scope: r.Scope,
		Outcome: OutcomeOK, Summary: truncate(sanitizeText(sum), 300)})
}
