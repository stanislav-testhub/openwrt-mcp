package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------- uci apply / rollback
//
// rpcd has its own apply-with-rollback (`ubus call uci apply {"rollback":true}`), which is
// what LuCI uses. It is not used here for two reasons:
//
//   - Its write methods are session-bound: they take a ubus_rpc_session with a uci write ACL,
//     which in practice means a LuCI login (a password stored on the router) or minting and
//     granting a session behind rpcd's back.
//   - Its rollback state lives in rpcd's memory and under /var/run (tmpfs). If a change takes
//     the router off the network and the operator power-cycles it -- the most likely recovery
//     step -- the pending rollback is gone and the bad config simply boots.
//
// So uci_apply snapshots the configs it touches to flash, commits, reloads and arms its own
// timer. The pending record and the snapshot both live under the state directory
// (/etc/openwrt-mcp, on the overlay), and the daemon rolls back any unconfirmed apply at
// startup -- including the first start after a reboot, since procd starts it after network.

type pendingApply struct {
	Token    string            `json:"token"`
	Dir      string            `json:"snapshot_dir"`
	Deadline time.Time         `json:"deadline"`
	Configs  []string          `json:"configs"`
	Modes    map[string]uint32 `json:"modes"`             // config -> file mode at snapshot
	Missing  []string          `json:"missing,omitempty"` // configs that did not exist; restore deletes them
	Client   string            `json:"client"`
	What     string            `json:"what"`

	timer *time.Timer
}

type uciApplyIn struct {
	Changes []UCIChange `json:"changes" jsonschema:"the UCI changes to make, applied in order and committed together"`
	Timeout int         `json:"timeout,omitempty" jsonschema:"seconds before automatic rollback if uci_confirm is not called (default 90, max 600)"`
	DryRun  bool        `json:"dry_run,omitempty" jsonschema:"stage the changes, report exactly what uci would change, then revert. Nothing is committed or reloaded."`
}

type uciTokenIn struct {
	Token string `json:"token" jsonschema:"the token returned by uci_apply"`
}

// uciConfDir is /etc/config on the router and a fixture directory in tests.
var uciConfDir = "/etc/config"

func (s *Server) pendingPath() string  { return path.Join(s.statePath, "pending.json") }
func (s *Server) snapshotRoot() string { return path.Join(s.statePath, "rollback") }

func (s *Server) pendingSummary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for _, p := range s.pending {
		out = append(out, fmt.Sprintf("%s (%s by %s, reverts %s)", p.Token, strings.Join(p.Configs, ","),
			p.Client, p.Deadline.Format(time.RFC3339)))
	}
	return strings.Join(out, "; ")
}

func (s *Server) uciApply(ctx context.Context, client string, in uciApplyIn) (string, string, error) {
	if len(in.Changes) == 0 {
		return "", "", fmt.Errorf("changes must not be empty")
	}
	configs := map[string]bool{}
	for _, c := range in.Changes {
		if err := validateChange(c); err != nil {
			return "", "", err
		}
		configs[c.Config] = true
	}
	var names []string
	for c := range configs {
		if s.isPolicyFile(filepath.Join(uciConfDir, c)) {
			return "", "", errPolicyFile
		}
		if _, err := os.Stat(filepath.Join(uciConfDir, c)); err != nil {
			return "", "", fmt.Errorf("no such UCI config %q", c)
		}
		names = append(names, c)
	}
	sort.Strings(names)

	// One staging operation at a time: uci's staging area (/tmp/.uci) is shared.
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	if !in.DryRun {
		if p := s.pendingSummary(); p != "" {
			return "", "", fmt.Errorf("an apply is already pending confirmation: %s\n"+
				"call uci_confirm or uci_rollback first", p)
		}
	}
	for _, c := range names {
		if out, err := uncommitted(ctx, c); err == nil && out != "" {
			return "", "", fmt.Errorf("refusing to apply: %s already has uncommitted changes "+
				"(someone else's edit in progress):\n%s", c, out)
		}
	}

	revertAll := func() {
		for _, c := range names {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
		}
	}
	for _, c := range in.Changes {
		for _, cmd := range uciCmds(c) {
			if out, err := run(ctx, defaultCmdTimeout, cmd.argv...); err != nil && !cmd.mayFail {
				revertAll()
				return "", "", fmt.Errorf("staging %s failed: %w\n%s", uciKey(c), err, out)
			}
		}
	}
	var diff strings.Builder
	for _, c := range names {
		out, _ := uncommitted(ctx, c)
		if out != "" {
			diff.WriteString(out + "\n")
		}
	}
	staged := strings.TrimSpace(diff.String())
	if staged == "" {
		staged = "(no effective change -- every value was already set)"
	}

	if in.DryRun {
		revertAll()
		return fmt.Sprintf("DRY RUN -- nothing was committed. uci would change:\n%s\n\n"+
				"Call uci_apply again without dry_run to apply this with a rollback timer.", staged),
			fmt.Sprintf("dry run of %d change(s)", len(in.Changes)), nil
	}

	timeout := clampSec(in.Timeout, 90, 600)
	p, err := s.snapshot(names, client, fmt.Sprintf("%d uci change(s)", len(in.Changes)), timeout)
	if err != nil {
		revertAll()
		return "", "", err
	}
	// Armed before the commit, so there is no instant at which a committed change exists
	// without a pending record on flash to undo it.
	s.arm(p, timeout)
	for _, c := range names {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", c); err != nil {
			var rerr error
			if s.take(p.Token) != nil {
				rerr = s.restore(ctx, p, false)
				s.savePending()
			}
			return "", "", fmt.Errorf("commit %s failed: %w\n%s (restore: %v)", c, err, out, rerr)
		}
	}
	reloadOut := reloadConfigs(ctx, names, false)

	return fmt.Sprintf(
		"Applied to %s and reloaded. Changes:\n%s\n\n"+
			"ROLLBACK ARMED: reverts automatically at %s (in %s) unless you call\n"+
			"  uci_confirm {\"token\": \"%s\"}\n"+
			"or undo it now with uci_rollback. The snapshot is on flash, so a reboot inside the\n"+
			"window also rolls back.\n\nVerify the router is still reachable and behaving BEFORE confirming.%s",
		strings.Join(names, ", "), staged, p.Deadline.Format(time.RFC3339), timeout, p.Token, indentOut(reloadOut),
	), fmt.Sprintf("applied %d change(s) to %s, rollback armed %s", len(in.Changes), strings.Join(names, ","), timeout), nil
}

// snapshot copies the named configs to flash and records a pending apply, not yet armed.
func (s *Server) snapshot(configs []string, client, what string, timeout time.Duration) (*pendingApply, error) {
	token := randToken()
	dir := path.Join(s.snapshotRoot(), token)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("snapshot failed: %w", err)
	}
	p := &pendingApply{Token: token, Dir: dir, Configs: configs, Modes: map[string]uint32{},
		Client: client, What: what, Deadline: time.Now().Add(timeout)}
	for _, c := range configs {
		src := filepath.Join(uciConfDir, c)
		st, err := os.Stat(src)
		if os.IsNotExist(err) {
			p.Missing = append(p.Missing, c)
			continue
		}
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("snapshot %s: %w", c, err)
		}
		b, err := os.ReadFile(src)
		if err == nil {
			err = writeSynced(path.Join(dir, c), b, 0o600)
		}
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, fmt.Errorf("snapshot %s: %w", c, err)
		}
		p.Modes[c] = uint32(st.Mode().Perm())
	}
	return p, nil
}

// arm registers a snapshotted change and starts its timer. The pending record is written
// before this returns, so a crash or reboot from here on rolls back.
func (s *Server) arm(p *pendingApply, timeout time.Duration) {
	s.mu.Lock()
	p.Deadline = time.Now().Add(timeout)
	p.timer = time.AfterFunc(timeout, func() { s.rollback(p.Token, "timeout") })
	s.pending[p.Token] = p
	s.mu.Unlock()
	s.savePending()
}

func (s *Server) take(token string) *pendingApply {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[token]
	if !ok {
		return nil
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	delete(s.pending, token)
	return p
}

func (s *Server) uciConfirm(_ context.Context, token string) (string, string, error) {
	p := s.take(token)
	if p == nil {
		return "", "", fmt.Errorf("no pending apply with token %q (it may have already rolled back)", token)
	}
	_ = os.RemoveAll(p.Dir)
	s.savePending()
	return fmt.Sprintf("Confirmed. Rollback cancelled; %s to %s are permanent.", p.What, strings.Join(p.Configs, ", ")),
		"confirmed " + token, nil
}

func (s *Server) uciRollbackNow(ctx context.Context, token string) (string, string, error) {
	p := s.take(token)
	if p == nil {
		return "", "", fmt.Errorf("no pending apply with token %q (it may have already rolled back)", token)
	}
	err := s.restore(ctx, p, false)
	s.savePending()
	if err != nil {
		return "", "rollback failed", fmt.Errorf("ROLLBACK FAILED: %w (snapshot kept at %s)", err, p.Dir)
	}
	return fmt.Sprintf("Rolled back %s: %s restored and reloaded.", p.What, strings.Join(p.Configs, ", ")),
		"rolled back " + token, nil
}

func (s *Server) rollback(token, reason string) {
	p := s.take(token)
	if p == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := s.restore(ctx, p, false)
	s.savePending()
	outcome, msg := OutcomeOK, fmt.Sprintf("rolled back %s (%s)", strings.Join(p.Configs, ", "), reason)
	if err != nil {
		outcome, msg = OutcomeError, fmt.Sprintf("ROLLBACK FAILED (snapshot kept at %s): %v", p.Dir, err)
	}
	log.Printf("openwrt-mcp: %s", msg)
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<system>", Tool: "uci_rollback", Outcome: outcome, Summary: msg})
}

// restore puts the snapshotted files back atomically, drops any staged uci changes for them,
// and reloads. The snapshot is deleted only after a successful restore.
func (s *Server) restore(ctx context.Context, p *pendingApply, atBoot bool) error {
	var failed []string
	for _, c := range p.Configs {
		dst := filepath.Join(uciConfDir, c)
		if contains(p.Missing, c) {
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				failed = append(failed, c+": "+err.Error())
			}
			continue
		}
		b, err := os.ReadFile(path.Join(p.Dir, c))
		if err != nil {
			failed = append(failed, c+": snapshot unreadable: "+err.Error())
			continue
		}
		mode := os.FileMode(p.Modes[c])
		if mode == 0 {
			mode = 0o644
		}
		tmp := filepath.Join(uciConfDir, "."+c+".openwrt-mcp-restore")
		if err := writeSynced(tmp, b, mode); err != nil {
			failed = append(failed, c+": "+err.Error())
			continue
		}
		if err := os.Rename(tmp, dst); err != nil {
			failed = append(failed, c+": "+err.Error())
		}
	}
	for _, c := range p.Configs {
		_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
	}
	reloadConfigs(ctx, p.Configs, atBoot)
	if len(failed) > 0 {
		return fmt.Errorf("restore incomplete: %s", strings.Join(failed, "; "))
	}
	_ = os.RemoveAll(p.Dir)
	return nil
}

// reloadConfigs makes committed configs take effect. /sbin/reload_config compares each
// config against the checksums it recorded last time and fires a config.change event for the
// ones that differ -- but if it has never run since boot there are no checksums and it fires
// nothing. In that case (and always at boot, where the running state came from the file we
// are about to replace) the events are sent explicitly for exactly the configs touched.
func reloadConfigs(ctx context.Context, configs []string, force bool) string {
	_, statErr := os.Stat(sysPath("/var/run/config.md5"))
	out, err := run(ctx, time.Minute, "/sbin/reload_config")
	if err != nil {
		out += "\nreload_config: " + err.Error()
	}
	if force || statErr != nil {
		for _, c := range configs {
			ev := fmt.Sprintf(`{"type":"config.change","data":{"package":%q}}`, c)
			if o, err := run(ctx, defaultCmdTimeout, "ubus", "call", "service", "event", ev); err != nil {
				out += fmt.Sprintf("\nconfig.change %s: %v %s", c, err, o)
			}
		}
	}
	return strings.TrimSpace(out)
}

func (s *Server) savePending() {
	s.mu.RLock()
	list := make([]*pendingApply, 0, len(s.pending))
	for _, p := range s.pending {
		list = append(list, p)
	}
	s.mu.RUnlock()
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	_ = os.MkdirAll(s.statePath, 0o700)
	if len(list) == 0 {
		_ = os.Remove(s.pendingPath())
		return
	}
	_ = writeSynced(s.pendingPath(), b, 0o600)
}

// recoverPending rolls back any apply that was still unconfirmed when we stopped. A restart
// during the confirmation window -- a crash, an upgrade, or a power cycle to recover a router
// the change knocked off the network -- means nobody ever vouched for the change.
func (s *Server) recoverPending() {
	b, err := os.ReadFile(s.pendingPath())
	if err != nil {
		return
	}
	var list []*pendingApply
	if json.Unmarshal(b, &list) != nil {
		log.Printf("openwrt-mcp: %s is corrupt; snapshots left in %s for manual recovery", s.pendingPath(), s.snapshotRoot())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, p := range list {
		log.Printf("openwrt-mcp: unconfirmed apply %s (%s) found at startup, rolling back", p.Token, strings.Join(p.Configs, ","))
		msg, outcome := "rolled back "+strings.Join(p.Configs, ", ")+" (unconfirmed at startup)", OutcomeOK
		if err := s.restore(ctx, p, true); err != nil {
			msg, outcome = fmt.Sprintf("ROLLBACK FAILED at startup (snapshot kept at %s): %v", p.Dir, err), OutcomeError
			log.Printf("openwrt-mcp: %s", msg)
		}
		s.audit.Record(AuditEvent{Time: nowISO(), Client: "<system>", Tool: "uci_rollback", Outcome: outcome, Summary: msg})
	}
	_ = os.Remove(s.pendingPath())
}

// writeSynced writes a file and fsyncs it: a snapshot that is still in the page cache when
// the power goes is not a snapshot.
func writeSynced(name string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(name, mode)
}

func indentOut(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return "\n\nreload output:\n  " + strings.ReplaceAll(s, "\n", "\n  ")
}

// errPolicyFile: whatever a client has been granted, it cannot grant itself more. Without
// this, uci_apply on scope '*' (the @operator preset) could add a policy with exec on '*'
// and confirm it.
var errPolicyFile = fmt.Errorf("the openwrt-mcp policy config cannot be changed through MCP, " +
	"whatever the grant; change it on the router with openwrt-mcp allow / revoke")

func (s *Server) isPolicyFile(p string) bool {
	p = filepath.ToSlash(filepath.Clean(p))
	return p == filepath.ToSlash(filepath.Clean(s.configPath)) || p == defaultConfigPath
}
