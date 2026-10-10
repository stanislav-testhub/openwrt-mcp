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
	"sync"
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
	Renew    []string          `json:"renew,omitempty"` // interfaces netifd is asked to renew after a restore (WireGuard peers)
	Files    []string          `json:"files,omitempty"` // client configs deleted when it is rolled back: they hold the key of a peer that goes

	timer *time.Timer
}

type uciApplyIn struct {
	Changes []UCIChange `json:"changes,omitempty" jsonschema:"the UCI changes to make, applied in order and committed together. Omit when restoring"`
	Timeout int         `json:"timeout,omitempty" jsonschema:"seconds before automatic rollback if uci_confirm is not called (default 90, max 600)"`
	DryRun  bool        `json:"dry_run,omitempty" jsonschema:"stage the changes, report exactly what uci would change, then revert. Nothing is committed or reloaded."`

	Force bool `json:"force,omitempty" jsonschema:"apply even though validation found NEW problems, or the change touches the management path and no probe is given. Only after reading why; the rollback timer still applies"`

	Probe     []probeSpec `json:"probe,omitempty" jsonschema:"checks run after the reload, each retried until it passes or probe_wait runs out: {kind: ping|resolve, target, server?}, at most 5. Needed when the change touches the management path (LAN interface or bridge, SSH listener, the zone and rule that let SSH in)"`
	ProbeWait int         `json:"probe_wait,omitempty" jsonschema:"seconds each probe may keep retrying (default 15, max 60)"`

	ExpectedRevisions map[string]string `json:"expected_revisions,omitempty" jsonschema:"config name -> the revision uci_get printed for it. If that config changed since (LuCI, another client) the call is refused with CONFLICT instead of overwriting it"`

	Restore string `json:"restore,omitempty" jsonschema:"put a past version of one config back instead of making changes: an id from uci_get history=list. Same rollback-armed apply; give no changes"`
}

type uciTokenIn struct {
	Token string `json:"token" jsonschema:"the token returned by uci_apply"`
}

// uciConfDir is /etc/config on the router and a fixture directory in tests.
var uciConfDir = "/etc/config"

func (s *Server) pendingPath() string  { return pendingPath(s.statePath) }
func (s *Server) snapshotRoot() string { return rollbackDir(s.statePath) }

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
	if in.Restore != "" {
		return s.uciRestore(ctx, client, in)
	}
	if len(in.Changes) == 0 {
		return "", "", invalid("changes must not be empty")
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
			return "", "", notFound("no such UCI config %q", c)
		}
		names = append(names, c)
	}
	sort.Strings(names)
	if err := validateExpectedRevisions(in.ExpectedRevisions, names); err != nil {
		return "", "", err
	}
	if err := validateProbes(in.Probe); err != nil {
		return "", "", err
	}

	// One staging operation at a time: uci's staging area (/tmp/.uci) is shared. Probes wait on
	// the network, so the lock is dropped before they run.
	s.applyMu.Lock()
	unlock := sync.OnceFunc(s.applyMu.Unlock)
	defer unlock()

	if err := s.preflight(ctx, names, in); err != nil {
		return "", "", err
	}

	revertAll := func() {
		for _, c := range names {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
		}
	}
	mgmt := mgmtReasons(ctx, in.Changes)
	var live *advice // the live state, for the dry run to compare the staged one with
	if in.DryRun && warnsOn(in.Changes) {
		live = takeAdvice(ctx)
	}
	baseline := checkAll(ctx, names)
	var skipped []string
	for _, c := range in.Changes {
		if c.op() == opAddList && listHas(ctx, uciKey(c), c.Value) {
			skipped = append(skipped, uciKey(c)+"="+c.Value)
			continue
		}
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
	if len(skipped) > 0 {
		staged += "\n(already present, skipped: " + strings.Join(skipped, ", ") + ")"
	}

	report, fresh := validationReport(names, baseline, checkAll(ctx, names))

	if in.DryRun {
		warnings := live.report(ctx)
		revertAll()
		return fmt.Sprintf("DRY RUN -- nothing was committed. uci would change:\n%s\n\n%s\n\n%s%s"+
				"Call uci_apply again without dry_run to apply this with a rollback timer. To refuse the apply "+
				"if a config changes first, pass expected_revisions with: %s", staged, report, mgmtNote(mgmt), warnings, revisionList(names)),
			fmt.Sprintf("dry run of %d change(s)", len(in.Changes)), nil
	}
	if fresh != "" && !in.Force {
		revertAll()
		return "", "", invalid("refusing to apply: validation found new problems, so the service would ignore or "+
			"reject part of this change. Nothing was committed.\n%s\nFix the change, or pass force=true to apply it anyway", fresh)
	}

	if err := mgmtGate(mgmt, in); err != nil {
		revertAll()
		return "", "", err
	}

	timeout := clampSec(in.Timeout, applyDefaultSec(mgmt), 600)
	p, err := s.snapshot(names, client, fmt.Sprintf("%d uci change(s)", len(in.Changes)), timeout)
	if err != nil {
		revertAll()
		return "", "", err
	}
	if err := s.commitArmed(ctx, p, names, timeout); err != nil {
		return "", "", err
	}
	// Read back before any service is reloaded: a commit that kept something else must not be
	// loaded by the daemons. The rollback stays armed, so the operator can undo what did land.
	mismatches, verified := verifyApplied(ctx, names, in.Changes)
	if len(mismatches) > 0 {
		return "", "", notApplied("committed %s, but re-reading it does not show what was asked for. "+
			"Nothing was reloaded:\n  %s\n\nThe rollback is still armed: it restores the previous config at %s, "+
			"or undo it now with uci_rollback {\"token\": \"%s\"}. Do not confirm.",
			strings.Join(names, ", "), strings.Join(mismatches, "\n  "), p.Deadline.Format(time.RFC3339), p.Token)
	}
	if verified != "" {
		verified += "\n\n"
	}
	reloadOut := reloadConfigs(ctx, names, false)

	unlock()
	msg := fmt.Sprintf("Applied to %s and reloaded. Changes:\n%s\n\n%s\n\n%s%s\nRevision after apply: %s%s",
		strings.Join(names, ", "), staged, report, verified, armedNotice(p, timeout), revisionList(names), indentOut(reloadOut))
	return msg + probeSection(ctx, in, timeout), fmt.Sprintf("applied %d change(s) to %s, rollback armed %s",
		len(in.Changes), strings.Join(names, ","), timeout), nil
}

// mgmtNote is the dry-run paragraph about the management path, with its trailing blank line.
func mgmtNote(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return "management path: this change touches it (" + strings.Join(reasons, "; ") + "). A real apply needs probe " +
		"entries that prove the router is still reachable (ping the gateway, resolve a name), or force=true; its " +
		fmt.Sprintf("rollback window then defaults to %ds.\n\n", mgmtRollbackSec)
}

// mgmtGate refuses a change to the management path that names no probe, unless forced.
func mgmtGate(reasons []string, in uciApplyIn) error {
	if len(reasons) == 0 || len(in.Probe) > 0 || in.Force {
		return nil
	}
	return invalid("refusing to apply: this change touches the management path (%s), and a bad one would cut the "+
		"session that has to confirm it. Nothing was committed. Pass probe entries that prove the router is still "+
		"reachable afterwards (for example ping its gateway and resolve a name), or force=true", strings.Join(reasons, "; "))
}

func applyDefaultSec(mgmt []string) int {
	if len(mgmt) > 0 {
		return mgmtRollbackSec
	}
	return 90
}

// probeSection runs the probes, if any, and returns the paragraph to append to the result.
// They get at most half the rollback window; the caller has released the staging lock.
func probeSection(ctx context.Context, in uciApplyIn, timeout time.Duration) string {
	if len(in.Probe) == 0 {
		return ""
	}
	text, _ := runProbes(ctx, in.Probe, probeWait(in.ProbeWait), timeout/2)
	return "\n\n" + text
}

// preflight is what every apply needs to be true before it stages or replaces anything.
// The caller holds applyMu.
func (s *Server) preflight(ctx context.Context, names []string, in uciApplyIn) error {
	if !in.DryRun {
		if p := s.pendingSummary(); p != "" {
			return pending("an apply is already pending confirmation: %s\n"+
				"call uci_confirm or uci_rollback first", p)
		}
	}
	for _, c := range names {
		if out, err := uncommitted(ctx, c); err == nil && out != "" {
			return conflict("refusing to apply: %s already has uncommitted changes "+
				"(someone else's edit in progress):\n%s", c, out)
		}
	}
	return checkRevisions(in.ExpectedRevisions)
}

func armedNotice(p *pendingApply, timeout time.Duration) string {
	return fmt.Sprintf("ROLLBACK ARMED: reverts automatically at %s (in %s) unless you call\n"+
		"  uci_confirm {\"token\": \"%s\"}\n"+
		"or undo it now with uci_rollback. The snapshot is on flash, so a reboot inside the\n"+
		"window also rolls back.\n\nVerify the router is still reachable and behaving BEFORE confirming.",
		p.Deadline.Format(time.RFC3339), timeout, p.Token)
}

// uciRestore is uci_apply restore=<id>: a past version of one config put back through the same
// pipeline as any apply. uci import cannot stage it (measured on the router: it writes the file
// at once), so the file is replaced like pkg_config_resolve does, and the checkers run on the
// installed file before anything reloads.
func (s *Server) uciRestore(ctx context.Context, client string, in uciApplyIn) (string, string, error) {
	if len(in.Changes) > 0 {
		return "", "", fmt.Errorf("restore replaces a whole config: give restore or changes, not both")
	}
	config, _, err := parseHistoryID(in.Restore)
	if err != nil {
		return "", "", err
	}
	if s.isPolicyFile(filepath.Join(uciConfDir, config)) {
		return "", "", errPolicyFile
	}
	names := []string{config}
	if err := validateExpectedRevisions(in.ExpectedRevisions, names); err != nil {
		return "", "", err
	}
	if err := validateProbes(in.Probe); err != nil {
		return "", "", err
	}
	e, body, err := s.loadHistory(in.Restore)
	if err != nil {
		return "", "", err
	}

	s.applyMu.Lock()
	unlock := sync.OnceFunc(s.applyMu.Unlock)
	defer unlock()
	if err := s.preflight(ctx, names, in); err != nil {
		return "", "", err
	}
	var mgmt []string
	if mgmtConfigs[config] {
		mgmt = []string{"restoring " + config + " replaces the whole config, which carries the management path"}
	}
	cur, _ := os.ReadFile(filepath.Join(uciConfDir, config))
	diff := fmt.Sprintf("--- current  +++ %s\n%s", in.Restore, settingsDiff(ctx, config, string(cur), string(body)))
	if in.DryRun {
		return fmt.Sprintf("DRY RUN -- nothing was changed. Restoring %s would change:\n%s\n\n"+
				"%sValidation runs on a real restore, before the reload. Call uci_apply again without dry_run to restore "+
				"with a rollback timer. To refuse it if the config changes first, pass expected_revisions with: %s",
				config, diff, mgmtNote(mgmt), revisionList(names)),
			"dry run of restore " + in.Restore, nil
	}

	if err := mgmtGate(mgmt, in); err != nil {
		return "", "", err
	}
	baseline := checkAll(ctx, names)
	timeout := clampSec(in.Timeout, applyDefaultSec(mgmt), 600)
	p, err := s.snapshot(names, client, "restoring "+config+" to "+in.Restore, timeout)
	if err != nil {
		return "", "", err
	}
	s.arm(p, timeout)
	undo := func(why error) (string, string, error) {
		var rerr error
		if s.take(p.Token) != nil {
			rerr = s.restore(ctx, p, false)
			s.savePending()
		}
		return "", "", fmt.Errorf("%w (restore of the previous version: %v)", why, rerr)
	}
	mode := os.FileMode(e.Mode)
	if mode == 0 {
		mode = 0o644
	}
	if err := installConfig(config, body, mode); err != nil {
		return undo(fmt.Errorf("installing %s failed: %w", config, err))
	}
	report, fresh := validationReport(names, baseline, checkAll(ctx, names))
	if fresh != "" && !in.Force {
		return undo(invalid("refusing to restore: validation found new problems, so the service would ignore or "+
			"reject part of that version. Nothing was reloaded and the current version is back.\n%s\n"+
			"Pass force=true to restore it anyway", fresh))
	}
	reloadOut := reloadConfigs(ctx, names, false)
	unlock()
	msg := fmt.Sprintf("Restored %s from %s and reloaded. Changes:\n%s\n\n%s\n\n%s\nRevision after apply: %s%s",
		config, in.Restore, diff, report, armedNotice(p, timeout), revisionList(names), indentOut(reloadOut))
	return msg + probeSection(ctx, in, timeout),
		fmt.Sprintf("restored %s from %s, rollback armed %s", config, in.Restore, timeout), nil
}

// installConfig atomically replaces /etc/config/<name> with body.
func installConfig(name string, body []byte, mode os.FileMode) error {
	tmp := filepath.Join(uciConfDir, "."+name+".openwrt-mcp-restore")
	if err := writeSynced(tmp, body, mode); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(uciConfDir, name))
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

// commitArmed arms the rollback of a snapshotted change, then commits the staged configs. Armed
// before the commit, so there is no instant at which a committed change exists without a pending
// record on flash to undo it. A commit that fails puts the snapshot back at once.
func (s *Server) commitArmed(ctx context.Context, p *pendingApply, names []string, timeout time.Duration) error {
	s.arm(p, timeout)
	for _, c := range names {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", c); err != nil {
			var rerr error
			if s.take(p.Token) != nil {
				rerr = s.restore(ctx, p, false)
				s.savePending()
			}
			return fmt.Errorf("commit %s failed: %w\n%s (restore: %v)", c, err, out, rerr)
		}
	}
	return nil
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
	s.promoteHistory(p)
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
		if err := installConfig(c, b, mode); err != nil {
			failed = append(failed, c+": "+err.Error())
		}
	}
	for _, c := range p.Configs {
		_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
	}
	reloadConfigs(ctx, p.Configs, atBoot)
	if !atBoot { // at boot the interfaces come up from the restored file
		for _, iface := range p.Renew {
			_ = renewInterface(ctx, iface)
		}
	}
	for _, f := range p.Files {
		s.removeClientFile(f)
	}
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

// renewInterface asks netifd to run the protocol handler's renew action. For WireGuard that syncs
// the peers from the config without taking the interface down. The name comes from our own state
// file but goes into an argv, so it must still be a UCI name.
func renewInterface(ctx context.Context, iface string) error {
	if !reUCIOption.MatchString(iface) {
		return fmt.Errorf("bad interface name %q", iface)
	}
	if out, err := run(ctx, defaultCmdTimeout, "ubus", "call", "network.interface."+iface, "renew"); err != nil {
		return fmt.Errorf("renewing %s: %w %s", iface, err, strings.TrimSpace(out))
	}
	return nil
}

// removeClientFile deletes a client config named in a pending record, if it is one: a record the
// daemon wrote can only name a .conf file in the directory wg_new_client leaves them in.
func (s *Server) removeClientFile(name string) {
	if path.Dir(name) == wgClientDir(s.cfg()) && strings.HasSuffix(name, ".conf") {
		_ = os.Remove(sysPath(name))
	}
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
