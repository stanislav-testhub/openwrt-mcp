package main

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests in rollback_test.go cover the path where everything works. These cover the one the
// feature exists for: something goes wrong halfway and the router must still be left as it was.

// waitFor polls cond until it holds or the deadline passes. A condition-based wait, not a sleep:
// the test proceeds the moment the behaviour is observed.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for: %s", within, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAnUnconfirmedChangeRevertsByItselfWhenTheTimerFires(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 1}); err != nil {
		t.Fatal(err)
	}
	if readConf(t, "dhcp") == origDHCP {
		t.Fatal("precondition: the change should be live")
	}
	// Nobody calls uci_confirm. The real timer (not a direct call to rollback) must undo it.
	// The poll reads while the daemon renames the restored file into place; on Windows that
	// read can fail with a sharing violation for an instant, which means "not yet", not "broken".
	waitFor(t, 6*time.Second, "the armed timer to restore dhcp", func() bool {
		b, err := os.ReadFile(filepath.Join(uciConfDir, "dhcp"))
		return err == nil && string(b) == origDHCP
	})
	waitFor(t, 2*time.Second, "the pending record to be cleared", func() bool {
		_, err := os.Stat(s.pendingPath())
		return os.IsNotExist(err)
	})
	// rollback() clears the pending record first and writes its audit entry last, so the entry
	// is waited for rather than read the instant the record disappears.
	waitFor(t, 2*time.Second, "the automatic rollback to be audited", func() bool {
		for _, ev := range auditEvents(t, s) {
			if ev.Client == "<system>" && ev.Tool == "uci_rollback" && ev.Outcome == OutcomeOK {
				return true
			}
		}
		return false
	})
}

func TestConfirmingStopsTheTimer(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciConfirm(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	// Outlive the 1 s window: a timer that was only forgotten, not stopped, would fire now.
	time.Sleep(1500 * time.Millisecond)
	if readConf(t, "dhcp") == origDHCP {
		t.Error("a confirmed change was undone when its original timer fired")
	}
}

func TestStagingFailureRevertsEverythingAndCommitsNothing(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.fail("uci set dhcp.pi.ip=192.168.1.50", "uci: Invalid argument")
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges})
	if err == nil || !strings.Contains(err.Error(), "staging dhcp.pi.ip failed") {
		t.Fatalf("err = %v", err)
	}
	if !f.ran("uci revert dhcp") {
		t.Error("half-staged changes were left for the next `uci commit` to pick up")
	}
	if f.ran("uci commit") || f.ran("/sbin/reload_config") {
		t.Error("a failed staging still committed or reloaded")
	}
	if len(s.pending) != 0 || readConf(t, "dhcp") != origDHCP {
		t.Error("state changed")
	}
}

func TestCommitFailureOnTheSecondConfigRestoresTheFirst(t *testing.T) {
	s, f, root := applyFixture(t)
	const origFW = "config defaults\n\toption input 'REJECT'\n"
	writeFixture(t, root, "etc/config/firewall", origFW)
	f.fail("uci commit firewall", "uci: Permission denied")

	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{
		{Config: "dhcp", Section: "pi", Type: "host"},
		{Config: "firewall", Section: "z", Type: "zone"},
	}})
	if err == nil || !strings.Contains(err.Error(), "commit firewall failed") {
		t.Fatalf("err = %v", err)
	}
	// dhcp commits first (alphabetical) and succeeded; it must not stay half-applied.
	if got := readConf(t, "dhcp"); got != origDHCP {
		t.Errorf("dhcp was left committed after firewall failed:\n%q", got)
	}
	if got := readConf(t, "firewall"); got != origFW {
		t.Errorf("firewall changed: %q", got)
	}
	if len(s.pending) != 0 {
		t.Error("a failed apply left a pending rollback armed")
	}
	if _, err := os.Stat(s.pendingPath()); !os.IsNotExist(err) {
		t.Error("a failed apply left a pending record on flash: the next start would roll back a change that never happened")
	}
}

func TestApplyRefusesBadRequestsBeforeTouchingUci(t *testing.T) {
	s, f, _ := applyFixture(t)
	ctx := context.Background()
	for name, in := range map[string]uciApplyIn{
		"no changes":       {},
		"unknown config":   {Changes: []UCIChange{{Config: "nosuch", Section: "x", Type: "t"}}},
		"invalid change":   {Changes: []UCIChange{{Config: "dhcp", Section: "x y", Option: "o", Value: "v"}}},
		"option as config": {Changes: []UCIChange{{Config: "-q", Section: "x", Option: "o", Value: "v"}}},
	} {
		if _, _, err := s.uciApply(ctx, "c", in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, c := range f.callList() {
		if strings.HasPrefix(c, "uci set") || strings.HasPrefix(c, "uci commit") {
			t.Errorf("a refused request still ran %q", c)
		}
	}
}

func TestAnApplyThatChangesNothingSaysSo(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.on("uci changes", "") // every value was already set
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, DryRun: true})
	if err != nil || !strings.Contains(out, "no effective change") {
		t.Errorf("%v\n%s", err, out)
	}
}

func TestConfirmAndRollbackOfAnUnknownTokenSayWhy(t *testing.T) {
	s := testServer(t, "")
	for name, fn := range map[string]func() error{
		"confirm":  func() error { _, _, err := s.uciConfirm(context.Background(), "nope"); return err },
		"rollback": func() error { _, _, err := s.uciRollbackNow(context.Background(), "nope"); return err },
	} {
		if err := fn(); err == nil || !strings.Contains(err.Error(), "no pending apply") {
			t.Errorf("%s of an unknown token: %v", name, err)
		}
	}
}

func TestReloadFailureIsReportedNotSwallowed(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.fail("/sbin/reload_config", "netifd: not running")
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "reload_config:") || !strings.Contains(out, "netifd: not running") {
		t.Errorf("a failed reload must be visible to the operator before they confirm:\n%s", out)
	}
	if !strings.Contains(out, "ROLLBACK ARMED") {
		t.Error("the rollback must stay armed when the reload fails")
	}
}

// ---------------------------------------------------------------- when the rollback itself fails

func breakSnapshot(t *testing.T, s *Server) (token, dir string) {
	t.Helper()
	token = firstToken(s)
	dir = s.pending[token].Dir
	if err := os.Remove(path.Join(dir, "dhcp")); err != nil {
		t.Fatal(err)
	}
	return token, dir
}

func TestAFailedManualRollbackKeepsTheSnapshotAndNamesIt(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	token, dir := breakSnapshot(t, s)
	_, _, err := s.uciRollbackNow(context.Background(), token)
	if err == nil || !strings.Contains(err.Error(), "ROLLBACK FAILED") || !strings.Contains(err.Error(), dir) {
		t.Errorf("the operator is not told where the snapshot is: %v", err)
	}
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Errorf("the snapshot directory was deleted although the restore failed: %v", statErr)
	}
}

func TestAFailedAutomaticRollbackIsAuditedAndNamesTheSnapshot(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	token, dir := breakSnapshot(t, s)
	s.rollback(token, "timeout")

	var last AuditEvent
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "uci_rollback" {
			last = ev
		}
	}
	if last.Outcome != OutcomeError || !strings.Contains(last.Summary, "ROLLBACK FAILED") {
		t.Fatalf("a failed automatic rollback is not recorded as an error: %+v", last)
	}
	// The explicit phrase, not just the path: the OS error text ("open <dir>/dhcp: ...") already
	// contains the directory, so a bare path check would pass without the operator being told.
	if !strings.Contains(last.Summary, "snapshot kept at "+dir) {
		t.Errorf("the audit entry does not say where the snapshot is kept:\n%s", last.Summary)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("snapshot gone: %v", err)
	}
}

func TestAFailedStartupRollbackIsAuditedAndKeepsTheSnapshot(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, p := range s.pending {
		p.timer.Stop() // the process "dies"
	}
	s.mu.Unlock()
	_, dir := breakSnapshot(t, s)

	s2, err := NewServer(s.configPath, s.statePath)
	if err != nil {
		t.Fatal(err)
	}
	var found AuditEvent
	for _, ev := range auditEvents(t, s2) {
		if strings.Contains(ev.Summary, "at startup") {
			found = ev
		}
	}
	if found.Outcome != OutcomeError || !strings.Contains(found.Summary, "ROLLBACK FAILED at startup") ||
		!strings.Contains(found.Summary, "snapshot kept at "+dir) {
		t.Errorf("startup rollback failure: %+v", found)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("snapshot gone after a failed startup rollback: %v", err)
	}
}

func TestACorruptPendingFileMakesStartupTouchNothing(t *testing.T) {
	s, _, _ := applyFixture(t)
	if err := os.MkdirAll(s.statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.pendingPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readConf(t, "dhcp")
	if _, err := NewServer(s.configPath, s.statePath); err != nil {
		t.Fatalf("a corrupt pending file must not stop the daemon from starting: %v", err)
	}
	if readConf(t, "dhcp") != before {
		t.Error("startup modified a config on the strength of a file it could not read")
	}
	if b, err := os.ReadFile(s.pendingPath()); err != nil || string(b) != "{not json" {
		t.Errorf("the corrupt file must be left for the operator: %v %q", err, b)
	}
}

func TestRestoreDeletesAConfigThatDidNotExistBeforeTheChange(t *testing.T) {
	s, _, root := applyFixture(t)
	writeFixture(t, root, "etc/config/brandnew", "config x\n")
	p := &pendingApply{Token: "t", Dir: filepath.Join(t.TempDir(), "snap"), Configs: []string{"brandnew"},
		Missing: []string{"brandnew"}, Modes: map[string]uint32{}}
	if err := s.restore(context.Background(), p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(uciConfDir, "brandnew")); !os.IsNotExist(err) {
		t.Error("a config created by the change survived its own rollback")
	}
}

func TestRestoreKeepsTheOriginalFileMode(t *testing.T) {
	s, _, _ := applyFixture(t)
	dir := filepath.Join(t.TempDir(), "snap")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dhcp"), []byte("snapshot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &pendingApply{Token: "t", Dir: dir, Configs: []string{"dhcp"}, Modes: map[string]uint32{"dhcp": 0o600}}
	if err := s.restore(context.Background(), p, false); err != nil {
		t.Fatal(err)
	}
	if got := readConf(t, "dhcp"); got != "snapshot\n" {
		t.Errorf("content %q", got)
	}
	if st, _ := os.Stat(filepath.Join(uciConfDir, "dhcp")); st.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("mode %o: a private config (Wi-Fi keys) came back group/world readable", st.Mode().Perm())
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }

func TestWriteSyncedReportsAnUnwritableTarget(t *testing.T) {
	err := writeSynced(filepath.Join(t.TempDir(), "missing-dir", "f"), []byte("x"), 0o600)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v", err)
	}
}
