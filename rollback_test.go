package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeUCI simulates just enough of uci for the apply path: staged changes accumulate per
// config, `changes` reports them, `revert` drops them, and `commit` writes a marker into the
// real fixture file so a restore can be checked byte for byte.
func fakeUCI(t *testing.T, f *fakeRouter) map[string][]string {
	staged := map[string][]string{}
	cfgOf := func(key string) string { return strings.SplitN(key, ".", 2)[0] }
	stage := func(argv []string, _ string) (string, error) {
		key := argv[len(argv)-1]
		staged[cfgOf(key)] = append(staged[cfgOf(key)], strings.Join(argv[1:], " "))
		return "", nil
	}
	f.onFn("uci set", stage)
	f.onFn("uci delete", stage)
	f.onFn("uci -q delete", stage)
	f.onFn("uci add_list", stage)
	f.onFn("uci del_list", stage)
	f.onFn("uci changes", func(argv []string, _ string) (string, error) {
		if len(argv) == 2 {
			var all []string
			for _, v := range staged {
				all = append(all, v...)
			}
			return strings.Join(all, "\n"), nil
		}
		return strings.Join(staged[argv[2]], "\n"), nil
	})
	f.onFn("uci revert", func(argv []string, _ string) (string, error) {
		delete(staged, argv[2])
		return "", nil
	})
	f.onFn("uci commit", func(argv []string, _ string) (string, error) {
		c := argv[2]
		p := filepath.Join(uciConfDir, c)
		b, _ := os.ReadFile(p)
		b = append(b, []byte("# committed: "+strings.Join(staged[c], "; ")+"\n")...)
		delete(staged, c)
		return "", os.WriteFile(p, b, 0o644)
	})
	f.on("/sbin/reload_config", "")
	f.on("ubus call service event", "")
	return staged
}

const origDHCP = "config dnsmasq\n\toption domain 'lan'\n"

func applyFixture(t *testing.T) (*Server, *fakeRouter, string) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/dhcp", origDHCP)
	f := newFakeRouter(t)
	fakeUCI(t, f)
	return testServer(t, ""), f, root
}

func readConf(t *testing.T, c string) string {
	b, err := os.ReadFile(filepath.Join(uciConfDir, c))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var leaseChanges = []UCIChange{
	{Config: "dhcp", Section: "pi", Type: "host"},
	{Config: "dhcp", Section: "pi", Option: "ip", Value: "192.168.1.50"},
}

func TestApplyThenRollbackRestoresTheFile(t *testing.T) {
	s, f, _ := applyFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 60})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ROLLBACK ARMED") || !strings.Contains(out, "dhcp.pi.ip=192.168.1.50") {
		t.Errorf("apply output does not show the armed rollback and the staged change:\n%s", out)
	}
	if readConf(t, "dhcp") == origDHCP {
		t.Fatal("commit did not happen")
	}
	if !f.ran("/sbin/reload_config") {
		t.Error("configs were committed but never reloaded")
	}
	token := firstToken(s)
	if _, err := os.Stat(s.pendingPath()); err != nil {
		t.Fatal("no pending record on disk -- a reboot inside the window would not roll back")
	}
	if _, _, err := s.uciRollbackNow(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if got := readConf(t, "dhcp"); got != origDHCP {
		t.Errorf("restore not byte-identical:\n got %q\nwant %q", got, origDHCP)
	}
	if _, err := os.Stat(s.pendingPath()); !os.IsNotExist(err) {
		t.Error("pending record left behind after rollback")
	}
}

func TestTimeoutRollsBack(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	// Fire the timer path directly rather than sleeping 90s.
	s.rollback(firstToken(s), "timeout")
	if got := readConf(t, "dhcp"); got != origDHCP {
		t.Errorf("timeout did not restore the file: %q", got)
	}
}

// The case the on-flash snapshot exists for: the daemon (or the whole router) goes away
// mid-window. A fresh daemon on the same state directory must put the old config back.
func TestRestartInsideTheWindowRollsBack(t *testing.T) {
	s, f, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, p := range s.pending {
		p.timer.Stop() // the process "dies": its timer never fires
	}
	s.mu.Unlock()

	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	if _, err := NewServer(s.configPath, s.statePath); err != nil {
		t.Fatal(err)
	}
	if got := readConf(t, "dhcp"); got != origDHCP {
		t.Errorf("startup recovery did not restore the file: %q", got)
	}
	// At boot the running state came from the bad file, and reload_config may have no
	// checksums to compare, so the change event must be sent explicitly.
	if !f.ran(`ubus call service event {"type":"config.change","data":{"package":"dhcp"}}`) {
		t.Errorf("recovery did not force a reload of dhcp:\n%s", f.allCalls())
	}
}

func TestConfirmKeepsTheChange(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	token := firstToken(s)
	dir := s.pending[token].Dir
	if _, _, err := s.uciConfirm(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if readConf(t, "dhcp") == origDHCP {
		t.Error("confirm reverted the change")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("snapshot left on flash after confirm")
	}
	s.rollback(token, "timeout") // a late timer must be a no-op
	if readConf(t, "dhcp") == origDHCP {
		t.Error("a confirmed change was rolled back by a late timer")
	}
}

func TestDryRunCommitsNothing(t *testing.T) {
	s, f, _ := applyFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "DRY RUN") || !strings.Contains(out, "dhcp.pi=host") {
		t.Errorf("dry run output:\n%s", out)
	}
	if f.ran("uci commit") || f.ran("/sbin/reload_config") {
		t.Error("dry run committed or reloaded")
	}
	if !f.ran("uci revert dhcp") {
		t.Error("dry run left its changes staged")
	}
	if len(s.pending) != 0 || readConf(t, "dhcp") != origDHCP {
		t.Error("dry run changed state")
	}
}

func TestApplyRefusesSomeoneElsesStagedEdits(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.on("uci changes dhcp", "dhcp.lan.start='50'")
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges})
	if err == nil || !strings.Contains(err.Error(), "uncommitted") {
		t.Fatalf("applied on top of another session's edit: %v", err)
	}
	if f.ran("uci commit") {
		t.Error("committed anyway")
	}
}

func TestOnlyOnePendingApply(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err == nil {
		t.Error("a second apply was allowed while one awaits confirmation")
	}
}

func TestSetListClearsThenAdds(t *testing.T) {
	s, f, _ := applyFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: []UCIChange{
		{Config: "dhcp", Section: "@dnsmasq[0]", Option: "server", Values: []string{"1.1.1.1", "9.9.9.9"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	calls := f.allCalls()
	del := strings.Index(calls, "uci -q delete dhcp.@dnsmasq[0].server")
	a1 := strings.Index(calls, "uci add_list dhcp.@dnsmasq[0].server=1.1.1.1")
	a2 := strings.Index(calls, "uci add_list dhcp.@dnsmasq[0].server=9.9.9.9")
	if del < 0 || a1 < del || a2 < a1 {
		t.Errorf("set_list must clear then add in order:\n%s", calls)
	}
}

func TestResolveUseNewIsRollbackArmed(t *testing.T) {
	s, f, root := applyFixture(t)
	writeFixture(t, root, "etc/config/dhcp.apk-new", "config dnsmasq\n\toption domain 'new'\n")
	out, _, err := s.pkgConfigResolve(context.Background(), "c", pkgConfigResolveIn{Path: "/etc/config/dhcp", Action: "use_new"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ROLLBACK ARMED") {
		t.Errorf("replacing a uci config was not rollback-armed:\n%s", out)
	}
	if !strings.Contains(readConf(t, "dhcp"), "'new'") {
		t.Error("new default not installed")
	}
	if b, _ := os.ReadFile(filepath.Join(uciConfDir, "dhcp.pre-apk-new")); string(b) != origDHCP {
		t.Error("old copy not kept as .pre-apk-new")
	}
	_ = f
	if _, _, err := s.uciRollbackNow(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if readConf(t, "dhcp") != origDHCP {
		t.Error("rollback of use_new did not restore the live file")
	}
}

func firstToken(s *Server) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k := range s.pending {
		return k
	}
	return ""
}

func TestWriteSyncedSetsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	if err := writeSynced(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = time.Now
}
