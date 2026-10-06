package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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

// A config's revision is the first 12 hex digits of the sha256 of its committed file. The
// literal is the digest of origDHCP computed outside the code under test.
const origDHCPRevision = "707f2b1ba4b6"

func TestUciGetPrintsTheRevisionOfTheWholeConfig(t *testing.T) {
	_, f, _ := applyFixture(t)
	f.on("uci show dhcp.lan", "dhcp.lan=dhcp\ndhcp.lan.start='100'")
	out, _, err := uciGet(context.Background(), uciGetIn{Config: "dhcp", Section: "lan"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "\n# revision of dhcp: "+origDHCPRevision) {
		t.Errorf("a section read must still end with the whole config's revision:\n%s", out)
	}
}

func TestApplyRefusesAStaleRevisionBeforeStagingAnything(t *testing.T) {
	s, f, _ := applyFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges,
		ExpectedRevisions: map[string]string{"dhcp": "000000000000"}})
	if err == nil || !strings.HasPrefix(err.Error(), "CONFLICT: dhcp changed") ||
		!strings.Contains(err.Error(), origDHCPRevision) || !strings.Contains(err.Error(), "uci_get") {
		t.Fatalf("want a CONFLICT naming the config, the current revision and uci_get, got %v", err)
	}
	if f.ran("uci set") || f.ran("uci commit") {
		t.Errorf("a refused apply touched uci:\n%s", f.allCalls())
	}
	if readConf(t, "dhcp") != origDHCP || s.pendingSummary() != "" {
		t.Error("a refused apply changed the file or armed a rollback")
	}
}

func TestApplyRefusesAStaleRevisionOnADryRunToo(t *testing.T) {
	s, _, _ := applyFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: leaseChanges,
		ExpectedRevisions: map[string]string{"dhcp": "000000000000"}})
	if err == nil || !strings.HasPrefix(err.Error(), "CONFLICT") {
		t.Fatalf("a dry run must not bless a stale revision, got %v", err)
	}
}

// What a dry run prints is what the next call can pass, and what an apply prints is what uci_get
// will show afterwards, so calls chain without a read in between.
func TestRevisionsChainFromDryRunToApplyToGet(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.on("uci show dhcp", "")
	dry, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: leaseChanges,
		ExpectedRevisions: map[string]string{"dhcp": origDHCPRevision}})
	if err != nil || !strings.Contains(dry, "expected_revisions") || !strings.Contains(dry, "dhcp="+origDHCPRevision) {
		t.Fatalf("dry run with the current revision: err=%v\n%s", err, dry)
	}
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges,
		ExpectedRevisions: map[string]string{"dhcp": origDHCPRevision}})
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(out, "Revision after apply: dhcp=")
	if !ok || len(after) < 12 || after[:12] == origDHCPRevision {
		t.Fatalf("the apply must print the new revision, which differs from the old one:\n%s", out)
	}
	got, _, err := uciGet(context.Background(), uciGetIn{Config: "dhcp"})
	if err != nil || !strings.HasSuffix(got, "# revision of dhcp: "+after[:12]) {
		t.Errorf("uci_get after the apply does not show the revision the apply printed (%v):\n%s", err, got)
	}
}

func TestExpectedRevisionsMustNameAChangedConfigAndLookLikeARevision(t *testing.T) {
	s, f, root := applyFixture(t)
	writeFixture(t, root, "etc/config/firewall", "config zone\n")
	fwRev, _ := configRevision("firewall") // a real, current revision of a config the call does not change
	for name, tc := range map[string]struct {
		exp  map[string]string
		want string
	}{
		"config not in the changes":               {map[string]string{"firewall": origDHCPRevision}, "does not change"},
		"current revision of an unchanged config": {map[string]string{"firewall": fwRev}, "does not change"},
		"typo in the config name":                 {map[string]string{"dhpc": origDHCPRevision}, "does not change"},
		"not hex":                                 {map[string]string{"dhcp": "not-a-revision"}, "not a revision"},
		"too short":                               {map[string]string{"dhcp": "707f2b"}, "not a revision"},
		"empty":                                   {map[string]string{"dhcp": ""}, "not a revision"},
	} {
		_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: leaseChanges, ExpectedRevisions: tc.exp})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error saying %q, got %v", name, tc.want, err)
		}
	}
	if f.ran("uci set") {
		t.Error("input validation must come before staging")
	}
}

// libuci's add_list appends even when the element is already there (verified on the router:
// 'p' becomes 'p' 'p'), so the server reads the list first. Staged edits count, so the same
// element twice in one batch is added once.
func TestAddListSkipsAnElementThatIsAlreadyThere(t *testing.T) {
	s, f, _ := applyFixture(t)
	var list []string
	f.onFn("uci add_list", func(argv []string, _ string) (string, error) {
		_, v, _ := strings.Cut(argv[len(argv)-1], "=")
		list = append(list, v)
		return "", nil
	})
	f.onFn("uci -q show dhcp.lan.server", func([]string, string) (string, error) {
		if len(list) == 0 {
			return "", errors.New("exit status 1") // uci -q show of a missing option
		}
		return "dhcp.lan.server='" + strings.Join(list, "' '") + "'", nil
	})
	f.on("uci -q show dhcp.lan.dns", "dhcp.lan.dns='1.1.1.1' '9.9.9.9' '11.2.3.45'")
	add := func(opt, v string) UCIChange {
		return UCIChange{Op: "add_list", Config: "dhcp", Section: "lan", Option: opt, Value: v}
	}
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: []UCIChange{
		add("dns", "1.1.1.1"), add("dns", "8.8.8.8"), add("dns", "1.2.3.4"), // 1.2.3.4 is inside 11.2.3.45, not an element
		add("server", "a"), add("server", "a"), add("server", "b"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, a := range f.argvList() {
		if len(a) > 1 && a[1] == "add_list" {
			added = append(added, a[2])
		}
	}
	want := "dhcp.lan.dns=8.8.8.8,dhcp.lan.dns=1.2.3.4,dhcp.lan.server=a,dhcp.lan.server=b"
	if got := strings.Join(added, ","); got != want {
		t.Errorf("add_list commands = %s, want %s", got, want)
	}
	for _, skipped := range []string{"dhcp.lan.dns=1.1.1.1", "dhcp.lan.server=a"} {
		if !strings.Contains(out, "already present, skipped") || !strings.Contains(out, skipped) {
			t.Errorf("result does not say %s was skipped:\n%s", skipped, out)
		}
	}
}

// del_list of an element that is not there already succeeds in libuci (verified on the
// router), so it is passed straight through with no read first.
func TestDelListIsPassedThroughWithoutARead(t *testing.T) {
	s, f, _ := applyFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Changes: []UCIChange{
		{Op: "del_list", Config: "dhcp", Section: "lan", Option: "dns", Value: "9.9.9.9"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !f.ran("uci del_list dhcp.lan.dns=9.9.9.9") || f.ran("uci -q show") {
		t.Errorf("del_list should run once and unread:\n%s", f.allCalls())
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
	s, _, root := applyFixture(t)
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

func TestWriteSyncedWritesTheContentAndTheRequestedMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x")
	// Write over an existing wider file: the mode must end up as asked, not inherited.
	if err := os.WriteFile(p, []byte("old content that is longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "a" {
		t.Errorf("content %q: the old file was not truncated", b)
	}
	if st, _ := os.Stat(p); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // Windows has no unix modes
		t.Errorf("mode %o, want 600", st.Mode().Perm())
	}
}

// A client with uci_apply on '*' must not be able to grant itself more through the policy file.
func TestApplyRefusesPolicyFile(t *testing.T) {
	s := testServer(t, "")
	old := uciConfDir
	defer func() { uciConfDir = old }()
	for _, dir := range []string{"/etc/config", filepath.Dir(s.configPath)} {
		uciConfDir = dir
		_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: []UCIChange{
			{Config: "openwrt-mcp", Section: "p", Type: "policy"},
			{Config: "openwrt-mcp", Section: "p", Option: "tools", Op: "add_list", Value: "exec"},
		}, DryRun: true})
		if err != errPolicyFile {
			t.Errorf("uciConfDir=%s: want errPolicyFile, got %v", dir, err)
		}
	}
}
