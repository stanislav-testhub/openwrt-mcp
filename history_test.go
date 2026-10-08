package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// historyClock gives every entry its own millisecond, in call order, so "newest first" is
// deterministic.
func historyClock(t *testing.T) {
	t.Helper()
	n := 0
	historyNow = func() time.Time { n++; return time.Date(2026, 10, 7, 10, 0, 0, n*int(time.Millisecond), time.UTC) }
	t.Cleanup(func() { historyNow = time.Now })
}

// plainUCIShow stands in for `uci show` over a private copy (what uciNormalised runs): one
// trimmed line per non-empty line of the copy, so any difference in the file shows in the diff.
func plainUCIShow(f *fakeRouter) {
	f.onFn("uci -q -c", func(argv []string, _ string) (string, error) {
		b, err := os.ReadFile(filepath.Join(filepath.FromSlash(argv[3]), argv[len(argv)-1]))
		var out []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n"), err
	})
}

// applyAndConfirm makes one confirmed change to dhcp and returns the history id it created.
func applyAndConfirm(t *testing.T, s *Server, in uciApplyIn) {
	t.Helper()
	if _, _, err := s.uciApply(context.Background(), "c", in); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciConfirm(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
}

func historyIDs(t *testing.T, s *Server, config string) []string {
	t.Helper()
	var ids []string
	for _, e := range s.historyEntries(config) {
		ids = append(ids, e.id())
	}
	return ids
}

func TestConfirmKeepsThePreChangeVersionAndRollbackKeepsNothing(t *testing.T) {
	historyClock(t)
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciRollbackNow(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if ids := historyIDs(t, s, "dhcp"); len(ids) != 0 {
		t.Fatalf("a rolled-back change left history behind: %v", ids)
	}

	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	es := s.historyEntries("dhcp")
	if len(es) != 1 {
		t.Fatalf("a confirmed change must leave one entry, got %d", len(es))
	}
	b, err := os.ReadFile(filepath.Join(s.historyPath("dhcp"), es[0].Stamp))
	if err != nil || string(b) != origDHCP {
		t.Errorf("the entry must hold the config as it was BEFORE the change: %q (%v)", b, err)
	}
	if es[0].Client != "c" || es[0].What != "2 uci change(s)" || es[0].Config != "dhcp" {
		t.Errorf("entry metadata = %+v", es[0])
	}
}

func TestHistoryKeepsOnlyTheNewestN(t *testing.T) {
	historyClock(t)
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/dhcp", origDHCP)
	fakeUCI(t, newFakeRouter(t))
	s := testServer(t, "\toption history_keep '2'\n")
	var want []string
	for i := 0; i < 4; i++ {
		applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
		want = append(historyIDs(t, s, "dhcp")[:1], want...) // newest first
	}
	got := historyIDs(t, s, "dhcp")
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("kept %v, want the newest two %v", got, want[:2])
	}
	files, _ := os.ReadDir(s.historyPath("dhcp"))
	if len(files) != 4 { // two entries, each a file and a .json sidecar
		t.Errorf("%d files on disk, want 2 entries x 2 files: pruned entries must take their sidecar along", len(files))
	}
}

func TestHistoryKeepZeroTurnsHistoryOff(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/dhcp", origDHCP)
	fakeUCI(t, newFakeRouter(t))
	s := testServer(t, "\toption history_keep '0'\n")
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	if ids := historyIDs(t, s, "dhcp"); len(ids) != 0 {
		t.Errorf("history_keep 0 still recorded %v", ids)
	}
	if _, err := os.Stat(historyDir(s.statePath)); err == nil {
		t.Error("history_keep 0 still created the directory")
	}
}

func TestHistoryFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on Windows; CI runs this on Linux")
	}
	historyClock(t)
	s, _, _ := applyFixture(t)
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	e := s.historyEntries("dhcp")[0]
	for p, want := range map[string]os.FileMode{
		historyDir(s.statePath):                               0o700,
		s.historyPath("dhcp"):                                 0o700,
		filepath.Join(s.historyPath("dhcp"), e.Stamp):         0o600,
		filepath.Join(s.historyPath("dhcp"), e.Stamp+".json"): 0o600,
	} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s mode = %v (%v), want %v: it holds secrets", p, st.Mode().Perm(), err, want)
		}
	}
}

func TestHistoryListAndDiff(t *testing.T) {
	historyClock(t)
	s, f, _ := applyFixture(t)
	plainUCIShow(f)
	out, _, err := s.uciHistory(context.Background(), uciGetIn{Config: "dhcp", History: "list"})
	if err != nil || !strings.Contains(out, "no confirmed change") {
		t.Fatalf("empty history: %v\n%s", err, out)
	}
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	id := historyIDs(t, s, "dhcp")[0]

	out, _, err = s.uciHistory(context.Background(), uciGetIn{Config: "dhcp", History: "list"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{id, "c", "2 uci change(s)", "2026-10-07T10:00:00Z", "restore=<id>"} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not show %q:\n%s", want, out)
		}
	}

	out, _, err = s.uciHistory(context.Background(), uciGetIn{Config: "dhcp", History: "diff:" + id})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, id) || !strings.Contains(out, "+# committed:") {
		t.Errorf("diff must show what the change added since that version:\n%s", out)
	}
	if !f.ran("uci -q -c") || strings.Contains(f.allCalls(), "/tmp/.uci") {
		t.Errorf("the diff must be built from private copies, not the shared staging area:\n%s", f.allCalls())
	}
}

func TestHistoryRequestsAreValidated(t *testing.T) {
	s, f, _ := applyFixture(t)
	historyClock(t)
	for name, in := range map[string]uciGetIn{
		"unknown mode":       {Config: "dhcp", History: "show"},
		"with a section":     {Config: "dhcp", Section: "lan", History: "list"},
		"with an option":     {Config: "dhcp", Section: "lan", Option: "x", History: "list"},
		"with ids":           {Config: "dhcp", History: "list", IDs: true},
		"malformed id":       {Config: "dhcp", History: "diff:dhcp:../../etc/shadow"},
		"id without a stamp": {Config: "dhcp", History: "diff:dhcp"},
		"no such entry":      {Config: "dhcp", History: "diff:dhcp:20261007-100000.001-abcdef12"},
	} {
		if _, _, err := s.uciHistory(context.Background(), in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f.noCalls(t, "a rejected history request")

	// An entry that exists for another config must not be served under this config's grant: the
	// scope of the read is the config named in the call, not the one in the id.
	s.saveHistory("network", []byte("config interface 'lan'\n"), 0o644, "c", "test", "seed")
	other := s.historyEntries("network")[0].id()
	if out, _, err := s.uciHistory(context.Background(), uciGetIn{Config: "dhcp", History: "diff:" + other}); err == nil ||
		!strings.Contains(err.Error(), "not dhcp") {
		t.Errorf("a version of network was served for dhcp: %v\n%s", err, out)
	}
}

func TestParseHistoryID(t *testing.T) {
	for id, want := range map[string]string{
		"dhcp:20261007-100000.001-abcdef12":            "dhcp|20261007-100000.001-abcdef12",
		"luci_statistics:20261231-235959.999-00ff00ff": "luci_statistics|20261231-235959.999-00ff00ff",
		"":                                       "",
		"dhcp":                                   "",
		"dhcp:":                                  "",
		":20261007-100000.001-abcdef12":          "",
		"../x:20261007-100000.001-abcdef12":      "",
		"dhcp:../20261007-100000.001-abcdef12":   "",
		"dhcp:20261007-100000.001-ABCDEF12":      "", // lower-case hex only
		"dhcp:20261007-100000.001-abcdef12.json": "", // the sidecar is not an entry
		"dhcp:20261007-100000.001-abcdef12\n":    "",
		"-x:20261007-100000.001-abcdef12":        "", // a config name never starts with '-'
	} {
		c, stamp, err := parseHistoryID(id)
		got := ""
		if err == nil {
			got = c + "|" + stamp
		}
		if got != want {
			t.Errorf("parseHistoryID(%q) = %q (%v), want %q", id, got, err, want)
		}
	}
}

func TestRestoreIsAnOrdinaryRollbackArmedApply(t *testing.T) {
	historyClock(t)
	s, f, _ := applyFixture(t)
	plainUCIShow(f)
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	id := historyIDs(t, s, "dhcp")[0]
	changed := readConf(t, "dhcp")

	dry, _, err := s.uciApply(context.Background(), "c", uciApplyIn{DryRun: true, Restore: id})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dry, "DRY RUN") || !strings.Contains(dry, "-# committed:") || readConf(t, "dhcp") != changed {
		t.Errorf("a restore dry run shows the diff and touches nothing:\n%s", dry)
	}

	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Restore: id})
	if err != nil {
		t.Fatal(err)
	}
	if got := readConf(t, "dhcp"); got != origDHCP {
		t.Errorf("restore did not put the history version back: %q", got)
	}
	for _, want := range []string{id, "ROLLBACK ARMED", "not checked", "Revision after apply: dhcp=" + origDHCPRevision} {
		if !strings.Contains(out, want) {
			t.Errorf("restore result lacks %q:\n%s", want, out)
		}
	}
	if !f.ran("/sbin/reload_config") {
		t.Error("restored but never reloaded")
	}

	// Not confirmed: the timer puts the pre-restore version back, like any apply.
	if _, _, err := s.uciRollbackNow(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if readConf(t, "dhcp") != changed {
		t.Error("rolling back a restore did not bring back the version it replaced")
	}

	// Confirmed: what it replaced becomes history too.
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Restore: id}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciConfirm(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if n := len(historyIDs(t, s, "dhcp")); n != 2 {
		t.Errorf("%d entries after a confirmed restore, want 2 (the original change and the restore)", n)
	}
}

func TestRestoreRefusals(t *testing.T) {
	historyClock(t)
	s, f, _ := applyFixture(t)
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	id := historyIDs(t, s, "dhcp")[0]
	before := readConf(t, "dhcp")
	reloads := strings.Count(f.allCalls(), "/sbin/reload_config")
	ctx := context.Background()

	for name, in := range map[string]uciApplyIn{
		"with changes":        {Restore: id, Changes: leaseChanges},
		"malformed id":        {Restore: "dhcp:../../etc/passwd"},
		"no such entry":       {Restore: "dhcp:20261007-100000.999-abcdef12"},
		"stale revision":      {Restore: id, ExpectedRevisions: map[string]string{"dhcp": "000000000000"}},
		"revision of another": {Restore: id, ExpectedRevisions: map[string]string{"network": origDHCPRevision}},
		"the policy file":     {Restore: "openwrt-mcp:20261007-100000.001-abcdef12"},
	} {
		if _, _, err := s.uciApply(ctx, "c", in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The policy file is refused as such even when a history entry for it exists (it cannot be
	// made through uci_apply, but the id is the caller's and the file name is the config's).
	s.saveHistory("openwrt-mcp", []byte("config server\n"), 0o600, "c", "test", "seed")
	policyID := s.historyEntries("openwrt-mcp")[0].id()
	fixtureDir := uciConfDir
	uciConfDir = filepath.Dir(s.configPath) // the policy file really is "<uciConfDir>/openwrt-mcp"
	_, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: policyID})
	uciConfDir = fixtureDir
	if err != errPolicyFile {
		t.Errorf("restore of the policy config: %v, want errPolicyFile", err)
	}
	if readConf(t, "dhcp") != before || strings.Count(f.allCalls(), "/sbin/reload_config") != reloads {
		t.Error("a refused restore changed the config or reloaded")
	}

	// One pending apply at a time, restores included.
	if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciApply(ctx, "c", uciApplyIn{Restore: id}); err == nil || !strings.Contains(err.Error(), "already pending") {
		t.Errorf("restore while another apply awaits confirmation: %v", err)
	}
}

func TestRestoreIsRefusedOnANewValidationProblemUnlessForced(t *testing.T) {
	historyClock(t)
	s, f := firewallFixture(t)
	applyAndConfirm(t, s, uciApplyIn{Changes: []UCIChange{{Config: "firewall", Section: "@zone[0]", Option: "masq", Value: "1"}}})
	id := historyIDs(t, s, "firewall")[0]
	before := readConf(t, "firewall")
	// The restored file is the one whose zone fw4 now rejects: the checker sees the file on disk.
	n := 0
	f.onFn("fw4 check", func([]string, string) (string, error) {
		n++
		if n == 1 {
			return benignWarning, nil // baseline
		}
		return benignWarning + "\n" + bogusZone, nil // candidate
	})
	probe := []probeSpec{{Kind: "ping", Target: "192.0.2.1"}} // restoring firewall touches the management path
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Restore: id, Probe: probe})
	if err == nil || !strings.Contains(err.Error(), bogusZone) {
		t.Fatalf("restore with a new problem: %v", err)
	}
	if readConf(t, "firewall") != before || s.pendingSummary() != "" {
		t.Error("a refused restore must put the file back and arm nothing")
	}
	n = 0
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Restore: id, Force: true}); err != nil {
		t.Errorf("force=true must restore anyway: %v", err)
	}
}

// A restore replaces a whole config, so its scope is the whole-config key, which "<config>.*"
// does not cover (the same rule as reading a whole config).
func TestRestoreAndHistoryScopeIsTheWholeConfig(t *testing.T) {
	historyClock(t)
	s, f, _ := applyFixture(t)
	plainUCIShow(f)
	applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
	id := historyIDs(t, s, "dhcp")[0]
	if got := uciScopes(uciApplyIn{Restore: id}); len(got) != 1 || got[0] != "dhcp" {
		t.Fatalf("restore scope = %v, want [dhcp]", got)
	}
	for _, tc := range []struct {
		scope   string
		allowed bool
	}{{"dhcp", true}, {"dhcp*", true}, {"dhcp.*", false}, {"network", false}} {
		s2 := testServer(t, policyFor("c", []string{"uci_apply", "uci_get"}, tc.scope))
		cs := connectClient(t, s2, "c")
		out, isErr := callText(t, cs, "uci_apply", map[string]any{"restore": id, "dry_run": true})
		if denied := isErr && strings.Contains(out, "denied"); denied == tc.allowed {
			t.Errorf("scope %q: restore denied=%v, want allowed=%v (%s)", tc.scope, denied, tc.allowed, out)
		}
		out, isErr = callText(t, cs, "uci_get", map[string]any{"config": "dhcp", "history": "list"})
		if denied := isErr && strings.Contains(out, "denied"); denied == tc.allowed {
			t.Errorf("scope %q: history read denied=%v, want allowed=%v (%s)", tc.scope, denied, tc.allowed, out)
		}
	}
}

// The 2.4 contract: every writer of a UCI config leaves a history entry, so "what did this look
// like before" has an answer whichever tool made the change.
func TestEveryWritePathLeavesAHistoryEntry(t *testing.T) {
	ctx := context.Background()
	t.Run("uci_apply", func(t *testing.T) {
		historyClock(t)
		s, _, _ := applyFixture(t)
		applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
		if n := len(s.historyEntries("dhcp")); n != 1 {
			t.Errorf("%d entries, want 1", n)
		}
	})
	t.Run("uci_apply restore", func(t *testing.T) {
		historyClock(t)
		s, _, _ := applyFixture(t)
		applyAndConfirm(t, s, uciApplyIn{Changes: leaseChanges})
		applyAndConfirm(t, s, uciApplyIn{Restore: historyIDs(t, s, "dhcp")[0]})
		if n := len(s.historyEntries("dhcp")); n != 2 {
			t.Errorf("%d entries, want 2", n)
		}
	})
	t.Run("pkg_config_resolve use_new", func(t *testing.T) {
		historyClock(t)
		s, _, root := applyFixture(t)
		writeFixture(t, root, "etc/config/dhcp.apk-new", "config dnsmasq\n\toption domain 'new'\n")
		if _, _, err := s.pkgConfigResolve(ctx, "c", pkgConfigResolveIn{Path: "/etc/config/dhcp", Action: "use_new"}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.uciConfirm(ctx, firstToken(s)); err != nil {
			t.Fatal(err)
		}
		if n := len(s.historyEntries("dhcp")); n != 1 {
			t.Errorf("%d entries, want 1", n)
		}
	})
	t.Run("wg_new_client", func(t *testing.T) {
		historyClock(t)
		root := withFixtureRoot(t)
		writeFixture(t, root, "etc/config/network", "config interface 'wg0'\n")
		f := wgFake(t, 0)
		f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
		f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
			"ipv4-address":[{"address":"100.72.1.2","mask":15}],
			"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
		f.on("wg genkey", "CLIENTPRIV=\n")
		f.on("wg pubkey", "CLIENTPUB=\n")
		newWGBackend(f, 0, false, false)
		s := testServer(t, "")
		if _, _, err := s.wgNewClient(ctx, "c", wgNewClientIn{Name: "laptop"}); err != nil {
			t.Fatal(err)
		}
		es := s.historyEntries("network")
		if len(es) != 1 || es[0].Client != "c" || !strings.Contains(es[0].What, "laptop") {
			t.Errorf("entries = %+v, want one for the new peer, by client c", es)
		}
	})
	t.Run("wg_remove_client", func(t *testing.T) {
		historyClock(t)
		root := withFixtureRoot(t)
		writeFixture(t, root, "etc/config/network", "config interface 'wg0'\n")
		f := wgFake(t, 0)
		newWGBackend(f, 0, false, false)
		s := testServer(t, "")
		if _, _, err := s.wgRemoveClient(ctx, "c", wgRemoveIn{Name: "tablet"}); err != nil {
			t.Fatal(err)
		}
		es := s.historyEntries("network")
		if len(es) != 1 || !strings.Contains(es[0].What, "tablet") {
			t.Errorf("entries = %+v, want one for the removed peer", es)
		}
	})
}

func TestHistoryKeepOption(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{"", 5},
		{"\toption history_keep '3'\n", 3},
		{"\toption history_keep '0'\n", 0}, // off is a real setting
		{"\toption history_keep '20'\n", 20},
		{"\toption history_keep '21'\n", 20}, // capped
		{"\toption history_keep '9999'\n", 20},
		{"\toption history_keep '-1'\n", 5}, // junk keeps the default
		{"\toption history_keep 'many'\n", 5},
		{"\toption history_keep ''\n", 5},
	} {
		dir := t.TempDir()
		p := filepath.Join(dir, "cfg")
		if err := os.WriteFile(p, []byte("config server\n"+tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if err != nil || c.HistoryKeep != tc.want {
			t.Errorf("%q: HistoryKeep = %d (%v), want %d", strings.TrimSpace(tc.body), c.HistoryKeep, err, tc.want)
		}
	}
}
