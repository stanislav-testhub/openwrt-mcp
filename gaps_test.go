package main

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests that close the gaps a mutation run found: each one kills a specific broken variant of
// the code (named in the comment) that the earlier suite let through.

// ---------------------------------------------------------------- policy

// Mutant: expiry grace. A grant stops working just after its expiry, not an hour after.
func TestAGrantExpiresExactlyAtItsExpiry(t *testing.T) {
	const expires = "2030-01-01T00:00:00Z"
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"a minute before", at.Add(-time.Minute), true},
		{"one nanosecond before", at.Add(-1), true},
		{"at the instant", at, true}, // "after" the expiry, not "at" it
		{"one nanosecond after", at.Add(1), false},
		{"a second after", at.Add(time.Second), false},
		{"two hours after", at.Add(2 * time.Hour), false},
	} {
		cfg := parse(t, basePolicy+"\toption expires '"+expires+"'\n")
		if got, _ := cfg.Authorise("claude-code", "logread", nil, c.now); got != c.want {
			t.Errorf("%s: authorised=%v, want %v", c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------- second factor

func TestOnlyAdjacentTOTPStepsAreAccepted(t *testing.T) {
	now := time.Unix(1700000000, 0)
	step := uint64(now.Unix()) / 30
	for _, c := range []struct {
		offset int
		want   bool
	}{{-2, false}, {-1, true}, {0, true}, {1, true}, {2, false}, {3, false}} {
		m, _ := newMFA(t)
		if _, _, err := m.Enrol("a", "openwrt-mcp", "r"); err != nil {
			t.Fatal(err)
		}
		m.mu.Lock()
		secret := m.secrets["a"]
		m.mu.Unlock()
		code, err := totpAt(secret, uint64(int64(step)+int64(c.offset)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.Unlock("a", code, time.Minute, now)
		if (err == nil) != c.want {
			t.Errorf("code from step %+d: accepted=%v, want %v (%v)", c.offset, err == nil, c.want, err)
		}
	}
}

// Mutant: the window stays open at its exact end. "Unlocked for 15 minutes" means closed at
// minute 15, not at minute 15 plus a nanosecond.
func TestTheMFAWindowClosesAtItsEndAndNotAfter(t *testing.T) {
	m, _ := newMFA(t)
	if _, _, err := m.Enrol("a", "openwrt-mcp", "r"); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	until, err := m.Unlock("a", codeNow(t, m, "a", now), 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if !until.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("window ends %s, want exactly 15 minutes after the unlock", until.Sub(now))
	}
	for _, c := range []struct {
		at   time.Time
		open bool
	}{
		{now, true},
		{until.Add(-time.Nanosecond), true},
		{until, false},
		{until.Add(time.Nanosecond), false},
	} {
		if _, open := m.UnlockedUntil("a", c.at); open != c.open {
			t.Errorf("at end%+dns: open=%v, want %v", c.at.Sub(until).Nanoseconds(), open, c.open)
		}
	}
}

// Mutant: dropping the empty-secret guard. HMAC with an empty key is a perfectly computable
// code, so a client that was never enrolled could unlock by deriving it.
func TestAnUnenrolledClientCannotUnlockWithTheEmptyKeyCode(t *testing.T) {
	m, _ := newMFA(t)
	now := time.Unix(1700000000, 0)
	step := uint64(now.Unix()) / 30
	for off := -1; off <= 1; off++ {
		code, err := totpAt("", uint64(int64(step)+int64(off)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Unlock("stranger", code, time.Hour, now); err == nil {
			t.Fatalf("an unenrolled client unlocked with the empty-key code for step %+d", off)
		}
	}
	if _, open := m.UnlockedUntil("stranger", now); open {
		t.Error("an unenrolled client has an open window")
	}
}

// ---------------------------------------------------------------- audit

func TestAuditEntriesAreBoundedPerField(t *testing.T) {
	read := func(a *Auditor) AuditEvent {
		b, err := os.ReadFile(a.path)
		if err != nil {
			t.Fatal(err)
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &ev); err != nil {
			t.Fatal(err)
		}
		return ev
	}
	a := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"), 16)
	a.Record(AuditEvent{Time: nowISO(), Client: "c", Outcome: OutcomeError,
		Summary: strings.Repeat("s", 5000), Error: strings.Repeat("e", 5000)})
	ev := read(a)
	const bound = 240 + len("…")
	if len(ev.Summary) != bound || len(ev.Error) != bound {
		t.Errorf("summary %d bytes, error %d bytes; want both cut to %d (a tool that echoes its input must not fill the disk)", len(ev.Summary), len(ev.Error), bound)
	}

	// At the bound nothing is cut; one over is.
	a = NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"), 16)
	a.Record(AuditEvent{Time: nowISO(), Client: "c", Outcome: OutcomeOK, Summary: strings.Repeat("s", 240)})
	if got := read(a).Summary; got != strings.Repeat("s", 240) {
		t.Errorf("a summary exactly at the bound was altered: %d bytes", len(got))
	}
}

func TestAuditLogRotatesAtItsSizeLimitAndNotBefore(t *testing.T) {
	const limit = 1 << 20 // maxMB = 1
	for _, c := range []struct {
		name       string
		preSize    int
		wantRotate bool
	}{{"one byte under", limit - 1, false}, {"exactly at the limit", limit, true}, {"over", limit + 1, true}} {
		p := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(p, []byte(strings.Repeat("x", c.preSize)), 0o600); err != nil {
			t.Fatal(err)
		}
		NewAuditor(p, 1).Record(AuditEvent{Time: nowISO(), Client: "c", Outcome: OutcomeOK, Summary: "new"})

		old, oldErr := os.Stat(p + ".1")
		cur, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if c.wantRotate {
			if oldErr != nil || old.Size() != int64(c.preSize) {
				t.Errorf("%s: the full log was not kept as .1 (%v)", c.name, oldErr)
			}
			if cur.Size() > 1000 {
				t.Errorf("%s: the live log still holds %d bytes after rotation", c.name, cur.Size())
			}
		} else if oldErr == nil || cur.Size() <= int64(c.preSize) {
			t.Errorf("%s: rotated too early (or the new line was lost)", c.name)
		}
	}
}

// Private by default: the log holds arguments and the snapshot holds Wi-Fi keys. Unix modes
// only exist on Linux, so these assertions are inert on Windows and run in CI.
func TestAuditLogAndItsDirectoryArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	p := filepath.Join(dir, "audit.jsonl")
	NewAuditor(p, 16).Record(AuditEvent{Time: nowISO(), Client: "c", Outcome: OutcomeOK})
	if !isWindows() {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("audit log mode %o, want 600", st.Mode().Perm())
		}
		if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
			t.Errorf("audit directory mode %o, want 700", st.Mode().Perm())
		}
	}
}

func TestSnapshotFilesArePrivate(t *testing.T) {
	s, _, _ := applyFixture(t)
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	dir := s.pending[firstToken(s)].Dir
	st, err := os.Stat(path.Join(dir, "dhcp"))
	if err != nil {
		t.Fatal(err)
	}
	if !isWindows() && st.Mode().Perm()&0o077 != 0 {
		t.Errorf("snapshot mode %o: a copy of a private config (Wi-Fi keys) is group/world readable", st.Mode().Perm())
	}
	if runtime.GOOS != "windows" {
		if d, _ := os.Stat(dir); d.Mode().Perm()&0o077 != 0 {
			t.Errorf("snapshot directory mode %o", d.Mode().Perm())
		}
	}
}

// ---------------------------------------------------------------- uci names and reads

func TestUCINamesWithDotsAreRefusedBecauseTheyWouldShiftTheKey(t *testing.T) {
	for _, section := range []string{"a.b", "x.y.z", ".", "a.", ".a", "a..b"} {
		if err := validateChange(UCIChange{Config: "dhcp", Section: section, Option: "ip", Value: "1"}); err == nil {
			t.Errorf("section %q accepted: uci would read it as part of the key", section)
		}
		if _, _, err := uciGet(context.Background(), uciGetIn{Config: "dhcp", Section: section}); err == nil {
			t.Errorf("uci_get section %q accepted", section)
		}
	}
	for _, option := range []string{"a.b", "x.y", "a=b"} {
		if err := validateChange(UCIChange{Config: "dhcp", Section: "pi", Option: option, Value: "1"}); err == nil {
			t.Errorf("option %q accepted", option)
		}
	}
	if err := validateChange(UCIChange{Config: "dhcp", Section: "pi", Option: "ip", Value: "1.2.3.4"}); err != nil {
		t.Errorf("a plain change was refused: %v", err)
	}
}

func TestUciGetRefusesAnOptionWithoutASectionInsteadOfDumpingTheConfig(t *testing.T) {
	f := newFakeRouter(t)
	f.on("uci", "everything: wifi keys included")
	_, _, err := uciGet(context.Background(), uciGetIn{Config: "wireless", Option: "key"})
	if err == nil || !strings.Contains(err.Error(), "option requires a section") {
		t.Errorf("err = %v", err)
	}
	f.noCalls(t, "an option with no section")
}

// ---------------------------------------------------------------- rollback reload

// Mutant: boot-time recovery stops forcing config.change events. The fixture must have
// /var/run/config.md5, or reload_config looks checksum-less and the events fire anyway.
func TestRollbackAtBootForcesEventsEvenWhenReloadConfigHasChecksums(t *testing.T) {
	s, f, root := applyFixture(t)
	writeFixture(t, root, "var/run/config.md5", "present")
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for _, p := range s.pending {
		p.timer.Stop()
	}
	s.mu.Unlock()
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()

	if _, err := NewServer(s.configPath, s.statePath); err != nil {
		t.Fatal(err)
	}
	if !f.ran(`ubus call service event {"type":"config.change","data":{"package":"dhcp"}}`) {
		t.Errorf("recovery at boot did not force the reload; the running state came from the bad file:\n%s", f.allCalls())
	}
}

func TestAnOrdinaryRollbackLeavesTheReloadToReloadConfigWhenItHasChecksums(t *testing.T) {
	s, f, root := applyFixture(t)
	writeFixture(t, root, "var/run/config.md5", "present")
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciRollbackNow(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if f.ran("ubus call service event") {
		t.Errorf("a manual rollback sent explicit events although reload_config can diff by itself:\n%s", f.allCalls())
	}
}

func TestWithoutChecksumsEvenAnOrdinaryRollbackSendsTheEvents(t *testing.T) {
	s, f, _ := applyFixture(t) // no var/run/config.md5: reload_config would fire nothing
	if _, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciRollbackNow(context.Background(), firstToken(s)); err != nil {
		t.Fatal(err)
	}
	if !f.ran(`ubus call service event {"type":"config.change","data":{"package":"dhcp"}}`) {
		t.Errorf("no explicit event although reload_config has no checksums:\n%s", f.allCalls())
	}
}

// ---------------------------------------------------------------- authorize-key and small helpers

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFO0iuRsB94YVh5gQOh1bEhtC7nqAo8hVcErAVnqOLmD mcp"

func TestAuthorizeKeyAppendsOneLockedDownLinePerKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	line, err := authorizeKey(p, "claude-code", testPubKey)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != line+"\n" || !strings.Contains(line, `--client claude-code"`) || !strings.HasSuffix(line, testPubKey) {
		t.Errorf("file holds %q for line %q", b, line)
	}
	if st, _ := os.Stat(p); !isWindows() && st.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode %o, want 600", st.Mode().Perm())
	}
	if _, err := authorizeKey(p, "other", testPubKey); err == nil || !strings.Contains(err.Error(), "already in") {
		t.Errorf("the same key twice must be refused (a key is a root login or an MCP key, not both): %v", err)
	}
	if after, _ := os.ReadFile(p); string(after) != string(b) {
		t.Error("a refused key changed the file")
	}
}

func TestAuthorizeKeyKeepsAnExistingLineIntactWhenItLacksANewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	const other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA someone"
	if err := os.WriteFile(p, []byte(other), 0o600); err != nil { // no trailing newline
		t.Fatal(err)
	}
	if _, err := authorizeKey(p, "claude-code", testPubKey); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 || lines[0] != other || !strings.HasPrefix(lines[1], "command=") {
		t.Errorf("the new key must start its own line and leave the old one untouched:\n%s", b)
	}
	for _, bad := range []struct{ client, key string }{{"c d", testPubKey}, {"c", "ssh-ed25519 short"}, {"c", ""}} {
		if _, err := authorizeKey(p, bad.client, bad.key); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSmallFormattingHelpers(t *testing.T) {
	for n, want := range map[int64]string{0: "0B", 1023: "1023B", 1024: "1K", 1536: "2K", 1 << 20: "1.0M", 5 << 29: "2.5G", 1 << 30: "1.0G"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	for in, want := range map[string]string{"": "", "abc": "abc", "12345678": "12345678", "123456789": "12345678"} {
		if got := short(in); got != want {
			t.Errorf("short(%q) = %q, want %q", in, got, want)
		}
	}
	for _, c := range []struct {
		s    string
		n    int
		want string
	}{{"abc", 3, "abc"}, {"abcd", 3, "ab~"}, {"abcd", 1, "~"}, {"", 5, ""}} {
		if got := trunc(c.s, c.n); got != c.want {
			t.Errorf("trunc(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
	for _, c := range [][3]string{
		{"vpn.example.com", "51820", "vpn.example.com:51820"},
		{"192.0.2.1", "51820", "192.0.2.1:51820"},
		{"2001:db8::1", "51820", "[2001:db8::1]:51820"},
		{"[2001:db8::1]", "51820", "[2001:db8::1]:51820"}, // already bracketed: not doubled
	} {
		if got := joinHostPort(c[0], c[1]); got != c[2] {
			t.Errorf("joinHostPort(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for in, want := range map[string]string{"10.1.0.1/24": "10.1.0.1", "fd00::1/64": "fd00::1", "10.1.0.1": "", "nonsense": "", "": ""} {
		if got := firstAddr(in); got != want {
			t.Errorf("firstAddr(%q) = %q, want %q", in, got, want)
		}
	}
	if orDefaultInt(0, 7) != 7 || orDefaultInt(3, 7) != 3 || orDefaultInt(-1, 7) != -1 {
		t.Error("orDefaultInt: zero takes the default, anything else (negative included) is kept")
	}
}
