package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ROADMAP 1.5: a failed-attempt limiter on mfa_unlock. Codes are single-use, but without a
// limit an attacker holding a client's token can try 10^6 codes at network speed. The spec
// these tests encode, written out here and not read from the code:
//
//   - N consecutive wrong codes lock that client out of mfa_unlock for 300 s (defaults N=5);
//   - a correct code during the lockout is refused, and is not consumed;
//   - each repeated lockout doubles the time, to a cap of one hour;
//   - success clears the count; re-enrolling clears it; other clients are unaffected;
//   - a client with no secret counts exactly like one with a secret (no enrolment oracle).

var limiterT0 = time.Unix(1700000000, 0)

// wrongCode returns a 6-digit code that is not accepted for client at now (the current step
// and its neighbours), so a "wrong guess" in a test can never turn out to be right by luck.
func wrongCode(t *testing.T, m *MFAStore, client string, now time.Time) string {
	t.Helper()
	ok := map[string]bool{}
	for d := -1; d <= 1; d++ {
		ok[codeNow(t, m, client, now.Add(time.Duration(d)*30*time.Second))] = true
	}
	for _, c := range []string{"918273", "364518", "705941", "286405", "531879", "642087", "109356"} {
		if !ok[c] {
			return c
		}
	}
	t.Fatal("no candidate wrong code")
	return ""
}

func lockoutOf(err error) (*LockoutError, bool) {
	var le *LockoutError
	return le, errors.As(err, &le)
}

// failN submits n wrong codes at now and returns the last error.
func failN(t *testing.T, m *MFAStore, client string, n int, now time.Time) error {
	t.Helper()
	var err error
	for i := 0; i < n; i++ {
		_, err = m.Unlock(client, wrongCode(t, m, client, now), 15*time.Minute, now)
		if err == nil {
			t.Fatal("a wrong code was accepted")
		}
	}
	return err
}

func enrolled(t *testing.T, clients ...string) *MFAStore {
	t.Helper()
	m, _ := newMFA(t)
	for _, c := range clients {
		if _, _, err := m.Enrol(c, "openwrt-mcp", "testrouter"); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestMFALockoutOnTheNthWrongCode(t *testing.T) {
	m := enrolled(t, "a")
	for i := 1; i <= 4; i++ {
		err := failN(t, m, "a", 1, limiterT0)
		if _, locked := lockoutOf(err); locked {
			t.Fatalf("locked after %d wrong code(s); the default limit is 5", i)
		}
		if err.Error() != "invalid code" {
			t.Errorf("wrong-code message changed: %q", err)
		}
	}
	err := failN(t, m, "a", 1, limiterT0)
	le, locked := lockoutOf(err)
	if !locked {
		t.Fatalf("the 5th wrong code did not lock: %v", err)
	}
	if le.RetryAfter != 300*time.Second {
		t.Errorf("first lockout = %s, want 5m0s", le.RetryAfter)
	}
	if !strings.Contains(err.Error(), "retry in 5m0s") {
		t.Errorf("the refusal does not say when to retry: %q", err)
	}
}

func TestMFAFourWrongThenCorrectSucceeds(t *testing.T) {
	m := enrolled(t, "a")
	failN(t, m, "a", 4, limiterT0)
	if _, err := m.Unlock("a", codeNow(t, m, "a", limiterT0), time.Minute, limiterT0); err != nil {
		t.Fatalf("a correct code after 4 wrong ones was refused: %v", err)
	}
}

func TestMFACorrectCodeDuringLockoutIsRefusedAndNotConsumed(t *testing.T) {
	m := enrolled(t, "a")
	m.SetLimit(5, 10*time.Second) // short, so the same code is still in its acceptance span at the end
	failN(t, m, "a", 5, limiterT0)

	code := codeNow(t, m, "a", limiterT0)
	at := limiterT0.Add(time.Second)
	_, err := m.Unlock("a", code, time.Minute, at)
	le, locked := lockoutOf(err)
	if !locked {
		t.Fatalf("a correct code during the lockout was not refused as a lockout: %v", err)
	}
	if le.RetryAfter != 9*time.Second {
		t.Errorf("retry-after at +1s = %s, want 9s", le.RetryAfter)
	}
	if _, open := m.UnlockedUntil("a", at); open {
		t.Fatal("the refused code opened the window anyway")
	}

	// At the end of the lockout the very same code is still valid: it was never consumed.
	end := limiterT0.Add(10 * time.Second)
	if _, err := m.Unlock("a", code, time.Minute, end); err != nil {
		t.Fatalf("the code refused during the lockout was consumed by it: %v", err)
	}
	if _, open := m.UnlockedUntil("a", end); !open {
		t.Error("unlock after the lockout did not open the window")
	}
}

func TestMFALockoutDoublesToAnHourCap(t *testing.T) {
	m := enrolled(t, "a")
	now := limiterT0
	for round, want := range []time.Duration{
		300 * time.Second, 600 * time.Second, 1200 * time.Second, 2400 * time.Second,
		3600 * time.Second, 3600 * time.Second, 3600 * time.Second,
	} {
		err := failN(t, m, "a", 5, now)
		le, locked := lockoutOf(err)
		if !locked || le.RetryAfter != want {
			t.Fatalf("lockout %d = %v (locked=%v), want %s", round+1, le, locked, want)
		}
		// Locked until exactly now+want: one second early is still locked, the instant is not.
		if _, err := m.Unlock("a", codeNow(t, m, "a", now), time.Minute, now.Add(want-time.Second)); err == nil {
			t.Fatalf("lockout %d ended one second early", round+1)
		} else if _, locked := lockoutOf(err); !locked {
			t.Fatalf("lockout %d: wrong error one second early: %v", round+1, err)
		}
		now = now.Add(want)
	}
}

func TestMFASuccessClearsTheCountAndTheStreak(t *testing.T) {
	m := enrolled(t, "a")
	// 4 wrong, success, 4 wrong: eight wrong codes in all, but never five in a row.
	failN(t, m, "a", 4, limiterT0)
	if _, err := m.Unlock("a", codeNow(t, m, "a", limiterT0), time.Minute, limiterT0); err != nil {
		t.Fatal(err)
	}
	if err := failN(t, m, "a", 4, limiterT0); err != nil {
		if _, locked := lockoutOf(err); locked {
			t.Fatal("success did not reset the count of wrong codes")
		}
	}

	// A lockout, then a success after it ends, then another lockout: back to the base time.
	m2 := enrolled(t, "a")
	failN(t, m2, "a", 5, limiterT0)
	end := limiterT0.Add(300 * time.Second)
	if _, err := m2.Unlock("a", codeNow(t, m2, "a", end), time.Minute, end); err != nil {
		t.Fatal(err)
	}
	le, locked := lockoutOf(failN(t, m2, "a", 5, end))
	if !locked || le.RetryAfter != 300*time.Second {
		t.Errorf("after a success the next lockout = %v, want the base 5m0s", le)
	}
}

func TestMFAOtherClientsAreUnaffected(t *testing.T) {
	m := enrolled(t, "a", "b")
	failN(t, m, "a", 5, limiterT0)
	if _, err := m.Unlock("b", codeNow(t, m, "b", limiterT0), time.Minute, limiterT0); err != nil {
		t.Fatalf("b was refused because a is locked out: %v", err)
	}
	if _, err := m.Unlock("a", codeNow(t, m, "a", limiterT0), time.Minute, limiterT0); err == nil {
		t.Fatal("a was not locked")
	}
}

func TestMFAReEnrolmentClearsTheLockout(t *testing.T) {
	m := enrolled(t, "a")
	failN(t, m, "a", 5, limiterT0)
	if _, _, err := m.Enrol("a", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	at := limiterT0.Add(time.Second)
	if _, err := m.Unlock("a", codeNow(t, m, "a", at), time.Minute, at); err != nil {
		t.Fatalf("recovery by re-enrolment is blocked by the old lockout: %v", err)
	}
}

// Another process rotating the secret (the CLI) is the same recovery path as Enrol.
func TestMFASecretChangedOnDiskClearsTheLockout(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mfa")
	daemon, err := LoadMFA(p)
	if err != nil {
		t.Fatal(err)
	}
	cli, _ := LoadMFA(p)
	if _, _, err := cli.Enrol("a", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	failN(t, daemon, "a", 5, limiterT0)

	if _, _, err := cli.Enrol("a", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(5 * time.Second) // mtime granularity: make the change observable
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	at := limiterT0.Add(time.Second)
	if _, err := daemon.Unlock("a", codeNow(t, cli, "a", at), time.Minute, at); err != nil {
		t.Fatalf("a rotated secret is still locked out: %v", err)
	}
}

func TestMFAUnenrolledClientLocksLikeAnEnrolledOne(t *testing.T) {
	m := enrolled(t, "real")
	for i := 1; i <= 7; i++ {
		_, errReal := m.Unlock("real", wrongCode(t, m, "real", limiterT0), time.Minute, limiterT0)
		_, errGhost := m.Unlock("ghost", "123456", time.Minute, limiterT0)
		if errReal == nil || errGhost == nil {
			t.Fatal("both should fail")
		}
		if errReal.Error() != errGhost.Error() {
			t.Fatalf("attempt %d: messages differ and reveal who is enrolled: %q vs %q", i, errReal, errGhost)
		}
		l1, k1 := lockoutOf(errReal)
		l2, k2 := lockoutOf(errGhost)
		if k1 != k2 || (k1 && l1.RetryAfter != l2.RetryAfter) {
			t.Fatalf("attempt %d: lockout state differs between enrolled and unenrolled", i)
		}
	}
}

func TestMFAWrongLengthAndJunkCodesCount(t *testing.T) {
	m := enrolled(t, "a")
	var err error
	for _, c := range []string{"", "12345", "1234567", "abcdef", "12 345"} {
		if _, err = m.Unlock("a", c, time.Minute, limiterT0); err == nil {
			t.Fatalf("%q accepted", c)
		}
	}
	if _, locked := lockoutOf(err); !locked {
		t.Errorf("five malformed submissions did not lock: %v", err)
	}
}

func TestMFAAReplayedCodeCountsAsAFailure(t *testing.T) {
	m := enrolled(t, "a")
	code := codeNow(t, m, "a", limiterT0)
	if _, err := m.Unlock("a", code, time.Minute, limiterT0); err != nil {
		t.Fatal(err)
	}
	var err error
	for i := 0; i < 5; i++ {
		_, err = m.Unlock("a", code, time.Minute, limiterT0)
	}
	if _, locked := lockoutOf(err); !locked {
		t.Errorf("five replays of a captured code did not lock: %v", err)
	}
}

func TestMFAParallelWrongGuessesLockExactlyOnce(t *testing.T) {
	m := enrolled(t, "a")
	wrong := wrongCode(t, m, "a", limiterT0)
	const n = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	invalid, locked := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Unlock("a", wrong, time.Minute, limiterT0)
			mu.Lock()
			defer mu.Unlock()
			if _, ok := lockoutOf(err); ok {
				locked++
			} else if err != nil && err.Error() == "invalid code" {
				invalid++
			}
		}()
	}
	wg.Wait()
	if invalid != 4 || locked != n-4 {
		t.Errorf("invalid=%d locked=%d, want 4 and %d", invalid, locked, n-4)
	}
	m.mu.Lock()
	streak := m.fails["a"].streak
	m.mu.Unlock()
	if streak != 1 {
		t.Errorf("streak = %d after one burst, want exactly one lockout", streak)
	}
}

func TestMFAConfigurableLimitAndClamps(t *testing.T) {
	m := enrolled(t, "a")
	m.SetLimit(3, 60*time.Second)
	if _, locked := lockoutOf(failN(t, m, "a", 2, limiterT0)); locked {
		t.Fatal("locked below the configured limit of 3")
	}
	le, locked := lockoutOf(failN(t, m, "a", 1, limiterT0))
	if !locked || le.RetryAfter != 60*time.Second {
		t.Fatalf("3rd wrong code: %v, want a 1m0s lockout", le)
	}

	for _, c := range []struct {
		name        string
		max         int
		lock        time.Duration
		wantN       int
		wantLockout time.Duration
	}{
		{"zero keeps the defaults", 0, 0, 5, 300 * time.Second},
		{"negative keeps the defaults", -3, -time.Second, 5, 300 * time.Second},
		{"huge failure count is capped", 100000, time.Second, 100, time.Second},
		{"one above the ceiling is capped", 101, time.Second, 100, time.Second},
		{"lockout over an hour is capped", 2, 5 * time.Hour, 2, time.Hour},
	} {
		m := enrolled(t, "a")
		m.SetLimit(c.max, c.lock)
		if _, locked := lockoutOf(failN(t, m, "a", c.wantN-1, limiterT0)); locked {
			t.Errorf("%s: locked before %d wrong codes", c.name, c.wantN)
		}
		le, locked := lockoutOf(failN(t, m, "a", 1, limiterT0))
		if !locked || le.RetryAfter != c.wantLockout {
			t.Errorf("%s: %d-th wrong code gave %v, want a %s lockout", c.name, c.wantN, le, c.wantLockout)
		}
	}
}

func TestMFALimitOptionsInConfig(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		body        string
		wantN       int
		wantLockout time.Duration
	}{
		{"", 5, 300 * time.Second},
		{"\toption mfa_max_failures '3'\n\toption mfa_lockout '2m'\n", 3, 2 * time.Minute},
		{"\toption mfa_lockout '45'\n", 5, 45 * time.Second}, // bare number = seconds
		{"\toption mfa_max_failures 'many'\n\toption mfa_lockout 'soon'\n", 5, 300 * time.Second},
		{"\toption mfa_max_failures '0'\n\toption mfa_lockout '0'\n", 5, 300 * time.Second},
		{"\toption mfa_max_failures '-4'\n\toption mfa_lockout '-1m'\n", 5, 300 * time.Second},
		{"\toption mfa_max_failures '99999'\n\toption mfa_lockout '5h'\n", 100, time.Hour},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "cfg"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte("config server\n"+c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("case %d: junk must keep the default, not fail the load: %v", i, err)
		}
		if cfg.MFAMaxFailures != c.wantN || cfg.MFALockout != c.wantLockout {
			t.Errorf("case %d (%q): got %d / %s, want %d / %s",
				i, strings.TrimSpace(c.body), cfg.MFAMaxFailures, cfg.MFALockout, c.wantN, c.wantLockout)
		}
	}
}

// The handler the tool wrapper runs, with the config's limits, a fixed clock and no wrapper.
func TestMFAUnlockHandlerAppliesTheConfiguredLimit(t *testing.T) {
	s := testServer(t, "config server\n\toption mfa_max_failures '2'\n\toption mfa_lockout '90'\n")
	if _, _, err := s.mfa.Enrol("c", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	wrong := wrongCode(t, s.mfa, "c", limiterT0)
	if _, _, err := s.mfaUnlock("c", wrong, limiterT0); err == nil {
		t.Fatal("wrong code accepted")
	} else if _, locked := lockoutOf(err); locked {
		t.Fatal("locked after one wrong code with a limit of 2")
	}
	_, _, err := s.mfaUnlock("c", wrong, limiterT0)
	le, locked := lockoutOf(err)
	if !locked || le.RetryAfter != 90*time.Second {
		t.Fatalf("2nd wrong code: %v, want a 1m30s lockout", err)
	}
	out, _, err := s.mfaUnlock("c", codeNow(t, s.mfa, "c", limiterT0.Add(91*time.Second)), limiterT0.Add(91*time.Second))
	if err != nil || !strings.Contains(out, "Unlocked until") {
		t.Fatalf("a correct code after the lockout: %q, %v", out, err)
	}
}

// Through the real client and wrapper: the failures are audited, the lockout is a DENIED (a
// decision, not a breakage), and no code the caller submitted ever reaches the audit log.
func TestMFAFailuresAreAuditedAndNoCodeIsLogged(t *testing.T) {
	s := testServer(t, "")
	if _, _, err := s.mfa.Enrol("c", "openwrt-mcp", "testrouter"); err != nil {
		t.Fatal(err)
	}
	cs := connectClient(t, s, "c")
	now := time.Now()

	// Five distinct wrong codes, none of them valid in any step near now.
	accepted := map[string]bool{}
	for d := -3; d <= 3; d++ {
		accepted[codeNow(t, s.mfa, "c", now.Add(time.Duration(d)*30*time.Second))] = true
	}
	var submitted []string
	for _, cand := range []string{"918273", "364518", "705941", "286405", "531879", "642087", "109356"} {
		if !accepted[cand] && len(submitted) < 5 {
			submitted = append(submitted, cand)
		}
	}
	for _, code := range submitted {
		text, isErr := callText(t, cs, "mfa_unlock", map[string]any{"code": code})
		if !isErr {
			t.Fatalf("wrong code %s accepted: %s", code, text)
		}
	}
	good := codeNow(t, s.mfa, "c", time.Now())
	submitted = append(submitted, good)
	text, isErr := callText(t, cs, "mfa_unlock", map[string]any{"code": good})
	if !isErr || !strings.Contains(text, "retry in") {
		t.Fatalf("a correct code during the lockout: isError=%v %q", isErr, text)
	}

	b, err := os.ReadFile(s.cfg().AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	for _, code := range submitted {
		if strings.Contains(log, code) {
			t.Errorf("the audit log contains the submitted code %s:\n%s", code, log)
		}
	}
	if n := strings.Count(log, `"tool":"mfa_unlock"`); n != 6 {
		t.Errorf("%d mfa_unlock calls audited, want 6 (every attempt):\n%s", n, log)
	}
	if n := strings.Count(log, `"outcome":"ERROR"`); n != 4 {
		t.Errorf("%d ERROR entries, want the 4 wrong codes before the lockout:\n%s", n, log)
	}
	if n := strings.Count(log, `"outcome":"DENIED"`); n != 2 {
		t.Errorf("%d DENIED entries, want 2 (the locking attempt and the refused correct code):\n%s", n, log)
	}
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		var ev struct {
			Args map[string]any `json:"args"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Args["code"] != "<redacted>" {
			t.Errorf("the code argument is not shown as redacted (%v): %s", err, line)
		}
	}
}

// A store built without LoadMFA has no failure map and no limits set. Nothing may panic, and the
// defaults apply.
func TestMFAZeroValueStoreStillLimitsWithTheDefaults(t *testing.T) {
	m := &MFAStore{
		path:    filepath.Join(t.TempDir(), "mfa"),
		secrets: map[string]string{"a": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		unlocks: map[string]time.Time{},
		lastCtr: map[string]uint64{},
	}
	if _, locked := lockoutOf(failN(t, m, "a", 4, limiterT0)); locked {
		t.Fatal("locked before the default limit of 5")
	}
	le, locked := lockoutOf(failN(t, m, "a", 1, limiterT0))
	if !locked || le.RetryAfter != 300*time.Second {
		t.Errorf("5th wrong code on a zero-value store: %v, want a 5m0s lockout", le)
	}
}

// A secret that is not valid base32 (a hand-edited file) can never match. The code is refused as
// any wrong code is, with the same message, and it counts towards the lockout.
func TestMFAUnreadableSecretCountsAsAWrongCode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mfa")
	if err := os.WriteFile(p, []byte("a !!!not-base32!!!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadMFA(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		if _, err := m.Unlock("a", "123456", time.Minute, limiterT0); err == nil || err.Error() != "invalid code" {
			t.Fatalf("attempt %d: %v, want the plain 'invalid code'", i, err)
		}
	}
	_, err = m.Unlock("a", "123456", time.Minute, limiterT0)
	if _, locked := lockoutOf(err); !locked {
		t.Errorf("the 5th refusal did not lock: %v", err)
	}
}

// The window a policy names is the one the handler opens; a client with no second-factor policy
// gets the default.
func TestMFAUnlockHandlerOpensTheWindowOfThePolicy(t *testing.T) {
	s := testServer(t, policyFor("c", []string{"exec"}, "*")+"\tlist mfa_tools 'exec'\n\toption mfa_window '5m'\n")
	for _, c := range []string{"c", "d"} {
		if _, _, err := s.mfa.Enrol(c, "openwrt-mcp", "testrouter"); err != nil {
			t.Fatal(err)
		}
	}
	out, _, err := s.mfaUnlock("c", codeNow(t, s.mfa, "c", limiterT0), limiterT0)
	if want := "Unlocked until " + limiterT0.Add(5*time.Minute).Format(time.RFC3339) + " (5m0s)."; err != nil || out != want {
		t.Errorf("client with a 5m policy: %q, %v; want %q", out, err, want)
	}
	out, _, err = s.mfaUnlock("d", codeNow(t, s.mfa, "d", limiterT0), limiterT0)
	if want := "Unlocked until " + limiterT0.Add(15*time.Minute).Format(time.RFC3339) + " (15m0s)."; err != nil || out != want {
		t.Errorf("client with no policy: %q, %v; want %q", out, err, want)
	}
}

// The code argument is masked by the recorder, not by whoever builds the event.
func TestAuditorMasksTheMFACode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a := NewAuditor(p, 1)
	a.Record(AuditEvent{Time: nowISO(), Client: "c", Tool: "mfa_unlock",
		Args: map[string]any{"code": "482913"}, Outcome: OutcomeError})
	a.Record(AuditEvent{Time: nowISO(), Client: "c", Tool: "exec",
		Args: map[string]any{"code": "482913"}, Outcome: OutcomeOK})
	b, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines: %q", lines)
	}
	if strings.Contains(lines[0], "482913") {
		t.Errorf("mfa_unlock code logged: %s", lines[0])
	}
	// Scoped to the one tool: another tool's argument named code is not a secret.
	if !strings.Contains(lines[1], "482913") {
		t.Errorf("an unrelated tool's `code` argument was masked: %s", lines[1])
	}
}
