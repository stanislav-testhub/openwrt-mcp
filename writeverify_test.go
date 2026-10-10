package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Verify after write (ROADMAP 4.9). A write that the router accepted and then did not keep is
// the failure a model cannot see from the exit status, so every write path re-reads what it
// changed and turns a difference into NOT_APPLIED. The lying backends below accept every write
// and keep none of it; the honest ones keep it, so a test that expects success cannot pass by
// the verifier being switched off.

// ---------------------------------------------------------------- the expectation model

func TestExpectationMismatches(t *testing.T) {
	set := func(sec, opt, v string) UCIChange {
		return UCIChange{Config: "dhcp", Section: sec, Option: opt, Value: v}
	}
	del := func(sec, opt string) UCIChange {
		return UCIChange{Op: "delete", Config: "dhcp", Section: sec, Option: opt}
	}
	add := func(sec, opt, v string) UCIChange {
		return UCIChange{Op: "add_list", Config: "dhcp", Section: sec, Option: opt, Value: v}
	}
	rm := func(sec, opt, v string) UCIChange {
		return UCIChange{Op: "del_list", Config: "dhcp", Section: sec, Option: opt, Value: v}
	}
	lst := func(sec, opt string, v ...string) UCIChange {
		return UCIChange{Op: "set_list", Config: "dhcp", Section: sec, Option: opt, Values: v}
	}
	create := func(sec, typ string) UCIChange { return UCIChange{Config: "dhcp", Section: sec, Type: typ} }

	cases := []struct {
		name      string
		show      string
		changes   []UCIChange
		want      []string // one substring per mismatch, in order
		unchecked int
	}{
		{"set that took", "dhcp.lan.start='100'", []UCIChange{set("lan", "start", "100")}, nil, 0},
		{"set that kept the old value", "dhcp.lan.start='50'", []UCIChange{set("lan", "start", "100")},
			[]string{"dhcp.lan.start: expected '100', found '50'"}, 0},
		{"set on an option that is missing", "dhcp.lan=dhcp", []UCIChange{set("lan", "start", "100")},
			[]string{"dhcp.lan.start: expected '100', found nothing"}, 0},
		{"an empty value means unset, and it is", "dhcp.lan=dhcp", []UCIChange{set("lan", "start", "")}, nil, 0},
		{"an empty value means unset, and it is not", "dhcp.lan.start='5'", []UCIChange{set("lan", "start", "")},
			[]string{"dhcp.lan.start: expected it unset, found '5'"}, 0},

		{"create that took", "dhcp.pi=host", []UCIChange{create("pi", "host")}, nil, 0},
		{"create that did not", "dhcp.lan=dhcp", []UCIChange{create("pi", "host")},
			[]string{"dhcp.pi: expected a section of type 'host', found none"}, 0},
		{"create with another type", "dhcp.pi=dnsmasq", []UCIChange{create("pi", "host")},
			[]string{"dhcp.pi: expected a section of type 'host', found 'dnsmasq'"}, 0},

		{"delete a section that went", "dhcp.lan=dhcp", []UCIChange{del("pi", "")}, nil, 0},
		{"delete a section that stayed", "dhcp.pi=host", []UCIChange{del("pi", "")},
			[]string{"dhcp.pi: expected it deleted, but it is still there"}, 0},
		{"a section known only by its options is still there", "dhcp.pi.ip='1'", []UCIChange{del("pi", "")},
			[]string{"dhcp.pi: expected it deleted"}, 0},
		{"delete an option that went", "dhcp.pi=host", []UCIChange{del("pi", "ip")}, nil, 0},
		{"delete an option that stayed", "dhcp.pi.ip='1'", []UCIChange{del("pi", "ip")},
			[]string{"dhcp.pi.ip: expected it unset, found '1'"}, 0},

		{"add_list that took", "dhcp.lan.server='1.1.1.1' '8.8.8.8'", []UCIChange{add("lan", "server", "8.8.8.8")}, nil, 0},
		{"add_list that did not", "dhcp.lan.server='1.1.1.1'", []UCIChange{add("lan", "server", "8.8.8.8")},
			[]string{"dhcp.lan.server: expected '8.8.8.8' in the list, found '1.1.1.1'"}, 0},
		{"del_list that took", "dhcp.lan.server='1.1.1.1'", []UCIChange{rm("lan", "server", "8.8.8.8")}, nil, 0},
		{"del_list that did not", "dhcp.lan.server='1.1.1.1' '8.8.8.8'", []UCIChange{rm("lan", "server", "8.8.8.8")},
			[]string{"dhcp.lan.server: expected '8.8.8.8' out of the list, found '1.1.1.1' '8.8.8.8'"}, 0},

		{"set_list exactly", "dhcp.lan.server='a' 'b'", []UCIChange{lst("lan", "server", "a", "b")}, nil, 0},
		{"set_list with an extra element", "dhcp.lan.server='a' 'b' 'c'", []UCIChange{lst("lan", "server", "a", "b")},
			[]string{"dhcp.lan.server: expected the list 'a' 'b', found 'a' 'b' 'c'"}, 0},
		{"set_list in another order", "dhcp.lan.server='b' 'a'", []UCIChange{lst("lan", "server", "a", "b")},
			[]string{"dhcp.lan.server: expected the list 'a' 'b'"}, 0},

		{"the last write to a key wins", "dhcp.lan.start='2'", []UCIChange{set("lan", "start", "1"), set("lan", "start", "2")}, nil, 0},
		{"the earlier write is not what is expected", "dhcp.lan.start='1'", []UCIChange{set("lan", "start", "1"), set("lan", "start", "2")},
			[]string{"dhcp.lan.start: expected '2', found '1'"}, 0},
		{"delete, then set", "dhcp.lan.start='7'", []UCIChange{del("lan", "start"), set("lan", "start", "7")}, nil, 0},
		{"set, then delete", "dhcp.lan.start='7'", []UCIChange{set("lan", "start", "7"), del("lan", "start")},
			[]string{"dhcp.lan.start: expected it unset, found '7'"}, 0},
		{"set_list, then add_list", "dhcp.lan.server='a' 'b'", []UCIChange{lst("lan", "server", "a"), add("lan", "server", "b")}, nil, 0},
		{"add_list, then del_list of the same element", "dhcp.lan.server='z'", []UCIChange{add("lan", "server", "a"), rm("lan", "server", "a")}, nil, 0},
		{"add_list, then del_list that did not take", "dhcp.lan.server='a'", []UCIChange{add("lan", "server", "a"), rm("lan", "server", "a")},
			[]string{"dhcp.lan.server: expected 'a' out of the list"}, 0},
		{"removing the last element removes the option", "dhcp.lan=dhcp", []UCIChange{lst("lan", "server", "a"), rm("lan", "server", "a")}, nil, 0},
		{"delete, then add_list", "dhcp.lan.server='a'", []UCIChange{del("lan", "server"), add("lan", "server", "a")}, nil, 0},
		{"delete, then add_list that is not what is there", "dhcp.lan.server='b'", []UCIChange{del("lan", "server"), add("lan", "server", "a")},
			[]string{"dhcp.lan.server: expected the list 'a', found 'b'"}, 0},
		{"removing the last element, but it stayed", "dhcp.lan.server='a'", []UCIChange{lst("lan", "server", "a"), rm("lan", "server", "a")},
			[]string{"dhcp.lan.server: expected it unset, found 'a'"}, 0},
		{"a section deleted and created again starts empty", "dhcp.pi=host\ndhcp.pi.ip='1'",
			[]UCIChange{set("pi", "name", "old"), del("pi", ""), create("pi", "host"), set("pi", "ip", "1")}, nil, 0},

		// Anonymous sections are addressed by position, which a delete or an add shifts.
		{"an anonymous section is not compared", "dhcp.lan=dhcp", []UCIChange{set("@host[0]", "ip", "1")}, nil, 1},
		{"a generated section name is not compared either", "dhcp.lan=dhcp", []UCIChange{set("cfg0a1b2c", "ip", "1")}, nil, 1},
		{"a name that only starts like one is", "dhcp.lan=dhcp", []UCIChange{set("cfgroup", "ip", "1")},
			[]string{"dhcp.cfgroup.ip"}, 0},
		{"counted once per change", "dhcp.lan=dhcp",
			[]UCIChange{set("@host[0]", "ip", "1"), set("@host[1]", "ip", "2"), set("lan", "start", "1")},
			[]string{"dhcp.lan.start"}, 2},
	}
	for _, tc := range cases {
		got, unchecked := expectationMismatches(parseUCIShow(tc.show), tc.changes)
		if len(got) != len(tc.want) {
			t.Errorf("%s: %d mismatches %q, want %d", tc.name, len(got), got, len(tc.want))
			continue
		}
		for i, w := range tc.want {
			if !strings.Contains(got[i], w) {
				t.Errorf("%s: mismatch %d is %q, want it to contain %q", tc.name, i, got[i], w)
			}
		}
		if unchecked != tc.unchecked {
			t.Errorf("%s: %d unchecked, want %d", tc.name, unchecked, tc.unchecked)
		}
	}
}

// A mismatch is shown to the operator and logged; the value of a secret option must not be in it.
func TestMismatchesNeverShowASecretValue(t *testing.T) {
	kinds := map[string]struct {
		show   string // what the router holds, with the old secret in it
		change func(opt string) UCIChange
	}{
		"set": {"OLD-SECRET", func(o string) UCIChange {
			return UCIChange{Config: "network", Section: "x", Option: o, Value: "NEW-SECRET"}
		}},
		"delete": {"OLD-SECRET", func(o string) UCIChange { return UCIChange{Op: "delete", Config: "network", Section: "x", Option: o} }},
		"add_list": {"OLD-SECRET", func(o string) UCIChange {
			return UCIChange{Op: "add_list", Config: "network", Section: "x", Option: o, Value: "NEW-SECRET"}
		}},
		"del_list": {"OLD-SECRET", func(o string) UCIChange {
			return UCIChange{Op: "del_list", Config: "network", Section: "x", Option: o, Value: "OLD-SECRET"}
		}},
		"set_list": {"OLD-SECRET", func(o string) UCIChange {
			return UCIChange{Op: "set_list", Config: "network", Section: "x", Option: o, Values: []string{"NEW-SECRET"}}
		}},
	}
	for _, opt := range []string{"private_key", "key", "psk", "password"} {
		for kind, k := range kinds {
			got, _ := expectationMismatches(parseUCIShow("network.x."+opt+"='"+k.show+"'"), []UCIChange{k.change(opt)})
			if len(got) != 1 || strings.Contains(got[0], "NEW-SECRET") || strings.Contains(got[0], "OLD-SECRET") ||
				!strings.Contains(got[0], "network.x."+opt) {
				t.Errorf("%s %s: want one mismatch naming the key and no value, got %q", kind, opt, got)
			}
		}
	}
}

// ---------------------------------------------------------------- uci_apply

func lyingApplyFixture(t *testing.T) (*Server, *fakeRouter) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "etc/config/dhcp", origDHCP)
	f := newFakeRouter(t)
	fakeUCIWith(t, f, true)
	return testServer(t, ""), f
}

func TestApplySaysWhatItVerified(t *testing.T) {
	s, f, _ := applyFixture(t)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 60})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: re-read dhcp after commit, 2 of 2 change(s) match.") {
		t.Errorf("a verified apply must say so:\n%s", out)
	}
	if !f.ran("/sbin/reload_config") {
		t.Error("a verified apply must still reload")
	}
}

func TestApplyCountsWhatItCouldNotCompare(t *testing.T) {
	s, _, _ := applyFixture(t)
	changes := append([]UCIChange{{Config: "dhcp", Section: "@host[0]", Option: "ip", Value: "192.168.1.60"}}, leaseChanges...)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: changes, Timeout: 60})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "2 of 3 change(s) match. (1 on a section addressed by position are not compared.)") {
		t.Errorf("the change on a positional section is not compared, and the result must say so:\n%s", out)
	}
}

func TestApplyChecksEachConfigAgainstItsOwnChanges(t *testing.T) {
	s, _, root := applyFixture(t)
	writeFixture(t, root, "etc/config/system", "config system\n")
	changes := append([]UCIChange{{Config: "system", Section: "ntp", Option: "enabled", Value: "1"}}, leaseChanges...)
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: changes, Timeout: 60})
	if err != nil {
		t.Fatalf("each config holds only its own changes: %v", err)
	}
	if !strings.Contains(out, "re-read dhcp, system after commit, 3 of 3 change(s) match.") {
		t.Errorf("want both configs read back:\n%s", out)
	}
}

func TestApplyFailsWhenTheCommitDidNotTakeEffect(t *testing.T) {
	s, f := lyingApplyFixture(t)
	_, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 60})
	if err == nil || errCode(err) != "NOT_APPLIED" {
		t.Fatalf("want NOT_APPLIED, got %v", err)
	}
	for _, want := range []string{"dhcp.pi: expected a section of type 'host'", "dhcp.pi.ip: expected '192.168.1.50'",
		"The rollback is still armed", "uci_rollback"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not contain %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "uci_confirm") {
		t.Errorf("a failed apply must not invite a confirm:\n%s", err)
	}
	token := firstToken(s)
	if token == "" || !strings.Contains(err.Error(), token) {
		t.Errorf("the error must carry the token that undoes it (%q):\n%s", token, err)
	}
	if f.ran("/sbin/reload_config") {
		t.Error("services were reloaded on a config that is not what was asked for")
	}
	if _, statErr := os.Stat(s.pendingPath()); statErr != nil {
		t.Error("the pending record must stay, or a reboot inside the window would not roll back")
	}
	if _, _, err := s.uciRollbackNow(context.Background(), token); err != nil {
		t.Errorf("the token in the error must work: %v", err)
	}
}

func TestApplyWithoutAReadBackSaysItWasNotVerified(t *testing.T) {
	s, f, _ := applyFixture(t)
	f.fail("uci -q show dhcp", "")
	out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Changes: leaseChanges, Timeout: 60})
	if err != nil {
		t.Fatalf("a read-back that cannot run is not a failed write: %v", err)
	}
	if !strings.Contains(out, "Not verified: could not re-read dhcp after commit") {
		t.Errorf("the missing check must be said, not hidden:\n%s", out)
	}
}

func TestApplyVerifiesAnAddListThatWasSkippedAsAlreadyPresent(t *testing.T) {
	s, _, _ := applyFixture(t)
	apply := func() string {
		out, _, err := s.uciApply(context.Background(), "c", uciApplyIn{Timeout: 60,
			Changes: []UCIChange{{Op: "add_list", Config: "dhcp", Section: "lan", Option: "server", Value: "9.9.9.9"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.uciConfirm(context.Background(), firstToken(s)); err != nil {
			t.Fatal(err)
		}
		return out
	}
	apply()
	out := apply() // second time: skipped, and the element is there
	if !strings.Contains(out, "already present, skipped") || !strings.Contains(out, "1 of 1 change(s) match") {
		t.Errorf("a skipped add_list is still checked against the committed list:\n%s", out)
	}
}

// ---------------------------------------------------------------- WireGuard

// wgBackend is the router's network config and kernel peer table for the wireguard tests,
// seeded with the sample from wireguard_test.go. Writes land in them, unless a lie flag says
// that layer accepts the write and keeps nothing.
type wgBackend struct {
	mu                sync.Mutex
	committed, staged []string
	dropped           map[string]bool
	kernel            []string
	lieUCI, lieKernel bool
	dropOnCommit      string // a commit keeps every staged line except those containing this

	// The config file on disk is the truth, as it is on the router: a commit writes a new
	// version of it, and a reload (netifd) reads whatever file is there, so a rollback that puts
	// the snapshot back is seen by the next reload. lieKernel makes netifd load nothing;
	// blindReload makes only the reload blind, so only an explicit renew loads the peers.
	confFile    string
	versions    map[string][]string // file body -> the committed lines it stands for
	rev         int
	renews      int
	blindReload bool
	slowLoad    int // the reload takes effect only after this many reads of the interface
	loadIn      int
}

func newWGBackend(t *testing.T, f *fakeRouter, handshakeC int64, lieUCI, lieKernel bool) *wgBackend {
	b := &wgBackend{dropped: map[string]bool{}, lieUCI: lieUCI, lieKernel: lieKernel, versions: map[string][]string{}}
	b.committed = strings.Split(strings.TrimSpace(sampleNetworkX), "\n")
	b.kernel = strings.Split(strings.TrimSpace(wgDump(handshakeC)), "\n")[1:]
	b.confFile = filepath.Join(uciConfDir, "network")
	seed := "rev 0\n"
	if body, err := os.ReadFile(b.confFile); err == nil {
		seed = string(body)
	} else if err := os.WriteFile(b.confFile, []byte(seed), 0o644); err != nil {
		t.Fatalf("the wireguard backend needs a fixture root for /etc/config/network: %v", err)
	}
	b.versions[seed] = append([]string(nil), b.committed...)
	locked := func(fn func(argv []string) string) func([]string, string) (string, error) {
		return func(argv []string, _ string) (string, error) {
			b.mu.Lock()
			defer b.mu.Unlock()
			return fn(argv), nil
		}
	}
	f.onFn("uci -q -X show network", locked(func([]string) string { return strings.Join(b.committed, "\n") }))
	f.onFn("wg show wg0 dump", locked(func([]string) string {
		if b.loadIn > 0 {
			b.loadIn--
			if b.loadIn == 0 {
				b.load()
			}
		}
		return "SERVERPRIV=\tSERVERPUB=\t51820\toff\n" + strings.Join(b.kernel, "\n")
	}))
	f.onFn("uci add network wireguard_wg0", locked(func([]string) string {
		b.staged = append(b.staged, "network.cfg1496fc=wireguard_wg0")
		return "cfg1496fc\n"
	}))
	stage := locked(func(argv []string) string {
		lhs, val, _ := strings.Cut(argv[len(argv)-1], "=")
		b.staged = append(b.staged, lhs+"='"+val+"'")
		return ""
	})
	f.onFn("uci set", stage)
	f.onFn("uci add_list", stage)
	f.onFn("uci delete", locked(func(argv []string) string {
		b.dropped[strings.TrimPrefix(argv[len(argv)-1], "network.")] = true
		return ""
	}))
	f.onFn("uci revert network", locked(func([]string) string { b.staged, b.dropped = nil, map[string]bool{}; return "" }))
	f.onFn("uci commit network", locked(func([]string) string {
		if !b.lieUCI {
			var keep []string
			for _, l := range b.committed {
				gone := false
				for sec := range b.dropped {
					gone = gone || strings.HasPrefix(l, "network."+sec+"=") || strings.HasPrefix(l, "network."+sec+".")
				}
				if !gone {
					keep = append(keep, l)
				}
			}
			for _, l := range b.staged {
				if b.dropOnCommit == "" || !strings.Contains(l, b.dropOnCommit) {
					keep = append(keep, l)
				}
			}
			b.committed = renumberAnon(keep)
		}
		b.staged, b.dropped = nil, map[string]bool{}
		b.rev++
		body := fmt.Sprintf("rev %d\n", b.rev)
		b.versions[body] = append([]string(nil), b.committed...)
		_ = os.WriteFile(b.confFile, []byte(body), 0o644)
		return ""
	}))
	f.onFn("/sbin/reload_config", locked(func([]string) string {
		b.reread()
		if b.slowLoad > 0 {
			b.loadIn = b.slowLoad
		} else if !b.blindReload {
			b.load()
		}
		return ""
	}))
	f.onFn("ubus call network.interface.wg0 renew", locked(func([]string) string {
		b.renews++
		b.reread()
		b.load()
		return ""
	}))
	f.on("ubus call service event", "")
	f.onFn("wg set wg0", locked(func(argv []string) string {
		pub := argv[4]
		if b.lieKernel {
			return ""
		}
		if argv[5] == "remove" {
			var keep []string
			for _, l := range b.kernel {
				if !strings.HasPrefix(l, pub+"\t") {
					keep = append(keep, l)
				}
			}
			b.kernel = keep
			return ""
		}
		b.kernel = append(b.kernel, pub+"\t(none)\t(none)\t"+argv[6]+"\t0\t0\t0\toff")
		return ""
	}))
	return b
}

// renumberAnon gives the anonymous sections the ids uci would give them on the next load. The
// file does not store them: uci numbers them by position (cfg + two hex digits counting up in file
// order + four of the type), so deleting a section hands its id to the next one.
func renumberAnon(lines []string) []string {
	idOf := func(l string) string { // "network.ID=type" or "network.ID.opt=v"
		id := strings.TrimPrefix(l, "network.")
		if i := strings.IndexAny(id, ".="); i >= 0 {
			id = id[:i]
		}
		return id
	}
	anon := func(id string) bool {
		if len(id) != 9 || !strings.HasPrefix(id, "cfg") {
			return false
		}
		var n int
		_, err := fmt.Sscanf(id[3:], "%x", &n)
		return err == nil
	}
	rename := map[string]string{}
	for _, l := range lines {
		if id := idOf(l); anon(id) && rename[id] == "" {
			rename[id] = fmt.Sprintf("cfg%02x%s", 0x11+len(rename), id[5:])
		}
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l
		if to := rename[idOf(l)]; to != "" {
			out[i] = "network." + to + strings.TrimPrefix(strings.TrimPrefix(l, "network."), idOf(l))
		}
	}
	return out
}

// reread is uci reading the file on disk again; the caller holds mu.
func (b *wgBackend) reread() {
	if body, err := os.ReadFile(b.confFile); err == nil {
		if lines, ok := b.versions[string(body)]; ok {
			b.committed = append([]string(nil), lines...)
		}
	}
}

// load is netifd running the interface's setup: the kernel ends up with the peers the committed
// config lists and no others, and a peer it already had keeps its counters. The caller holds mu.
func (b *wgBackend) load() {
	if b.lieKernel {
		return
	}
	pubs, allowed := map[string]string{}, map[string]string{}
	for _, l := range b.committed {
		if sec, ok := strings.CutSuffix(l, "=wireguard_wg0"); ok {
			pubs[sec], allowed[sec] = "", ""
		}
	}
	for _, l := range b.committed {
		lhs, val, _ := strings.Cut(l, "=")
		val = strings.Trim(val, "'")
		for sec := range pubs {
			switch lhs {
			case sec + ".public_key":
				pubs[sec] = val
			case sec + ".allowed_ips":
				allowed[sec] = val
			}
		}
	}
	var kernel []string
	have := map[string]bool{}
	for _, l := range b.kernel {
		pub, _, _ := strings.Cut(l, "\t")
		for _, want := range pubs {
			if want == pub {
				kernel = append(kernel, l)
				have[pub] = true
			}
		}
	}
	for sec, pub := range pubs {
		if pub != "" && !have[pub] {
			kernel = append(kernel, pub+"\t(none)\t(none)\t"+allowed[sec]+"\t0\t0\t0\toff")
		}
	}
	b.kernel = kernel
}

func (b *wgBackend) kernelHas(pub string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, l := range b.kernel {
		if strings.HasPrefix(l, pub+"\t") {
			return true
		}
	}
	return false
}

func TestNewClientSaysWhatItVerified(t *testing.T) {
	s, _, _ := wgNewFake(t)
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is in the network config and on the running wg0.") {
		t.Errorf("a verified client must say so:\n%s", out)
	}
}

func TestNewClientFailsWhenTheCommitDidNotKeepThePeer(t *testing.T) {
	s, f, _ := wgNewFakeWith(t, true, false)
	_, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "not in the network config") {
		t.Fatalf("want NOT_APPLIED naming the config, got %v", err)
	}
	if f.ran("/sbin/reload_config") {
		t.Error("a peer that is not in the config must not be loaded: nothing may be reloaded")
	}
	if firstToken(s) == "" || !strings.Contains(err.Error(), "The rollback is still armed") || !strings.Contains(err.Error(), firstToken(s)) {
		t.Errorf("the rollback must stay armed and the error name its token:\n%v", err)
	}
}

// A commit that kept the peer but lost part of it is as wrong as one that kept nothing: a peer
// with no allowed_ips routes nothing, and one with no description cannot be found by name.
func TestNewClientFailsWhenTheCommitKeptOnlyPartOfThePeer(t *testing.T) {
	for _, lost := range []string{".allowed_ips", ".description"} {
		root := withFixtureRoot(t)
		_ = root
		f := wgFake(t, 0)
		f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
		f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
			"ipv4-address":[{"address":"100.72.1.2","mask":15}],
			"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
		f.on("wg genkey", "CLIENTPRIV=\n")
		f.on("wg pubkey", "CLIENTPUB=\n")
		b := newWGBackend(t, f, 0, false, false)
		b.dropOnCommit = lost
		s := testServer(t, "")
		_, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
		if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "not in the network config") {
			t.Errorf("a commit that lost %s: want NOT_APPLIED, got %v", lost, err)
		}
		if f.ran("/sbin/reload_config") {
			t.Errorf("a commit that lost %s: nothing may be reloaded", lost)
		}
	}
}

func TestNewClientFailsWhenNetifdDidNotLoadThePeer(t *testing.T) {
	s, f, dir := wgNewFakeWith(t, false, true)
	_, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "not on the running wg0") {
		t.Fatalf("want NOT_APPLIED naming the interface, got %v", err)
	}
	if !strings.Contains(err.Error(), "ifup wg0") || !strings.Contains(err.Error(), "uci_rollback") || !strings.Contains(err.Error(), firstToken(s)) {
		t.Errorf("the error must say how to load the saved peer and how to undo it:\n%s", err)
	}
	if !f.ran("/sbin/reload_config") || !f.ran("ubus call network.interface.wg0 renew") || f.ran("wg set") {
		t.Fatalf("want a reload, then a renew of the interface, and no wg set:\n%s", f.allCalls())
	}
	// The peer is saved and the operator cannot be handed the key by this error: leave the
	// client file where wg-show finds it.
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("the client's config file must stay for `openwrt-mcp wg-show`, found %d file(s) in %s", len(ents), dir)
	}
}

// A kernel-only peer (someone ran `wg set`) is in no config, so there is nothing to snapshot or
// to roll back; it is removed from the interface directly, and checked there.
func TestRemoveClientRemovesAPeerOnlyTheInterfaceKnows(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	b.kernel = append(b.kernel, "LOOSE=\t(none)\t(none)\t10.20.30.9/32\t0\t0\t0\toff")
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{PublicKey: "LOOSE="})
	if err != nil {
		t.Fatal(err)
	}
	if b.kernelHas("LOOSE=") || !f.ran("wg set wg0 peer LOOSE= remove") || f.ran("uci commit") || firstToken(s) != "" {
		t.Errorf("want a direct removal and no config change or rollback:\n%s", f.allCalls())
	}
	if !strings.Contains(out, "Verified: the peer is gone from wg0.") {
		t.Errorf("a verified removal must say so:\n%s", out)
	}
	f.fail("wg set wg0", "Unable to access interface: No such device")
	b.kernel = append(b.kernel, "LOOSE=\t(none)\t(none)\t10.20.30.9/32\t0\t0\t0\toff")
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{PublicKey: "LOOSE="}); err == nil ||
		!strings.Contains(err.Error(), "live removal failed") {
		t.Errorf("a failed removal must be reported as the failed wg call, got %v", err)
	}
}

func TestRemoveClientSaysWhatItVerified(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	newWGBackend(t, f, 0, false, false)
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is gone from the network config and from wg0.") {
		t.Errorf("a verified removal must say so:\n%s", out)
	}
}

func TestRemoveClientStopsWhenThePeerIsStillOnTheInterface(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	newWGBackend(t, f, 0, false, true)
	s := testServer(t, "")
	_, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "still on the running wg0") {
		t.Fatalf("want NOT_APPLIED naming the interface, got %v", err)
	}
	if !strings.Contains(err.Error(), "uci_rollback") || !strings.Contains(err.Error(), firstToken(s)) || !f.ran("ubus call network.interface.wg0 renew") {
		t.Errorf("the interface must have been renewed, and the error say how to undo the removal:\n%v", err)
	}
}

func TestRemoveClientFailsWhenTheCommitDidNotDropThePeer(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	newWGBackend(t, f, 0, true, false)
	s := testServer(t, "")
	_, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "still in the network config") {
		t.Fatalf("want NOT_APPLIED naming the config, got %v", err)
	}
}

// ---------------------------------------------------------------- service_control

func TestServiceControlFailsWhenTheFinalStateContradictsTheAction(t *testing.T) {
	servicePoll = 0
	t.Cleanup(func() { servicePoll = 500 * time.Millisecond })
	const procdDown = `{"svc":{"instances":{"instance1":{"running":false,"exit_code":1}}}}`
	for _, tc := range []struct {
		action, state, procd, want string // want "" = a clean success; "note:" = success with that note; else NOT_APPLIED
	}{
		{"stop", svcUp, "", "expected running=false"},
		{"enable", `{"enabled":false,"running":false}`, "", "expected enabled=true"},
		{"disable", svcUp, "", "expected enabled=false"},
		// "stopped" is also what a one-shot init script always reports, so a start that ends there
		// is an error only when procd has an instance for the service that is not running.
		{"start", svcDown, "", "note:expected running=true"},
		{"restart", svcDown, "", "note:expected running=true"},
		{"reload", svcDown, `{}`, "note:expected running=true"},
		{"start", svcDown, `{"svc":{"instances":{"instance1":{"running":true}}}}`, "note:expected running=true"},
		{"start", svcDown, procdDown, "expected running=true"},
		{"restart", svcDown, procdDown, "expected running=true"},
		{"start", svcUp, "", ""},
		{"stop", svcDown, "", ""},
	} {
		f := newFakeRouter(t)
		f.on("ubus call rc init", "")
		rcSequence(f, tc.state)
		if tc.procd != "" {
			f.on("ubus call service list", tc.procd)
		}
		out, _, err := serviceControl(context.Background(), serviceControlIn{Name: "svc", Action: tc.action})
		switch {
		case tc.want == "":
			if err != nil || strings.Contains(out, "expected ") {
				t.Errorf("%s ending %s: want a clean success, got %q / %v", tc.action, tc.state, out, err)
			}
		case strings.HasPrefix(tc.want, "note:"):
			if err != nil || !strings.Contains(out, "Note: "+strings.TrimPrefix(tc.want, "note:")) {
				t.Errorf("%s ending %s: want a success carrying the note, got %q / %v", tc.action, tc.state, out, err)
			}
		default:
			if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "svc") {
				t.Errorf("%s ending %s: want NOT_APPLIED containing %q, got %v", tc.action, tc.state, tc.want, err)
			}
		}
	}
}

// ---------------------------------------------------------------- pkg_change

// fakeApk keeps /etc/apk/world the way apk does: add puts the names in, del takes them out.
// lie makes both exit 0 and change nothing.
func fakeApk(t *testing.T, f *fakeRouter, lie bool, world string) {
	t.Helper()
	root := withFixtureRoot(t)
	if world != "" {
		writeFixture(t, root, "etc/apk/world", world)
	}
	path := filepath.Join(root, "etc", "apk", "world")
	read := func() []string {
		b, _ := os.ReadFile(path)
		return strings.Fields(string(b))
	}
	write := func(names []string) { _ = os.WriteFile(path, []byte(strings.Join(names, "\n")+"\n"), 0o644) }
	f.on("apk update", "fetch ok")
	f.onFn("apk add", func(argv []string, _ string) (string, error) {
		if !lie {
			write(append(read(), argv[2:]...))
		}
		return "OK: 1 package", nil
	})
	f.onFn("apk del", func(argv []string, _ string) (string, error) {
		if !lie {
			var keep []string
			for _, n := range read() {
				if !contains(argv[2:], n) {
					keep = append(keep, n)
				}
			}
			write(keep)
		}
		return "OK: 0 packages", nil
	})
}

func TestPkgChangeSaysWhatItVerified(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, false, "base-files\nluci>=1.0\nold\n")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || !strings.Contains(out, "Verified: /etc/apk/world lists tcpdump.") {
		t.Errorf("add: want a verified result, got %q / %v", out, err)
	}
	out, _, err = pkgChange(context.Background(), pkgChangeIn{Action: "del", Packages: []string{"old"}, Commit: true})
	if err != nil || !strings.Contains(out, "Verified: /etc/apk/world no longer lists old.") {
		t.Errorf("del: want a verified result, got %q / %v", out, err)
	}
}

func TestPkgChangeFailsWhenApkDidNotChangeTheWorld(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, true, "base-files\nold\n")
	_, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump", "base-files"}, Commit: true})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "tcpdump") || strings.Contains(err.Error(), "base-files") {
		t.Errorf("add: want NOT_APPLIED naming only the missing package, got %v", err)
	}
	_, _, err = pkgChange(context.Background(), pkgChangeIn{Action: "del", Packages: []string{"old"}, Commit: true})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "old") {
		t.Errorf("del: want NOT_APPLIED naming the package, got %v", err)
	}
}

func TestPkgChangeMatchesWorldEntriesByNameNotByPrefix(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, true, "luci-app-firewall\nlibfoo>=2\n")
	_, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"luci"}, Commit: true})
	if err == nil || errCode(err) != "NOT_APPLIED" {
		t.Errorf("luci-app-firewall is not luci: %v", err)
	}
	_, _, err = pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"libfoo"}, Commit: true})
	if err != nil {
		t.Errorf("an entry with a version constraint is still that package: %v", err)
	}
}

func TestPkgChangeDoesNotCountAForbiddenEntryAsInstalled(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, true, "!tcpdump\n")
	_, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}, Commit: true})
	if err == nil || errCode(err) != "NOT_APPLIED" {
		t.Errorf("'!tcpdump' keeps tcpdump out, it does not list it: %v", err)
	}
}

func TestPkgUpgradeIsNotCheckedAgainstTheWorld(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, true, "base-files\n")
	f.on("apk upgrade", "OK")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || strings.Contains(out, "Verified") || strings.Contains(out, "Not verified") {
		t.Errorf("an upgrade changes versions, not the world file: want a plain success, got %q / %v", out, err)
	}
}

func TestPkgChangeWithoutAWorldFileSaysItWasNotVerified(t *testing.T) {
	f := newFakeRouter(t)
	fakeApk(t, f, false, "")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || !strings.Contains(out, "Not verified: could not read /etc/apk/world") {
		t.Errorf("want a success that says it was not checked, got %q / %v", out, err)
	}
}

// ---------------------------------------------------------------- the contract

// Every tool that is not read-only either re-reads what it wrote and answers NOT_APPLIED when
// the router did not keep it, or is listed here with the reason that nothing is left to check.
// A tool added later must be put in one list or the other.
func TestEveryWritePathVerifiesAfterWrite(t *testing.T) {
	exempt := map[string]string{
		"uci_confirm":        "drops the pending record; there is no router state behind it to read back",
		"uci_rollback":       "restores the snapshot byte for byte, which TestApplyThenRollbackRestoresTheFile reads back",
		"pkg_config_resolve": "plain file operations by the daemon itself: a failed remove, write or rename returns its error, so there is no accepted-but-ignored write",
		"sysupgrade":         "the backup mode writes a file the tool itself reads back for size and mode; it never flashes",
		"exec":               "a generic hatch: the command's own output is the result",
		"ubus_call":          "a generic hatch: the call's own reply is the result",
		"mfa_unlock":         "changes daemon memory only",
	}

	covered := map[string]func(t *testing.T) (string, bool){
		"uci_apply": func(t *testing.T) (string, bool) {
			lyingApplyFixture(t)
			cs := connectClient(t, testServer(t, grantAll()), "c")
			return callText(t, cs, "uci_apply", map[string]any{"changes": []any{
				map[string]any{"config": "dhcp", "section": "pi", "type": "host"},
				map[string]any{"config": "dhcp", "section": "pi", "option": "ip", "value": "192.168.1.50"}}})
		},
		"wg_new_client": func(t *testing.T) (string, bool) {
			wgNewFakeWith(t, true, false)
			cs := connectClient(t, testServer(t, grantAll()), "c")
			return callText(t, cs, "wg_new_client", map[string]any{"name": "laptop"})
		},
		"wg_remove_client": func(t *testing.T) (string, bool) {
			withFixtureRoot(t)
			f := wgFake(t, 0)
			newWGBackend(t, f, 0, true, false)
			cs := connectClient(t, testServer(t, grantAll()), "c")
			return callText(t, cs, "wg_remove_client", map[string]any{"name": "tablet"})
		},
		"service_control": func(t *testing.T) (string, bool) {
			servicePoll = 0
			t.Cleanup(func() { servicePoll = 500 * time.Millisecond })
			f := newFakeRouter(t)
			f.on("ubus call rc init", "")
			rcSequence(f, svcUp) // "stop" that leaves it running
			cs := connectClient(t, testServer(t, grantAll()), "c")
			return callText(t, cs, "service_control", map[string]any{"name": "svc", "action": "stop"})
		},
		"pkg_change": func(t *testing.T) (string, bool) {
			f := newFakeRouter(t)
			fakeApk(t, f, true, "base-files\n")
			cs := connectClient(t, testServer(t, grantAll()), "c")
			return callText(t, cs, "pkg_change", map[string]any{"action": "add", "packages": []any{"tcpdump"}, "commit": true})
		},
	}

	withFixtureRoot(t)
	var writers []string
	for _, tl := range listedTools(t, connectClient(t, testServer(t, grantAll()), "c")) {
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			writers = append(writers, tl.Name)
		}
	}
	if len(writers) < 8 {
		t.Fatalf("only %d tools are not read-only (%v); the check below would prove little", len(writers), writers)
	}
	for _, name := range writers {
		_, isCovered := covered[name]
		reason, isExempt := exempt[name]
		switch {
		case isCovered && isExempt:
			t.Errorf("%s is both covered and exempt", name)
		case !isCovered && !isExempt:
			t.Errorf("%s writes to the router but neither verifies after the write nor says why it need not: add a lying-backend case to `covered`, or a reason to `exempt`", name)
		case isExempt && len(reason) < 20:
			t.Errorf("%s is exempt without a reason worth the name: %q", name, reason)
		}
	}
	for name := range covered {
		if !contains(writers, name) {
			t.Errorf("%s is covered here but is not a write tool", name)
		}
	}
	for name := range exempt {
		if !contains(writers, name) {
			t.Errorf("%s is exempt here but is not a write tool: remove the entry", name)
		}
	}
	for name, run := range covered {
		t.Run(name, func(t *testing.T) {
			out, isErr := run(t)
			if !isErr || !strings.HasSuffix(out, "\n[code: NOT_APPLIED]") {
				t.Errorf("a write the router accepted and did not keep must end with NOT_APPLIED, got (isErr=%v):\n%s", isErr, out)
			}
		})
	}
}
