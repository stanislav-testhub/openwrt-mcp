package main

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Shapes captured from an OpenWrt 25.12.5 router (keys replaced). Note the two peers that
// share a description -- that happens in real configs and must not confuse removal.
const sampleNetworkX = `network.loopback=interface
network.loopback.proto='static'
network.wan=interface
network.wan.proto='dhcp'
network.wg0=interface
network.wg0.proto='wireguard'
network.wg0.private_key='SERVERPRIV='
network.wg0.listen_port='51820'
network.wg0.addresses='10.20.30.1/24'
network.wg0.mtu='1380'
network.cfg1196fc=wireguard_wg0
network.cfg1196fc.public_key='PEERA='
network.cfg1196fc.allowed_ips='10.20.30.4/32'
network.cfg1196fc.description='phone'
network.cfg1296fc=wireguard_wg0
network.cfg1296fc.public_key='PEERB='
network.cfg1296fc.allowed_ips='10.20.30.5/32'
network.cfg1296fc.description='phone'
network.cfg1396fc=wireguard_wg0
network.cfg1396fc.public_key='PEERC='
network.cfg1396fc.allowed_ips='10.20.30.6/32'
network.cfg1396fc.description='tablet'
`

func wgDump(handshakeC int64) string {
	return "SERVERPRIV=\tSERVERPUB=\t51820\toff\n" +
		"PEERA=\t(none)\t(none)\t10.20.30.4/32\t0\t0\t0\toff\n" +
		"PEERB=\t(none)\t(none)\t10.20.30.5/32\t0\t0\t0\toff\n" +
		"PEERC=\t(none)\t203.0.113.9:5555\t10.20.30.6/32\t" + itoa(handshakeC) + "\t2048\t4096\toff\n"
}

func itoa(n int64) string { return strings.TrimSpace(strings.Repeat(" ", 0) + fmtInt(n)) }
func fmtInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func wgFake(t *testing.T, handshakeC int64) *fakeRouter {
	f := newFakeRouter(t)
	f.on("uci -q -X show network", sampleNetworkX)
	f.on("wg show wg0 dump", wgDump(handshakeC))
	f.on("uci changes network", "")
	return f
}

func TestLoadWGMergesConfigAndKernel(t *testing.T) {
	wgFake(t, 0)
	_, srv, peers, err := loadWG(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if srv.Iface != "wg0" || srv.Port != "51820" || srv.PubKey != "SERVERPUB=" || srv.MTU != 1380 {
		t.Errorf("server = %+v", srv)
	}
	if len(peers) != 3 {
		t.Fatalf("peers = %d, want 3", len(peers))
	}
	c := peers[2]
	if c.Name != "tablet" || c.Endpoint != "203.0.113.9:5555" || c.Rx != 2048 || !c.InUCI || !c.InKernel {
		t.Errorf("peer C = %+v", c)
	}
}

func TestListClientsNeverPrintsThePrivateKey(t *testing.T) {
	wgFake(t, 0)
	out, _, err := wgListClients(context.Background(), wgListIn{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "SERVERPRIV") {
		t.Fatal("the server private key leaked into wg_list_clients output")
	}
	if !strings.Contains(out, "share a name (phone)") {
		t.Errorf("duplicate names not flagged:\n%s", out)
	}
}

func TestNewClientAllocatesAndStagesThePeer(t *testing.T) {
	root := withFixtureRoot(t)
	_ = root
	f := wgFake(t, 0)
	f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
	f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
		"ipv4-address":[{"address":"100.72.1.2","mask":15}],
		"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
	f.on("wg genkey", "CLIENTPRIV=\n")
	f.on("wg pubkey", "CLIENTPUB=\n")
	newWGBackend(t, f, 0, false, false)

	s := testServer(t, "")
	out, summary, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop", Reveal: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Address = 10.20.30.2/32", // lowest free: .1 server, .4-.6 taken
		"DNS = 10.20.30.1",        // server's tunnel address
		"MTU = 1380",              // follows the interface
		"PublicKey = SERVERPUB=",  // from the running interface, not the private key
		"Endpoint = 100.72.1.2:51820",
		"CGNAT", // and says why that endpoint will not work
		"Scan with the WireGuard app",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(summary, "PRIV") {
		t.Error("audit summary contains key material")
	}
	calls := f.allCalls()
	for _, want := range []string{
		"uci set network.cfg1496fc.description=laptop",
		"uci set network.cfg1496fc.public_key=CLIENTPUB=",
		"uci add_list network.cfg1496fc.allowed_ips=10.20.30.2/32",
		"uci commit network",
		"/sbin/reload_config",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q:\n%s", want, calls)
		}
	}
	if f.ran("wg set") {
		t.Errorf("the interface was changed by hand:\n%s", calls)
	}
	// The private key must reach wg pubkey on stdin, never as an argument.
	if strings.Contains(calls, "CLIENTPRIV") {
		t.Error("private key passed as an argv element")
	}
}

func TestNewClientRefusesADuplicateName(t *testing.T) {
	wgFake(t, 0)
	s := testServer(t, "")
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "tablet"}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate name accepted: %v", err)
	}
}

func TestNewClientRefusesOnTopOfStagedNetworkEdits(t *testing.T) {
	f := wgFake(t, 0)
	f.on("uci changes network", "network.lan.ipaddr='10.0.0.1'")
	s := testServer(t, "")
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "x"}); err == nil ||
		!strings.Contains(err.Error(), "uncommitted") {
		t.Errorf("committed over someone else's staged network edit: %v", err)
	}
}

func TestRemoveAmbiguousNameAsksToNarrow(t *testing.T) {
	wgFake(t, 0)
	s := testServer(t, "")
	_, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "phone"})
	if err == nil || !strings.Contains(err.Error(), "2 peers match") {
		t.Fatalf("ambiguous removal not refused: %v", err)
	}
}

func TestRemoveRefusesALiveTunnelUnlessForced(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, time.Now().Unix()-30)
	newWGBackend(t, f, time.Now().Unix()-30, false, false)
	s := testServer(t, "")
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"}); err == nil ||
		!strings.Contains(err.Error(), "connected right now") {
		t.Fatalf("removed a peer with a live handshake: %v", err)
	}
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet", Force: true}); err != nil {
		t.Fatal(err)
	}
	if !f.ran("uci delete network.cfg1396fc") || f.ran("wg set") {
		t.Errorf("forced removal did not delete the peer from the config and leave the interface to netifd:\n%s", f.allCalls())
	}
}

// Handing two devices the same address silently breaks whichever connects second.
func TestNextFreeClientIP(t *testing.T) {
	a, err := nextFreeClientIP("10.1.0.1/24", []string{"10.1.0.2/32", "10.1.0.4"})
	if err != nil || a.String() != "10.1.0.3" {
		t.Errorf("got %v %v, want 10.1.0.3", a, err)
	}
	if _, err := nextFreeClientIP("10.1.0.1/30", []string{"10.1.0.2/32"}); err == nil {
		t.Error("a full /30 (server, one peer, broadcast) must be an error, not a reuse")
	}
	if _, err := nextFreeClientIP("nonsense", nil); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func TestClientConfigRendersPSKOnlyWhenSet(t *testing.T) {
	c := wgClientConfig{PrivateKey: "P", Address: "10.1.0.3/32", ServerPubKey: "S",
		AllowedIPs: "0.0.0.0/0", Endpoint: "h:51820"}
	if strings.Contains(c.String(), "PresharedKey") {
		t.Error("PresharedKey emitted with none set")
	}
	c.PresharedKey = "K="
	if !strings.Contains(c.String(), "PresharedKey = K=") {
		t.Error("PresharedKey missing")
	}
	if strings.Index(c.String(), "[Interface]") > strings.Index(c.String(), "[Peer]") {
		t.Error("[Peer] before [Interface]")
	}
}

// A QR that does not vary with its content is a fixed image that would scan as somebody
// else's tunnel.
func TestRenderQRIsContentDependent(t *testing.T) {
	a, _ := renderQR("[Interface]\nPrivateKey = AAA=\n")
	b, _ := renderQR("[Interface]\nPrivateKey = BBB=\n")
	if a == b || a == "" {
		t.Fatal("QR output does not depend on content")
	}
}

// Request scopes are matched as literals against policy globs, so they must never contain
// a glob metacharacter themselves.
func TestWGScopesAreLiterals(t *testing.T) {
	for _, sc := range append(wgNewScope(wgNewClientIn{Iface: "wg0"}), wgRemoveScope(wgRemoveIn{Name: "tablet"})...) {
		if strings.ContainsAny(sc, "*?[") {
			t.Errorf("scope %q contains a glob metacharacter", sc)
		}
	}
	if ok, _ := path.Match("wireguard.wg0", wgNewScope(wgNewClientIn{Iface: "wg0"})[0]); !ok {
		t.Error("a grant for wg0 does not cover an explicit request for wg0")
	}
}

// wg_new_client prints the new client's private key and a QR code, and both are the point of
// the tool. The sanitiser, the masker and the line cap all sit on its path now, so the one thing
// worth asserting end to end is that the wrapper hands the operator exactly what the tool built:
// the key line unmasked, and the QR (block characters, many short lines) intact.
func TestWgNewClientThroughTheWrapperIsUntouched(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
	f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
		"ipv4-address":[{"address":"100.72.1.2","mask":15}],
		"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
	f.on("wg genkey", "CLIENTPRIV=\n")
	f.on("wg pubkey", "CLIENTPUB=\n")
	newWGBackend(t, f, 0, false, false)

	// The client name is echoed back in the output. Its shape, a UCI option assignment with a
	// secret name, is exactly what the masker looks for, so only a real exemption leaves it alone.
	const name = "lab.x.psk=hunter2"
	s := testServer(t, grantAll())
	direct, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: name, Reveal: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciRollbackNow(context.Background(), armedToken(t, s)); err != nil { // the first call's peer would make the second a duplicate
		t.Fatal(err)
	}
	wrapped, isErr := callText(t, connectClient(t, s, "c"), "wg_new_client", map[string]any{"name": name, "reveal": true})
	if isErr {
		t.Fatalf("the tool failed through the wrapper:\n%s", wrapped)
	}

	// The test would prove nothing if the output had no key and no QR to damage.
	if !strings.Contains(direct, "PrivateKey = CLIENTPRIV=") || !strings.Contains(direct, "psk=hunter2") {
		t.Fatalf("setup: the output lacks the private key line or the echoed name:\n%s", direct)
	}
	blocks := 0
	for _, line := range strings.Split(direct, "\n") {
		if strings.ContainsAny(line, "█▀▄") {
			blocks++
		}
	}
	if blocks < 10 {
		t.Fatalf("setup: only %d QR lines in the output:\n%s", blocks, direct)
	}

	// Everything but the rollback notice, whose token and deadline differ from call to call.
	const armed = "\n\nThe client exists for good only once"
	dHead, dTail, _ := strings.Cut(direct, armed)
	wHead, wTail, _ := strings.Cut(wrapped, armed)
	if wHead != dHead {
		t.Errorf("the wrapper changed wg_new_client's output (it is exempt from masking and from the line cap, and has nothing to sanitise)\n direct  %q\n wrapped %q", dHead, wHead)
	}
	if !strings.Contains(dTail, "ROLLBACK ARMED") || !strings.Contains(wTail, "ROLLBACK ARMED") {
		t.Errorf("the rollback notice is missing:\n direct  %q\n wrapped %q", dTail, wTail)
	}
	if !strings.Contains(wrapped, "PrivateKey = CLIENTPRIV=") || !strings.Contains(wrapped, "psk=hunter2") {
		t.Error("something a masker would hide was hidden from the operator (wg_new_client is exempt)")
	}
	if strings.Contains(wrapped, "untrusted text") {
		t.Error("wg_new_client output carries an untrusted-text marker")
	}
}

// ---------------------------------------------------------------- the private key stays off the transcript
//
// ROADMAP 3.6. By default wg_new_client leaves the client's config in a root-only file and tells
// the operator how to collect it; the key reaches the model only on request. Expected values here
// are the spec's, not read back from the code.

// wgNewFake is wgFake plus everything wg_new_client runs, in a fixture root so the config file
// lands in a temp dir. The returned directory is where the daemon leaves client configs: beside
// the default socket, in RAM.
func wgNewFake(t *testing.T) (*Server, *fakeRouter, string) { return wgNewFakeWith(t, false, false) }

// wgNewFakeWith is wgNewFake over a backend that keeps what is written to it, or, with a lie
// flag, accepts the write to that layer (the network config, the kernel's peer table) and keeps nothing.
func wgNewFakeWith(t *testing.T, lieUCI, lieKernel bool) (*Server, *fakeRouter, string) {
	t.Helper()
	s, f, _, dir := wgNewFakeBackend(t, lieUCI, lieKernel)
	return s, f, dir
}

// wgNewFakeBackend is wgNewFakeWith that also hands back the backend, for a test that reads the
// router's state or changes how netifd behaves.
func wgNewFakeBackend(t *testing.T, lieUCI, lieKernel bool) (*Server, *fakeRouter, *wgBackend, string) {
	t.Helper()
	root := withFixtureRoot(t)
	f := wgFake(t, 0)
	f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
	f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
		"ipv4-address":[{"address":"100.72.1.2","mask":15}],
		"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
	f.on("wg genkey", "CLIENTPRIV=\n")
	f.on("wg pubkey", "CLIENTPUB=\n")
	b := newWGBackend(t, f, 0, lieUCI, lieKernel)
	return testServer(t, ""), f, b, filepath.Join(root, "var", "run", "openwrt-mcp", "wg")
}

func TestNewClientKeepsThePrivateKeyOutOfTheResultByDefault(t *testing.T) {
	s, _, dir := wgNewFake(t)
	opens, _ := recordOpens(t)
	out, summary, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop", PresharedKey: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"CLIENTPRIV", "PrivateKey", "PresharedKey"} {
		if strings.Contains(out, secret) || strings.Contains(summary, secret) {
			t.Errorf("%q reached the result:\n%s", secret, out)
		}
	}
	if strings.ContainsAny(out, "█▀▄") {
		t.Errorf("a QR code reached the result:\n%s", out)
	}
	for _, want := range []string{
		"Public key: CLIENTPUB=",
		"/var/run/openwrt-mcp/wg/laptop.conf", // where it is, in RAM
		"openwrt-mcp wg-show 'laptop'",        // what the operator runs
		"Created client \"laptop\"",
		"10.20.30.2/32",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result lacks %q:\n%s", want, out)
		}
	}

	b, err := os.ReadFile(filepath.Join(dir, "laptop.conf"))
	if err != nil {
		t.Fatalf("no config file left for the operator: %v", err)
	}
	assertMode(t, filepath.Join(dir, "laptop.conf"), 0o600)
	assertMode(t, dir, 0o700)
	for _, want := range []string{"PrivateKey = CLIENTPRIV=", "Address = 10.20.30.2/32", "PublicKey = SERVERPUB="} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the file lacks %q:\n%s", want, b)
		}
	}
	// Owner read/write only, and never over an existing file.
	var made *openCall
	for i := range *opens {
		if strings.HasSuffix(filepath.ToSlash((*opens)[i].name), "wg/laptop.conf") {
			made = &(*opens)[i]
		}
	}
	if made == nil || made.perm != 0o600 || made.flag&os.O_EXCL == 0 {
		t.Errorf("config file created as %+v, want mode 600 with O_EXCL", made)
	}
}

func TestNewClientRevealReturnsTheKeyAndLeavesNoFile(t *testing.T) {
	s, _, dir := wgNewFake(t)
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop", Reveal: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "PrivateKey = CLIENTPRIV=") {
		t.Errorf("reveal=true did not return the key:\n%s", out)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("reveal=true left %d file(s) behind", len(ents))
	}
}

// A peer whose key cannot be handed over is worse than no peer, and a failed commit must not
// leave a key lying in RAM.
func TestNewClientLeavesNeitherPeerNorFileWhenItCannotHandTheKeyOver(t *testing.T) {
	t.Run("a config for this name is already waiting", func(t *testing.T) {
		s, f, dir := wgNewFake(t)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		waiting := filepath.Join(dir, "laptop.conf")
		if err := os.WriteFile(waiting, []byte("an older key"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
		if err == nil || !strings.Contains(err.Error(), "wg-show") {
			t.Fatalf("overwrote or ignored a waiting config: %v", err)
		}
		if b, _ := os.ReadFile(waiting); string(b) != "an older key" {
			t.Errorf("the waiting config became %q", b)
		}
		if f.ran("uci add network") || f.ran("uci commit network") {
			t.Errorf("a peer was created although its key could not be handed over:\n%s", f.allCalls())
		}
	})
	t.Run("the commit fails", func(t *testing.T) {
		s, f, dir := wgNewFake(t)
		f.fail("uci commit network", "read-only file system")
		if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err == nil {
			t.Fatal("a failed commit was reported as success")
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("a key was left in %s after a failed commit", dir)
		}
		// A failed commit puts the snapshot back at once and leaves no rollback behind it, and the
		// staged peer does not stay for the next writer to trip over.
		if firstToken(s) != "" || !f.ran("uci revert network") {
			t.Errorf("a failed commit must restore and disarm (pending %q):\n%s", firstToken(s), f.allCalls())
		}
	})
}

func TestNewClientConfigFileNameStaysInsideItsDirectory(t *testing.T) {
	for _, tc := range []struct{ name, wantFile string }{
		{"laptop", "laptop.conf"},
		{"../../etc/passwd", "etcpasswd.conf"},
		{"a/b\\c", "abc.conf"},
		{"my phone", "myphone.conf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, dir := wgNewFake(t)
			if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: tc.name}); err != nil {
				t.Fatal(err)
			}
			ents, _ := os.ReadDir(dir)
			if len(ents) != 1 || ents[0].Name() != tc.wantFile {
				t.Errorf("files in %s: %v, want just %s", dir, ents, tc.wantFile)
			}
		})
	}

	// A name with no letters or digits still gets its own file, and a different one for a different name.
	files := map[string]string{}
	for _, name := range []string{"ноутбук", "телефон"} {
		s, _, dir := wgNewFake(t)
		if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: name}); err != nil {
			t.Fatal(err)
		}
		ents, _ := os.ReadDir(dir)
		if len(ents) != 1 || !strings.HasPrefix(ents[0].Name(), "client-") {
			t.Fatalf("%q: files %v, want one client-<hash>.conf", name, ents)
		}
		files[name] = ents[0].Name()
	}
	if files["ноутбук"] == files["телефон"] {
		t.Errorf("two different names share the file %s", files["ноутбук"])
	}
}

func TestWGShowPrintsTheConfigAndQRThenDeletesIt(t *testing.T) {
	s, _, dir := wgNewFake(t)
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := runWGShow(&buf, s.cfg(), "laptop", true); err != nil { // --keep
		t.Fatal(err)
	}
	out := buf.String()
	blocks := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.ContainsAny(line, "█▀▄") {
			blocks++
		}
	}
	if !strings.Contains(out, "PrivateKey = CLIENTPRIV=") || blocks < 10 {
		t.Errorf("wg-show did not print the config and a QR (%d QR lines):\n%s", blocks, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "laptop.conf")); err != nil {
		t.Errorf("--keep removed the file: %v", err)
	}

	buf.Reset()
	if err := runWGShow(&buf, s.cfg(), "laptop", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "laptop.conf")); err == nil {
		t.Error("the config is still on the router after wg-show")
	}
	err := runWGShow(&buf, s.cfg(), "laptop", false)
	if err == nil || !strings.Contains(err.Error(), "no pending config") {
		t.Errorf("a second wg-show: %v", err)
	}
}

func TestStaleClientConfigsAreSweptAndNothingElse(t *testing.T) {
	root := withFixtureRoot(t)
	dir := "/var/run/openwrt-mcp/wg"
	onDisk := filepath.Join(root, "var", "run", "openwrt-mcp", "wg")
	if err := os.MkdirAll(onDisk, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	for name, mtime := range map[string]time.Time{
		"stale.conf": old, "fresh.conf": time.Now().Add(-23 * time.Hour), "stale.txt": old,
	} {
		p := filepath.Join(onDisk, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	sweepWGConfigs(dir, 24*time.Hour)
	var left []string
	ents, _ := os.ReadDir(onDisk)
	for _, e := range ents {
		left = append(left, e.Name())
	}
	if strings.Join(left, ",") != "fresh.conf,stale.txt" {
		t.Errorf("left %v, want only the fresh .conf and the non-.conf file", left)
	}
}

// ---------------------------------------------------------------- the writers use the rollback path (MCP-1)
//
// A peer change is a change to /etc/config/network like any other: the file is snapshotted, the
// rollback armed, the change committed, read back and reloaded. The running interface is brought
// in line by netifd (the reload, or an explicit renew), never by `wg set`, so restoring the
// snapshot puts the interface back with it.

// armedToken is the token of the one rollback a writer armed.
func armedToken(t *testing.T, s *Server) string {
	t.Helper()
	tok := firstToken(s)
	if tok == "" {
		t.Fatal("no rollback is armed")
	}
	return tok
}

func TestNewClientArmsARollbackAndLeavesTheInterfaceToNetifd(t *testing.T) {
	s, f, b, _ := wgNewFakeBackend(t, false, false)
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	tok := armedToken(t, s)
	for _, want := range []string{"ROLLBACK ARMED", `uci_confirm {"token": "` + tok + `"}`, "(in 1m30s)",
		"Verified: the peer is in the network config and on the running wg0."} {
		if !strings.Contains(out, want) {
			t.Errorf("result lacks %q:\n%s", want, out)
		}
	}
	p := s.pending[tok]
	if len(s.pending) != 1 || strings.Join(p.Configs, ",") != "network" || p.Client != "c" || !strings.Contains(p.What, "laptop") {
		t.Errorf("pending = %+v", s.pending)
	}
	if snap, err := os.ReadFile(path.Join(p.Dir, "network")); err != nil || string(snap) != "rev 0\n" {
		t.Errorf("the snapshot holds %q (%v), want the config from before the change", snap, err)
	}
	calls := f.allCalls()
	if f.ran("wg set") {
		t.Errorf("the interface was changed by hand; netifd is meant to do it:\n%s", calls)
	}
	if c, r := strings.Index(calls, "uci commit network"), strings.Index(calls, "/sbin/reload_config"); c < 0 || r < c {
		t.Errorf("want the commit and then the reload:\n%s", calls)
	}
	if !b.kernelHas("CLIENTPUB=") {
		t.Error("the peer never reached the interface")
	}
	if b.renews != 0 {
		t.Errorf("the reload had already loaded the peer, yet the interface was renewed %d time(s)", b.renews)
	}
}

func TestNewClientConfirmedKeepsThePeerItsFileAndAHistoryEntry(t *testing.T) {
	historyClock(t)
	s, _, b, dir := wgNewFakeBackend(t, false, false)
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.uciConfirm(context.Background(), armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if firstToken(s) != "" {
		t.Error("still pending after the confirm")
	}
	es := s.historyEntries("network")
	if len(es) != 1 || es[0].Client != "c" || !strings.Contains(es[0].What, "laptop") {
		t.Errorf("history = %+v, want one entry for the new peer, by client c", es)
	}
	if !b.kernelHas("CLIENTPUB=") {
		t.Error("the confirmed peer is not on the interface")
	}
	if _, err := os.Stat(filepath.Join(dir, "laptop.conf")); err != nil {
		t.Errorf("the client's config is gone after the confirm: %v", err)
	}
}

func TestNewClientRolledBackLeavesNeitherPeerNorFile(t *testing.T) {
	s, _, b, dir := wgNewFakeBackend(t, false, false)
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "laptop.conf")); err != nil {
		t.Fatalf("setup: no client file to lose: %v", err)
	}
	if _, _, err := s.uciRollbackNow(context.Background(), armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if b.kernelHas("CLIENTPUB=") {
		t.Error("the peer is still on the interface after the rollback")
	}
	if got := strings.Join(b.committed, "\n"); strings.Contains(got, "CLIENTPUB=") {
		t.Errorf("the peer is still in the network config after the rollback:\n%s", got)
	}
	if body, _ := os.ReadFile(b.confFile); string(body) != "rev 0\n" {
		t.Errorf("the config file is %q, want the snapshot back", body)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("a key for a peer that no longer exists was left in %s: %v", dir, ents)
	}
}

// If netifd does not notice a peer-only change, the reload leaves the interface as it was. The
// writer then renews the interface itself, and so must the rollback, or the peer would stay on the
// interface with no trace of it in the config.
func TestNewClientRenewsTheInterfaceWhenTheReloadDidNotLoadThePeer(t *testing.T) {
	s, f, b, _ := wgNewFakeBackend(t, false, false)
	b.blindReload = true
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is in the network config and on the running wg0.") {
		t.Errorf("want a verified peer:\n%s", out)
	}
	if !f.ran("ubus call network.interface.wg0 renew") || f.ran("wg set") {
		t.Errorf("want an explicit renew and no wg set:\n%s", f.allCalls())
	}
	if _, _, err := s.uciRollbackNow(context.Background(), armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if b.kernelHas("CLIENTPUB=") {
		t.Error("the rollback left the peer on the interface: netifd did not see the reload and nobody renewed it")
	}
}

func TestRemoveClientIsRollbackArmedAndARollbackPutsThePeerBack(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err != nil {
		t.Fatal(err)
	}
	tok := armedToken(t, s)
	for _, want := range []string{"ROLLBACK ARMED", tok, "(in 1m30s)", "Verified: the peer is gone from the network config and from wg0."} {
		if !strings.Contains(out, want) {
			t.Errorf("result lacks %q:\n%s", want, out)
		}
	}
	if f.ran("wg set") || b.kernelHas("PEERC=") {
		t.Errorf("want the peer taken off the interface by netifd, not by hand:\n%s", f.allCalls())
	}
	if !f.ran("/sbin/reload_config") || b.renews != 0 {
		t.Errorf("want the reload to do it, with no renew (%d) to cover for a missing reload:\n%s", b.renews, f.allCalls())
	}
	if _, _, err := s.uciRollbackNow(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if !b.kernelHas("PEERC=") || !strings.Contains(strings.Join(b.committed, "\n"), "network.cfg1396fc=wireguard_wg0") {
		t.Errorf("the rollback did not put the peer back (kernel %v)", b.kernel)
	}
}

// Hardware, 2026-10-10: removing a peer that was not the last one failed its own read-back. uci
// numbers anonymous sections by position, so the next peer takes over the removed one's id and
// "is this section still there" answers yes. The peer is the key, not the id.
func TestRemoveClientOfAPeerThatIsNotTheLastOne(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{PublicKey: "PEERA="})
	if err != nil {
		t.Fatalf("the later peers take over the id, but the peer is gone: %v", err)
	}
	if !strings.Contains(out, "Verified: the peer is gone from the network config and from wg0.") {
		t.Errorf("result lacks the verification:\n%s", out)
	}
	if got := strings.Join(b.committed, "\n"); strings.Contains(got, "PEERA=") || !strings.Contains(got, "PEERB=") || !strings.Contains(got, "PEERC=") {
		t.Errorf("want only PEERA removed:\n%s", got)
	}
}

func TestWGWritersRefuseWhileAnApplyIsPending(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := wgNewFakeBackend(t, false, false)
	if _, _, err := s.wgNewClient(ctx, "c", wgNewClientIn{Name: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.wgNewClient(ctx, "c", wgNewClientIn{Name: "laptop2"}); errCode(err) != codeRollbackPending {
		t.Errorf("a second new client while one awaits confirmation: %v", err)
	}
	if _, _, err := s.wgRemoveClient(ctx, "c", wgRemoveIn{Name: "tablet"}); errCode(err) != codeRollbackPending {
		t.Errorf("a removal while a new client awaits confirmation: %v", err)
	}
	if _, _, err := s.uciConfirm(ctx, armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.wgRemoveClient(ctx, "c", wgRemoveIn{Name: "tablet"}); err != nil {
		t.Errorf("after the confirm: %v", err)
	}
}

// B3 left this one for MCP-1: a session that arrives through a WireGuard peer is cut by removing
// that peer. The handshake check does not see it when the tunnel has been quiet for a while.
func TestRemoveClientRefusesThePeerTheSessionArrivesThrough(t *testing.T) {
	for _, tc := range []struct {
		name  string
		peer  string
		force bool
		want  string // "" = removed
	}{
		{"an address inside the peer's allowed IPs", "10.20.30.6", false, "arrives through"},
		{"the same, forced", "10.20.30.6", true, ""},
		{"a client on the LAN", "192.0.2.50", false, ""},
		{"a client behind another peer", "10.20.30.5", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixtureRoot(t)
			f := wgFake(t, 0)
			newWGBackend(t, f, 0, false, false)
			ctx := withProfile(context.Background(), sessionProfile{Peer: netip.MustParseAddr(tc.peer)})
			_, _, err := testServer(t, "").wgRemoveClient(ctx, "c", wgRemoveIn{Name: "tablet", Force: tc.force})
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "force=true")):
				t.Errorf("want a refusal naming %q and force=true, got %v", tc.want, err)
			case tc.want != "" && f.ran("uci delete"):
				t.Error("the peer was deleted although the call was refused")
			}
		})
	}
}

func init() {
	wgSettleFor, wgSettleStep = 0, 0 // the fakes load a peer at once or never; nothing to wait for
}

// The pending record is on flash, so a restart inside the window rolls the new client back like
// any other change: the key file goes with the peer, and the interface is not renewed (at boot it
// comes up from the restored file).
func TestRestartInsideTheWindowOfANewClientRollsItBackWithItsFile(t *testing.T) {
	s, f, b, dir := wgNewFakeBackend(t, false, false)
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err != nil {
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
	if body, _ := os.ReadFile(b.confFile); string(body) != "rev 0\n" {
		t.Errorf("startup recovery left the config as %q", body)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("startup recovery left the key of a peer that is gone: %v", ents)
	}
	if f.ran("ubus call network.interface.wg0 renew") {
		t.Error("an interface was renewed at boot, where it comes up from the restored file")
	}
}

// What a pending record names goes into an argv and into a remove, so a record that names
// anything but a UCI interface or a client config is ignored.
func TestRestoreOnlyRenewsRealInterfacesAndOnlyDeletesClientFiles(t *testing.T) {
	s, f, _, _ := wgNewFakeBackend(t, false, false)
	wgDir := wgClientDir(s.cfg())
	for name, body := range map[string]string{wgDir + "/laptop.conf": "key", wgDir + "/notes.txt": "n", "/etc/passwd": "root", "/etc/other.conf": "x"} {
		if err := os.MkdirAll(filepath.Dir(sysPath(name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sysPath(name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	renews := func() int {
		n := 0
		for _, c := range strings.Split(f.allCalls(), "\n") {
			if strings.HasPrefix(c, "ubus call network.interface.") && strings.HasSuffix(c, " renew") {
				n++
			}
		}
		return n
	}
	restore := func(atBoot bool) {
		t.Helper()
		p, err := s.snapshot([]string{"network"}, "c", "x", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		p.Renew = []string{"wg0", "wg0 x", "../x", ""}
		p.Files = []string{wgDir + "/laptop.conf", wgDir + "/notes.txt", "/etc/passwd", "/etc/other.conf", wgDir + "/../../../etc/passwd"}
		if err := s.restore(context.Background(), p, atBoot); err != nil {
			t.Fatal(err)
		}
	}

	restore(true)
	if n := renews(); n != 0 {
		t.Errorf("%d interface(s) renewed at boot", n)
	}
	restore(false)
	if n := renews(); n != 1 || !f.ran("ubus call network.interface.wg0 renew") {
		t.Errorf("want only wg0 renewed, got %d renew(s):\n%s", n, f.allCalls())
	}
	if _, err := os.Stat(sysPath(wgDir + "/laptop.conf")); err == nil {
		t.Error("the client config named in the record was not deleted")
	}
	for _, kept := range []string{wgDir + "/notes.txt", "/etc/passwd", "/etc/other.conf"} {
		if _, err := os.Stat(sysPath(kept)); err != nil {
			t.Errorf("%s was deleted although it is not a client config: %v", kept, err)
		}
	}
}

// netifd takes a moment after the reload. The writer waits for the peer to show up, and only an
// interface that has not changed by the end of the window is asked to renew.
func TestNewClientWaitsForNetifdBeforeRenewing(t *testing.T) {
	wgSettleFor, wgSettleStep = time.Second, time.Millisecond
	t.Cleanup(func() { wgSettleFor, wgSettleStep = 0, 0 })
	s, f, b, _ := wgNewFakeBackend(t, false, false)
	b.slowLoad = 3
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is in the network config and on the running wg0.") {
		t.Errorf("want a verified peer:\n%s", out)
	}
	if f.ran("ubus call network.interface.wg0 renew") {
		t.Error("the interface was renewed although the reload loaded the peer within the window")
	}
}

func TestRemoveClientRollbackRenewsWhenTheReloadIsBlind(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	b.blindReload = true
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is gone from the network config and from wg0.") || !f.ran("ubus call network.interface.wg0 renew") {
		t.Errorf("want the interface renewed and the removal verified:\n%s\n%s", out, f.allCalls())
	}
	if _, _, err := s.uciRollbackNow(context.Background(), armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if !b.kernelHas("PEERC=") {
		t.Error("the rollback left the peer off the interface: netifd did not see the reload and nobody renewed it")
	}
}

// A peer that is in the config but was never loaded has nothing to leave the interface, so the
// removal is checked against the config alone.
func TestRemoveClientOfAPeerTheInterfaceNeverLoaded(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	b.kernel = b.kernel[:2] // PEERC is in the config only
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is gone from the network config.") || strings.Contains(out, "and from wg0") {
		t.Errorf("want a removal verified against the config only:\n%s", out)
	}
}

func TestRemoveClientStopsWhenALoosePeerStaysOnTheInterface(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, true)
	b.kernel = append(b.kernel, "LOOSE=\t(none)\t(none)\t10.20.30.9/32\t0\t0\t0\toff")
	_, _, err := testServer(t, "").wgRemoveClient(context.Background(), "c", wgRemoveIn{PublicKey: "LOOSE="})
	if err == nil || errCode(err) != "NOT_APPLIED" || !strings.Contains(err.Error(), "still on wg0") {
		t.Errorf("want NOT_APPLIED naming the interface, got %v", err)
	}
}

// A local session is not arriving through any peer, whatever routes a peer is allowed.
func TestRemoveClientIgnoresALocalSessionWhateverTheRoutes(t *testing.T) {
	for _, tc := range []struct {
		peer    string
		refused bool
	}{
		{"127.0.0.1", false},
		{"10.20.30.9", true}, // the same route covers this one
	} {
		t.Run(tc.peer, func(t *testing.T) {
			withFixtureRoot(t)
			f := wgFake(t, 0)
			b := newWGBackend(t, f, 0, false, false)
			b.committed = append(b.committed, "network.cfg1596fc=wireguard_wg0", "network.cfg1596fc.public_key='SPLIT='",
				"network.cfg1596fc.allowed_ips='0.0.0.0/1'", "network.cfg1596fc.description='split'")
			b.kernel = append(b.kernel, "SPLIT=\t(none)\t(none)\t0.0.0.0/1\t0\t0\t0\toff")
			ctx := withProfile(context.Background(), sessionProfile{Peer: netip.MustParseAddr(tc.peer)})
			_, _, err := testServer(t, "").wgRemoveClient(ctx, "c", wgRemoveIn{Name: "split"})
			if refused := err != nil && strings.Contains(err.Error(), "arrives through"); refused != tc.refused || (err != nil) != tc.refused {
				t.Errorf("session from %s: refused=%v (%v), want %v", tc.peer, refused, err, tc.refused)
			}
		})
	}
}

func TestInAllowed(t *testing.T) {
	for _, tc := range []struct {
		allowed []string
		addr    string
		want    bool
	}{
		{[]string{"10.20.30.6/32"}, "10.20.30.6", true},
		{[]string{"10.20.30.6/32"}, "10.20.30.7", false},
		{[]string{"10.20.30.0/24"}, "10.20.30.7", true},
		{[]string{"10.20.30.6"}, "10.20.30.6", true}, // a bare address
		{[]string{"10.20.30.6"}, "10.20.30.7", false},
		{[]string{"0.0.0.0/0"}, "10.20.30.7", false}, // a catch-all says nothing about where a session comes from
		{[]string{"::/0", "0.0.0.0/0"}, "2001:db8::1", false},
		{[]string{"2001:db8::/64"}, "2001:db8::1", true},
		{[]string{"not-an-address", "10.20.30.0/24"}, "10.20.30.7", true},
		{nil, "10.20.30.7", false},
	} {
		if got := inAllowed(tc.allowed, netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("inAllowed(%v, %s) = %v, want %v", tc.allowed, tc.addr, got, tc.want)
		}
	}
}

// A writer that cannot take its snapshot has changed nothing: what it staged is reverted, no
// rollback is left behind, and no key stays on the router.
func TestWGWritersRevertWhatTheyStagedWhenTheSnapshotFails(t *testing.T) {
	ctx := context.Background()
	for name, call := range map[string]func(s *Server) error{
		"wg_new_client": func(s *Server) error {
			_, _, err := s.wgNewClient(ctx, "c", wgNewClientIn{Name: "laptop"})
			return err
		},
		"wg_remove_client": func(s *Server) error {
			_, _, err := s.wgRemoveClient(ctx, "c", wgRemoveIn{Name: "tablet"})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, f, _, dir := wgNewFakeBackend(t, false, false)
			if err := os.MkdirAll(filepath.Dir(s.snapshotRoot()), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.snapshotRoot(), []byte("in the way"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := call(s); err == nil || !strings.Contains(err.Error(), "snapshot failed") {
				t.Fatalf("want the snapshot failure, got %v", err)
			}
			if !f.ran("uci revert network") || f.ran("uci commit") || firstToken(s) != "" {
				t.Errorf("want the staged change reverted, nothing committed and nothing armed:\n%s", f.allCalls())
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("a key was left in %s: %v", dir, ents)
			}
		})
	}
}

func TestRemoveClientRevertsWhenTheDeleteFails(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	newWGBackend(t, f, 0, false, false)
	f.fail("uci delete", "Entry not found")
	s := testServer(t, "")
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"}); err == nil {
		t.Fatal("a failed delete was reported as success")
	}
	if !f.ran("uci revert network") || f.ran("uci commit") || firstToken(s) != "" {
		t.Errorf("want the staging reverted, nothing committed and nothing armed:\n%s", f.allCalls())
	}
}

func TestWgSettleStopsWhenTheCallIsCancelled(t *testing.T) {
	wgSettleFor, wgSettleStep = time.Hour, time.Millisecond
	t.Cleanup(func() { wgSettleFor, wgSettleStep = 0, 0 })
	wgNewFakeBackend(t, false, true) // netifd never loads anything
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	var err error
	done := make(chan struct{})
	go func() {
		_, err = wgSettle(ctx, "wg0", "NOPE=", true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wgSettle kept waiting after the call was cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the cancellation", err)
	}
}

func TestWgSettleReportsAReadFailure(t *testing.T) {
	_, f, _, _ := wgNewFakeBackend(t, false, false)
	f.fail("uci -q -X show network", "uci: Entry not found")
	if settled, err := wgSettle(context.Background(), "wg0", "NOPE=", true); err == nil || settled {
		t.Errorf("settled=%v err=%v, want the read failure", settled, err)
	}
}

func TestRemoveClientRefusesOnTopOfStagedNetworkEdits(t *testing.T) {
	f := wgFake(t, 0)
	f.on("uci changes network", "network.lan.ipaddr='10.0.0.1'")
	s := testServer(t, "")
	_, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if errCode(err) != "CONFLICT" || !strings.Contains(err.Error(), "uncommitted") {
		t.Errorf("committed over someone else's staged network edit: %v", err)
	}
	if f.ran("uci delete") || f.ran("uci commit") {
		t.Errorf("the refusal came after a change:\n%s", f.allCalls())
	}
}
