package main

import (
	"bytes"
	"context"
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

func TestNewClientAllocatesConfiguresAndHotAdds(t *testing.T) {
	root := withFixtureRoot(t)
	_ = root
	f := wgFake(t, 0)
	f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
	f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
		"ipv4-address":[{"address":"100.72.1.2","mask":15}],
		"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
	f.on("wg genkey", "CLIENTPRIV=\n")
	f.on("wg pubkey", "CLIENTPUB=\n")
	f.on("uci add network wireguard_wg0", "cfg1496fc\n")
	f.on("uci set", "")
	f.on("uci add_list", "")
	f.on("uci commit network", "")
	f.on("wg set wg0", "")

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
		"wg set wg0 peer CLIENTPUB= allowed-ips 10.20.30.2/32",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q:\n%s", want, calls)
		}
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
	f := wgFake(t, time.Now().Unix()-30)
	f.on("wg set wg0 peer PEERC= remove", "")
	f.on("uci delete network.cfg1396fc", "")
	f.on("uci commit network", "")
	s := testServer(t, "")
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"}); err == nil ||
		!strings.Contains(err.Error(), "connected right now") {
		t.Fatalf("removed a peer with a live handshake: %v", err)
	}
	if _, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet", Force: true}); err != nil {
		t.Fatal(err)
	}
	if !f.ran("uci delete network.cfg1396fc") || !f.ran("wg set wg0 peer PEERC= remove") {
		t.Errorf("forced removal did not remove from both config and kernel:\n%s", f.allCalls())
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
	f.on("uci add network wireguard_wg0", "cfg1496fc\n")
	f.on("uci set", "")
	f.on("uci add_list", "")
	f.on("uci commit network", "")
	f.on("wg set wg0", "")

	// The client name is echoed back in the output. Its shape, a UCI option assignment with a
	// secret name, is exactly what the masker looks for, so only a real exemption leaves it alone.
	const name = "lab.x.psk=hunter2"
	s := testServer(t, grantAll())
	direct, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: name, Reveal: true})
	if err != nil {
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

	if wrapped != direct {
		t.Errorf("the wrapper changed wg_new_client's output (it is exempt from masking and from the line cap, and has nothing to sanitise)\n direct  %q\n wrapped %q", direct, wrapped)
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
func wgNewFake(t *testing.T) (*Server, *fakeRouter, string) {
	t.Helper()
	root := withFixtureRoot(t)
	f := wgFake(t, 0)
	f.on("uci -q show ddns", "ddns.myddns_ipv4=service\nddns.myddns_ipv4.enabled='0'\nddns.myddns_ipv4.lookup_host='yourhost.example.com'\n")
	f.on("ubus call network.interface dump", `{"interface":[{"interface":"WAN","up":true,"metric":1,
		"ipv4-address":[{"address":"100.72.1.2","mask":15}],
		"route":[{"target":"0.0.0.0","mask":0,"nexthop":"100.64.0.1"}]}]}`)
	f.on("wg genkey", "CLIENTPRIV=\n")
	f.on("wg pubkey", "CLIENTPUB=\n")
	f.on("uci add network wireguard_wg0", "cfg1496fc\n")
	f.on("uci set", "")
	f.on("uci add_list", "")
	f.on("uci commit network", "")
	f.on("wg set wg0", "")
	return testServer(t, ""), f, filepath.Join(root, "var", "run", "openwrt-mcp", "wg")
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
