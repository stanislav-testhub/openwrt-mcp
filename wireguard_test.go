package main

import (
	"context"
	"path"
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
	out, summary, err := s.wgNewClient(context.Background(), wgNewClientIn{Name: "laptop"})
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
	if _, _, err := s.wgNewClient(context.Background(), wgNewClientIn{Name: "tablet"}); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate name accepted: %v", err)
	}
}

func TestNewClientRefusesOnTopOfStagedNetworkEdits(t *testing.T) {
	f := wgFake(t, 0)
	f.on("uci changes network", "network.lan.ipaddr='10.0.0.1'")
	s := testServer(t, "")
	if _, _, err := s.wgNewClient(context.Background(), wgNewClientIn{Name: "x"}); err == nil ||
		!strings.Contains(err.Error(), "uncommitted") {
		t.Errorf("committed over someone else's staged network edit: %v", err)
	}
}

func TestRemoveAmbiguousNameAsksToNarrow(t *testing.T) {
	wgFake(t, 0)
	s := testServer(t, "")
	_, _, err := s.wgRemoveClient(context.Background(), wgRemoveIn{Name: "phone"})
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
	if _, _, err := s.wgRemoveClient(context.Background(), wgRemoveIn{Name: "tablet"}); err == nil ||
		!strings.Contains(err.Error(), "connected right now") {
		t.Fatalf("removed a peer with a live handshake: %v", err)
	}
	if _, _, err := s.wgRemoveClient(context.Background(), wgRemoveIn{Name: "tablet", Force: true}); err != nil {
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
