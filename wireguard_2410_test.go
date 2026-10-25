package main

import (
	"context"
	"strings"
	"testing"
)

// wgHandler installs the netifd WireGuard protocol handler the router would have. 25.12 defines
// proto_wireguard_renew (peers are synced in place); 24.10 does not, and `ubus call ... renew`
// there succeeds and does nothing, so a peer change only reaches the interface through `ifup`.
func wgHandler(t *testing.T, renew bool) {
	t.Helper()
	body := "proto_wireguard_setup() { :; }\nproto_wireguard_teardown() { :; }\n"
	if renew {
		body += "proto_wireguard_renew() { :; }\n"
	}
	writeFixture(t, sysRoot, "lib/netifd/proto/wireguard.sh", body)
}

func TestNewClientBringsThePeerUpWithIfupWhereTheHandlerHasNoRenew(t *testing.T) {
	s, f, b, _ := wgNewFakeBackend(t, false, false)
	wgHandler(t, false)
	b.blindReload = true
	out, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is in the network config and on the running wg0.") {
		t.Errorf("want a verified peer:\n%s", out)
	}
	if b.renews != 0 || b.ifups == 0 || f.ran("wg set") {
		t.Errorf("want ifup and no renew or wg set (renews %d, ifups %d):\n%s", b.renews, b.ifups, f.allCalls())
	}
	if _, _, err := s.uciRollbackNow(context.Background(), armedToken(t, s)); err != nil {
		t.Fatal(err)
	}
	if b.kernelHas("CLIENTPUB=") {
		t.Error("the rollback left the peer on the interface: it must bring the interface up again as well")
	}
}

func TestRemoveClientTakesThePeerOffWithIfupWhereTheHandlerHasNoRenew(t *testing.T) {
	withFixtureRoot(t)
	f := wgFake(t, 0)
	b := newWGBackend(t, f, 0, false, false)
	wgHandler(t, false)
	b.blindReload = true
	s := testServer(t, "")
	out, _, err := s.wgRemoveClient(context.Background(), "c", wgRemoveIn{Name: "tablet"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Verified: the peer is gone from the network config and from wg0.") {
		t.Errorf("want a verified removal:\n%s", out)
	}
	if b.renews != 0 || b.ifups == 0 || b.kernelHas("PEERC=") {
		t.Errorf("want the peer off the interface through ifup (renews %d, ifups %d):\n%s", b.renews, b.ifups, f.allCalls())
	}
}

func TestNewClientKeepsRenewWhereTheHandlerHasIt(t *testing.T) {
	s, _, b, _ := wgNewFakeBackend(t, false, false)
	wgHandler(t, true)
	b.blindReload = true
	if _, _, err := s.wgNewClient(context.Background(), "c", wgNewClientIn{Name: "laptop"}); err != nil {
		t.Fatal(err)
	}
	if b.renews == 0 || b.ifups != 0 {
		t.Errorf("25.12 syncs in place; ifup would drop every session (renews %d, ifups %d)", b.renews, b.ifups)
	}
}
