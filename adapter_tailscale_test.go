package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// tsVariant is the running-node fixture with edit applied, so each test states only what differs.
func tsVariant(t *testing.T, edit func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(adapterFixture(t, "tailscale_running.json")), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tsPeer(m map[string]any, host string) map[string]any {
	for _, p := range m["Peer"].(map[string]any) {
		if p.(map[string]any)["HostName"] == host {
			return p.(map[string]any)
		}
	}
	panic("no peer " + host)
}

func tsDetail(t *testing.T, f *fakeRouter, status string) []string {
	t.Helper()
	f.on("tailscale status --json", status)
	return detailBody(t, listServices(t, serviceListIn{Detail: "tailscale"}))
}

func TestTailscaleDetailForARunningNode(t *testing.T) {
	f, _ := adapterRouter(t)
	got := tsDetail(t, f, adapterFixture(t, "tailscale_running.json"))
	want := []string{
		"tailscale 1.98.3: Running",
		"tailnet: example.ts.net (MagicDNS off)",
		"this node: router 100.64.0.1 fd7a:115c:a1e0::1 online",
		"advertised routes: 192.0.2.0/24",
		"exit node: offered by this node",
		"health: ok",
		"peers: 3, 2 online",
		"laptop 100.64.0.2 linux online direct rx 12.0M tx 3.0M",
		"nas 100.64.0.4 linux online relay fra",
		"phone 100.64.0.3 android offline last seen 2026-10-07T11:00:00Z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tailscale detail:\n got %q\nwant %q", got, want)
	}
}

// None of this is needed to diagnose a tailnet, and some of it is credential-like or private.
func TestTailscaleDetailPrintsNoKeysAddressesOrLinks(t *testing.T) {
	f, _ := adapterRouter(t)
	status := tsVariant(t, func(m map[string]any) {
		m["AuthURL"] = "https://login.example.com/a/canaryloginlink"
	})
	out := strings.Join(tsDetail(t, f, status), "\n")
	for _, canary := range []string{
		"nodekey:", "5e1f", // public node keys
		"203.0.113.9", "198.51.100.7", // endpoints (a peer's public address)
		"canaryloginlink", "login.example.com", // a login link lets whoever opens it join the node
		"canary-owner", "example.com", // the tailnet's display name is the owner's account
		"PeerAPI", "62000", "KeyExpiry", "2027-04-01", "cap/ssh",
	} {
		if strings.Contains(out, canary) {
			t.Errorf("the detail leaks %q:\n%s", canary, out)
		}
	}
}

func TestTailscaleDetailWhenTheNodeNeedsLogin(t *testing.T) {
	f, _ := adapterRouter(t)
	status := tsVariant(t, func(m map[string]any) {
		m["BackendState"] = "NeedsLogin"
		m["AuthURL"] = "https://login.example.com/a/canaryloginlink"
		m["Self"], m["Peer"], m["TailscaleIPs"] = nil, nil, nil
		m["Health"] = []any{"You are logged out."}
	})
	got := tsDetail(t, f, status)
	want := []string{
		"tailscale 1.98.3: NeedsLogin",
		`not logged in: run "tailscale up" on the router to log in (the login link is not shown here)`,
		"health:",
		"- You are logged out.",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("needs-login detail:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(strings.Join(got, "\n"), "canaryloginlink") {
		t.Error("the login link was printed")
	}
}

func TestTailscaleDetailWhenStoppedOrStarting(t *testing.T) {
	f, _ := adapterRouter(t)
	for state, want := range map[string][]string{
		"Stopped":  {"tailscale 1.98.3: Stopped", `tailscale is stopped: "tailscale up" brings it back`},
		"Starting": {"tailscale 1.98.3: Starting"},
		"NoState":  {"tailscale 1.98.3: NoState"},
	} {
		got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
			m["BackendState"] = state
			m["Self"], m["Peer"] = nil, nil
		}))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %q\nwant %q", state, got, want)
		}
	}
}

func TestTailscaleDetailShowsTheExitNodeInUse(t *testing.T) {
	f, _ := adapterRouter(t)
	got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		tsPeer(m, "nas")["ExitNode"] = true
	}))
	if got[4] != "exit node: in use, nas; offered by this node" {
		t.Errorf("exit node line = %q\n%q", got[4], got)
	}
	got = tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		tsPeer(m, "nas")["ExitNode"] = true
		m["Self"].(map[string]any)["ExitNodeOption"] = false
	}))
	if got[4] != "exit node: in use, nas" {
		t.Errorf("exit node line = %q\n%q", got[4], got)
	}
	// Neither offered nor used: no line at all.
	got = tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		m["Self"].(map[string]any)["ExitNodeOption"] = false
		m["Self"].(map[string]any)["PrimaryRoutes"] = nil
	}))
	for _, l := range got {
		if strings.HasPrefix(l, "exit node") || strings.HasPrefix(l, "advertised routes") {
			t.Errorf("a line for something this node does not do: %q", l)
		}
	}
}

func TestTailscaleDetailListsHealthWarnings(t *testing.T) {
	f, _ := adapterRouter(t)
	got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		m["Health"] = []any{"The Tailscale coordination server is not reachable.", "Tailscale can't reach the configured DNS servers.\x1b[2J"}
	}))
	want := []string{"health:", "- The Tailscale coordination server is not reachable.", "- Tailscale can't reach the configured DNS servers."}
	if !reflect.DeepEqual(got[5:8], want) {
		t.Errorf("health lines:\n got %q\nwant %q", got[5:8], want)
	}
}

func TestTailscaleDetailBoundsWhatPeersCanSay(t *testing.T) {
	f, _ := adapterRouter(t)
	long := strings.Repeat("x", 300)
	got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		tsPeer(m, "laptop")["HostName"] = long
		m["Health"] = []any{long}
	}))
	for _, l := range got {
		if len(l) > 220 {
			t.Errorf("a %d-byte line: %.60s...", len(l), l)
		}
	}
	for _, l := range got {
		switch {
		case strings.Contains(l, " 100.64.0.2 "): // the peer line: name clipped to 40 characters and an ellipsis
			if name, _, _ := strings.Cut(l, " "); name != strings.Repeat("x", 40)+"…" {
				t.Errorf("peer name = %q", name)
			}
		case strings.HasPrefix(l, "- x"): // the health line: clipped to 160
			if l != "- "+strings.Repeat("x", 160)+"…" {
				t.Errorf("health line = %q", l)
			}
		}
	}

	// Twenty-five peers: the first twenty, then how many are left.
	got = tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		peers := map[string]any{}
		for i := 0; i < 25; i++ {
			peers[fmt.Sprintf("nodekey:%02d", i)] = map[string]any{
				"HostName": fmt.Sprintf("host%02d", i), "OS": "linux", "Online": true,
				"TailscaleIPs": []any{fmt.Sprintf("100.64.1.%d", i)}, "Relay": "fra",
			}
		}
		m["Peer"] = peers
	}))
	var shown int
	for _, l := range got {
		if strings.HasPrefix(l, "host") {
			shown++
		}
	}
	if shown != 20 || got[len(got)-1] != "... 5 more peers not shown" || !contains(got, "peers: 25, 25 online") {
		t.Errorf("shown %d peers, last line %q, want 20 and '... 5 more peers not shown'", shown, got[len(got)-1])
	}
}

func TestTailscaleDetailWhenTailscaledDoesNotAnswer(t *testing.T) {
	f, _ := adapterRouter(t)
	f.fail("tailscale status --json", "failed to connect to local tailscaled; it doesn't appear to be running\nsecond line")
	out := listServices(t, serviceListIn{Detail: "tailscale"})
	body := detailBody(t, out)
	want := []string{"tailscaled is not responding: failed to connect to local tailscaled; it doesn't appear to be running"}
	if !reflect.DeepEqual(body, want) {
		t.Errorf("got %q, want %q", body, want)
	}
}

func TestTailscaleDetailWhenTheStatusIsNotJSON(t *testing.T) {
	f, _ := adapterRouter(t)
	for _, junk := range []string{"", "not json", `["a"]`, `{"BackendState": 5}`, `null`} {
		got := tsDetail(t, f, junk)
		if len(got) != 1 || !strings.HasPrefix(got[0], "tailscale status could not be read") {
			t.Errorf("status %q -> %q", junk, got)
		}
	}
}

func TestTailscaleDetailToleratesAPartialStatus(t *testing.T) {
	f, _ := adapterRouter(t)
	// A node that is running but has no self entry, no tailnet and no peers.
	got := tsDetail(t, f, `{"Version":"1.98.3","BackendState":"Running"}`)
	if got[0] != "tailscale 1.98.3: Running" || !contains(got, "peers: 0, 0 online") {
		t.Errorf("partial status: %q", got)
	}
}

func TestTailscaleDetailNamesPeersWhateverTheyCarry(t *testing.T) {
	f, _ := adapterRouter(t)
	got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		m["Peer"] = map[string]any{
			"a": map[string]any{"DNSName": "box.example.ts.net.", "Online": false, "LastSeen": "0001-01-01T00:00:00Z"},
			"b": map[string]any{"Online": false},
			"c": map[string]any{"HostName": "up", "OS": "linux", "Online": true, "TailscaleIPs": []any{"100.64.9.9"}},
			"d": nil,
		}
	}))
	want := []string{
		"peers: 3, 1 online",
		"up 100.64.9.9 linux online",
		"(unnamed) - - offline never seen",
		"box - - offline never seen",
	}
	if i := indexOf(got, want[0]); i < 0 || !reflect.DeepEqual(got[i:], want) {
		t.Errorf("peers:\n got %q\nwant %q", got, want)
	}
}

func indexOf(ss []string, s string) int {
	for i, x := range ss {
		if x == s {
			return i
		}
	}
	return -1
}

func TestTailscaleDetailThisNodeAndTailnet(t *testing.T) {
	f, _ := adapterRouter(t)
	got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		m["CurrentTailnet"].(map[string]any)["MagicDNSEnabled"] = true
		m["Self"].(map[string]any)["Online"] = false
	}))
	if got[1] != "tailnet: example.ts.net (MagicDNS on)" || got[2] != "this node: router 100.64.0.1 fd7a:115c:a1e0::1 offline" {
		t.Errorf("tailnet/node lines: %q", got[:3])
	}
	// No suffix, no tailnet line (the display name is not a substitute).
	got = tsDetail(t, f, tsVariant(t, func(m map[string]any) {
		m["CurrentTailnet"].(map[string]any)["MagicDNSSuffix"] = ""
	}))
	for _, l := range got {
		if strings.HasPrefix(l, "tailnet:") {
			t.Errorf("tailnet line without a suffix: %q", l)
		}
	}
}

func TestTailscaleDetailCapsHealthWarningsAtFive(t *testing.T) {
	f, _ := adapterRouter(t)
	five := []string{"health:", "- warning 1", "- warning 2", "- warning 3", "- warning 4", "- warning 5"}
	for n, want := range map[int][]string{
		5: five,
		6: append(append([]string(nil), five...), "- ... 1 more"),
		7: append(append([]string(nil), five...), "- ... 2 more"),
	} {
		got := tsDetail(t, f, tsVariant(t, func(m map[string]any) {
			var w []any
			for i := 1; i <= n; i++ {
				w = append(w, fmt.Sprintf("warning %d", i))
			}
			m["Health"] = w
		}))
		if i := indexOf(got, "health:"); i < 0 || !reflect.DeepEqual(got[i:i+len(want)], want) || got[i+len(want)] != "peers: 3, 2 online" {
			t.Errorf("%d warnings: %q", n, got)
		}
	}
}

func TestTailscaleDetailWhenTailscaledSaysNothingOrALot(t *testing.T) {
	f, _ := adapterRouter(t)
	f.fail("tailscale status --json", "")
	if got := detailBody(t, listServices(t, serviceListIn{Detail: "tailscale"})); !reflect.DeepEqual(got, []string{"tailscaled is not responding: exit status 1"}) {
		t.Errorf("silent failure: %q", got)
	}
	f.fail("tailscale status --json", strings.Repeat("e", 400))
	got := detailBody(t, listServices(t, serviceListIn{Detail: "tailscale"}))
	if len(got) != 1 || got[0] != "tailscaled is not responding: "+strings.Repeat("e", 160)+"…" {
		t.Errorf("long failure: %q", got)
	}
}

func FuzzRenderTailscale(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"BackendState":"Running","Peer":{"a":{"HostName":5}}}`, `{"Health":[1,null,"x"],"Self":[]}`,
		`{"Peer":{"a":null},"Self":{"TailscaleIPs":"x"}}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := renderTailscale(s)
		if strings.TrimSpace(out) == "" {
			t.Error("empty rendering")
		}
	})
}
