package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Milestone 8.7. Pair from LuCI is an optional channel: off after install, audited when switched,
// and with a harm notice the Settings tab can show.

func (r *rpcdRig) pairRig() string {
	r.t.Helper()
	keys := filepath.Join(filepath.Dir(r.env.configPath), "authorized_keys")
	r.env.authKeysPath = keys
	return keys
}

func TestEveryChannelIsOffAfterInstallAndCarriesItsHarmNotice(t *testing.T) {
	r := newRig(t)
	m := r.ok("settings", nil)
	list, _ := m["channels"].([]any)
	if len(list) != len(channels) || len(list) == 0 {
		t.Fatalf("settings lists %d channels, want %d", len(list), len(channels))
	}
	for _, x := range list {
		c := x.(map[string]any)
		if c["enabled"] != false {
			t.Errorf("channel %v is on after install", c["name"])
		}
		if h, _ := c["harm"].(string); len(h) < 40 {
			t.Errorf("channel %v has no harm notice: %q", c["name"], h)
		}
		if title, _ := c["title"].(string); title == "" {
			t.Errorf("channel %v has no title", c["name"])
		}
	}
	// The shipped config template must not switch any on.
	b, err := os.ReadFile("files/etc/config/openwrt-mcp")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range channels {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 3 && f[0] == "option" && f[1] == c.option && f[2] != "'0'" {
				t.Errorf("the shipped config turns %s on: %q", c.Name, l)
			}
		}
	}
}

func TestSwitchingAChannelIsAuditedAndKeepsTheRestOfTheFile(t *testing.T) {
	r := newRig(t)
	r.ok("set_channel", map[string]any{"channel": "pair", "enabled": true})
	if !r.config().Pairing {
		t.Error("the switch did not turn pairing on")
	}
	if !strings.Contains(r.audit(), `"set_channel"`) || !strings.Contains(r.audit(), "pairing=1") {
		t.Errorf("the switch is not audited: %s", r.audit())
	}
	if r.config().RequestWait == 0 {
		t.Error("switching a channel lost another setting")
	}
	r.ok("set_channel", map[string]any{"channel": "pair", "enabled": false})
	if r.config().Pairing {
		t.Error("the switch did not turn pairing off")
	}
	r.fails("set_channel", map[string]any{"channel": "nope", "enabled": true}, "channel")
	r.fails("set_channel", map[string]any{"channel": "pair"}, "enabled")
}

func TestPairIsRefusedWhileTheChannelIsOffAndWritesNothing(t *testing.T) {
	r := newRig(t)
	keys := r.pairRig()
	r.fails("pair", map[string]any{"client": "laptop", "pubkey": testPubKey}, "off")
	if _, err := os.Stat(keys); err == nil {
		t.Error("a refused pairing wrote authorized_keys")
	}
	if len(r.config().Policies) != 0 {
		t.Error("a refused pairing wrote a grant")
	}
}

func TestPairWritesTheCLIsKeyLineAndAStartingPreset(t *testing.T) {
	r := newRig(t)
	keys := r.pairRig()
	r.ok("set_channel", map[string]any{"channel": "pair", "enabled": true})
	r.ok("pair", map[string]any{"client": "laptop", "pubkey": testPubKey})
	got, _ := os.ReadFile(keys)
	want, _ := authorizedKeyLine("laptop", testPubKey)
	if strings.TrimSpace(string(got)) != want {
		t.Errorf("authorized_keys holds %q, want the CLI's %q", got, want)
	}
	if !r.allowed("laptop", "uci_get", "network") || r.allowed("laptop", "uci_apply", "network.lan") {
		t.Error("the default starting preset is not read-only")
	}
	a := r.audit()
	if !strings.Contains(a, `"pair"`) || strings.Contains(a, "AAAAC3NzaC1lZDI1NTE5") {
		t.Errorf("audit should record the pairing without the key itself: %s", a)
	}

	r.ok("pair", map[string]any{"client": "op", "pubkey": strings.Replace(testPubKey, "FO0iu", "FO0iv", 1), "preset": "operator", "duration": "8h"})
	if !r.allowed("op", "uci_apply", "network.lan") {
		t.Error("the operator preset was not granted")
	}
}

func TestPairCanLeaveTheKeyWithNoGrantAndRefusesBadInput(t *testing.T) {
	r := newRig(t)
	keys := r.pairRig()
	r.ok("set_channel", map[string]any{"channel": "pair", "enabled": true})
	r.ok("pair", map[string]any{"client": "quiet", "pubkey": testPubKey, "preset": "none"})
	if len(r.config().Policies) != 0 {
		t.Error("preset none still granted something")
	}
	before, _ := os.ReadFile(keys)
	for name, in := range map[string]map[string]any{
		"not a key":        {"client": "x", "pubkey": "hello world"},
		"bad client":       {"client": "bad name!", "pubkey": testPubKey},
		"unknown preset":   {"client": "x", "pubkey": strings.Replace(testPubKey, "FO0iu", "FO0iw", 1), "preset": "all"},
		"bad duration":     {"client": "x", "pubkey": strings.Replace(testPubKey, "FO0iu", "FO0ix", 1), "duration": "30d"},
		"duplicate key":    {"client": "y", "pubkey": testPubKey},
		"option injection": {"client": "x", "pubkey": testPubKey + "\ncommand=\"sh\" ssh-ed25519 AAAA"},
	} {
		if m := r.call("pair", in); m["error"] == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if after, _ := os.ReadFile(keys); string(after) != string(before) {
		t.Errorf("a refused pairing changed authorized_keys:\n%s", after)
	}
}
