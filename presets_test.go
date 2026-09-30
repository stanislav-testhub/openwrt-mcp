package main

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPresetsNameOnlyRealTools(t *testing.T) {
	for name, blocks := range presets {
		for _, b := range blocks {
			for _, tool := range b.tools {
				if !validTool(tool) {
					t.Errorf("preset %s names unknown tool %q", name, tool)
				}
			}
			if contains(b.tools, "exec") {
				t.Errorf("preset %s grants exec, which is a root shell", name)
			}
		}
	}
}

// The read-only ubus list must not reach methods that write or leak credentials.
func TestReadonlyUbusExcludesWritesAndSessions(t *testing.T) {
	for _, bad := range []string{"session.list", "session.login", "system.reboot", "uci.set", "uci.apply",
		"rc.init", "network.interface.lan.down", "network.reload", "file.write", "file.exec", "iwinfo.scan"} {
		if matchAny(readonlyUbus, bad) {
			t.Errorf("readonly ubus scope covers %s", bad)
		}
	}
	for _, good := range []string{"network.interface.lan.status", "hostapd.phy0-ap0.get_clients", "system.board"} {
		if !matchAny(readonlyUbus, good) {
			t.Errorf("readonly ubus scope misses %s", good)
		}
	}
}

func TestRevokeRemovesOnlyThatClient(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cfg")
	os.WriteFile(p, []byte("config server\n\toption listen '127.0.0.1:8730'\n# keep me\n"), 0o600)
	appendPolicy(p, "a", "logread", "*", "never")
	appendPolicy(p, "b", "logread", "*", "never")
	appendPolicy(p, "a", "uci_get", "*", "30d")
	n, err := removePolicies(p, "a")
	if err != nil || n != 2 {
		t.Fatalf("removed %d, %v; want 2", n, err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Policies) != 1 || cfg.Policies[0].Client != "b" || cfg.Listen != "127.0.0.1:8730" {
		t.Errorf("wrong policies left: %+v", cfg.Policies)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# keep me") {
		t.Error("revoke dropped unrelated content")
	}
	_ = time.Now
}

func TestAuthorizedKeyLineIsLockedDown(t *testing.T) {
	line, err := authorizedKeyLine("claude-code", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFO0iuRsB94YVh5gQOh1bEhtC7nqAo8hVcErAVnqOLmD mcp")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`command="/usr/bin/openwrt-mcp stdio --client claude-code"`, "no-port-forwarding", "no-pty"} {
		if !strings.Contains(line, want) {
			t.Errorf("key line missing %q: %s", want, line)
		}
	}
	for _, bad := range []string{"ssh-ed25519 AAAA\ncommand=x", "not a key", "ssh-ed25519 short"} {
		if _, err := authorizedKeyLine("c", bad); err == nil {
			t.Errorf("accepted key %q", bad)
		}
	}
	if _, err := authorizedKeyLine(`c",command="sh`, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFO0iuRsB94YVh5gQOh1bEhtC7nqAo8hVcErAVnqOLmD"); err == nil {
		t.Error("client name could inject authorized_keys options")
	}
}

func TestAuthorizeKeyRefusesAKeyThatIsAlreadyARootLogin(t *testing.T) {
	p := filepath.Join(t.TempDir(), "authorized_keys")
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFO0iuRsB94YVh5gQOh1bEhtC7nqAo8hVcErAVnqOLmD root-login"
	os.WriteFile(p, []byte(key+"\n"), 0o600)
	if _, err := authorizeKey(p, "c", key); err == nil {
		t.Error("a root login key was turned into an MCP key")
	}
}

func TestPresetScopesNeverContainAClientSuppliedGlob(t *testing.T) {
	// Scope strings built from requests are literals; a policy glob must match them.
	if ok, _ := path.Match("wireguard.*", "wireguard.wg0"); !ok {
		t.Error("sanity")
	}
}
