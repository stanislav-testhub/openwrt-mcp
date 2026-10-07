package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ROADMAP 3.2, the client side. Expected shapes are the ones each client documents (see the
// list in clientcfg.go), written out here, not produced by the code under test.

func testParams() connectParams {
	return connectParams{Client: "cursor", Name: "claude-code", Host: "192.0.2.1", Port: 22, User: "root", Key: "/home/u/.ssh/openwrt_mcp"}
}

func TestSSHArgsAreTheDocumentedBridgeCommand(t *testing.T) {
	got := strings.Join(testParams().sshArgs(), " ")
	want := "-T -i /home/u/.ssh/openwrt_mcp -p 22 -o BatchMode=yes -o IdentitiesOnly=yes " +
		"-o ServerAliveInterval=30 -o ServerAliveCountMax=3 root@192.0.2.1"
	if got != want {
		t.Errorf("ssh args:\n got  %s\n want %s", got, want)
	}
}

func TestConnectParamsRefuseWhatCouldBecomeAnSSHOption(t *testing.T) {
	ok := testParams()
	if err := ok.validate(); err != nil {
		t.Fatalf("a good set of parameters: %v", err)
	}
	for name, mutate := range map[string]func(*connectParams){
		"host starting with a dash": func(p *connectParams) { p.Host = "-oProxyCommand=calc" },
		"host that is just -v":      func(p *connectParams) { p.Host = "-v" },
		"host that is -J<jump>":     func(p *connectParams) { p.Host = "-Jevil" },
		"host with a space":         func(p *connectParams) { p.Host = "a b" },
		"host with a user":          func(p *connectParams) { p.Host = "root@router" },
		"empty host":                func(p *connectParams) { p.Host = "" },
		"port 0":                    func(p *connectParams) { p.Port = 0 },
		"port too big":              func(p *connectParams) { p.Port = 70000 },
		"user in capitals":          func(p *connectParams) { p.User = "Root" },
		"user with a dash first":    func(p *connectParams) { p.User = "-root" },
		"name with a space":         func(p *connectParams) { p.Name = "a b" },
		"name with a quote":         func(p *connectParams) { p.Name = "a'b" },
		"key starting with a dash":  func(p *connectParams) { p.Key = "-i" },
		"empty key":                 func(p *connectParams) { p.Key = "" },
	} {
		p := ok
		mutate(&p)
		if err := p.validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, host := range []string{"router.lan", "192.168.1.1", "fe80::1", "fe80::1%eth0", "my-router"} {
		p := ok
		p.Host = host
		if err := p.validate(); err != nil {
			t.Errorf("host %q refused: %v", host, err)
		}
	}
}

func TestClientConfigPathsPerClientAndOS(t *testing.T) {
	const home, appdata, cwd = "/h", "/h/AppData/Roaming", "/w"
	for _, tc := range []struct {
		goos, client, want string
	}{
		{"linux", "cursor", "/h/.cursor/mcp.json"},
		{"windows", "cursor", "/h/.cursor/mcp.json"},
		{"linux", "gemini", "/h/.gemini/settings.json"},
		{"darwin", "gemini", "/h/.gemini/settings.json"},
		{"linux", "vscode", "/w/.vscode/mcp.json"},
		{"windows", "claude-desktop", "/h/AppData/Roaming/Claude/claude_desktop_config.json"},
		{"darwin", "claude-desktop", "/h/Library/Application Support/Claude/claude_desktop_config.json"},
	} {
		got, err := clientConfigPath(tc.goos, tc.client, home, appdata, cwd)
		if err != nil || filepath.ToSlash(got) != tc.want {
			t.Errorf("%s on %s: %q, %v; want %q", tc.client, tc.goos, got, err, tc.want)
		}
	}
	if _, err := clientConfigPath("linux", "claude-desktop", home, appdata, cwd); err == nil {
		t.Error("Claude Desktop has no Linux build; a path was invented for it")
	}
	if _, err := clientConfigPath("windows", "claude-desktop", home, "", cwd); err == nil {
		t.Error("Claude Desktop on Windows with no %APPDATA% got a path")
	}
	for _, c := range []string{"claude-code", "codex"} {
		if _, err := clientConfigPath("linux", c, home, appdata, cwd); err == nil {
			t.Errorf("%s is configured by its own command, but got a file path", c)
		}
	}
}

func TestCLIClientsGetTheirDocumentedAddCommand(t *testing.T) {
	p := testParams()
	ssh := "ssh -T -i /home/u/.ssh/openwrt_mcp -p 22 -o BatchMode=yes -o IdentitiesOnly=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 root@192.0.2.1"
	for client, want := range map[string]string{
		"claude-code": "claude mcp add --scope user openwrt -- " + ssh,
		"codex":       "codex mcp add openwrt -- " + ssh,
	} {
		if got := strings.Join(cliAddArgv(client, p), " "); got != want {
			t.Errorf("%s:\n got  %s\n want %s", client, got, want)
		}
	}
}

func TestMergeServerKeepsEverythingElseAndEscapesNothing(t *testing.T) {
	entry := serverEntry(testParams(), false)
	existing := `{
  "globalShortcut": "Ctrl+Space",
  "mcpServers": {
    "other": {"command": "sh", "args": ["-c", "a && b <c>"]}
  }
}`
	out, changed, err := mergeServer([]byte(existing), "mcpServers", entry, false)
	if err != nil || !changed {
		t.Fatalf("merge: changed %v, %v", changed, err)
	}
	if !strings.Contains(string(out), "a && b <c>") {
		t.Errorf("another server's arguments were rewritten (HTML-escaped?):\n%s", out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["globalShortcut"] != "Ctrl+Space" {
		t.Errorf("a top-level setting was lost: %v", doc)
	}
	servers := doc["mcpServers"].(map[string]any)
	if len(servers) != 2 || servers["other"] == nil || servers["openwrt"] == nil {
		t.Fatalf("servers: %v", servers)
	}
	e := servers["openwrt"].(map[string]any)
	if e["command"] != "ssh" || len(e["args"].([]any)) != 14 || e["type"] != nil {
		t.Errorf("openwrt entry: %v", e)
	}

	// The same entry again changes nothing and returns the document untouched.
	again, changed, err := mergeServer(out, "mcpServers", entry, false)
	if err != nil || changed || string(again) != string(out) {
		t.Errorf("merging the same entry twice: changed %v err %v", changed, err)
	}
}

func TestMergeServerCases(t *testing.T) {
	typed := serverEntry(testParams(), true)
	if typed["type"] != "stdio" {
		t.Errorf("VS Code needs the type: %v", typed)
	}
	for _, empty := range []string{"", "  \n"} {
		out, changed, err := mergeServer([]byte(empty), "servers", typed, false)
		if err != nil || !changed || !strings.Contains(string(out), `"servers"`) || !strings.Contains(string(out), `"type": "stdio"`) {
			t.Errorf("an empty file %q: %s, %v, %v", empty, out, changed, err)
		}
	}

	other := map[string]any{"command": "ssh", "args": []string{"somewhere-else"}}
	have, _, _ := mergeServer(nil, "mcpServers", other, false)
	if _, _, err := mergeServer(have, "mcpServers", serverEntry(testParams(), false), false); !errors.Is(err, errExists) {
		t.Errorf("a different openwrt entry was overwritten without --replace: %v", err)
	}
	out, changed, err := mergeServer(have, "mcpServers", serverEntry(testParams(), false), true)
	if err != nil || !changed || strings.Contains(string(out), "somewhere-else") {
		t.Errorf("--replace did not replace: %s %v %v", out, changed, err)
	}

	for name, doc := range map[string]string{
		"a comment":      "{\n // keep\n \"servers\": {}\n}",
		"trailing comma": `{"servers": {},}`,
		"not an object":  `["servers"]`,
		"half a file":    `{"servers": {`,
	} {
		if _, _, err := mergeServer([]byte(doc), "servers", typed, false); !errors.Is(err, errNotJSON) {
			t.Errorf("%s: want errNotJSON, got %v", name, err)
		}
	}
	if _, _, err := mergeServer([]byte(`{"servers": 3}`), "servers", typed, false); err == nil || errors.Is(err, errNotJSON) {
		t.Errorf("servers that is not an object: %v", err)
	}
}

func TestWriteClientConfigCreatesKeepsTheOriginalOnceAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deep", "er", "mcp.json")
	entry := serverEntry(testParams(), false)

	if changed, err := writeClientConfig(path, "mcpServers", entry, false); err != nil || !changed {
		t.Fatalf("new file: changed %v, %v", changed, err)
	}
	if _, err := os.Stat(path + ".before-openwrt-mcp"); err == nil {
		t.Error("a backup was made of a file that did not exist")
	}

	original := `{"mcpServers": {"keep": {"command": "x"}}, "other": 1}`
	path2 := filepath.Join(dir, "claude.json")
	if err := os.WriteFile(path2, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeClientConfig(path2, "mcpServers", entry, false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path2 + ".before-openwrt-mcp"); string(b) != original {
		t.Errorf("the original was not kept:\n%s", b)
	}
	// A later change must not replace the first backup with our own output.
	entry2 := serverEntry(testParams(), false)
	entry2["args"] = []string{"changed"}
	if _, err := writeClientConfig(path2, "mcpServers", entry2, true); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path2 + ".before-openwrt-mcp"); string(b) != original {
		t.Errorf("the backup no longer holds the original:\n%s", b)
	}

	// A file we cannot parse is left exactly as it was.
	bad := filepath.Join(dir, "commented.json")
	text := "{\n// my servers\n\"servers\": {}\n}\n"
	if err := os.WriteFile(bad, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeClientConfig(bad, "servers", entry, false); !errors.Is(err, errNotJSON) {
		t.Errorf("commented file: %v", err)
	}
	if b, _ := os.ReadFile(bad); string(b) != text {
		t.Errorf("a file we refused was changed:\n%s", b)
	}

	var stray []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
		if strings.Contains(filepath.Base(p), ".tmp") {
			stray = append(stray, p)
		}
		return nil
	})
	if len(stray) != 0 {
		t.Errorf("temp files left behind: %v", stray)
	}
}

// What the operator pastes must survive spaces in the key path and quotes in names, in the
// style of the shell they are using. The files we write need none of this: they hold arrays.
func TestQuotingForDisplayPerShell(t *testing.T) {
	for _, tc := range []struct {
		goos string
		in   []string
		want string
	}{
		{"linux", []string{"ssh", "-i", "/home/u/.ssh/key"}, "ssh -i /home/u/.ssh/key"},
		{"linux", []string{"ssh", "-i", "/home/a b/.ssh/key"}, "ssh -i '/home/a b/.ssh/key'"},
		{"linux", []string{"x", "it's"}, `x 'it'\''s'`},
		{"linux", []string{"x", ""}, "x ''"},
		{"darwin", []string{"x", "$HOME"}, "x '$HOME'"},
		{"windows", []string{"ssh", "-i", `C:\Users\Ann Lee\.ssh\openwrt_mcp`}, `ssh -i "C:\Users\Ann Lee\.ssh\openwrt_mcp"`},
		{"windows", []string{"ssh", "-i", `C:\Users\ann\.ssh\k`}, `ssh -i C:\Users\ann\.ssh\k`},
		{"windows", []string{"x", `say "hi"`}, `x "say \"hi\""`},
		{"windows", []string{"x", ""}, `x ""`},
	} {
		if got := quoteCommand(tc.goos, tc.in); got != tc.want {
			t.Errorf("%s %q:\n got  %s\n want %s", tc.goos, tc.in, got, tc.want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	for in, want := range map[string]string{
		"~": "/h", "~/.ssh/k": "/h/.ssh/k", `~\.ssh\k`: "/h/.ssh/k", "/abs/k": "/abs/k", "rel/k": "rel/k", "~user/k": "~user/k",
	} {
		if got := filepath.ToSlash(expandHome(in, "/h")); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}
