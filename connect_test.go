package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------- stand-ins for ssh and ssh-keygen
//
// connect and doctor drive the PC's own OpenSSH. A test cannot rely on it, so the test binary
// stands in for it: sshCommand and keygenCommand point back at this binary, which runs
// TestHelperFakeTool and behaves as the scenario in OPENWRT_FAKE_TOOL says. For a healthy router
// the fake serves the real MCP server over its stdin/stdout, so doctor talks to the real thing.

const fakePub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"

func fakeTool(t *testing.T, mode string) {
	t.Helper()
	t.Setenv("OPENWRT_FAKE_TOOL", mode)
	oldSSH, oldKeygen := sshCommand, keygenCommand
	self := []string{os.Args[0], "-test.run=^TestHelperFakeTool$", "--"}
	sshCommand, keygenCommand = self, self
	t.Cleanup(func() { sshCommand, keygenCommand = oldSSH, oldKeygen })
}

func TestHelperFakeTool(t *testing.T) {
	mode := os.Getenv("OPENWRT_FAKE_TOOL")
	if mode == "" {
		return // an ordinary run of the suite
	}
	args := os.Args
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	stderr := func(s string) { fmt.Fprint(os.Stderr, s) }
	switch mode {
	case "keygen":
		if log := os.Getenv("OPENWRT_FAKE_LOG"); log != "" {
			f, _ := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			fmt.Fprintf(f, "%q\n", args)
			f.Close()
		}
		for i, a := range args {
			switch a {
			case "-y":
				fmt.Println(fakePub + " derived")
				os.Exit(0)
			case "-f":
				_ = os.WriteFile(args[i+1], []byte("FAKE PRIVATE KEY\n"), 0o600)
				_ = os.WriteFile(args[i+1]+".pub", []byte(fakePub+" openwrt-mcp:claude-code\n"), 0o644)
				os.Exit(0)
			}
		}
		os.Exit(2)

	case "ssh:ok", "ssh:empty":
		srv := mcp.NewServer(&mcp.Implementation{Name: "openwrt-mcp", Version: "9.9.9"}, nil)
		if mode == "ssh:ok" {
			mcp.AddTool(srv, &mcp.Tool{Name: "system_status", Description: "a tool for the doctor to count"},
				func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
					return nil, nil, nil
				})
		}
		ss, err := srv.Connect(context.Background(), &mcp.StdioTransport{}, nil)
		if err != nil {
			os.Exit(3)
		}
		_ = ss.Wait()

	case "ssh:resolve":
		stderr("ssh: Could not resolve hostname router.invalid: Name or service not known\n")
		os.Exit(255)
	case "ssh:refused":
		stderr("ssh: connect to host 192.0.2.1 port 22: Connection refused\n")
		os.Exit(255)
	case "ssh:timeout":
		stderr("ssh: connect to host 192.0.2.1 port 22: Connection timed out\n")
		os.Exit(255)
	case "ssh:hostkey-unknown":
		stderr("No ED25519 host key is known for 192.0.2.1 and you have requested strict checking.\nHost key verification failed.\n")
		os.Exit(255)
	case "ssh:hostkey-changed":
		stderr("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
			"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\nHost key verification failed.\n")
		os.Exit(255)
	case "ssh:denied":
		stderr("root@192.0.2.1: Permission denied (publickey,password).\n")
		os.Exit(255)
	case "ssh:key-too-open":
		stderr("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @\n" +
			"Permissions 0644 for 'k' are too open.\nroot@192.0.2.1: Permission denied (publickey).\n")
		os.Exit(255)
	case "ssh:no-key-file":
		stderr("Warning: Identity file /nope/k not accessible: No such file or directory.\nroot@192.0.2.1: Permission denied (publickey).\n")
		os.Exit(255)
	case "ssh:daemon-down":
		stderr("openwrt-mcp: daemon not reachable on /var/run/openwrt-mcp/mcp.sock (is it running? /etc/init.d/openwrt-mcp start): dial unix /var/run/openwrt-mcp/mcp.sock: connect: no such file or directory\n")
		os.Exit(1)
	case "ssh:bridge-disabled":
		stderr("openwrt-mcp: the stdio bridge is disabled (option socket '' in /etc/config/openwrt-mcp)\n")
		os.Exit(1)
	case "ssh:shell":
		// A key authorized without its forced command: a shell reads our JSON and complains.
		_, _ = io.Copy(io.Discard, os.Stdin)
		stderr("sh: {\"jsonrpc\":\"2.0\"...: not found\n")
		os.Exit(127)
	case "ssh:silent":
		time.Sleep(time.Minute)
	case "ssh:banner":
		fmt.Println("Welcome to OpenWrt!")
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

// ---------------------------------------------------------------- connect

func testEnv(t *testing.T, goos string) connectEnv {
	t.Helper()
	dir := t.TempDir()
	return connectEnv{goos: goos, home: filepath.Join(dir, "home"), appdata: filepath.Join(dir, "appdata"), cwd: filepath.Join(dir, "work")}
}

func connectOK(t *testing.T, env connectEnv, p connectParams, write, replace bool) string {
	t.Helper()
	var out, errs bytes.Buffer
	if err := runConnect(&out, &errs, env, p, write, replace, ""); err != nil {
		t.Fatalf("connect: %v\n%s%s", err, out.String(), errs.String())
	}
	return out.String()
}

func TestConnectMakesTheKeyAndPrintsThePlanWithoutTouchingTheClient(t *testing.T) {
	fakeTool(t, "keygen")
	log := filepath.Join(t.TempDir(), "keygen.log")
	t.Setenv("OPENWRT_FAKE_LOG", log)
	env := testEnv(t, "linux")
	p := testParams()
	p.Key = "~/.ssh/openwrt_mcp"

	out := connectOK(t, env, p, false, false)
	key := filepath.Join(env.home, ".ssh", "openwrt_mcp")
	if _, err := os.Stat(key); err != nil {
		t.Fatalf("no key was made: %v", err)
	}
	for _, want := range []string{
		"Made the key " + key,
		// The comment in the .pub is free text and must not reach the command the operator pastes.
		"openwrt-mcp authorize-key claude-code '" + fakePub + "'",
		"openwrt-mcp allow claude-code @readonly 30d",
		"ssh -p 22 root@192.0.2.1",
		`"mcpServers"`, `"command": "ssh"`,
		"connect doctor --host 192.0.2.1",
		"host key", // step 2 is where the operator accepts it
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "openwrt-mcp:claude-code") {
		t.Errorf("the key comment leaked into the plan:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(env.home, ".cursor", "mcp.json")); err == nil {
		t.Error("the client's config was written without --write")
	}

	// The key was asked for as ed25519, with an empty passphrase and a comment naming the client.
	logged, _ := os.ReadFile(log)
	for _, want := range []string{`"-t" "ed25519"`, `"-N" ""`, `"-C" "openwrt-mcp:claude-code"`, `"-f" "` + filepath.ToSlash(key)} {
		if !strings.Contains(strings.ReplaceAll(string(logged), `\\`, "/"), want) {
			t.Errorf("ssh-keygen was not run with %s:\n%s", want, logged)
		}
	}

	// A second run reuses the key and never overwrites it.
	if err := os.WriteFile(key, []byte("MY OWN KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = connectOK(t, env, p, false, false)
	if !strings.Contains(out, "already there") {
		t.Errorf("second run:\n%s", out)
	}
	if b, _ := os.ReadFile(key); string(b) != "MY OWN KEY" {
		t.Errorf("an existing key was overwritten: %q", b)
	}
	if n := strings.Count(string(mustRead(t, log)), "\n"); n != 1 {
		t.Errorf("ssh-keygen ran %d times, want once", n)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The public key ends up inside a command the operator pastes into a shell on the router, so only
// "<type> <base64>" may pass; the comment is free text and is dropped.
func TestPublicKeyOnlyEverCarriesATypeAndBase64(t *testing.T) {
	dir := t.TempDir()
	for body, want := range map[string]string{
		"ssh-ed25519 AAAAC3Nza comment here\n":                "ssh-ed25519 AAAAC3Nza",
		"ssh-rsa AAAAB3NzaC1yc2E+/= me@pc\n":                  "ssh-rsa AAAAB3NzaC1yc2E+/=",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNh x\n":                "ecdsa-sha2-nistp256 AAAAE2VjZHNh",
		"sk-ssh-ed25519@openssh.com AAAAGnNr c\n":             "sk-ssh-ed25519@openssh.com AAAAGnNr",
		"ssh-ed25519 AAAA';reboot;'\n":                        "",
		"ssh-ed25519 AAAA$(id)\n":                             "",
		"ssh-ed25519 AAAA\"x\n":                               "",
		"ssh-ed25519 AAAA`id`\n":                              "",
		"ssh-ed25519 AAAA\\ x\n":                              "",
		"ssh-dss AAAAB3NzaC1kc3M\n":                           "",
		"ssh-ed25519\n":                                       "",
		"command=\"/bin/sh\" ssh-ed25519 AAAAC3Nza comment\n": "",
	} {
		key := filepath.Join(dir, "k")
		if err := os.WriteFile(key+".pub", []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := publicKey(key)
		if want == "" {
			if err == nil {
				t.Errorf("%q was accepted as %q", body, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", body, got, err, want)
		}
	}
}

func TestConnectWriteMergesIntoTheClientFile(t *testing.T) {
	fakeTool(t, "keygen")
	env := testEnv(t, "linux")
	cfg := filepath.Join(env.home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(`{"mcpServers":{"mine":{"command":"node","args":["x.js"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := testParams()
	p.Key = filepath.Join(env.home, ".ssh", "k")

	out := connectOK(t, env, p, true, false)
	b := string(mustRead(t, cfg))
	for _, want := range []string{`"mine"`, `"openwrt"`, `"command": "ssh"`, "BatchMode=yes", "ServerAliveInterval=30"} {
		if !strings.Contains(b, want) {
			t.Errorf("config lacks %s:\n%s", want, b)
		}
	}
	if !strings.Contains(out, "Wrote "+cfg) {
		t.Errorf("no report of the write:\n%s", out)
	}
	if again := connectOK(t, env, p, true, false); !strings.Contains(again, "already has exactly this entry") {
		t.Errorf("an unchanged entry was reported as a change:\n%s", again)
	}

	// A different router under the same name is not silently replaced.
	other := p
	other.Host = "198.51.100.7"
	var out2, errs bytes.Buffer
	err := runConnect(&out2, &errs, env, other, true, false, "")
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("a different openwrt entry was overwritten without --replace: %v", err)
	}
	connectOK(t, env, other, true, true)
	if !strings.Contains(string(mustRead(t, cfg)), "198.51.100.7") || !strings.Contains(string(mustRead(t, cfg)), `"mine"`) {
		t.Errorf("--replace lost the new host or the other server:\n%s", mustRead(t, cfg))
	}
}

// VS Code files may carry comments, which we cannot rewrite faithfully: leave them alone and say what to add.
func TestConnectWriteRefusesAFileItCannotParse(t *testing.T) {
	fakeTool(t, "keygen")
	env := testEnv(t, "linux")
	p := testParams()
	p.Client, p.Key = "vscode", filepath.Join(env.home, ".ssh", "k")
	cfg := filepath.Join(env.cwd, ".vscode", "mcp.json")
	text := "{\n  // my servers\n  \"servers\": {}\n}\n"
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	err := runConnect(&out, &errs, env, p, true, false, "")
	if err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("a commented file: %v", err)
	}
	if !strings.Contains(out.String(), `"type": "stdio"`) || !strings.Contains(out.String(), `"servers"`) {
		t.Errorf("the snippet to add by hand is missing or lacks VS Code's shape:\n%s", out.String())
	}
	if string(mustRead(t, cfg)) != text {
		t.Error("the commented file was changed")
	}
}

func TestConnectKeyPathsWithSpacesStayWholeInFilesAndAreQuotedOnScreen(t *testing.T) {
	fakeTool(t, "keygen")
	env := testEnv(t, "windows")
	env.home = filepath.Join(env.home, "Ann Lee")
	p := testParams()
	p.Client, p.Key = "cursor", filepath.Join(env.home, ".ssh", "openwrt mcp")

	out := connectOK(t, env, p, true, false)
	if !strings.Contains(out, `--key "`+p.Key+`"`) { // the doctor line is the one a shell sees
		t.Errorf("the key path is not quoted on screen for Windows:\n%s", out)
	}
	cfg := filepath.Join(env.home, ".cursor", "mcp.json")
	b := mustRead(t, cfg)
	var doc struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	args := doc.MCPServers["openwrt"].Args
	if len(args) < 3 || args[1] != "-i" || args[2] != p.Key {
		t.Errorf("the key path was split or altered in the file: %q", args)
	}
	if bytes.Contains(b, []byte("\r\n")) || bytes.HasPrefix(b, []byte("\xef\xbb\xbf")) {
		t.Error("the file has CRLF line endings or a byte-order mark")
	}
	if strings.Contains(out, "\r") {
		t.Error("CRs in the printed plan: pasted into a shell on the router they would break the command")
	}
}

func TestConnectRefusesBadInputBeforeMakingAnything(t *testing.T) {
	fakeTool(t, "keygen")
	env := testEnv(t, "linux")
	for name, mutate := range map[string]func(*connectParams){
		"a host that is an ssh option": func(p *connectParams) { p.Host = "-oProxyCommand=calc" },
		"an unknown client":            func(p *connectParams) { p.Client = "notepad" },
		"a client name with a quote":   func(p *connectParams) { p.Name = "a'b" },
	} {
		p := testParams()
		p.Key = filepath.Join(env.home, ".ssh", "k")
		mutate(&p)
		var out, errs bytes.Buffer
		if err := runConnect(&out, &errs, env, p, true, false, ""); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if _, err := os.Stat(p.Key); err == nil {
			t.Errorf("%s: a key was made anyway", name)
		}
	}
	var out, errs bytes.Buffer
	p := testParams()
	p.Client = "claude-desktop"
	p.Key = filepath.Join(env.home, ".ssh", "k")
	if err := runConnect(&out, &errs, env, p, true, false, ""); err == nil || !strings.Contains(err.Error(), "linux") {
		t.Errorf("Claude Desktop on Linux: %v", err)
	}
}

func TestConnectCLIClientsRunTheirOwnCommandOnlyWithWrite(t *testing.T) {
	fakeTool(t, "keygen")
	env := testEnv(t, "linux")
	p := testParams()
	p.Client, p.Key = "claude-code", filepath.Join(env.home, ".ssh", "k")

	var ran [][]string
	var found = true
	var runErr error
	old := clientCLI
	clientCLI = func(argv []string, _, _ io.Writer) (bool, error) {
		ran = append(ran, argv)
		return found, runErr
	}
	t.Cleanup(func() { clientCLI = old })

	out := connectOK(t, env, p, false, false)
	if len(ran) != 0 || !strings.Contains(out, "claude mcp add --scope user openwrt --") {
		t.Errorf("without --write: ran %v, output:\n%s", ran, out)
	}
	connectOK(t, env, p, true, false)
	if len(ran) != 1 || strings.Join(ran[0][:7], " ") != "claude mcp add --scope user openwrt --" {
		t.Errorf("with --write ran %v", ran)
	}

	found = false
	if out := connectOK(t, env, p, true, false); !strings.Contains(out, "not on this PC's PATH") {
		t.Errorf("a client that is not installed:\n%s", out)
	}
	found, runErr = true, errors.New("exit status 1")
	var o, e bytes.Buffer
	if err := runConnect(&o, &e, env, p, true, false, ""); err == nil || !strings.Contains(err.Error(), "claude failed") {
		t.Errorf("a failing client command: %v", err)
	}
}
