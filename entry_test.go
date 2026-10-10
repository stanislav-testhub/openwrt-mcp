package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The SSH forced command is fixed (`openwrt-mcp stdio --client X`); what a client types after the
// host name arrives as SSH_ORIGINAL_COMMAND. That string is the one input of the bridge a client
// controls, so the grammar is an allow-list that can only narrow a session and never names a
// client, a path or a shell.

func TestParseEntryAccepts(t *testing.T) {
	for _, c := range []struct {
		name, in string
		want     entry
	}{
		{"empty is the plain bridge", "", entry{Mode: entryStdio}},
		{"blank", " \t ", entry{Mode: entryStdio}},
		{"read-only", "--read-only", entry{Mode: entryStdio, ReadOnly: true}},
		{"a trailing line end is ignored", "--read-only\r\n", entry{Mode: entryStdio, ReadOnly: true}},
		{"one toolset", "--toolset diag", entry{Mode: entryStdio, Toolsets: []string{"diag"}}},
		{"toolset with =", "--toolset=diag,pkg", entry{Mode: entryStdio, Toolsets: []string{"diag", "pkg"}}},
		{"toolsets come out in canonical order", "--toolset wg,config,diag", entry{Mode: entryStdio, Toolsets: []string{"diag", "config", "wg"}}},
		{"all four toolsets", "--toolset pkg,wg,config,diag", entry{Mode: entryStdio, Toolsets: []string{"diag", "config", "pkg", "wg"}}},
		{"both options", "--read-only --toolset wg", entry{Mode: entryStdio, ReadOnly: true, Toolsets: []string{"wg"}}},
		{"options in the other order", "--toolset wg --read-only", entry{Mode: entryStdio, ReadOnly: true, Toolsets: []string{"wg"}}},
		{"extra blanks and tabs", "  --read-only\t\t--toolset   wg  ", entry{Mode: entryStdio, ReadOnly: true, Toolsets: []string{"wg"}}},
		{"call without arguments", "call system_status", entry{Mode: entryCall, Tool: "system_status", Args: "{}"}},
		{"call --list", "call --list", entry{Mode: entryCall, List: true}},
		{"call --list under a profile", "--read-only --toolset wg call  --list ", entry{Mode: entryCall, List: true, ReadOnly: true, Toolsets: []string{"wg"}}},
		{"call TOOL --help", "call uci_get --help", entry{Mode: entryCall, Tool: "uci_get", Help: true}},
		{"help with extra blanks", "call uci_get 	 --help  ", entry{Mode: entryCall, Tool: "uci_get", Help: true}},
		{"call with arguments", `call uci_get {"config":"network"}`, entry{Mode: entryCall, Tool: "uci_get", Args: `{"config":"network"}`}},
		{"the JSON keeps its own spaces", "call exec  \t{\"argv\": [\"ls\", \"/tmp\"]}\n", entry{Mode: entryCall, Tool: "exec", Args: `{"argv": ["ls", "/tmp"]}`}},
		{"options before call", `--read-only --toolset diag call logread {"lines":5}`, entry{Mode: entryCall, ReadOnly: true, Toolsets: []string{"diag"}, Tool: "logread", Args: `{"lines":5}`}},
		{"the word call inside the JSON is data", `call uci_get {"section":"call --client x"}`, entry{Mode: entryCall, Tool: "uci_get", Args: `{"section":"call --client x"}`}},
		{"non-ASCII text in JSON", `call uci_get {"name":"Küche"}`, entry{Mode: entryCall, Tool: "uci_get", Args: `{"name":"Küche"}`}},
		{"tool name at the length limit", "call a" + strings.Repeat("b", 39), entry{Mode: entryCall, Tool: "a" + strings.Repeat("b", 39), Args: "{}"}},
	} {
		got, err := parseEntry(c.in)
		if err != nil {
			t.Errorf("%s: %q refused: %v", c.name, c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q = %+v, want %+v", c.name, c.in, got, c.want)
		}
	}
}

func TestParseEntryRefuses(t *testing.T) {
	for name, in := range map[string]string{
		// anything that would name or change the identity, or widen the session
		"client is fixed by the key":       "--client other",
		"client with =":                    "--client=other",
		"the daemon's own subcommand":      "stdio",
		"the binary name":                  "openwrt-mcp stdio --client x",
		"a policy flag":                    "--allow-all",
		"read-only cannot be switched off": "--read-only=false",
		"read-only twice":                  "--read-only --read-only",
		"toolset twice":                    "--toolset diag --toolset pkg",
		"toolset twice, mixed forms":       "--toolset diag --toolset=pkg",
		"toolset without a value":          "--toolset",
		"toolset with an empty value":      "--toolset=",
		"toolset followed by an option":    "--toolset --read-only",
		"empty toolset in the list":        "--toolset diag,,pkg",
		"trailing comma":                   "--toolset diag,",
		"toolset repeated in the list":     "--toolset diag,diag",
		"toolset that does not exist":      "--toolset all",
		"toolset names are lower case":     "--toolset DIAG",
		"toolset next to junk":             "--toolset diag extra",
		// shell syntax is data, never syntax
		"shell command":                      "sh",
		"command chaining":                   "--read-only; id",
		"command substitute":                 "$(id)",
		"backticks":                          "`id`",
		"pipe":                               "uci_get | sh",
		"redirect":                           "call uci_get > /etc/passwd",
		"ampersand":                          "--read-only & id",
		"newline separates a second command": "--read-only\nid",
		"escape sequence":                    "\x1b[31m",
		"NUL":                                "--read-only\x00",
		"non-ASCII in the head":              "--toolset dïag",
		// call
		"call without a tool":               "call",
		"call with only blanks":             "call   ",
		"upper-case tool":                   "call UCI_GET",
		"upper-case first letter only":      "call Uci_get",
		"dash in the tool":                  "call uci-get",
		"tool starting with a digit":        "call 1x",
		"tool too long":                     "call a" + strings.Repeat("b", 40),
		"path as the tool":                  "call ../../bin/sh",
		"options after the tool":            "call uci_get --read-only",
		"options between call and tool":     "call --read-only uci_get",
		"call twice":                        "call call uci_get",
		"second command after the tool":     "call uci_get; id",
		"arguments that are not JSON":       "call uci_get config=network",
		"unterminated JSON":                 "call uci_get {",
		"JSON array":                        "call uci_get []",
		"JSON null":                         "call uci_get null",
		"JSON number":                       "call uci_get 5",
		"JSON string":                       `call uci_get "x"`,
		"text after the JSON object":        `call uci_get {"a":1} extra`,
		"second JSON object":                `call uci_get {"a":1}{"b":2}`,
		"invalid UTF-8 in the JSON":         "call uci_get {\"a\":\"\xff\"}",
		"raw control byte in a JSON string": "call uci_get {\"a\":\"x\x01y\"}",
		"over the length limit":             "call uci_get {\"a\":\"" + strings.Repeat("x", entryMaxLen) + "\"}",
		"--list takes nothing":              "call --list extra",
		"--list with arguments":             "call --list {}",
		"--list twice":                      "call --list --list",
		"--list is lower case":              "call --LIST",
		"a longer option is not --list":     "call --listx",
		"--help needs a tool":               "call --help",
		"--help takes nothing":              "call uci_get --help x",
		"--help with arguments":             "call uci_get --help {}",
		"--help is lower case":              "call uci_get --HELP",
		"--help before the tool":            "call --help uci_get",
	} {
		if got, err := parseEntry(in); err == nil {
			t.Errorf("%s: %q accepted as %+v", name, in, got)
		}
	}
}

func TestParseEntryLengthBoundary(t *testing.T) {
	const head, tail = `call uci_get {"a":"`, `"}`
	atLimit := head + strings.Repeat("x", entryMaxLen-len(head)-len(tail)) + tail
	if len(atLimit) != entryMaxLen {
		t.Fatalf("test input is %d bytes, want %d", len(atLimit), entryMaxLen)
	}
	if _, err := parseEntry(atLimit); err != nil {
		t.Errorf("%d bytes (the limit) refused: %v", entryMaxLen, err)
	}
	if _, err := parseEntry(atLimit[:len(atLimit)-2] + "x" + tail); err == nil {
		t.Errorf("%d bytes (one over the limit) accepted", entryMaxLen+1)
	}
	if _, err := parseEntry(atLimit[:len(atLimit)-3] + tail); err != nil {
		t.Errorf("%d bytes (one under the limit) refused: %v", entryMaxLen-1, err)
	}
}

func TestParseEntryErrorsNeverEchoTheInput(t *testing.T) {
	// The message goes back to the client and into logs; text the client typed must not ride along.
	const marker = "ZZMARKER"
	for _, in := range []string{
		"--" + marker, "--toolset " + marker, "--toolset=diag," + marker, marker, "call " + marker,
		"call uci_get " + marker, `call uci_get {"a":"` + marker + `"`, "--read-only " + marker,
	} {
		if _, err := parseEntry(in); err == nil {
			t.Errorf("%q accepted", in)
		} else if strings.Contains(err.Error(), marker) {
			t.Errorf("error for %q echoes the input: %v", in, err)
		}
	}
}

func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{"", "--read-only", "--toolset=diag,wg", "call uci_get {}", `call exec {"argv":["ls"]}`,
		"--client x", "call", "\x00", "call a {\"a\":[1,2,{\"b\":null}]}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		e, err := parseEntry(in)
		if err != nil {
			if e.Tool != "" || e.Args != "" || e.ReadOnly || e.Toolsets != nil {
				t.Fatalf("%q: error with a partly filled result %+v", in, e)
			}
			return
		}
		if len(in) > entryMaxLen {
			t.Fatalf("accepted %d bytes", len(in))
		}
		if e.Mode != entryStdio && e.Mode != entryCall {
			t.Fatalf("%q: mode %q", in, e.Mode)
		}
		seen := map[string]bool{}
		last := -1
		for _, ts := range e.Toolsets {
			idx := -1
			for i, n := range toolsetNames {
				if n == ts {
					idx = i
				}
			}
			if idx <= last || seen[ts] {
				t.Fatalf("%q: toolsets %v are not a canonical, duplicate-free subset", in, e.Toolsets)
			}
			seen[ts], last = true, idx
		}
		if e.Mode == entryStdio && (e.Tool != "" || e.Args != "") {
			t.Fatalf("%q: stdio entry carries a call %+v", in, e)
		}
		if e.Mode == entryStdio && (e.List || e.Help) {
			t.Fatalf("%q: stdio entry asks for a listing %+v", in, e)
		}
		if e.Mode == entryCall {
			var m map[string]any
			switch {
			case e.List && e.Help, e.List && (e.Tool != "" || e.Args != ""), e.Help && (e.Tool == "" || e.Args != ""):
				t.Fatalf("%q: inconsistent listing or help %+v", in, e)
			case e.List || e.Help:
			case e.Tool == "" || json.Unmarshal([]byte(e.Args), &m) != nil || m == nil:
				t.Fatalf("%q: call without a tool or a JSON object: %+v", in, e)
			}
		}
		// What is accepted must survive being parsed again: no state hides in the spelling.
		if e2, err := parseEntry(in); err != nil || !reflect.DeepEqual(e, e2) {
			t.Fatalf("%q: not deterministic", in)
		}
	})
}

// ---- the daemon side: the bridge forwards the raw command, the daemon parses and audits it

func TestBridgeRefusesAnUnparsableCommandAndAuditsIt(t *testing.T) {
	for _, cmd := range []string{"--client other", "sh -c id", "call uci_get; reboot"} {
		s := testServer(t, "")
		sock := listenTestSocket(t, s)
		reply := bridgeRaw(t, sock, `{"client":"claude-code","command":`+jsonString(cmd)+`}`)
		if !strings.Contains(reply, `"error"`) || strings.Contains(reply, `"serverInfo"`) {
			t.Errorf("%q: reply %q, want a JSON-RPC error and no session", cmd, reply)
		}
		var sessions []AuditEvent
		for _, ev := range auditEvents(t, s) {
			if ev.Tool == "session" {
				sessions = append(sessions, ev)
			}
		}
		if len(sessions) != 1 || sessions[0].Outcome != OutcomeDenied || sessions[0].Client != "claude-code" {
			t.Errorf("%q: audit = %+v, want one DENIED session event for claude-code", cmd, sessions)
		}
	}
}

// The command is the client's own text. The audit line shows it quoted, so the operator sees the
// escape sequence that was tried instead of a log that quietly lost it, and a terminal tailing the
// log cannot be driven by it.
func TestBridgeAuditOfARefusedCommandShowsControlBytesEscaped(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)
	bridgeRaw(t, sock, `{"client":"claude-code","command":`+jsonString("--x\x1b[2J\r\nFORGED line")+`}`)
	seen := false
	for _, ev := range auditEvents(t, s) {
		if ev.Tool != "session" {
			continue
		}
		seen = true
		if strings.ContainsAny(ev.Summary, "\x1b\r\n") || !strings.Contains(ev.Summary, `\x1b[2J\r\nFORGED`) {
			t.Errorf("audit summary = %q, want the command quoted with its control bytes escaped", ev.Summary)
		}
	}
	if !seen {
		t.Error("the refusal was not audited at all")
	}
}

func TestBridgeStillServesAnEmptyCommand(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)
	reply := bridgeRaw(t, sock, `{"client":"claude-code","command":""}`+"\n"+initializeRPC)
	if !strings.Contains(reply, `"serverInfo"`) {
		t.Fatalf("empty command: %q", reply)
	}
}

func TestRunBridgeForwardsSSHOriginalCommand(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)
	stdinW, stdoutR := swapStdio(t)
	t.Setenv("SSH_ORIGINAL_COMMAND", "--client other")
	done := make(chan error, 1)
	go func() { done <- runBridge(sock, "claude-code") }()
	_, _ = io.WriteString(stdinW, initializeRPC+"\n")
	line, _ := bufio.NewReader(stdoutR).ReadString('\n')
	if strings.Contains(line, `"serverInfo"`) || !strings.Contains(line, `"error"`) {
		t.Fatalf("a refused command still got a session: %q", line)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge did not end after the daemon refused the command")
	}
}

func TestRunBridgeRefusesAnOversizedCommandBeforeDialling(t *testing.T) {
	t.Setenv("SSH_ORIGINAL_COMMAND", "call uci_get {\"a\":\""+strings.Repeat("x", entryMaxLen)+"\"}")
	// No daemon here: the error must be about the command, not about the socket.
	err := runBridge(t.TempDir()+"/none.sock", "claude-code")
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("runBridge = %v, want a 'too long' error", err)
	}
}

// ---- helpers

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// bridgeRaw speaks the bridge protocol by hand: `lines` is written as is, and everything the daemon
// sends back until it closes (or a short deadline) is returned.
func bridgeRaw(t *testing.T, sock, lines string) string {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, lines+"\n")
	br := bufio.NewReader(conn)
	var out strings.Builder
	for {
		line, err := br.ReadString('\n')
		out.WriteString(line)
		if err != nil || strings.Contains(line, `"serverInfo"`) {
			break
		}
	}
	return out.String()
}

// A refused command ends the session at once, which looks like a daemon crash from the bridge's
// side. The person at the shell must be told the command was refused, and why.
func TestRunBridgeNamesTheRefusalNotADeadDaemon(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)
	swapStdio(t)
	t.Setenv("SSH_ORIGINAL_COMMAND", "--toolset bogus")
	done := make(chan error, 1)
	go func() { done <- runBridge(sock, "claude-code") }()
	select {
	case err := <-done:
		if err == nil || strings.Contains(err.Error(), "daemon closed") || !strings.Contains(err.Error(), "bad toolset") {
			t.Fatalf("runBridge = %v, want the refusal reason", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runBridge did not end after the daemon refused the command")
	}
}
