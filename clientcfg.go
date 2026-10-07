package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

// The client side of `openwrt-mcp connect`: the entry that makes a client start the SSH bridge,
// and where each client keeps it. Formats and locations are from each client's own documentation
// (checked 2026-10-07), not from memory:
//
//	claude-code     `claude mcp add --scope user openwrt -- ssh ...`      (code.claude.com/docs/en/mcp)
//	codex           `codex mcp add openwrt -- ssh ...`                    (Codex CLI docs, MCP page)
//	claude-desktop  mcpServers.openwrt in claude_desktop_config.json      (modelcontextprotocol.io quickstart)
//	                  Windows %APPDATA%\Claude\, macOS ~/Library/Application Support/Claude/
//	cursor          mcpServers.openwrt in ~/.cursor/mcp.json              (cursor.com/docs/context/mcp)
//	gemini          mcpServers.openwrt in ~/.gemini/settings.json         (Gemini CLI MCP docs)
//	vscode          servers.openwrt in .vscode/mcp.json, "type": "stdio"  (VS Code MCP docs)
//
// The first two have a command that edits their own configuration, which is more robust than
// editing a file they own; the rest are plain JSON files we merge into.

// serverName is the name of the entry in the client's configuration.
const serverName = "openwrt"

var connectClients = []string{"claude-code", "claude-desktop", "codex", "cursor", "gemini", "vscode"}

// cliClients are managed through the client's own `mcp add` command.
var cliClients = map[string]string{"claude-code": "claude", "codex": "codex"}

// jsonClients keep the entry in a JSON file: the top-level key, and whether the entry says
// "type": "stdio" (VS Code and Claude Code's .mcp.json require it).
var jsonClients = map[string]struct {
	key   string
	typed bool
}{
	"claude-desktop": {"mcpServers", false},
	"cursor":         {"mcpServers", false},
	"gemini":         {"mcpServers", false},
	"vscode":         {"servers", true},
}

// clientConfigPath is where a JSON client keeps its servers. home and appdata are passed in so a
// test never touches the real ones.
func clientConfigPath(goos, client, home, appdata, cwd string) (string, error) {
	switch client {
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "gemini":
		return filepath.Join(home, ".gemini", "settings.json"), nil
	case "vscode":
		return filepath.Join(cwd, ".vscode", "mcp.json"), nil
	case "claude-desktop":
		switch goos {
		case "windows":
			if appdata == "" {
				return "", errors.New("%APPDATA% is not set")
			}
			return filepath.Join(appdata, "Claude", "claude_desktop_config.json"), nil
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		}
		return "", fmt.Errorf("Claude Desktop is not available on %s; use --config to name the file if you run it some other way", goos)
	}
	return "", fmt.Errorf("%s keeps its servers with its own command, not in a file we edit", client)
}

// serverEntry is what a client stores: ssh, with the arguments as an array so no quoting is ever
// needed, whatever the OS and whatever is in the key path.
func serverEntry(p connectParams, typed bool) map[string]any {
	e := map[string]any{"command": "ssh", "args": p.sshArgs()}
	if typed {
		e["type"] = "stdio"
	}
	return e
}

var (
	errNotJSON = errors.New("the file is not plain JSON (comments or a syntax error)")
	errExists  = errors.New("an entry named " + serverName + " is already there and differs")
)

// mergeServer returns doc with servers[serverName] set to entry, every other member kept. It
// changes nothing, and says so, when the entry is already there as given. A different entry of
// the same name is an error unless replace is set. An empty file counts as {}.
func mergeServer(doc []byte, topKey string, entry map[string]any, replace bool) (out []byte, changed bool, err error) {
	top := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(doc)) > 0 {
		if err := json.Unmarshal(doc, &top); err != nil {
			return nil, false, fmt.Errorf("%w: %v", errNotJSON, err)
		}
	}
	servers := map[string]json.RawMessage{}
	if raw, ok := top[topKey]; ok {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return nil, false, fmt.Errorf("%q is not an object: %w", topKey, err)
		}
	}
	want := rawJSON(entry)
	if have, ok := servers[serverName]; ok {
		var a, b any
		if json.Unmarshal(have, &a) == nil && json.Unmarshal(want, &b) == nil && reflect.DeepEqual(a, b) {
			return doc, false, nil
		}
		if !replace {
			return nil, false, errExists
		}
	}
	servers[serverName] = want
	top[topKey] = rawJSON(servers)
	return encodeIndented(top), true, nil
}

// rawJSON marshals v without HTML escaping, so a '&' or '<' already in the file stays one.
func rawJSON(v any) json.RawMessage {
	return bytes.TrimRight(encodeIndented(v), "\n")
}

// displaySnippet is the entry as it reads in the file, with the arguments on one line so the
// plan stays short. The file itself is written by mergeServer.
func displaySnippet(topKey string, entry map[string]any) []string {
	lines := []string{"{", `  "` + topKey + `": {`, `    "` + serverName + `": {`}
	if t, ok := entry["type"].(string); ok {
		lines = append(lines, `      "type": "`+t+`",`)
	}
	return append(lines,
		`      "command": "ssh",`,
		`      "args": `+string(rawJSONCompact(entry["args"])),
		"    }", "  }", "}")
}

func rawJSONCompact(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// encodeIndented writes JSON the way an editor would: two spaces, and no HTML escapes (a '<' stays one).
func encodeIndented(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return b.Bytes()
}

// writeClientConfig merges the entry into the file at path, creating it (and its directory) if
// need be. The file is rewritten whole, so its original is kept once as <file>.before-openwrt-mcp,
// and the new content goes in through a temp file and a rename, so a crash cannot leave half a file.
func writeClientConfig(path, topKey string, entry map[string]any, replace bool) (changed bool, err error) {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	out, changed, err := mergeServer(old, topKey, entry, replace)
	if err != nil || !changed {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	if len(old) > 0 {
		keep := path + ".before-openwrt-mcp"
		if _, err := os.Stat(keep); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(keep, old, 0o600); err != nil {
				return false, fmt.Errorf("keeping a copy of %s: %w", path, err)
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// quoteArg quotes one argument for display in a command line the operator may paste. The files
// we write never need it: they store arguments as arrays.
func quoteArg(goos, s string) string {
	if goos == "windows" {
		if s != "" && !strings.ContainsAny(s, " \t\"&|<>()^;%$'") {
			return s
		}
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	if s != "" && !strings.ContainsAny(s, " \t\n\"'\\$`&|;<>()*?[]{}~!#") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoteCommand(goos string, argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = quoteArg(goos, a)
	}
	return strings.Join(q, " ")
}

// cliAddArgv is the client's own command that registers the bridge.
func cliAddArgv(client string, p connectParams) []string {
	ssh := append([]string{"ssh"}, p.sshArgs()...)
	switch client {
	case "claude-code":
		return append([]string{"claude", "mcp", "add", "--scope", "user", serverName, "--"}, ssh...)
	case "codex":
		return append([]string{"codex", "mcp", "add", serverName, "--"}, ssh...)
	}
	return nil
}

// isWSL reports whether this is Linux running under Windows: its ssh and ~/.ssh are not the
// ones a Windows-side client would use.
func isWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false
	}
	s := strings.ToLower(string(b))
	return strings.Contains(s, "microsoft") || strings.Contains(s, "wsl")
}
