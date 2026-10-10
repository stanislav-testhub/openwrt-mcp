package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// skills/openwrt-mcp/SKILL.md is what an agent with a shell loads instead of the 22 KB tool
// catalogue: how to call a tool over SSH, the few rules that matter, and one line per tool. The
// tool lines are generated from the registered tools, so the file cannot name a tool that does not
// exist; run `UPDATE_SKILL=1 go test -run TestSkillFileIsCurrent` after changing a tool's title or
// the text below.

var skillPath = filepath.Join("skills", "openwrt-mcp", "SKILL.md")

const skillIntro = `---
name: openwrt-mcp
description: Inspect and change an OpenWrt router through its openwrt-mcp SSH bridge from the shell: status, logs, clients, firewall, packages, WireGuard, and configuration changes with automatic rollback. Use when the user asks about their router and no openwrt MCP server is connected.
---

# openwrt-mcp from the shell

openwrt-mcp runs on the router. Each tool is one SSH command; the policy, audit log, redaction and
rollback are the same as over MCP.

    ssh -T [-i KEY] [-p PORT] USER@ROUTER call TOOL '{"arg":"value"}'

Use the same ssh options as the user's MCP client entry (` + "`openwrt-mcp connect`" + ` prints them).

- ` + "`call --list`" + ` prints the tools this session has, one per line. ` + "`call TOOL --help`" + ` prints one tool's
  description and argument schema: run it before the first use of a tool.
- Arguments are one JSON object; leave them out for none. Quote the JSON for your local shell
  (single quotes in bash and zsh).
- Output is text on stdout. A refusal or an error goes to stderr and the exit status is 1.
- A refusal names the exact ` + "`openwrt-mcp allow ...`" + ` command. Show it to the user; do not look for another way in.
- Start with ` + "`system_status`" + `. Prefer the specific tools to ` + "`ubus_call`" + ` and ` + "`exec`" + `.
- Change configuration with ` + "`uci_apply`" + `: run it with ` + "`dry_run`" + ` first, then for real. It arms an automatic
  rollback; check that the router still works, then ` + "`uci_confirm`" + `.
- Package changes simulate unless ` + "`commit`" + ` is true.
- Anything that prints keys (` + "`wg_new_client`" + `, backups) is a credential: show it to the user, never store it.
- To narrow a session, put options between ` + "`--`" + ` (which ends ssh's own options) and ` + "`call`" + `:
  ` + "`ssh ... USER@ROUTER -- --read-only --toolset diag,pkg call ...`" + ` (toolsets: diag, config, pkg, wg).

## Tools
`

func renderSkill(tools []*mcp.Tool) string {
	sorted := append([]*mcp.Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	b.WriteString(skillIntro)
	b.WriteString("\n")
	for _, tl := range sorted {
		fmt.Fprintf(&b, "- `%s`: %s\n", tl.Name, tl.Title)
	}
	return b.String()
}

func TestSkillFileIsCurrent(t *testing.T) {
	want := renderSkill(listedTools(t, connectClient(t, testServer(t, ""), "c")))
	if os.Getenv("UPDATE_SKILL") != "" {
		if err := os.MkdirAll(filepath.Dir(skillPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(skillPath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatalf("%v (UPDATE_SKILL=1 go test -run TestSkillFileIsCurrent writes it)", err)
	}
	if strings.ReplaceAll(string(got), "\r\n", "\n") != want {
		t.Errorf("%s is out of date: UPDATE_SKILL=1 go test -run TestSkillFileIsCurrent", skillPath)
	}
}

func TestSkillNamesOnlyRealToolsAndStaysSmall(t *testing.T) {
	b, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if len(text) > 4096 {
		t.Errorf("SKILL.md is %d bytes; it exists to cost less than the catalogue, keep it under 4096", len(text))
	}
	// Words in backticks that look like tool names (snake_case) must be tools or known arguments.
	arguments := []string{"dry_run"}
	for _, m := range regexp.MustCompile("`([a-z]+(?:_[a-z]+)+)`").FindAllStringSubmatch(text, -1) {
		if !slices.Contains(allToolNames, m[1]) && !slices.Contains(arguments, m[1]) {
			t.Errorf("SKILL.md mentions `%s`, which is not a tool", m[1])
		}
	}
	for _, name := range allToolNames {
		if !strings.Contains(text, "- `"+name+"`: ") {
			t.Errorf("SKILL.md has no line for %s", name)
		}
	}
	if !strings.HasPrefix(text, "---\nname: openwrt-mcp\ndescription: ") {
		t.Error("SKILL.md frontmatter must start with name and description")
	}
}
