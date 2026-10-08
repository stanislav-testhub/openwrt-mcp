package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------- output bounds

// A reply over the size gate whose arrays are only a little over the cap: pruning drops a few
// elements and adds a marker and a notice, which can cost more than it saves. The documented
// rule is that the result is never longer than the reply it replaces.
func TestPruningNeverMakesAReplyLongerAcrossTheWholeSpace(t *testing.T) {
	var pruned, kept int
	for valueLen := 1; valueLen <= 64; valueLen++ {
		for n := maxArrayElems + 1; n <= maxArrayElems+80; n++ {
			items := make([]any, n)
			for i := range items {
				items[i] = strings.Repeat("v", valueLen)
			}
			b, _ := json.MarshalIndent(map[string]any{"pad": strings.Repeat("p", pruneMinBytes), "a": items}, "", "\t")
			in := string(b)
			out := pruneUbusJSON(in)
			if len(out) > len(in) {
				t.Fatalf("%d elements of %d bytes: pruning grew the reply %d -> %d", n, valueLen, len(in), len(out))
			}
			if out == in {
				kept++
			} else {
				pruned++
			}
		}
	}
	// Both outcomes occur in this space, so the loop above is not vacuous either way.
	if pruned == 0 || kept == 0 {
		t.Errorf("the sweep never reached both outcomes: pruned=%d kept=%d", pruned, kept)
	}
}

func TestTextResultCutsOnACharacterBoundary(t *testing.T) {
	for _, unit := range []string{"a", "é", "€", "😀"} { // 1, 2, 3 and 4 bytes
		for shift := 0; shift < 4; shift++ { // vary where the cap lands inside a character
			body := strings.Repeat("x", shift) + strings.Repeat(unit, maxResultBytes/len(unit)+10)
			got := textResult(body).Content[0].(*mcp.TextContent).Text
			if !utf8.ValidString(got) {
				t.Errorf("unit %q shift %d: the cut split a character", unit, shift)
			}
			head, notice, ok := strings.Cut(got, "\n\n[truncated: ")
			if !ok {
				t.Fatalf("unit %q shift %d: no notice", unit, shift)
			}
			if len(head) > maxResultBytes || len(head) < maxResultBytes-utf8.UTFMax {
				t.Errorf("unit %q shift %d: kept %d bytes, want within %d of %d", unit, shift, len(head), utf8.UTFMax, maxResultBytes)
			}
			var total, shown int
			if _, err := fmt.Sscanf(notice, "%d bytes total, %d shown", &total, &shown); err != nil || total != len(body) || shown != len(head) {
				t.Errorf("unit %q shift %d: the notice says total=%d shown=%d, truth is %d and %d (%v)", unit, shift, total, shown, len(body), len(head), err)
			}
		}
	}
}

func TestTextResultBoundaryIsExactlyTheCap(t *testing.T) {
	at := strings.Repeat("x", maxResultBytes)
	if got := textResult(at).Content[0].(*mcp.TextContent).Text; got != at {
		t.Error("an output exactly at the cap was altered")
	}
	over := at + "x"
	if got := textResult(over).Content[0].(*mcp.TextContent).Text; !strings.Contains(got, "truncated:") {
		t.Error("one byte over the cap was not truncated")
	}
	if got := textResult("  \n\t").Content[0].(*mcp.TextContent).Text; got != "(no output)" {
		t.Errorf("blank output should say so, got %q", got)
	}
}

// ---------------------------------------------------------------- config parsing edge cases

func parseOne(t *testing.T, text string) []uciSection {
	t.Helper()
	return parseUCI(bufio.NewScanner(strings.NewReader(text)))
}

func TestSplitUCIQuotingAndComments(t *testing.T) {
	for _, c := range []struct {
		line string
		want []string
	}{
		{"option a 'b c'", []string{"option", "a", "b c"}},
		{`option a "b c"`, []string{"option", "a", "b c"}},
		{"option a b # trailing note", []string{"option", "a", "b"}},
		{"option a 'b # not a comment'", []string{"option", "a", "b # not a comment"}},
		{"option url 'http://x/#frag'", []string{"option", "url", "http://x/#frag"}},
		{"option a b#c", []string{"option", "a", "b#c"}},
		{"\toption\ta\t'b'", []string{"option", "a", "b"}},
		{"option a ''", []string{"option", "a", ""}}, // an explicit empty value is a value: `option socket ''` relies on it
		{"option a '' # note", []string{"option", "a", ""}},
		{`option a ""`, []string{"option", "a", ""}},
	} {
		got, ok := splitUCI(c.line)
		if !ok || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("splitUCI(%q) = %q %v, want %q", c.line, got, ok, c.want)
		}
	}
	for _, blank := range []string{"", "   ", "# a comment", "\t# indented comment"} {
		if f, ok := splitUCI(blank); ok || len(f) != 0 {
			t.Errorf("splitUCI(%q) = %q %v, want nothing", blank, f, ok)
		}
	}
}

func TestParseUCIKeepsSectionsOptionsAndListsApart(t *testing.T) {
	secs := parseOne(t, `
# header
config policy 'a'
	option client 'one'
	list tools 'x'
	list tools 'y'
	option stray

config policy
	option client 'two'
option orphan 'ignored: no section yet is impossible here, but a line before one must not panic'
`)
	if len(secs) != 2 || secs[0].Name != "a" || secs[1].Name != "" || secs[1].Type != "policy" {
		t.Fatalf("%+v", secs)
	}
	if secs[0].Options["client"] != "one" || strings.Join(secs[0].Lists["tools"], ",") != "x,y" {
		t.Errorf("section a: %+v", secs[0])
	}
	if _, bad := secs[0].Options["stray"]; bad {
		t.Error("an option with no value was recorded")
	}
	// An empty list element is not an element; an empty option value is a value.
	empty := parseOne(t, "config policy\n\tlist tools ''\n\toption socket ''\n")
	if len(empty) != 1 || len(empty[0].Lists["tools"]) != 0 {
		t.Errorf("an empty list element was kept: %+v", empty)
	}
	if v, ok := empty[0].Options["socket"]; !ok || v != "" {
		t.Errorf("an explicitly empty option was dropped: %+v", empty[0].Options)
	}
	// An option line before any `config` line has nowhere to go and must not panic.
	if got := parseOne(t, "option a 'b'\n"); len(got) != 0 {
		t.Errorf("%+v", got)
	}
}

func TestPolicyOptionSpellingsAreAcceptedAndMeanTheSameThing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg")
	write := func(body string) *Config {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	c := write("config policy\n\toption client 'c'\n\toption tools 'logread uci_get'\n\toption scopes 'a b'\n")
	pol := c.Policies[0]
	if strings.Join(pol.Tools, ",") != "logread,uci_get" || strings.Join(pol.Scopes, ",") != "a,b" {
		t.Errorf("space-separated option spelling: %+v", pol)
	}
	c = write("config policy\n\toption client 'c'\n\tlist tools 'logread'\n\tlist tools 'uci_get'\n\tlist scopes 'a'\n\tlist scopes 'b'\n")
	if strings.Join(c.Policies[0].Tools, ",") != "logread,uci_get" || strings.Join(c.Policies[0].Scopes, ",") != "a,b" {
		t.Errorf("list spelling: %+v", c.Policies[0])
	}
	c = write("config policy\n\toption client 'c'\n\toption tools 'exec uci_get'\n\toption mfa_tools 'exec'\n\toption mfa_window '5m'\n")
	if !c.Policies[0].NeedsMFA("exec") || c.Policies[0].NeedsMFA("uci_get") || c.Policies[0].MFAWindow != 5*time.Minute {
		t.Errorf("mfa spelling: %+v", c.Policies[0])
	}

	// Server section options.
	c = write("config server\n\toption socket ''\n\toption audit_max_mb '3'\n\toption listen '127.0.0.1:9999'\n")
	if c.Socket != "" || c.AuditMaxMB != 3 || c.Listen != "127.0.0.1:9999" {
		t.Errorf("server options: %+v", c)
	}
	for _, v := range []string{"0", "-4", "many", ""} {
		c = write("config server\n\toption audit_max_mb '" + v + "'\n")
		if c.AuditMaxMB != defaultAuditMaxMB {
			t.Errorf("audit_max_mb %q gave %d: a nonsense value must keep the default, not disable rotation", v, c.AuditMaxMB)
		}
	}

	for _, bad := range []string{
		"config policy\n\toption client 'c'\n\toption tools 'logread'\n\toption mfa_window 'soon'\n",
		"config policy\n\toption client 'c'\n\toption tools 'logread'\n\toption mfa_window '0s'\n",
		"config policy\n\toption client 'c'\n\toption tools 'logread'\n\toption expires 'tomorrow'\n",
	} {
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
