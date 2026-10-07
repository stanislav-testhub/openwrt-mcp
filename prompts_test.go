package main

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ROADMAP 3.8. The five names are the spec's. What matters about a recipe beyond that is that
// following it cannot fail on a missing tool or a refused call, for a client holding the
// @readonly preset, which is who will use them first.

var specPrompts = []string{"router-health", "who-is-online", "secure-my-router", "wifi-doctor", "upgrade-plan"}

func TestPromptsAreListedAndReturnOneUserMessage(t *testing.T) {
	cs := connectClient(t, testServer(t, ""), "c")
	list, err := cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range list.Prompts {
		got = append(got, p.Name)
		if strings.TrimSpace(p.Description) == "" || strings.TrimSpace(p.Title) == "" {
			t.Errorf("prompt %s lacks a title or description", p.Name)
		}
	}
	sort.Strings(got) // the SDK lists prompts by name
	want := append([]string(nil), specPrompts...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("prompts %v, want %v", got, want)
	}
	for _, name := range specPrompts {
		res, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: name})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(res.Messages) != 1 || res.Messages[0].Role != "user" {
			t.Fatalf("%s: messages %+v", name, res.Messages)
		}
		text := res.Messages[0].Content.(*mcp.TextContent).Text
		// A recipe is a few steps, not a manual: it is paid for in the context of whoever uses it.
		if n := len(text); n < 200 || n > 1400 {
			t.Errorf("%s is %d bytes; a recipe is between 200 and 1400", name, n)
		}
		if !strings.Contains(text, "hange nothing") {
			t.Errorf("%s does not say it changes nothing", name)
		}
	}
	// Fetching one runs nothing on the router and leaves nothing in the audit log.
	if _, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "no-such-prompt"}); err == nil {
		t.Error("an unknown prompt was returned")
	}
}

// Every call a recipe tells the model to make is one @readonly allows.
func TestEveryPromptStaysInsideTheReadonlyPreset(t *testing.T) {
	readable := map[string]bool{}
	for _, b := range presets["readonly"] {
		for _, tool := range b.tools {
			readable[tool] = true
		}
	}
	toolName := regexp.MustCompile(`\b[a-z]+(?:_[a-z]+)+\b|\blogread\b|\bsysupgrade\b|\bexec\b`)
	ubusObject := regexp.MustCompile(`object=(\w+)`)
	ubusMethod := regexp.MustCompile(`method=(\w+)`)
	sysAction := regexp.MustCompile(`sysupgrade with action=(\w+)`)
	var sysScopes []string
	for _, b := range presets["readonly"] {
		if contains(b.tools, "sysupgrade") {
			sysScopes = b.scopes
		}
	}
	for _, r := range recipes {
		for _, m := range toolName.FindAllString(r.body, -1) {
			if validTool(m) && !readable[m] {
				t.Errorf("%s tells the model to use %s, which @readonly does not grant", r.name, m)
			}
		}
		// A recipe names one ubus object and the methods to call on it: every pair must be allowed.
		for _, o := range ubusObject.FindAllStringSubmatch(r.body, -1) {
			for _, m := range ubusMethod.FindAllStringSubmatch(r.body, -1) {
				if !matchAny(readonlyUbus, o[1]+"."+m[1]) {
					t.Errorf("%s calls ubus %s.%s, which @readonly does not allow", r.name, o[1], m[1])
				}
			}
		}
		for _, m := range sysAction.FindAllStringSubmatch(r.body, -1) {
			if !contains(sysScopes, m[1]) {
				t.Errorf("%s runs sysupgrade %s, which @readonly does not allow", r.name, m[1])
			}
		}
	}
	// The recipes together exercise more than one tool, or the check above proves little.
	seen := map[string]bool{}
	for _, r := range recipes {
		for _, m := range toolName.FindAllString(r.body, -1) {
			if validTool(m) {
				seen[m] = true
			}
		}
	}
	if len(seen) < 8 {
		t.Errorf("the recipes name only %d tools (%v); the readonly check is vacuous", len(seen), seen)
	}
}
