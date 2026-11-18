package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesConf = `
config rule 'ssh_keys_only'
	option path 'dropbear.*.PasswordAuth'
	option eq 'on'
	option why 'keys only'

config rule 'wifi_switch'
	option path 'wireless.*.disabled'
	option mode 'only'
	list in '0'
	list in '1'

config rule 'wan_input'
	option path 'firewall.*.input'
	option eq 'ACCEPT'
	list when '@type=zone'
	list when 'name=wan'

config rule 'lab_only'
	option client 'agent-*'
	option path 'network.*.proto'
	option regex 'pppoe|l2tp'
`

func loadRules(t *testing.T, text string) []*argRule {
	t.Helper()
	p := filepath.Join(t.TempDir(), "openwrt-mcp")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return c.Rules
}

func set(cfg, sec, opt, val string) UCIChange {
	return UCIChange{Config: cfg, Section: sec, Option: opt, Value: val}
}

func refusal(t *testing.T, f *fakeRouter, client string, changes ...UCIChange) string {
	t.Helper()
	return ruleRefusal(context.Background(), loadRules(t, rulesConf), client, uciApplyIn{Changes: changes})
}

func TestRulesTheThreeRoadmapExamples(t *testing.T) {
	f := newFakeRouter(t)
	if r := refusal(t, f, "c", set("dropbear", "cfg1", "PasswordAuth", "on")); !strings.Contains(r, `rule "ssh_keys_only"`) || !strings.Contains(r, "keys only") {
		t.Errorf("password auth on: %q", r)
	}
	if r := refusal(t, f, "c", set("dropbear", "cfg1", "PasswordAuth", "off")); r != "" {
		t.Errorf("password auth off refused: %q", r)
	}
	for _, v := range []string{"0", "1"} {
		if r := refusal(t, f, "c", set("wireless", "radio0", "disabled", v)); r != "" {
			t.Errorf("disabled=%s refused: %q", v, r)
		}
	}
	if r := refusal(t, f, "c", set("wireless", "radio0", "disabled", "2")); !strings.Contains(r, "wifi_switch") {
		t.Errorf("disabled=2: %q", r)
	}
	// Zone input ACCEPT: the zone's name comes from the live config.
	f.on("uci -q get firewall.z1.@type", "")
	f.on("uci -q get firewall.z1", "zone")
	f.on("uci -q get firewall.z1.name", "wan")
	if r := refusal(t, f, "c", set("firewall", "z1", "input", "ACCEPT")); !strings.Contains(r, "wan_input") {
		t.Errorf("wan ACCEPT: %q", r)
	}
	f.on("uci -q get firewall.z2", "zone")
	f.on("uci -q get firewall.z2.name", "lan")
	if r := refusal(t, f, "c", set("firewall", "z2", "input", "ACCEPT")); r != "" {
		t.Errorf("lan ACCEPT refused: %q", r)
	}
}

func TestRulesWhenReadsTheSameCallBeforeTheLiveConfig(t *testing.T) {
	newFakeRouter(t) // a lookup of the live config would find nothing
	r := ruleRefusal(context.Background(), loadRules(t, rulesConf), "c", uciApplyIn{Changes: []UCIChange{
		{Config: "firewall", Section: "zwan", Op: "create", Type: "zone"},
		set("firewall", "zwan", "name", "wan"),
		set("firewall", "zwan", "input", "ACCEPT"),
	}})
	if !strings.Contains(r, "wan_input") {
		t.Errorf("a zone created and opened in one call got through: %q", r)
	}
}

func TestRulesAnyRefusingRuleDeniesAndPredicatesAreAnded(t *testing.T) {
	rules := loadRules(t, `
config rule 'a'
	option path 'x.*.y'
	option eq '1'
	option regex '[0-9]+'
config rule 'b'
	option path 'x.*.y'
	option eq '2'
`)
	run := func(v string) string {
		return ruleRefusal(context.Background(), rules, "c", uciApplyIn{Changes: []UCIChange{set("x", "s", "y", v)}})
	}
	if run("1") == "" || run("2") == "" {
		t.Error("a value matching either rule must be refused")
	}
	if run("3") != "" {
		t.Error("a value matching neither was refused")
	}
	// eq and regex in one rule are ANDed: 'z' fails the regex, so rule a does not apply.
	if r := run("z"); r != "" {
		t.Errorf("z: %q", r)
	}
}

func TestRulesListsDeletesAndClients(t *testing.T) {
	f := newFakeRouter(t)
	_ = f
	rules := loadRules(t, rulesConf)
	ctx := context.Background()
	// set_list: one bad element refuses the whole call.
	r := ruleRefusal(ctx, rules, "c", uciApplyIn{Changes: []UCIChange{{Config: "wireless", Section: "r", Option: "disabled", Values: []string{"0", "9"}}}})
	if !strings.Contains(r, `"9"`) {
		t.Errorf("set_list: %q", r)
	}
	// An `only` rule ignores a delete; a deny rule with no predicate would not.
	if r := ruleRefusal(ctx, rules, "c", uciApplyIn{Changes: []UCIChange{{Config: "wireless", Section: "r", Option: "disabled", Delete: true}}}); r != "" {
		t.Errorf("delete refused by an only rule: %q", r)
	}
	if r := ruleRefusal(ctx, loadRules(t, "config rule 'n'\n\toption path 'a.*.b'\n"), "c", uciApplyIn{Changes: []UCIChange{{Config: "a", Section: "s", Option: "b", Delete: true}}}); r == "" {
		t.Error("a deny rule with no predicate let a delete through")
	}
	// The client glob narrows who a rule binds.
	if r := ruleRefusal(ctx, rules, "other", uciApplyIn{Changes: []UCIChange{set("network", "wan", "proto", "pppoe")}}); r != "" {
		t.Errorf("rule for agent-* bound other: %q", r)
	}
	if r := ruleRefusal(ctx, rules, "agent-1", uciApplyIn{Changes: []UCIChange{set("network", "wan", "proto", "pppoe")}}); r == "" {
		t.Error("rule for agent-* did not bind agent-1")
	}
	// Whole-section changes are not value writes.
	if r := ruleRefusal(ctx, rules, "agent-1", uciApplyIn{Changes: []UCIChange{{Config: "network", Section: "wan", Delete: true}}}); r != "" {
		t.Errorf("section delete: %q", r)
	}
}

func TestRuleConfigErrorsAreRefusedAtLoad(t *testing.T) {
	for _, bad := range []string{
		"config rule 'a'\n\toption path 'a.b'\n",                           // not config.section.option
		"config rule 'a'\n\toption path 'a.*.b'\n\toption mode 'only'\n",   // only without predicate
		"config rule 'a'\n\toption path 'a.*.b'\n\toption mode 'x'\n",      // unknown mode
		"config rule 'a'\n\toption path 'a.*.b'\n\toption regex '('\n",     // bad regex
		"config rule 'a'\n\toption path 'a.*.b'\n\toption exists 'yes'\n",  // bad exists
		"config rule 'a'\n\toption path 'a.*.b'\n\tlist when 'noequals'\n", // bad when
	} {
		p := filepath.Join(t.TempDir(), "c")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	_ = bufio.NewScanner
}

func TestARuleRefusesThroughTheServerWhateverTheGrant(t *testing.T) {
	f := newFakeRouter(t)
	f.on("uci", "ok")
	s := testServer(t, policyFor("c", allToolNames, "*")+rulesConf)
	cs := connectClient(t, s, "c")
	out, isErr := callText(t, cs, "uci_apply", map[string]any{"dry_run": true, "changes": []any{
		map[string]any{"config": "dropbear", "section": "cfg1", "option": "PasswordAuth", "value": "on"}}})
	if !isErr || !strings.Contains(out, `denied by rule "ssh_keys_only"`) || !strings.Contains(out, "POLICY_DENIED") {
		t.Errorf("isErr=%v\n%s", isErr, out)
	}
	if len(f.argvList()) != 0 {
		t.Errorf("a refused change ran commands: %s", f.allCalls())
	}
}
