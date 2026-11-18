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

const toolRulesConf = `
config rule 'no_reboot'
	option tool 'ubus_call'
	option path 'system.reboot'
	option why 'reboots go through service_control'

config rule 'kick_reason'
	option tool 'ubus_call'
	option path 'hostapd.*.del_client'
	option arg 'reason'
	option mode 'only'
	list in '0'
	list in '5'

config rule 'no_recursive_rm'
	option tool 'exec'
	option path 'rm'
	option regex '-[a-zA-Z]*[rR][a-zA-Z]*'

config rule 'no_dd'
	option tool 'exec'
	option path 'dd'
	option client 'agent-*'
`

func ubusRefusal(t *testing.T, client, obj, method string, args map[string]any) string {
	t.Helper()
	return ruleRefusal(context.Background(), loadRules(t, toolRulesConf), client, ubusCallIn{Object: obj, Method: method, Args: args})
}

func execRefusal(t *testing.T, client string, argv ...string) string {
	t.Helper()
	return ruleRefusal(context.Background(), loadRules(t, toolRulesConf), client, execIn{Argv: argv})
}

func TestUbusRulesMatchObjectMethodAndArg(t *testing.T) {
	if r := ubusRefusal(t, "c", "system", "reboot", nil); !strings.Contains(r, `rule "no_reboot"`) || !strings.Contains(r, "service_control") {
		t.Errorf("reboot: %q", r)
	}
	if r := ubusRefusal(t, "c", "system", "board", nil); r != "" {
		t.Errorf("system board refused: %q", r)
	}
	// The object name has dots of its own; the glob is over object.method.
	if r := ubusRefusal(t, "c", "hostapd.wlan0", "del_client", map[string]any{"reason": float64(3)}); !strings.Contains(r, "kick_reason") {
		t.Errorf("reason 3 (JSON number): %q", r)
	}
	if r := ubusRefusal(t, "c", "hostapd.wlan0", "del_client", map[string]any{"reason": float64(5)}); r != "" {
		t.Errorf("reason 5 refused: %q", r)
	}
	// An absent arg is not a value in the list: an only rule refuses it.
	if r := ubusRefusal(t, "c", "hostapd.wlan1", "del_client", nil); !strings.Contains(r, "kick_reason") {
		t.Errorf("absent arg: %q", r)
	}
	if r := ubusRefusal(t, "c", "hostapd.wlan1", "get_clients", nil); r != "" {
		t.Errorf("another method: %q", r)
	}
}

func TestExecRulesJudgeEachArgumentAndTheBusyboxApplet(t *testing.T) {
	for _, argv := range [][]string{
		{"rm", "-rf", "/tmp/x"},
		{"/bin/rm", "-r", "x"},
		{"/bin/../bin/rm", "-fR", "x"},
		{"busybox", "rm", "-rf", "x"},
		{"/bin/busybox", "rm", "-r", "x"},
		{"rm", "x", "-rf"},
	} {
		if r := execRefusal(t, "c", argv...); !strings.Contains(r, "no_recursive_rm") {
			t.Errorf("%v: %q", argv, r)
		}
	}
	for _, argv := range [][]string{
		{"rm", "/tmp/x"},
		{"rm"},
		{"ls", "-r"},
		{"busybox", "ls", "-r"},
		{"busybox"},
		{},
	} {
		if r := execRefusal(t, "c", argv...); r != "" {
			t.Errorf("%v refused: %q", argv, r)
		}
	}
	// No predicate: any call of the program, for the clients the rule names.
	if r := execRefusal(t, "agent-1", "/bin/dd", "if=/dev/zero"); !strings.Contains(r, "no_dd") {
		t.Errorf("dd: %q", r)
	}
	if r := execRefusal(t, "other", "dd", "if=/dev/zero"); r != "" {
		t.Errorf("client glob ignored: %q", r)
	}
}

func TestToolRulesDoNotCrossTools(t *testing.T) {
	// A ubus rule must not bind an exec call, nor the other way round, nor uci_apply.
	ctx := context.Background()
	rules := loadRules(t, toolRulesConf+rulesConf)
	if r := ruleRefusal(ctx, rules, "c", execIn{Argv: []string{"system.reboot"}}); r != "" {
		t.Errorf("ubus rule bound exec: %q", r)
	}
	if r := ruleRefusal(ctx, rules, "c", ubusCallIn{Object: "rm", Method: "x", Args: map[string]any{"a": "-rf"}}); r != "" {
		t.Errorf("exec rule bound ubus: %q", r)
	}
	if r := ruleRefusal(ctx, rules, "c", uciApplyIn{Changes: []UCIChange{set("system", "reboot", "x", "y")}}); r != "" {
		t.Errorf("tool rule bound uci_apply: %q", r)
	}
	// Catch-all paths, so only the tool field can keep a rule off the other tools.
	onlyExec := loadRules(t, "config rule 'e'\n\toption tool 'exec'\n\toption path '*'\n")
	onlyUbus := loadRules(t, "config rule 'u'\n\toption tool 'ubus_call'\n\toption path '*'\n")
	if r := ruleRefusal(ctx, onlyExec, "c", ubusCallIn{Object: "a", Method: "b"}); r != "" {
		t.Errorf("exec rule bound ubus: %q", r)
	}
	if r := ruleRefusal(ctx, onlyUbus, "c", execIn{Argv: []string{"ls"}}); r != "" {
		t.Errorf("ubus rule bound exec: %q", r)
	}
	if ruleRefusal(ctx, onlyExec, "c", execIn{Argv: []string{"ls"}}) == "" || ruleRefusal(ctx, onlyUbus, "c", ubusCallIn{Object: "a", Method: "b"}) == "" {
		t.Error("a catch-all rule did not bind its own tool")
	}
}

func TestToolRuleConfigErrorsAreRefusedAtLoad(t *testing.T) {
	for _, bad := range []string{
		"config rule 'a'\n\toption tool 'sysupgrade'\n\toption path 'x'\n",                        // unknown tool
		"config rule 'a'\n\toption tool 'exec'\n",                                                 // no path
		"config rule 'a'\n\toption tool 'exec'\n\toption path 'rm'\n\toption arg 'x'\n",           // arg is ubus only
		"config rule 'a'\n\toption tool 'exec'\n\toption path 'rm'\n\tlist when 'a=b'\n",          // when is uci only
		"config rule 'a'\n\toption tool 'ubus_call'\n\toption path 'x.y'\n\toption eq '1'\n",      // predicate without arg
		"config rule 'a'\n\toption tool 'ubus_call'\n\toption path 'x.y'\n\toption mode 'only'\n", // only without predicate
	} {
		p := filepath.Join(t.TempDir(), "c")
		os.WriteFile(p, []byte(bad), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestToolRulesRefuseThroughTheServerWhateverTheGrant(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, policyFor("c", allToolNames, "*")+toolRulesConf)
	cs := connectClient(t, s, "c")
	out, isErr := callText(t, cs, "ubus_call", map[string]any{"object": "system", "method": "reboot"})
	if !isErr || !strings.Contains(out, `denied by rule "no_reboot"`) || !strings.Contains(out, "POLICY_DENIED") {
		t.Errorf("ubus: isErr=%v\n%s", isErr, out)
	}
	out, isErr = callText(t, cs, "exec", map[string]any{"argv": []any{"rm", "-rf", "/tmp/x"}})
	if !isErr || !strings.Contains(out, `denied by rule "no_recursive_rm"`) {
		t.Errorf("exec: isErr=%v\n%s", isErr, out)
	}
	if len(f.argvList()) != 0 {
		t.Errorf("a refused call ran commands: %s", f.allCalls())
	}
}
