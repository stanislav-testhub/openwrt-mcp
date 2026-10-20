package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

// The rpcd exec plugin behind the LuCI approval page (docs/luci-approvals.md, 8.3).
// /usr/libexec/rpcd/openwrt-mcp is a two-line wrapper that runs `openwrt-mcp rpcd "$@"`; rpcd
// calls it as `list` (print the method signatures) and `call <method>` (JSON in on stdin, JSON out).
//
// It is the one surface that writes grants for a browser. Reading is the read ACL group, every
// change is the write group, and rpcd enforces both before this process starts: the split in
// the ACL file is pinned against rpcdMethods by a test. Nothing here is an MCP tool, so no
// policy can cover it, and the deny floor (floor.go) keeps an agent away from the binary, the
// plugin and the mirror it reads.
//
// The plugin is a separate process from the daemon. They share two files: the policy config,
// which the daemon re-reads when it changes, and the request mirror, which both rewrite under a
// lock (requests.go). An error is an {"error": ...} object with exit status 0, so LuCI can show it.

const rpcdActor = "luci"

// rpcdDurations are the lengths the page offers. "never" is for the Permissions tab only, so a
// request card cannot create a grant that does not expire.
var rpcdDurations = []string{"15m", "1h", "8h", "1d", "7d"}

const rpcdDefaultDuration = "1h"

type rpcdEnv struct {
	configPath, statePath, requestsPath string
	authKeysPath                        string // "" is /etc/dropbear/authorized_keys
	now                                 func() time.Time
}

func (e rpcdEnv) time() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

type rpcdMethod struct {
	name  string
	write bool
	sig   map[string]string // the argument names and types rpcd advertises
	fn    func(rpcdEnv, json.RawMessage) (any, error)
}

var rpcdMethods = []rpcdMethod{
	{"status", false, map[string]string{"audit": "Integer"}, rpcdStatus},
	{"requests", false, map[string]string{}, rpcdRequests},
	{"settings", false, map[string]string{}, rpcdSettings},
	{"tools", false, map[string]string{}, rpcdTools},
	{"decide", true, map[string]string{"id": "String", "decision": "String", "breadth": "String",
		"duration": "String", "confirm": "Boolean"}, rpcdDecide},
	{"grant", true, map[string]string{"client": "String", "tool": "String", "scope": "String",
		"duration": "String", "confirm": "Boolean", "replace": "Boolean"}, rpcdGrant},
	{"revoke", true, map[string]string{"client": "String", "index": "Integer", "all": "Boolean"}, rpcdRevoke},
	{"revoke_tools", true, map[string]string{"client": "String", "tools": "Array"}, rpcdRevokeTools},
	{"grant_preset", true, map[string]string{"client": "String", "preset": "String", "duration": "String"}, rpcdGrantPreset},
	{"permit_all", true, map[string]string{"client": "String", "duration": "String", "confirm": "Boolean"}, rpcdPermitAll},
	{"end_permit_all", true, map[string]string{"client": "String"}, rpcdEndPermitAll},
	{"set_channel", true, map[string]string{"channel": "String", "enabled": "Boolean"}, rpcdSetChannel},
	{"pair", true, map[string]string{"client": "String", "pubkey": "String", "preset": "String", "duration": "String"}, rpcdPair},
	{"set_settings", true, map[string]string{"request_wait": "Integer", "request_ttl": "Integer"}, rpcdSetSettings},
}

type rpcdError struct {
	Msg  string `json:"error"`
	Code string `json:"code,omitempty"`
}

func (e rpcdError) Error() string { return e.Msg }

func rpcdFail(format string, a ...any) error { return rpcdError{Msg: fmt.Sprintf(format, a...)} }

// runRpcd implements the plugin protocol and returns the exit status.
func runRpcd(env rpcdEnv, args []string, stdin io.Reader, stdout io.Writer) int {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: openwrt-mcp rpcd list | call <method>")
		return 2
	}
	switch args[0] {
	case "list":
		sigs := map[string]map[string]string{}
		for _, m := range rpcdMethods {
			sigs[m.name] = m.sig
		}
		enc.Encode(sigs)
		return 0
	case "call":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: openwrt-mcp rpcd call <method>")
			return 2
		}
		i := slices.IndexFunc(rpcdMethods, func(m rpcdMethod) bool { return m.name == args[1] })
		if i < 0 {
			enc.Encode(rpcdError{Msg: fmt.Sprintf("unknown method %q", args[1])})
			return 0
		}
		in, err := io.ReadAll(io.LimitReader(stdin, 64<<10))
		if err != nil {
			enc.Encode(rpcdError{Msg: err.Error()})
			return 0
		}
		out, err := rpcdMethods[i].fn(env, in)
		var re rpcdError
		switch {
		case errors.As(err, &re):
			enc.Encode(re)
		case err != nil:
			enc.Encode(rpcdError{Msg: err.Error()})
		default:
			enc.Encode(out)
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "openwrt-mcp rpcd: unknown subcommand %q\n", args[0])
	return 2
}

// decodeArgs reads the method's JSON object, refusing a field the method does not take: a typo
// such as "breath" must not quietly fall back to a default. rpcd adds the caller's session id as
// "ubus_rpc_session" to every call; it is not an argument, so it is dropped first.
func decodeArgs(raw json.RawMessage, v any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) == nil {
		if _, ok := fields["ubus_rpc_session"]; ok {
			delete(fields, "ubus_rpc_session")
			raw, _ = json.Marshal(fields)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return rpcdFail("bad arguments: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------- reading

// rpcdRequest is a request as the page shows it: the stored facts, the state as of now (an open
// request past its time reads expired, and one a grant now covers reads allowed), and the family
// scope the "family" breadth would grant.
type rpcdRequest struct {
	Request
	Family string `json:"family"`
}

// scopeFamily is "wireless.*" for "wireless.radio1.disabled". A scope with no dot has no family
// and stays exact.
func scopeFamily(scope string) string {
	if head, _, ok := strings.Cut(scope, "."); ok && head != "" {
		return head + ".*"
	}
	return scope
}

func (e rpcdEnv) listRequests(cfg *Config) ([]rpcdRequest, error) {
	reqs, err := readMirror(e.requestsPath)
	if err != nil {
		return nil, rpcdFail("cannot read the request list: %v", err)
	}
	now := e.time()
	out := make([]rpcdRequest, 0, len(reqs))
	for _, r := range reqs {
		if r.State == reqOpen {
			if p, _, _ := cfg.authorise(r.Client, r.Tool, []string{r.Scope}, now); p != nil {
				r.State, r.Decider, r.Decided = reqAllowed, "policy", now
			} else if now.After(r.Expires) {
				r.State = reqExpired
			}
		}
		out = append(out, rpcdRequest{r, scopeFamily(r.Scope)})
	}
	return out, nil
}

func rpcdStatus(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Audit *int `json:"audit"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	lines := 40
	if in.Audit != nil {
		lines = min(max(*in.Audit, 0), 500)
	}
	rep, err := buildStatus(env.configPath, env.statePath, lines)
	if err != nil {
		return nil, err
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	reqs, err := env.listRequests(cfg)
	if err != nil {
		return nil, err
	}
	return struct {
		statusReport
		Requests []rpcdRequest `json:"requests"`
	}{rep, reqs}, nil
}

func rpcdRequests(env rpcdEnv, raw json.RawMessage) (any, error) {
	if err := decodeArgs(raw, &struct{}{}); err != nil {
		return nil, err
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	reqs, err := env.listRequests(cfg)
	return map[string]any{"requests": reqs}, err
}

func rpcdSettings(env rpcdEnv, raw json.RawMessage) (any, error) {
	if err := decodeArgs(raw, &struct{}{}); err != nil {
		return nil, err
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	var mfa []string
	if m, err := LoadMFA(mfaPath(env.statePath)); err == nil {
		mfa = m.Clients()
	}
	return map[string]any{
		"request_wait": int(cfg.RequestWait / time.Second), "request_ttl": int(cfg.RequestTTL / time.Second),
		"wait_max": int(maxRequestWait / time.Second),
		"ttl_min":  int(minRequestTTL / time.Second), "ttl_max": int(maxRequestTTL / time.Second),
		"mfa_clients": mfa, // read only here: enrolment stays on the command line
		"channels":    channelReport(cfg),
	}, nil
}

// ---------------------------------------------------------------- deciding

func rpcdAudit(cfg *Config, env rpcdEnv, tool, client, scope, summary string) {
	NewAuditor(cfg.AuditPath, cfg.AuditMaxMB).Record(AuditEvent{Time: env.time().UTC().Format(time.RFC3339),
		Client: "<" + rpcdActor + ">", Tool: tool, Scope: scope, Outcome: OutcomeOK, Summary: summary})
}

// planGrant is what Allow writes for a request at the chosen breadth, narrowest first. The result
// must cover the very call that was refused, or the held call would never be released.
func planGrant(r Request, breadth string) ([]presetPolicy, error) {
	if strings.ContainsAny(r.Scope, " \t\r\n") {
		return nil, rpcdFail("the scope %q contains a space, so a grant cannot name it exactly: use the command line", r.Scope)
	}
	var blocks []presetPolicy
	switch breadth {
	case "", "exact":
		blocks = []presetPolicy{{tools: []string{r.Tool}, scopes: []string{r.Scope}}}
	case "family":
		blocks = []presetPolicy{{tools: []string{r.Tool}, scopes: []string{scopeFamily(r.Scope)}}}
	case "tool":
		blocks = []presetPolicy{{tools: []string{r.Tool}, scopes: []string{"*"}}}
	case "operator":
		blocks, _ = expandPreset("@operator")
	default:
		return nil, rpcdFail("unknown breadth %q (exact, family, tool or operator)", breadth)
	}
	covered := slices.ContainsFunc(blocks, func(b presetPolicy) bool {
		return slices.Contains(b.tools, r.Tool) && matchAny(b.scopes, r.Scope)
	})
	if !covered {
		return nil, rpcdFail("that grant would not cover %s on %s (the operator preset leaves out the tools that bypass the safety rails): choose another breadth",
			r.Tool, r.Scope)
	}
	return blocks, nil
}

// writeGrants appends the blocks the way the CLI does: an expired grant for the same tools and
// scopes is replaced, not piled up.
func writeGrants(configPath, client string, blocks []presetPolicy, duration string) error {
	for _, b := range blocks {
		if _, err := removeExpired(configPath, time.Now(), func(p *Policy) bool {
			return p.Client == client && sameSet(p.Tools, b.tools) && sameSet(p.Scopes, b.scopes)
		}); err != nil {
			return err
		}
		if err := appendPolicy(configPath, client, strings.Join(b.tools, ","), strings.Join(b.scopes, " "), duration); err != nil {
			return err
		}
	}
	return nil
}

func rpcdDecide(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
		Breadth  string `json:"breadth"`
		Duration string `json:"duration"`
		Confirm  bool   `json:"confirm"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.Decision != "allow" && in.Decision != "deny" {
		return nil, rpcdFail("decision must be allow or deny")
	}
	if in.Duration == "" {
		in.Duration = rpcdDefaultDuration
	}
	if in.Decision == "allow" && !slices.Contains(rpcdDurations, in.Duration) {
		return nil, rpcdFail("duration %q is not offered here (%s); a longer or permanent grant is made on the Permissions tab",
			in.Duration, strings.Join(rpcdDurations, ", "))
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}

	unlock, err := lockMirror(env.requestsPath)
	if err != nil {
		return nil, rpcdFail("%v", err)
	}
	defer unlock()
	reqs, err := readMirror(env.requestsPath)
	if err != nil {
		return nil, rpcdFail("cannot read the request list: %v", err)
	}
	i := slices.IndexFunc(reqs, func(r Request) bool { return r.ID == in.ID })
	if i < 0 {
		return nil, rpcdFail("no request %q", in.ID)
	}
	r := &reqs[i]
	now := env.time()
	switch {
	case r.State != reqOpen:
		return nil, rpcdFail("request %s is already %s", r.ID, r.State)
	case now.After(r.Expires):
		return nil, rpcdFail("request %s expired: the agent has to ask again", r.ID)
	}
	if p, _, _ := cfg.authorise(r.Client, r.Tool, []string{r.Scope}, now); p != nil {
		return nil, rpcdFail("request %s is already allowed by an existing grant", r.ID)
	}

	summary := fmt.Sprintf("%s denied by %s", r.ID, rpcdActor)
	state := reqDenied
	if in.Decision == "allow" {
		blocks, err := planGrant(*r, in.Breadth)
		if err != nil {
			return nil, err
		}
		var hit []string
		for _, b := range blocks {
			hit = append(hit, shellEquivalentNames(b.tools, b.scopes)...)
		}
		if len(hit) > 0 && !in.Confirm {
			return nil, rpcdError{Code: "needs_confirm", Msg: fmt.Sprintf(
				"this grant lets %s run %s, and each of those can run any other program: it is a root shell whatever the other scopes say",
				r.Client, describeShellEquivalent(hit))}
		}
		if err := writeGrants(env.configPath, r.Client, blocks, in.Duration); err != nil {
			return nil, rpcdFail("cannot write the grant: %v", err)
		}
		state = reqAllowed
		breadth := in.Breadth
		if breadth == "" {
			breadth = "exact"
		}
		summary = fmt.Sprintf("%s allowed by %s: %s on %s for %s (%s)", r.ID, rpcdActor, r.Tool, r.Scope, in.Duration, breadth)
	}
	r.State, r.Decider, r.Decided = state, rpcdActor, now
	if err := writeMirror(env.requestsPath, reqs); err != nil {
		return nil, rpcdFail("the grant is written but the request list is not updated: %v", err)
	}
	rpcdAudit(cfg, env, "decide", r.Client, r.Scope, summary)
	return map[string]any{"id": r.ID, "state": string(state)}, nil
}

// ---------------------------------------------------------------- grants

func rpcdRevoke(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client string `json:"client"`
		Index  *int   `json:"index"`
		All    bool   `json:"all"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.Client == "" || (in.Index == nil) == !in.All {
		return nil, rpcdFail("give a client and exactly one of index and all")
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	n := 0
	removed, err := removePoliciesWhere(env.configPath, func(s uciSection) bool {
		if s.Options["client"] != in.Client {
			return false
		}
		hit := in.All || n == *in.Index
		n++
		return hit
	})
	if err != nil {
		return nil, rpcdFail("cannot revoke: %v", err)
	}
	if removed == 0 && !in.All {
		return nil, rpcdFail("no grant %d for %q", *in.Index, in.Client)
	}
	what := fmt.Sprintf("grant %d", orZero(in.Index))
	if in.All {
		what = "every grant"
	}
	rpcdAudit(cfg, env, "revoke", in.Client, "", fmt.Sprintf("removed %d policy block(s) for %q (%s)", removed, in.Client, what))
	return map[string]any{"removed": removed}, nil
}

// rpcdRevokeTools is the Permissions tab's switch turned off: it takes single tools out of the
// client's grants, which a preset writes as blocks that hold several abilities at once. Revoke by
// index removes a whole block and so cannot do this.
func rpcdRevokeTools(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client string   `json:"client"`
		Tools  []string `json:"tools"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if !reClientName.MatchString(in.Client) {
		return nil, rpcdFail("bad client name %q", in.Client)
	}
	if len(in.Tools) == 0 {
		return nil, rpcdFail("give the tools to revoke")
	}
	for _, t := range in.Tools {
		if !slices.Contains(allToolNames, t) {
			return nil, rpcdFail("no tool %q", t)
		}
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	removed, err := removeToolsFromPolicies(env.configPath, in.Client, in.Tools)
	if err != nil {
		return nil, rpcdFail("cannot revoke: %v", err)
	}
	if removed == 0 {
		return nil, rpcdFail("no grant of %s for %q", strings.Join(in.Tools, ", "), in.Client)
	}
	rpcdAudit(cfg, env, "revoke_tools", in.Client, "", fmt.Sprintf("removed %s from the grants of %q", strings.Join(in.Tools, ", "), in.Client))
	return map[string]any{"removed": removed}, nil
}

func orZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// rpcdGrant is the Permissions tab's single-tool grant: the owner acting, not answering an agent,
// so "never" is allowed here and not on a request card. A grant that amounts to a root shell
// needs the same second confirmation as a request for one.
func rpcdGrant(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client   string `json:"client"`
		Tool     string `json:"tool"`
		Scope    string `json:"scope"`
		Duration string `json:"duration"`
		Confirm  bool   `json:"confirm"`
		Replace  bool   `json:"replace"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if !reClientName.MatchString(in.Client) {
		return nil, rpcdFail("bad client name %q", in.Client)
	}
	if !slices.Contains(allToolNames, in.Tool) {
		return nil, rpcdFail("no tool %q", in.Tool)
	}
	if ungatedTools[in.Tool] {
		return nil, rpcdFail("%s needs no grant", in.Tool)
	}
	if in.Scope == "" {
		in.Scope = "*"
	}
	// Limits are separated by spaces, as on the CLI.
	if err := checkScopes(in.Scope); err != nil {
		return nil, rpcdFail("%v", err)
	}
	scopes := strings.Fields(in.Scope)
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	if unscopedTools[in.Tool] && (len(scopes) != 1 || scopes[0] != "*") {
		return nil, rpcdFail("%s cannot be limited: it has nothing to limit by, so a limit would never match", in.Tool)
	}
	if in.Duration == "" {
		in.Duration = rpcdDefaultDuration
	}
	if in.Duration != "never" && !slices.Contains(rpcdDurations, in.Duration) {
		return nil, rpcdFail("duration %q is not offered (%s, never)", in.Duration, strings.Join(rpcdDurations, ", "))
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	in.Scope = strings.Join(scopes, " ")
	blocks := []presetPolicy{{tools: []string{in.Tool}, scopes: scopes}}
	if hit := shellEquivalentNames(blocks[0].tools, blocks[0].scopes); len(hit) > 0 && !in.Confirm {
		return nil, rpcdError{Code: "needs_confirm", Msg: fmt.Sprintf(
			"this grant lets %s run %s, and each of those can run any other program: it is a root shell whatever the other scopes say",
			in.Client, describeShellEquivalent(hit))}
	}
	// Replacing happens only after every check above, and puts the old grant back if the write
	// fails, so an edit that is refused never leaves the tool without its grant.
	var before []byte
	if in.Replace {
		if before, err = os.ReadFile(env.configPath); err != nil {
			return nil, rpcdFail("cannot read the config: %v", err)
		}
		if _, err := removeToolsFromPolicies(env.configPath, in.Client, []string{in.Tool}); err != nil {
			return nil, rpcdFail("cannot replace the grant: %v", err)
		}
	}
	if err := writeGrants(env.configPath, in.Client, blocks, in.Duration); err != nil {
		if before != nil {
			_ = os.WriteFile(env.configPath, before, 0o600)
		}
		return nil, rpcdFail("cannot write the grant: %v", err)
	}
	rpcdAudit(cfg, env, "grant", in.Client, in.Scope, fmt.Sprintf("%s on %s for %s", in.Tool, in.Scope, in.Duration))
	return map[string]any{"blocks": 1}, nil
}

func rpcdGrantPreset(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client   string `json:"client"`
		Preset   string `json:"preset"`
		Duration string `json:"duration"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if !reClientName.MatchString(in.Client) {
		return nil, rpcdFail("bad client name %q", in.Client)
	}
	blocks, err := expandPreset("@" + strings.TrimPrefix(in.Preset, "@"))
	if err != nil {
		return nil, rpcdFail("%v", err)
	}
	if in.Duration != "never" && !slices.Contains(rpcdDurations, in.Duration) {
		return nil, rpcdFail("duration %q is not offered (%s, never)", in.Duration, strings.Join(rpcdDurations, ", "))
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	if err := writeGrants(env.configPath, in.Client, blocks, in.Duration); err != nil {
		return nil, rpcdFail("cannot write the grant: %v", err)
	}
	rpcdAudit(cfg, env, "grant_preset", in.Client, "", fmt.Sprintf("@%s for %s, %d policy block(s)",
		strings.TrimPrefix(in.Preset, "@"), in.Duration, len(blocks)))
	return map[string]any{"blocks": len(blocks)}, nil
}

// ---------------------------------------------------------------- settings

func rpcdSetSettings(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Wait *int `json:"request_wait"`
		TTL  *int `json:"request_ttl"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.Wait == nil && in.TTL == nil {
		return nil, rpcdFail("nothing to change: give request_wait or request_ttl")
	}
	if in.Wait != nil && (*in.Wait < 0 || time.Duration(*in.Wait)*time.Second > maxRequestWait) {
		return nil, rpcdFail("request_wait must be 0 to %d seconds", int(maxRequestWait/time.Second))
	}
	if in.TTL != nil && (time.Duration(*in.TTL)*time.Second < minRequestTTL || time.Duration(*in.TTL)*time.Second > maxRequestTTL) {
		return nil, rpcdFail("request_ttl must be %d to %d seconds", int(minRequestTTL/time.Second), int(maxRequestTTL/time.Second))
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, o := range []struct {
		name string
		v    *int
	}{{"request_wait", in.Wait}, {"request_ttl", in.TTL}} {
		if o.v == nil {
			continue
		}
		if err := setServerOption(env.configPath, o.name, fmt.Sprint(*o.v)); err != nil {
			return nil, rpcdFail("cannot write the setting: %v", err)
		}
		parts = append(parts, fmt.Sprintf("%s=%d", o.name, *o.v))
	}
	rpcdAudit(cfg, env, "set_settings", "", "", strings.Join(parts, " "))
	return rpcdSettings(env, nil)
}

// setServerOption sets one option in the `config server` section, replacing it or adding it
// right under the section line. Everything else, comments included, is copied through.
func setServerOption(configPath, name, value string) error {
	b, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	line := fmt.Sprintf("\toption %s '%s'", name, value)
	var out []string
	inServer, done := false, false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		text := sc.Text()
		f, _ := splitUCI(text)
		if len(f) > 0 && f[0] == "config" {
			inServer = len(f) > 1 && f[1] == "server" && !done
			out = append(out, text)
			if inServer {
				out = append(out, line)
				done = true
			}
			continue
		}
		if inServer && len(f) > 1 && f[0] == "option" && f[1] == name {
			continue // the new line is already in place above
		}
		out = append(out, text)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if !done {
		out = append([]string{"config server", line, ""}, out...)
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, configPath)
}
