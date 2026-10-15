package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Permit all (docs/luci-approvals.md, 8.6): every gated tool on every scope, for a client, for a
// short time. It is a root shell, so it is a preset of its own that no other path reaches: the
// CLI needs --shell-equivalent, the LuCI page needs a typed client name and a confirm flag, and
// neither accepts "never" or more than 24 hours. The deny floor, the audit log, rollback on
// uci_apply, redaction and the rate limit all still apply under it. Second factors do not: they
// are set per grant, and this one carries none, so a client that has enrolled one is refused.

var permitAllDurations = []string{"15m", "1h", "4h", "24h"}

const (
	permitAllMax      = 24 * time.Hour
	permitAllDefault  = "1h"
	permitAllWarning  = "Not recommended. For the next %s, the agent can do anything root can: change or break Wi-Fi, firewall and network settings (and lock you out), read every password and key on the router, install or remove software, and run any program. Mistakes are not always reversible: only uci_apply changes roll back. Prefer approving requests one by one."
	permitAllAuditVia = "permit-all"
)

// permitAllBlocks is the one policy block @all expands to. Not in `presets`: expandPreset serves
// the CLI and rpcd's preset grants, and neither may reach this without its confirmation.
func permitAllBlocks() []presetPolicy {
	var tools []string
	for _, t := range allToolNames {
		if !ungatedTools[t] {
			tools = append(tools, t)
		}
	}
	return []presetPolicy{{tools: tools, scopes: []string{"*"}}}
}

// permitsAll reports whether the grant covers every gated tool on every scope, however it was
// written: the banner and End now follow the shape, not a label an edit could drop.
func (p *Policy) permitsAll() bool {
	if !contains(p.Scopes, "*") {
		return false
	}
	for _, t := range allToolNames {
		if !ungatedTools[t] && !contains(p.Tools, t) {
			return false
		}
	}
	return true
}

// checkPermitAllDuration accepts a positive duration of at most 24 hours. "never" is not one.
func checkPermitAllDuration(s string) error {
	d, err := parseDuration(s)
	if err != nil || d <= 0 {
		return fmt.Errorf("permit all takes a duration up to 24h, not %q (never is not allowed)", s)
	}
	if d > permitAllMax {
		return fmt.Errorf("permit all is capped at 24h, not %s", s)
	}
	return nil
}

// permitAllMFA refuses a client with an enrolled second factor: the @all block carries none, so
// it would be a way round it.
func permitAllMFA(statePath, client string) error {
	if m, err := LoadMFA(mfaPath(statePath)); err == nil && slices.Contains(m.Clients(), client) {
		return fmt.Errorf("%q has a second factor enrolled, and permit all carries none: grant the tools you need "+
			"with mfa_tools by hand instead", client)
	}
	return nil
}

type permitAllRow struct {
	Client  string `json:"client"`
	Expires string `json:"expires"` // RFC3339 of the longest block running; "" for one that never ends (a hand-written grant)
}

// activePermitAll lists the clients that hold a live permit-all grant, with when it ends.
func activePermitAll(cfg *Config, now time.Time) []permitAllRow {
	rows := []permitAllRow{} // never null in the JSON
	for _, p := range cfg.Policies {
		if !p.Enabled || (!p.Expires.IsZero() && now.After(p.Expires)) || !p.permitsAll() {
			continue
		}
		exp := ""
		if !p.Expires.IsZero() {
			exp = p.Expires.Format(time.RFC3339)
		}
		i := slices.IndexFunc(rows, func(r permitAllRow) bool { return r.Client == p.Client })
		switch {
		case i < 0:
			rows = append(rows, permitAllRow{p.Client, exp})
		case rows[i].Expires != "" && (exp == "" || exp > rows[i].Expires): // "" is never: the longest
			rows[i].Expires = exp
		}
	}
	return rows
}

// ---------------------------------------------------------------- rpcd

func rpcdPermitAll(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client   string `json:"client"`
		Duration string `json:"duration"`
		Confirm  bool   `json:"confirm"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if !reClientName.MatchString(in.Client) {
		return nil, rpcdFail("bad client name %q", in.Client)
	}
	if in.Duration == "" {
		in.Duration = permitAllDefault
	}
	if !slices.Contains(permitAllDurations, in.Duration) {
		return nil, rpcdFail("duration %q is not offered (%s); there is no never", in.Duration, strings.Join(permitAllDurations, ", "))
	}
	if err := permitAllMFA(env.statePath, in.Client); err != nil {
		return nil, rpcdFail("%v", err)
	}
	if !in.Confirm {
		return nil, rpcdError{Code: "needs_confirm", Msg: fmt.Sprintf(permitAllWarning, in.Duration)}
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	if err := writeGrants(env.configPath, in.Client, permitAllBlocks(), in.Duration); err != nil {
		return nil, rpcdFail("cannot write the grant: %v", err)
	}
	rpcdAudit(cfg, env, "permit_all", in.Client, "*", fmt.Sprintf("full root access for %s", in.Duration))
	return map[string]any{"client": in.Client, "duration": in.Duration}, nil
}

func rpcdEndPermitAll(env rpcdEnv, raw json.RawMessage) (any, error) {
	var in struct {
		Client string `json:"client"`
	}
	if err := decodeArgs(raw, &in); err != nil {
		return nil, err
	}
	if in.Client == "" {
		return nil, rpcdFail("give a client")
	}
	cfg, err := LoadConfig(env.configPath)
	if err != nil {
		return nil, err
	}
	removed, err := removePoliciesWhere(env.configPath, func(s uciSection) bool {
		if s.Options["client"] != in.Client {
			return false
		}
		p, perr := policyFromSection(s)
		return perr == nil && p.permitsAll()
	})
	if err != nil {
		return nil, rpcdFail("cannot end it: %v", err)
	}
	if removed == 0 {
		return nil, rpcdFail("%q has no permit-all grant", in.Client)
	}
	rpcdAudit(cfg, env, "end_permit_all", in.Client, "*", fmt.Sprintf("removed %d block(s)", removed))
	return map[string]any{"removed": removed}, nil
}
