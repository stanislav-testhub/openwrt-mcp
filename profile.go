package main

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A session profile is what the client asked for in its SSH command (entry.go): a narrower
// catalogue (--toolset) or no changes at all (--read-only). It rides on the context given to
// Server.Connect, which the SDK hands to every handler and middleware of that connection
// (pinned by session_ctx_test.go), so the server stays shared per client while each connection
// keeps its own profile. A profile only removes: the client's grants are still checked after it.
// It also says who is on the other end of the SSH link, which the management-path rule and the
// dry-run warnings use to tell what this session depends on.
type sessionProfile struct {
	Toolsets []string // nil: every toolset, and exec
	ReadOnly bool
	Peer     netip.Addr // the client's address as sshd reports it; the zero value when unknown
}

// parsePeer keeps what the bridge reports only if it is an address.
func parsePeer(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.WithZone("").Unmap()
}

type profileKey struct{}

func withProfile(ctx context.Context, p sessionProfile) context.Context {
	return context.WithValue(ctx, profileKey{}, p)
}

// profileFrom returns the zero profile (no narrowing) when a connection carries none, as on the
// HTTP transport.
func profileFrom(ctx context.Context) sessionProfile {
	p, _ := ctx.Value(profileKey{}).(sessionProfile)
	return p
}

// toolsetTools are the tools each toolset adds. coreTools are listed whenever any toolset is
// selected; unrestrictedTools belong to no toolset, so only a session that selects none has them
// (exec is the escape hatch, and a narrowed session should not carry it by accident). A tool
// missing from all three fails TestToolsetTablePartitionsEveryTool.
var toolsetTools = map[string][]string{
	"diag":   {"logread", "network_clients", "firewall_show", "net_diag", "service_list", "ubus_list", "ubus_call"},
	"config": {"uci_get", "uci_apply", "uci_confirm", "uci_rollback", "service_control"},
	"pkg":    {"pkg_query", "pkg_change", "pkg_config_diff", "pkg_config_resolve", "sysupgrade"},
	"wg":     {"wg_list_clients", "wg_new_client", "wg_remove_client"},
}

var (
	coreTools         = []string{"system_status", "mfa_unlock"}
	unrestrictedTools = []string{"exec"}
)

func (p sessionProfile) inToolsets(tool string) bool {
	if p.Toolsets == nil || slices.Contains(coreTools, tool) {
		return true
	}
	for _, ts := range p.Toolsets {
		if slices.Contains(toolsetTools[ts], tool) {
			return true
		}
	}
	return false
}

// readOnlyCovers reports whether a read-only session may make this call. The definition of
// "read" is the @readonly preset, the one the operator already reasons about, so a mode added to a
// tool is read-only exactly when the preset's scopes say so. ubus_list needs no grant and only
// names objects; mfa_unlock and uci_confirm are not in the preset and so are out.
func readOnlyCovers(tool string, scopes []string) bool {
	if tool == "ubus_list" {
		return true
	}
	for _, b := range presets["readonly"] {
		if slices.Contains(b.tools, tool) {
			if _, ok := firstUncovered(b.scopes, scopes); ok {
				return true
			}
		}
	}
	return false
}

// readOnlyListed is readOnlyCovers for the catalogue, where no scopes are known yet.
func readOnlyListed(tool string) bool {
	return tool == "ubus_list" || slices.ContainsFunc(presets["readonly"], func(b presetPolicy) bool {
		return slices.Contains(b.tools, tool)
	})
}

// lists reports whether the tool is shown in this session's catalogue.
func (p sessionProfile) lists(tool string) bool {
	return p.inToolsets(tool) && (!p.ReadOnly || readOnlyListed(tool))
}

// refusal is the denial for a call this profile does not allow, or "" when it does. It runs
// before the client's own grants are looked at.
func (p sessionProfile) refusal(tool string, scopes []string) string {
	if !p.inToolsets(tool) {
		return fmt.Sprintf("denied: %s is not available in this session (toolsets: %s); reconnect without --toolset or with one that includes it",
			tool, strings.Join(p.Toolsets, ","))
	}
	if p.ReadOnly && !readOnlyCovers(tool, scopes) {
		return fmt.Sprintf("denied: this session is read-only (--read-only), so %s %s is not allowed; reconnect without --read-only to make changes",
			tool, strings.Join(scopes, " "))
	}
	return ""
}

// String is the profile as the audit log shows it; empty for the zero profile.
func (p sessionProfile) String() string {
	var parts []string
	if p.ReadOnly {
		parts = append(parts, "read-only")
	}
	if p.Toolsets != nil {
		parts = append(parts, "toolsets "+strings.Join(p.Toolsets, ","))
	}
	return strings.Join(parts, ", ")
}

// profileCatalogue trims tools/list to the session's profile. It is presentation only: the
// call-time check in addTool is what enforces.
func profileCatalogue(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if lr, ok := res.(*mcp.ListToolsResult); ok && err == nil {
			p := profileFrom(ctx)
			kept := make([]*mcp.Tool, 0, len(lr.Tools))
			for _, tl := range lr.Tools {
				if p.lists(tl.Name) {
					kept = append(kept, tl)
				}
			}
			lr.Tools = kept
		}
		return res, err
	}
}
