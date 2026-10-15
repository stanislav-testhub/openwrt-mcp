package main

import (
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The tool groups on the LuCI Permissions tab (docs/luci-approvals.md, 8.4). Which tool is in which
// group is a decision made here; the title, the read/write badge and the rollback and key notes
// come from the tool registry itself (toolTitles and the annotations addTool registers), so the
// page cannot drift from the server. TestEveryToolHasExactlyOneGroup fails when a tool is added
// without a place on the page.
var toolGroups = []struct {
	ID, Title string
	Tools     []string
}{
	{"diagnostics", "Diagnostics", []string{"system_status", "logread", "network_clients", "firewall_show", "service_list", "net_diag", "ubus_list"}},
	{"configuration", "Configuration", []string{"uci_get", "uci_apply", "uci_confirm", "uci_rollback"}},
	{"packages", "Packages", []string{"pkg_query", "pkg_config_diff", "pkg_change", "pkg_config_resolve"}},
	{"vpn", "VPN", []string{"wg_list_clients", "wg_new_client", "wg_remove_client"}},
	{"system", "System", []string{"service_control", "sysupgrade", "mfa_unlock"}},
	{"raw", "Raw access", []string{"exec", "ubus_call"}},
}

// Badge values: how much a tool can change, as the owner reads it.
const (
	badgeRead  = "read"
	badgeWrite = "write"
	badgeShell = "shell" // runs any program or any ubus method: a root shell whatever the scope says
)

// rootShellTools are the tools whose grant is a root shell by design (SECURITY.md).
var rootShellTools = []string{"exec", "ubus_call"}

type toolRow struct {
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Badge    string   `json:"badge"`
	Notes    []string `json:"notes,omitempty"` // "rollback", "keys"
	Ungated  bool     `json:"ungated,omitempty"`
	Unscoped bool     `json:"unscoped,omitempty"` // a grant is on or off: there is nothing to limit it by
	Why      string   `json:"why,omitempty"` // why the row cannot be granted
	Readonly bool     `json:"readonly"`      // in the @readonly preset
}

type toolGroupRow struct {
	ID    string    `json:"id"`
	Title string    `json:"title"`
	Tools []toolRow `json:"tools"`
}

// registryTools lists the tools exactly as an MCP client sees them, through the same server
// construction the daemon uses. The handlers are never run, so a bare Server is enough.
func registryTools(ctx context.Context) ([]*mcp.Tool, error) {
	s := &Server{servers: map[string]*mcp.Server{}}
	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.newServerForClient("rpcd").Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "openwrt-mcp-rpcd", Version: version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// buildToolGroups joins the group table with the registry. A tool the table does not place, or a
// table entry the registry lacks, is an error rather than a silently missing row.
func buildToolGroups(tools []*mcp.Tool) ([]toolGroupRow, error) {
	byName := map[string]*mcp.Tool{}
	for _, t := range tools {
		byName[t.Name] = t
	}
	var out []toolGroupRow
	placed := map[string]bool{}
	for _, g := range toolGroups {
		row := toolGroupRow{ID: g.ID, Title: g.Title}
		for _, name := range g.Tools {
			t, ok := byName[name]
			if !ok {
				return nil, rpcdFail("tool group %s lists %s, which is not registered", g.ID, name)
			}
			placed[name] = true
			row.Tools = append(row.Tools, rowFor(t))
		}
		out = append(out, row)
	}
	var missing []string
	for name := range byName {
		if !placed[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, rpcdFail("tools with no group on the Permissions tab: %v", missing)
	}
	return out, nil
}

func rowFor(t *mcp.Tool) toolRow {
	r := toolRow{Name: t.Name, Title: t.Title, Badge: badgeWrite, Ungated: ungatedTools[t.Name], Unscoped: unscopedTools[t.Name], Readonly: readOnlyListed(t.Name)}
	if t.Annotations != nil {
		if t.Annotations.ReadOnlyHint {
			r.Badge = badgeRead
		}
		if t.Annotations.Title != "" && r.Title == "" {
			r.Title = t.Annotations.Title
		}
	}
	if slices.Contains(rootShellTools, t.Name) {
		r.Badge = badgeShell
	}
	switch t.Name {
	case "uci_apply":
		r.Notes = append(r.Notes, "rollback")
	case "wg_new_client":
		r.Notes = append(r.Notes, "keys")
	}
	if r.Ungated {
		r.Why = "needs no grant"
	}
	return r
}

func rpcdTools(env rpcdEnv, raw json.RawMessage) (any, error) {
	if err := decodeArgs(raw, &struct{}{}); err != nil {
		return nil, err
	}
	tools, err := registryTools(context.Background())
	if err != nil {
		return nil, rpcdFail("cannot list the tools: %v", err)
	}
	groups, err := buildToolGroups(tools)
	if err != nil {
		return nil, err
	}
	return map[string]any{"groups": groups}, nil
}
