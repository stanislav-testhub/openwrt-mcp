package main

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverInstructions = `openwrt-mcp runs ON an OpenWrt 25.12 router (apk, fw4/nftables, procd, netifd).
Start with system_status. Prefer the specific tools over ubus_call/exec; use ubus_list to discover
anything else. Every call is authorised by a standing policy and audited; a denial names the
missing scope and the exact grant command, so relay it to the operator rather than working around it.
Configuration changes go through uci_apply: run it with dry_run first, then for real -- it arms an
automatic rollback that you must uci_confirm after checking the router still works. Package changes
(pkg_change) simulate unless commit=true. Anything that prints keys (wg_new_client, backups)
is a credential: show it to the operator, never store it.`

// newServerForClient builds an MCP server whose handlers are closed over one authenticated
// client name. Identity therefore comes from the validated token or SSH key at connection
// time and can never be spoofed by a tool argument or a self-asserted clientInfo.name.
func (s *Server) newServerForClient(client string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "openwrt-mcp", Version: version},
		&mcp.ServerOptions{Instructions: serverInstructions})

	// ---- discovery and generic access

	addTool(s, srv, client, "ubus_list",
		"List ubus objects and their methods with argument signatures -- the discovery tool for anything the "+
			"specific tools don't cover. Always permitted (introspection only, returns no configuration data).",
		annRead,
		noScope[ubusListIn],
		func(ctx context.Context, in ubusListIn) (string, string, error) {
			argv := []string{"ubus", "-v", "list"}
			if in.Filter != "" {
				argv = append(argv, in.Filter)
			}
			out, err := run(ctx, defaultCmdTimeout, argv...)
			return out, "listed ubus objects", err
		})

	addTool(s, srv, client, "ubus_call",
		"Call any ubus method: network.interface.*, network.wireless, iwinfo, hostapd.*, luci-rpc, dnsmasq, "+
			"system, service, rc, file, ... Replies over 8 KB have long arrays pruned. Some methods WRITE "+
			"(system.reboot, network.interface.*.down, uci.set, rc.init) -- prefer the dedicated tools for those. "+
			"Policy scope: \"<object>.<method>\".",
		nil,
		func(in ubusCallIn) []string { return []string{in.Object + "." + in.Method} },
		ubusCall)

	addTool(s, srv, client, "exec",
		"Run one program with arguments, directly -- no shell, so no pipes, globs or redirection. A broad "+
			"grant is a root shell; use the specific tools where one exists. Policy scope: argv[0].",
		annDest, execScope, execTool)

	// ---- state

	addTool(s, srv, client, "system_status",
		"One-call overview: model, release, kernel, uptime, load, memory, storage, temperatures, conntrack, every "+
			"interface (state, addresses, default route, errors), radios and SSIDs, and anything outstanding "+
			"(uncommitted uci edits, an apply awaiting confirmation, .apk-new files). Call this first.",
		annRead, noScope[systemStatusIn], s.systemStatus)

	addTool(s, srv, client, "logread",
		"Read the system log (kernel and daemons). Filters apply to the whole log buffer before the line limit, "+
			"so a rare message is not lost behind noise.",
		annRead, noScope[logreadIn], logread)

	addTool(s, srv, client, "network_clients",
		"Who is on the network: DHCP leases and static hosts joined by MAC with the neighbour table and every "+
			"access point's association list -- host name, IP, MAC, SSID/interface, signal, rates, connected time, lease.",
		annRead, noScope[networkClientsIn], networkClients)

	addTool(s, srv, client, "firewall_show",
		"Read the fw4/nftables firewall: the live ruleset, what fw4 would render from /etc/config/firewall, a "+
			"config check, or one table/chain. (iptables does not exist on OpenWrt 22.03+.)",
		annRead, noScope[firewallShowIn], firewallShow)

	addTool(s, srv, client, "net_diag",
		"Network diagnostics from the router: ping, traceroute, nslookup (optionally from a given interface, for "+
			"multi-uplink setups), and the IPv4/IPv6 routing table, policy rules and neighbours. "+
			"Policy scope: \"<action>.<target>\" or \"<action>\".",
		annRead, netDiagScope, netDiag)

	// ---- configuration (uci)

	addTool(s, srv, client, "uci_get",
		"Read configuration as config.section.option=value lines. Give a config to dump it, a section to narrow, "+
			"an option for one value; ids=true shows anonymous sections by stable id. Includes secrets such as "+
			"Wi-Fi keys. Policy scope: '<config>', '<config>.<section>' or '<config>.<section>.<option>' "+
			"('<config>.*' covers section/option reads, not the whole config).",
		annRead, uciGetScope, uciGet)

	addTool(s, srv, client, "uci_apply",
		"Change configuration safely. Stages the changes, commits, reloads the affected services, and ARMS A "+
			"ROLLBACK: unless uci_confirm is called before the timeout the router restores the previous files -- "+
			"also after a reboot. Run with dry_run=true first to see exactly what uci would change.\n"+
			"Ops: set (option=value), create (named section of a type), delete (option or section), add_list / "+
			"del_list (one list element), set_list (replace a whole list). Example, a static lease:\n"+
			"  {config:dhcp, section:pi, op:create, type:host}\n"+
			"  {config:dhcp, section:pi, option:mac, value:'88:a2:9e:8a:e4:15'}\n"+
			"  {config:dhcp, section:pi, option:ip, value:'192.168.1.141'}\n"+
			"Changes run in order. Policy scope per change: '<config>.<section>.<option>' or '<config>.<section>'.",
		annDest, uciScopes,
		func(ctx context.Context, in uciApplyIn) (string, string, error) { return s.uciApply(ctx, client, in) })

	addTool(s, srv, client, "uci_confirm",
		"Make a pending uci_apply (or pkg_config_resolve use_new) permanent. Only after verifying the router is "+
			"reachable and behaving; doing nothing is the safe default -- the change reverts.",
		annIdem, noScope[uciTokenIn],
		func(ctx context.Context, in uciTokenIn) (string, string, error) { return s.uciConfirm(ctx, in.Token) })

	addTool(s, srv, client, "uci_rollback",
		"Undo a pending uci_apply right now instead of waiting for its timer.",
		annIdem, noScope[uciTokenIn],
		func(ctx context.Context, in uciTokenIn) (string, string, error) {
			return s.uciRollbackNow(ctx, in.Token)
		})

	// ---- services

	addTool(s, srv, client, "service_list",
		"List init scripts with boot state (enabled/disabled) and whether procd has them running.",
		annRead, noScope[serviceListIn], serviceList)

	addTool(s, srv, client, "service_control",
		"start / stop / restart / reload / enable / disable an init script via procd. Stopping or disabling "+
			"dropbear, network, rpcd or openwrt-mcp is refused (it would cut the path to this tool). "+
			"Policy scope: \"<service>.<action>\".",
		annDest, serviceControlScope, serviceControl)

	// ---- packages (apk)

	addTool(s, srv, client, "pkg_query",
		"Query apk: installed (optionally a glob), upgradable, search, info, files, owner (which package owns a "+
			"path), policy (available versions), audit (files changed since install), world (explicitly requested "+
			"packages). refresh=true runs 'apk update' first.",
		annRead, noScope[pkgQueryIn], pkgQuery)

	addTool(s, srv, client, "pkg_change",
		"Install, remove or upgrade packages with apk. SIMULATES unless commit=true, so call once to see the "+
			"plan, then again to do it. Reports any new .apk-new config files. Upgrading everything in place is "+
			"discouraged on OpenWrt. Policy scope: '<action>.<package>' each, or 'upgrade' for a full upgrade.",
		annDest, pkgChangeScope, pkgChange)

	addTool(s, srv, client, "pkg_config_diff",
		"Show the .apk-new files an upgrade left behind (new package defaults not applied because the live config "+
			"was modified), each as a diff against the live file.",
		annRead, noScope[pkgConfigDiffIn], pkgConfigDiff)

	addTool(s, srv, client, "pkg_config_resolve",
		"Resolve one .apk-new: keep_current deletes it; use_new installs it over the live file (old copy kept as "+
			".pre-apk-new; for /etc/config/* with a rollback timer and uci_confirm, like uci_apply). "+
			"Policy scope: the live path, e.g. '/etc/config/dhcp'.",
		annDest, pkgResolveScope,
		func(ctx context.Context, in pkgConfigResolveIn) (string, string, error) {
			return s.pkgConfigResolve(ctx, client, in)
		})

	addTool(s, srv, client, "sysupgrade",
		"Firmware helpers that never flash: list (files a sysupgrade keeps), test (validate an image already in "+
			"/tmp), check (owut: is a newer release available), backup (config archive in /tmp). "+
			"Policy scope: the action.",
		nil, sysupgradeScope, sysupgradeTool)

	// ---- wireguard

	addTool(s, srv, client, "wg_list_clients",
		"List WireGuard peers: name, allowed IPs, last handshake, endpoint, traffic, and whether config and "+
			"kernel agree.",
		annRead, noScope[wgListIn], wgListClients)

	addTool(s, srv, client, "wg_new_client",
		"Issue a WireGuard client: keypair, next free tunnel address, peer saved in /etc/config/network and "+
			"hot-added without restarting the interface. Returns the client config and a QR code. The output "+
			"contains a NEW PRIVATE KEY: show it to the operator, never store it. One config per device. "+
			"Policy scope: 'wireguard.<iface>' (or 'wireguard' when iface is omitted).",
		annDest, wgNewScope,
		func(ctx context.Context, in wgNewClientIn) (string, string, error) { return s.wgNewClient(ctx, in) })

	addTool(s, srv, client, "wg_remove_client",
		"Remove a WireGuard peer (by name, public key or section) from the running interface and the config. "+
			"Refuses a peer connected in the last 3 minutes unless force=true. "+
			"Policy scope: 'wireguard.<iface>.<name>' ('_' for iface when omitted).",
		annDest, wgRemoveScope,
		func(ctx context.Context, in wgRemoveIn) (string, string, error) { return s.wgRemoveClient(ctx, in) })

	// ---- second factor

	addTool(s, srv, client, "mfa_unlock",
		"Supply a 6-digit TOTP code to unlock the tools this client's policy marks as needing a second factor. "+
			"One code opens a time-boxed window; ask the operator for a code once and work until it expires. "+
			"Codes are single-use.",
		annIdem, noScope[mfaUnlockIn],
		func(ctx context.Context, in mfaUnlockIn) (string, string, error) {
			now := time.Now()
			window := defaultMFAWindow
			// Use the window from any policy that names this client, so a policy saying
			// 5m is not silently stretched to the default.
			for _, p := range s.cfg().Policies {
				if p.Client == client && p.Enabled && len(p.MFATools) > 0 {
					window = p.MFAWindow
					break
				}
			}
			until, err := s.mfa.Unlock(client, in.Code, window, now)
			if err != nil {
				// Returned as an error so it audits as ERROR, distinct from a policy DENIED.
				return "", "mfa_unlock", err
			}
			return fmt.Sprintf("Unlocked until %s (%s).", until.Format(time.RFC3339), window), "mfa_unlock", nil
		})

	return srv
}

// allToolNames is every tool the server registers, for presets and validation.
var allToolNames = []string{
	"ubus_list", "ubus_call", "exec", "system_status", "logread", "network_clients", "firewall_show",
	"net_diag", "uci_get", "uci_apply", "uci_confirm", "uci_rollback", "service_list", "service_control",
	"pkg_query", "pkg_change", "pkg_config_diff", "pkg_config_resolve", "sysupgrade", "wg_list_clients",
	"wg_new_client", "wg_remove_client", "mfa_unlock",
}

// ---------------------------------------------------------------- small tool inputs

type ubusListIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"optional ubus object path, e.g. 'network.interface.lan' or 'hostapd.*'. Omit to list every object."`
}

type ubusCallIn struct {
	Object string         `json:"object" jsonschema:"ubus object name, e.g. 'network.interface.lan' or 'iwinfo'"`
	Method string         `json:"method" jsonschema:"method to call on that object, e.g. 'status'"`
	Args   map[string]any `json:"args,omitempty" jsonschema:"JSON arguments for the method; omit for none"`
}

type mfaUnlockIn struct {
	Code string `json:"code" jsonschema:"the current 6-digit code from the operator's authenticator app"`
}

// ubusCall is the ubus_call handler. It is a named function rather than a closure so a test
// can assert that the reply really is pruned on the way out.
func ubusCall(ctx context.Context, in ubusCallIn) (string, string, error) {
	if in.Object == "" || in.Method == "" {
		return "", "", fmt.Errorf("object and method are required")
	}
	argv := []string{"ubus", "call", in.Object, in.Method}
	if len(in.Args) > 0 {
		argv = append(argv, jsonCompact(in.Args))
	}
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if err == nil {
		out = pruneUbusJSON(out)
	}
	return out, in.Object + "." + in.Method, err
}
