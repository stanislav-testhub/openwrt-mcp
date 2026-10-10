---
name: openwrt-mcp
description: Inspect and change an OpenWrt router through its openwrt-mcp SSH bridge from the shell: status, logs, clients, firewall, packages, WireGuard, and configuration changes with automatic rollback. Use when the user asks about their router and no openwrt MCP server is connected.
---

# openwrt-mcp from the shell

openwrt-mcp runs on the router. Each tool is one SSH command; the policy, audit log, redaction and
rollback are the same as over MCP.

    ssh -T [-i KEY] [-p PORT] USER@ROUTER call TOOL '{"arg":"value"}'

Use the same ssh options as the user's MCP client entry (`openwrt-mcp connect` prints them).

- `call --list` prints the tools this session has, one per line. `call TOOL --help` prints one tool's
  description and argument schema: run it before the first use of a tool.
- Arguments are one JSON object; leave them out for none. Quote the JSON for your local shell
  (single quotes in bash and zsh).
- Output is text on stdout. A refusal or an error goes to stderr and the exit status is 1.
- A refusal names the exact `openwrt-mcp allow ...` command. Show it to the user; do not look for another way in.
- Start with `system_status`. Prefer the specific tools to `ubus_call` and `exec`.
- Change configuration with `uci_apply`: run it with `dry_run` first, then for real. It arms an automatic
  rollback; check that the router still works, then `uci_confirm`.
- Package changes simulate unless `commit` is true.
- Anything that prints keys (`wg_new_client`, backups) is a credential: show it to the user, never store it.
- To narrow a session, put options between `--` (which ends ssh's own options) and `call`:
  `ssh ... USER@ROUTER -- --read-only --toolset diag,pkg call ...` (toolsets: diag, config, pkg, wg).

## Tools

- `exec`: Run a command (no shell)
- `firewall_show`: Firewall ruleset
- `logread`: System log
- `mfa_unlock`: Unlock MFA-gated tools
- `net_diag`: Network diagnostics
- `network_clients`: Network clients
- `pkg_change`: Install, remove or upgrade packages
- `pkg_config_diff`: Review new package configs
- `pkg_config_resolve`: Resolve a package config
- `pkg_query`: Query packages
- `service_control`: Control a service
- `service_list`: List services
- `system_status`: Router status
- `sysupgrade`: Firmware checks and backup (never flashes)
- `ubus_call`: Call a ubus method
- `ubus_list`: List ubus objects
- `uci_apply`: Change configuration (auto-rollback)
- `uci_confirm`: Confirm pending change
- `uci_get`: Read configuration
- `uci_rollback`: Roll back pending change
- `wg_list_clients`: List WireGuard peers
- `wg_new_client`: Add WireGuard peer
- `wg_remove_client`: Remove WireGuard peer
