# openwrt-mcp -- an MCP server for OpenWrt 25.12+

[![CI](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![OpenWrt 25.12+](https://img.shields.io/badge/OpenWrt-25.12%2B-00B5E2)

An [MCP](https://modelcontextprotocol.io) server that runs **on** an OpenWrt router, so
Claude Code (or any MCP client) can inspect and change it -- behind deny-by-default policies,
an audit log, and an automatic rollback for configuration changes.

> **Based on [GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp)** by Ian
> Williams, which targets GL.iNet firmware 4.x (OpenWrt 21.02, `opkg`). This is a port to
> **stock OpenWrt 25.12** (`apk`, fw4/nftables, procd, netifd, LuCI JS). The security core is
> upstream's; see [Credits](#credits) for what came from where.

## Requirements

- **Router:** stock OpenWrt **25.12.0 or newer** (the `apk` releases). Nothing to install on the
  router beforehand. 24.10 and older (`opkg`, 21.02-era tooling) are not supported -- use
  upstream for GL.iNet 4.x firmware.
- **Workstation:** Go 1.26+, `ssh`, `tar` (Linux, macOS, or Git Bash on Windows).
- **Any CPU OpenWrt and Go share:** `install.sh` reads the router's `DISTRIB_ARCH` and
  cross-compiles a static binary (arm64, armv5/v7, mips/mipsle softfloat, mips64, x86, riscv64).

Tested on a GL.iNet GL-MT6000 (mediatek/filogic, `aarch64_cortex-a53`) with OpenWrt 25.12.5.
Nothing in the code is specific to that board.

---

## What changed from upstream

| | upstream 0.5 (21.02 / GL.iNet) | this port (25.12) |
|---|---|---|
| Packaging | `.ipk` for `opkg` | `install.sh` file install + `keep.d` (25.12's apk has no `mkpkg`; see below) |
| Web UI | GL.iNet oui-httpd page | LuCI page, *Services -> MCP Server* (read-only) |
| Transport | HTTP over an `ssh -L` tunnel | same, **plus stdio over SSH** via a key-bound forced command -- no tunnel to keep alive |
| Rollback snapshot | `/tmp` (lost on reboot) | **on flash**; an unconfirmed change is rolled back at the next start, including after a power cycle |
| `uci_apply` | set / create / delete | **+ `add_list`, `del_list`, `set_list`, `dry_run`**, shows the staged `uci changes`, strict name validation |
| Reload | `ubus call uci reload_config` (async) | `/sbin/reload_config`, plus explicit `config.change` events when it has no checksums (first run after boot) |
| WireGuard | GL `wireguard_server` / `gl_ddns` | stock `network.<iface>` + `wireguard_<iface>` peers, DDNS from `ddns`, CGNAT warning, PSK, list and remove |
| Packages | -- | `pkg_query`, `pkg_change` (simulate first), `.apk-new` review with a settings-level diff |
| Firewall | -- | `firewall_show`: nft ruleset, `fw4 print`, `fw4 check` |
| Services | -- | `service_list` / `service_control` via rpcd `rc` |
| Scope globs | `[0]` was a character class | brackets are literal: `firewall.@rule[3].*` means what it says |
| Presets | -- | `openwrt-mcp allow <client> @readonly|@operator <dur>` |

---

## Tools

| Tool | Scope | |
|---|---|---|
| `system_status` | tool | Model, release, uptime, load, memory, storage, temperatures, conntrack, every interface (state, addresses, default route, errors), radios/SSIDs, and what is outstanding. Call first. |
| `logread` | tool | Whole log buffer filtered (substring, RE2, last N minutes) *before* the line limit. |
| `network_clients` | tool | DHCP leases + static hosts + neighbour table + every AP's association list, joined by MAC: name, IP, SSID, signal, rates, connected time, lease. |
| `firewall_show` | tool | `nft list ruleset`, `fw4 print`, `fw4 check`, one table or chain. |
| `net_diag` | `<action>[.<target>]` | ping / traceroute / nslookup (optionally from a given interface), routes, policy rules, neighbours. |
| `uci_get` | `<config>[.<section>[.<option>]]` | `uci show`, optionally with stable `cfgXXXXXX` ids. |
| `uci_apply` | `<config>.<section>[.<option>]` per change | Stage, commit, reload, **rollback armed**. `dry_run` shows exactly what would change. |
| `uci_confirm` / `uci_rollback` | tool | Make a pending change permanent / undo it now. |
| `service_list` / `service_control` | tool / `<service>.<action>` | procd services; stopping or disabling dropbear, network, rpcd or openwrt-mcp is refused. |
| `pkg_query` | tool | installed, upgradable, search, info, files, owner, policy, `apk audit`, world. |
| `pkg_change` | `<action>.<pkg>` / `upgrade` | apk add/del/upgrade; **simulates unless `commit=true`**; reports new `.apk-new` files. |
| `pkg_config_diff` | tool | Every `.apk-new` as a diff against the live file -- for `/etc/config/*` by setting (`uci show`), so quoting/indentation noise disappears. |
| `pkg_config_resolve` | live path | keep_current (drop the new default) or use_new (install it; rollback-armed for UCI configs). |
| `sysupgrade` | `<action>` | list (preserved files), test (validate an image in /tmp), check (`owut`), backup. **Never flashes.** |
| `wg_list_clients` | tool | Peers with handshake age, endpoint, traffic, config/kernel mismatch, duplicate names. |
| `wg_new_client` | `wireguard.<iface>` | Keypair, next free address, peer saved and hot-added, config + QR. |
| `wg_remove_client` | `wireguard.<iface>.<name>` | By name, key or section; refuses a peer connected in the last 3 minutes unless forced. |
| `ubus_list` | *(ungated)* | Discovery: every object, method and argument signature. |
| `ubus_call` | `<object>.<method>` | Anything else on the bus. Replies over 8 KB have long arrays pruned. |
| `exec` | `argv[0]` | One program, no shell. A broad grant is a root shell. |
| `mfa_unlock` | *(ungated)* | Opens the TOTP window for MFA-gated tools. |

---

## Install

```sh
git clone https://github.com/stanislav-testhub/openwrt-mcp
cd openwrt-mcp
ROUTER=root@192.168.1.1 SSH_PORT=22 SSH_KEY=~/.ssh/id_ed25519 ./install.sh install
```

`ROUTER`, `SSH_PORT` and `SSH_KEY` are your router's root login (defaults: `root@192.168.1.1`,
22, your ssh defaults).

It reads the router's `DISTRIB_ARCH`, runs the tests, cross-compiles a static binary, and
installs `/usr/bin/openwrt-mcp`, the init script, the default config (never overwriting an
existing one), the `keep.d` entry and the LuCI page; then enables and starts the service. It
refuses to restart the daemon while a `uci_apply` awaits confirmation (that would roll it back)
unless `FORCE=1`. `./install.sh uninstall [--purge]` reverses it.

**Why not an `.apk`:** 25.12 packages are apk-tools v3 ADB archives. Building one needs the
OpenWrt SDK or a host apk-tools with `mkpkg` (the router's apk has no `mkpkg`), and an
unsigned package then needs `--allow-untrusted` anyway. A static binary loses nothing by being
installed as files: `/etc/config` survives sysupgrade on its own, and `/lib/upgrade/keep.d/openwrt-mcp`
carries the binary, init script, rc.d links, state and LuCI page. (An `owut`/ASU image
rebuilds *packages*, not loose files -- the keep.d entry is what preserves this across one.)

---

## Connect

### stdio over SSH (recommended)

A dedicated key, bound on the router to the MCP bridge and nothing else:

```sh
ssh-keygen -t ed25519 -N '' -f ~/.ssh/openwrt_mcp
ssh root@router "openwrt-mcp authorize-key claude-code '$(cat ~/.ssh/openwrt_mcp.pub)'"
ssh root@router "openwrt-mcp allow claude-code @readonly 30d"
claude mcp add openwrt -- ssh -T -i ~/.ssh/openwrt_mcp -o BatchMode=yes root@router
```

`authorize-key` writes a line like
`command="/usr/bin/openwrt-mcp stdio --client claude-code",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 ...`
into `/etc/dropbear/authorized_keys`: that key gets the MCP server as client `claude-code` and
cannot open a shell or forward ports. It refuses a key that is already a root login.

The bridge pipes the session into a root-only unix socket (`/var/run/openwrt-mcp/mcp.sock`,
0600 in a 0700 directory). The **daemon** runs the tools, so a rollback armed in one session
outlives it. The client name on the socket is asserted, not proven -- sound because only root
can connect, and root can already edit the policy file; the SSH key is the real
authentication.

On Windows, the built-in OpenSSH client works for this (`ssh.exe`); use a full path to the key.

### HTTP over a tunnel

Unchanged from upstream: `openwrt-mcp pair <client>` prints a bearer token once;
`ssh -N -L 8730:127.0.0.1:8730 root@router`; then
`claude mcp add --transport http openwrt http://127.0.0.1:8730/mcp --header "Authorization: Bearer $TOK"`.
The daemon refuses to bind anything but loopback.

### Make the policy mean something

If the agent can also run `ssh root@router ...` through its shell tool, the policy is
advisory. Deny that in the client (Claude Code: a `permissions.deny` rule for
`Bash(ssh * root@<router>*)`), or keep the root key where the agent cannot read it.

---

## Policies

Deny by default. A policy grants one client a list of tools, scope globs (`*` and `?` are
wildcards; brackets are literal), a calls/minute ceiling and an expiry. Changes to
`/etc/config/openwrt-mcp` take effect without a restart.

```sh
openwrt-mcp allow claude-code @readonly 30d          # every read tool; ubus_call on an allow-list of read methods
openwrt-mcp allow claude-code @operator 7d           # + uci_apply/confirm/rollback, service_control, pkg_change,
                                                      #   pkg_config_resolve, wg_new/remove_client, sysupgrade backup
openwrt-mcp allow claude-code uci_apply 'dhcp.* wireless.*.disabled' 30d
openwrt-mcp allow claude-code service_control 'dnsmasq.restart adguardhome.*' 30d
openwrt-mcp revoke claude-code                        # remove every policy for the client
openwrt-mcp policies | status | clients
```

Neither preset includes `exec` or unrestricted `ubus_call`; both bypass the safety rails. The
read-only ubus list is explicit `object.method` pairs, not `*.list`-style globs, because
`session.list` returns LuCI session ids. `uci_get '*'` does read secrets (Wi-Fi keys), as any
config read on OpenWrt does.

A refusal names the uncovered scope and prints the exact `allow` line that would cover it.

### Second factor

Unchanged from upstream: `openwrt-mcp mfa enrol <client>` prints an `otpauth://` URI; then in a
policy `list mfa_tools 'uci_apply'`, `option mfa_window '15m'`. One code opens a time-boxed
window; codes are single-use; unlocks live in memory only.

---

## Safety model

- **Rollback that survives the thing most likely to happen.** `uci_apply` snapshots the touched
  configs to `/etc/openwrt-mcp/rollback/<token>/` (fsynced), writes the pending record *before*
  committing, commits, reloads, and arms a timer (default 90 s, max 600 s). No `uci_confirm` ->
  files restored atomically, staged changes reverted, services reloaded. If the router is
  power-cycled inside the window, procd starts the daemon after network (S95) and it rolls back
  at startup, forcing a `config.change` for each restored config.
- **Nobody else's edits.** Every committing tool refuses to run while the configs it would
  commit have uncommitted changes from another session, and while an unconfirmed apply is
  pending.
- **No self-promotion.** `uci_apply` and `pkg_config_resolve` refuse the openwrt-mcp policy
  config whatever the grant, so a client cannot write itself a wider policy. Policies change
  only through `openwrt-mcp allow` / `revoke` on the router.
- **`@operator` is powerful.** `uci_apply` on `*` reaches every UCI config, including
  `dropbear`, `rpcd` and `uhttpd`, and `pkg_change` installs packages as root. Grant it for a
  working session (`2h`), and keep long-lived grants to narrow scopes such as
  `'dhcp.* wireless.*.disabled'`.
- **Names are validated against UCI's grammar**, so a section like `lan.ipaddr=x` cannot make
  uci act on a different key from the scope the policy approved.
- **No shell, anywhere.** Every command is an argv; targets and names that could be read as
  options (`-f`) are refused.
- **Lifelines.** `service_control` will not stop or disable dropbear, network, rpcd or
  openwrt-mcp. `sysupgrade` has no flash action -- validate an image with `test`, flash by hand.
  `wg_remove_client` will not drop a tunnel that handshook in the last 3 minutes unless forced.
- **Credentials.** `wg_new_client` output contains a new private key; the audit log records
  arguments and a summary, never tool output, and redacts secret-looking fields. The server
  private key is read from `wg show dump` and discarded.
- **Upstream's findings still hold:** rpcd ACLs do not bind a root process on the local ubus
  socket, so they are not relied on; rpcd's own apply/rollback keeps its state in rpcd memory
  and tmpfs, which is why the snapshot is ours and on flash.

---

## Verified

On a GL-MT6000, stock OpenWrt 25.12.5, installed with `install.sh`'s steps and driven from
Windows exactly as Claude Code does (`ssh.exe` with a forced-command key, stdio bridge):

- **Install:** procd service with respawn, `S95`/`K10` links, socket `0600` in a `0700`
  directory, HTTP on `127.0.0.1` only, forced-command line in dropbear's `authorized_keys`,
  `@readonly` + time-limited `@operator` policies picked up without a restart.
- **Reads against live data:** all 23 tools listed with schemas and server instructions;
  `system_status`, `network_clients`, `wg_list_clients` (duplicate-name warning),
  `service_list`, `pkg_query upgradable`, `pkg_config_diff` (11 real `.apk-new` files,
  settings-level diffs), `firewall_show check`, `net_diag ping` from `br-WAN`, `logread`
  filtering, `uci_get`, `sysupgrade list`, `ubus_call`.
- **Writes with rollback** (on a scratch UCI config): `uci_apply` including `set_list` ->
  automatic rollback at the deadline, file restored byte-identical and `pending.json` removed;
  a second apply refused while one is pending; `uci_confirm`; `uci_rollback` on demand;
  `dry_run`.
- **Crash recovery:** the daemon `SIGKILL`ed with an unconfirmed apply -> procd respawned it
  after 6 s and it rolled the change back at startup.
- **Refusals:** `exec`, `ubus_call session.list`, out-of-scope `uci_apply` (each naming the
  grant line), any `uci_apply` on the policy config, unauthenticated HTTP (audited).

Unit and end-to-end tests (real MCP client over in-memory transport and over the bridge
handshake) run on any OS against a fake router: apply/confirm/rollback/timeout, **restart
inside the window**, dry run, refusal on foreign staged edits, list ops, WireGuard
add/list/remove against a captured 25.12 config, client join, log filtering, apk simulation,
`.apk-new` resolution with rollback, preset contents, scope glob semantics.

**Not yet verified on hardware** (covered by the fake-router tests only): `service_control`,
`pkg_change` with `commit`, `wg_new_client` / `wg_remove_client`, the LuCI page rendering, a
real power cycle (the recovery path is the same one the `SIGKILL` test exercises), and keep.d
across a real sysupgrade. Reports from other boards are welcome.

---

## Credits

- **[GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp)** (Ian Williams, MIT) --
  the base of this project. Kept from it: the on-router static Go daemon under procd, standing
  deny-by-default policies with scope globs, rate limits and expiry, bearer tokens stored as
  digests, TOTP windows, the JSONL audit log with secret redaction, loopback-only HTTP, ubus
  reply pruning, and the confirm-or-roll-back idea for `uci_apply`. The git history of the
  upstream project is preserved in this repository.
- **[jsebgiraldo/openwrt_ssh_mcp](https://github.com/jsebgiraldo/openwrt_ssh_mcp)** -- an
  off-router Python server (SSH per call, regex command whitelist), reviewed for ideas. Four
  were taken and reimplemented here:
  1. validating a firmware image before flashing (`sysupgrade -T` -> `sysupgrade` action `test`);
  2. firmware and board information (part of `system_status`);
  3. package management (rewritten for `apk`: `pkg_query`, `pkg_change`);
  4. ping / traceroute / nslookup (`net_diag`).

  Not taken: OpenThread border-router tools (hardware-specific), `opkg` and `iptables` commands
  (gone in 25.12), a flash-firmware tool (irreversible and unrecoverable remotely), and regex
  whitelisting of shell strings (argv + policy scopes instead).

## Contributing and security

Bug reports and pull requests are welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md). Please
report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in a public
issue.

## Licence

MIT -- see [LICENSE](LICENSE). Copyright (c) 2026 Ian Williams (upstream) and Stanislav Chupin
(OpenWrt 25.12 port).
