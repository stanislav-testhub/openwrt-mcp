# openwrt-mcp -- an MCP server for OpenWrt 25.12+

[![CI](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/stanislav-testhub/openwrt-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/stanislav-testhub/openwrt-mcp)](https://github.com/stanislav-testhub/openwrt-mcp/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![OpenWrt 25.12+](https://img.shields.io/badge/OpenWrt-25.12%2B-00B5E2)

An [MCP](https://modelcontextprotocol.io) server that runs **on** an OpenWrt router, so
Claude Code (or any MCP client) can inspect and change it -- behind deny-by-default policies,
an audit log, and an automatic rollback for configuration changes.

**Local and private.** The server makes no outbound connections of its own and sends no
telemetry; it listens on loopback and on a root-only socket, and talks to your client over an
SSH session you set up. The tools that can make the router itself reach out (`net_diag`,
`pkg_query` with `refresh`, `pkg_change`, `sysupgrade check`, the `uci_apply` probes, `ubus_call`,
`exec`) say so in their MCP annotations (`openWorldHint`), and each needs a grant from you.
Secret values are masked in tool output by default, and a new WireGuard key never enters the
conversation unless you ask for it.

**Footprint.** One static binary with no dependencies: 9.1 to 11.3 MB for the router architectures
(9.6 MB on arm64, about 3.7 MB compressed in the release archive), about 10 MB resident on a
GL-MT6000 right after start, and 23 tools in about 22 KB of tool descriptions. Every release file is checksummed and carries a build attestation.

> **Based on [GlassOnTin/openwrt-mcp](https://github.com/GlassOnTin/openwrt-mcp)** by Ian
> Williams, which targets GL.iNet firmware 4.x (OpenWrt 21.02, `opkg`). This is a port to
> **stock OpenWrt 25.12** (`apk`, fw4/nftables, procd, netifd, LuCI JS). The security core is
> upstream's; see [Credits](#credits) for what came from where.

## Requirements

- **Router:** stock OpenWrt **25.12.0 or newer** (the `apk` releases). Nothing to install on the
  router beforehand. 24.10 and older (`opkg`, 21.02-era tooling) are not supported -- use
  upstream for GL.iNet 4.x firmware.
- **Your PC:** OpenSSH (Windows 10 and later, macOS and Linux have it). Installing from a release
  needs nothing else. Building from source needs Go 1.26+, `ssh` and `tar` (Linux, macOS, or Git
  Bash on Windows).
- **Any CPU OpenWrt and Go share:** the release has a binary for each (arm64, armv5/v7,
  mips/mipsle softfloat, mips64/mips64le, x86, x86-64, riscv64); `install.sh` reads the router's
  `DISTRIB_ARCH` and picks it, or cross-compiles when you build from source.

Tested on a GL.iNet GL-MT6000 (mediatek/filogic, `aarch64_cortex-a53`) with OpenWrt 25.12.5.
Nothing in the code is specific to that board.

---

## How it differs from other OpenWrt MCP servers

From each project's own README on 2026-10-07; "not stated" means the README does not say. Corrections
are welcome.

| | this project | [openwrt_ssh_mcp](https://github.com/jsebgiraldo/openwrt_ssh_mcp) | [paulomac1000/openwrt-mcp](https://github.com/paulomac1000/openwrt-mcp) | [openwrt-luci-mcp](https://github.com/JeffersonYoung/openwrt-luci-mcp) |
|---|---|---|---|---|
| Runs on | the router | a PC, in Docker | a PC, in Docker or Python | a PC, in Node.js |
| Reaches the router by | SSH to a key-bound forced command, or loopback HTTP | SSH | SSH | LuCI's HTTP `/ubus` |
| Changes configuration | yes, through one tool that checks first and arms a rollback | yes, including packages and a firmware flash | read-only unless `ENABLE_WRITE_OPERATIONS=1` | no |
| Automatic rollback of a bad change | yes, and it survives a reboot | not stated | not stated | not applicable |
| Access control and audit | per-client grants with scopes, expiry and a rate limit, audit log, optional TOTP | command whitelist, audit log | audit log | secrets hidden, no audit log |
| Package manager | `apk` (OpenWrt 25.12+) | `opkg` | `opkg` | lists installed and available |
| Flashing firmware | never | yes | not stated | no |
| Needs on the router | the binary | SSH | SSH | `uhttpd-mod-ubus`, `rpcd` |

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
| `system_status` | tool | Model, release, uptime, load, memory, storage, temperatures, conntrack, every interface (state, addresses, default route, errors), radios/SSIDs, and what is outstanding. Call first. `mode=doctor` returns ranked health findings (radio down, interface without an address, enabled service that died, conntrack and storage nearly full, pending `.apk-new`, NTP or an unset clock, a newer kernel installed than running). `mode=audit` returns ranked security findings (what the firewall lets in from the internet, SSH and LuCI exposure, password logins, UPnP, WPS, open or weak Wi-Fi, an empty root password, modified package files, stale WireGuard peers). Both are advisory, each finding names a next read-only call and an OpenWrt wiki page, and both list what they could not check. They are separate scopes: `openwrt-mcp allow <client> system_status doctor`. |
| `logread` | tool | Whole log buffer filtered (substring, RE2, last N minutes) *before* the line limit; `offset` pages back from the newest line. `mode=summary` collapses it to distinct messages (numbers, addresses and ids become placeholders) with count, first and last time and worst severity. `baseline=save` returns a token; `baseline=<token>` shows only the messages that were not in the log then. Baselines hold fingerprints, not log text, and live in memory. |
| `network_clients` | tool | DHCP leases + static hosts + neighbour table + every AP's association list, joined by MAC: name, IP, SSID, signal, rates, connected time, each client's share of its radio's airtime (from hostapd), lease; 100 rows a page, `offset` for the next. |
| `firewall_show` | tool | `nft list ruleset`, `fw4 print`, `fw4 check`, one table or chain. |
| `net_diag` | `<action>[.<target>]` | ping / traceroute / nslookup (optionally from a given interface), routes, policy rules, neighbours. `wifi_survey` reports, per radio, how busy the channel it stays on has been (busy, rx and tx airtime, noise); other channels are unmeasured, so it never recommends one. `traffic` samples interface rates for a few seconds and ranks the conntrack table by source. `usage` reads nlbwmon's totals per device for an accounting period (a month by default). All three only read. |
| `uci_get` | `<config>[.<section>[.<option>]]` | `uci show`, optionally with stable `cfgXXXXXX` ids. Ends with the config's **revision**. `history=list` / `diff:<id>` shows the kept versions from before each confirmed change. |
| `uci_apply` | `<config>.<section>[.<option>]` per change; `<config>` for `restore`; `probe.<kind>.<target>` per probe | Stage, check, commit, reload, **rollback armed**. `dry_run` shows exactly what would change and what the service's own checker says. `expected_revisions` refuses if a config moved meanwhile, `probe` checks the router afterwards, `restore=<id>` puts a past version back. After the commit the config is read back; a change the router did not keep is `NOT_APPLIED` and nothing is reloaded. |
| `uci_confirm` / `uci_rollback` | tool | Make a pending change permanent / undo it now. |
| `service_list` / `service_control` | tool / `<service>.<action>` | procd services; stopping or disabling dropbear, network, rpcd or openwrt-mcp is refused. `service_control` waits for the state to settle (`wait`) and says if it did not; a final state that contradicts the action is `NOT_APPLIED`. |
| `pkg_query` | tool | installed, upgradable, search, info, files, owner, policy, `apk audit`, world; 200 lines a page, `offset` for the next. |
| `pkg_change` | `<action>.<pkg>` / `upgrade` | apk add/del/upgrade; **simulates unless `commit=true`**; reports new `.apk-new` files; checks `/etc/apk/world` afterwards. |
| `pkg_config_diff` | tool | Every `.apk-new` as a diff against the live file -- for `/etc/config/*` by setting (`uci show`), so quoting/indentation noise disappears. |
| `pkg_config_resolve` | live path | keep_current (drop the new default) or use_new (install it; rollback-armed for UCI configs). |
| `sysupgrade` | `<action>` | list (preserved files), test (validate an image in /tmp), check (`owut`), backup (mode 0600; the previous archive this tool made is removed). **Never flashes.** |
| `wg_list_clients` | tool | Peers with handshake age, endpoint, traffic, config/kernel mismatch, duplicate names. |
| `wg_new_client` | `wireguard.<iface>` | Keypair, next free address, peer saved, hot-added and read back. The private key and config go to a root-only file; you collect them with `openwrt-mcp wg-show <name>` (config and QR in your own terminal). `reveal=true` returns them in the result instead. |
| `wg_remove_client` | `wireguard.<iface>.<name>` | By name, key or section; refuses a peer connected in the last 3 minutes unless forced; reads the peer's absence back. |
| `ubus_list` | *(ungated)* | Discovery: every object, method and argument signature. |
| `ubus_call` | `<object>.<method>` | Anything else on the bus. Replies over 8 KB have long arrays pruned. |
| `exec` | `argv[0]` | One program, no shell. A grant for `sh`, `find`, `awk`, `env`, `ssh` and the like is a root shell: `allow` refuses it without `--shell-equivalent`. |
| `mfa_unlock` | *(ungated)* | Opens the TOTP window for MFA-gated tools. |

**Prompts.** Clients that show MCP prompts (as slash commands, usually) get five recipes:
`router-health`, `who-is-online`, `secure-my-router`, `wifi-doctor` and `upgrade-plan`. Each is a
few lines that name the tools to call and end in a report or a proposal, never a change. They use
only what the `@readonly` preset grants, so a read-only client can follow them to the end, and they
cost nothing until used. Listing or fetching one runs nothing on the router, so no policy applies
and nothing is audited.

---

## Install

**On the router, from a release** (nothing needed beyond a default 25.12 image):

```sh
wget -O /tmp/install-router.sh https://github.com/stanislav-testhub/openwrt-mcp/releases/latest/download/install-router.sh
sh /tmp/install-router.sh
```

It picks the archive for the router's `DISTRIB_ARCH`, checks it against the release's
`SHA256SUMS` (refusing on a mismatch), and installs. `VERSION=v1.2.0` selects a release other
than the latest. Each release file also carries a build attestation:
`gh attestation verify <file> --repo stanislav-testhub/openwrt-mcp`.

**From a PC, building from source** (needs Go, ssh and tar; Git Bash works on Windows):

```sh
git clone https://github.com/stanislav-testhub/openwrt-mcp
cd openwrt-mcp
ROUTER=root@192.168.1.1 SSH_PORT=22 SSH_KEY=~/.ssh/id_ed25519 ./install.sh install
```

`ROUTER`, `SSH_PORT` and `SSH_KEY` are your router's root login (defaults: `root@192.168.1.1`,
22, your ssh defaults). `./install.sh install --release [vX.Y.Z]` skips the build and has the
router fetch a verified release instead; that is also what happens when no Go toolchain is found.

Either way the same installer runs on the router.
- It installs:
  - `/usr/bin/openwrt-mcp`;
  - the init script;
  - the default config, never overwriting an existing one;
  - the `keep.d` entry;
  - the LuCI page.
- It then enables and starts the service.
- It refuses to restart the daemon while a `uci_apply` awaits confirmation, because that would roll it back,
  unless `FORCE=1`.
- It checks that the binary fits on the overlay first.

`./install.sh uninstall [--purge]` reverses it.

**Why not an `.apk`:** 25.12 packages are apk-tools v3 ADB archives. Building one needs the
OpenWrt SDK or a host apk-tools with `mkpkg` (the router's apk has no `mkpkg`), and an
unsigned package then needs `--allow-untrusted` anyway. A static binary loses nothing by being
installed as files: `/etc/config` survives sysupgrade on its own, and `/lib/upgrade/keep.d/openwrt-mcp`
carries the binary, init script, rc.d links, state and LuCI page. (An `owut`/ASU image
rebuilds *packages*, not loose files -- the keep.d entry is what preserves this across one.)

---

## Connect

### `openwrt-mcp connect` (recommended)

The release has a binary for your PC too (`openwrt-mcp_<version>_windows_amd64.zip`, `darwin_arm64.tar.gz`
and so on; a Linux PC can use the `linux_` archive). Unpack it anywhere on your `PATH`; it needs
OpenSSH, which Windows 10 and later, macOS and Linux have. Then, on your PC:

```sh
openwrt-mcp connect --client claude-code --host 192.168.1.1          # or claude-desktop, codex, cursor, gemini, vscode
```

It makes a dedicated ed25519 key (`~/.ssh/openwrt_mcp`, never overwriting one), prints the two
commands to run on the router once, and shows the entry to add to your client. Add `--write` and it
does that last step: for Claude Code and Codex by running their own `mcp add`, for Claude Desktop,
Cursor, Gemini CLI and VS Code by merging one `openwrt` entry into their JSON file (other servers
stay; the original is kept once as `<file>.before-openwrt-mcp`; a file with comments is left alone and
the snippet printed instead). The entry stores `ssh` and its arguments as a list, so spaces in a key
path need no quoting, and it sets keep-alives so a router that rebooted is noticed.

```sh
openwrt-mcp connect doctor --host 192.168.1.1
```

checks the chain in order and stops at the first break, with one fix for it:

```
[ ok ] ssh reachable   192.168.1.1:22
[ ok ] host key
[ ok ] key accepted    /home/you/.ssh/openwrt_mcp
[FAIL] forced command  the key logged in, but nothing answered as an MCP server (...)
       fix: the key is probably authorized without its forced command ...
[skip] daemon socket
```

The steps are: SSH reachable, host key, key accepted, forced command, daemon socket, `initialize`,
`tools/list`. Wrong key, a missing forced command, a stopped daemon and a disabled socket each name
their own step. The weekly reboot disconnects the bridge; the client reconnects on its next start.

### stdio over SSH, by hand

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
openwrt-mcp prune --older-than 7d                     # delete grants that expired over a week ago (audited)
openwrt-mcp policies | status [--all] | clients
```

Granting the same tools and scopes again replaces the client's expired grant instead of adding
a block. `status` counts expired grants in one line; `--all` lists them.

Neither preset includes `exec` or unrestricted `ubus_call`; both bypass the safety rails. The
read-only ubus list is explicit `object.method` pairs, not `*.list`-style globs, because
`session.list` returns LuCI session ids. `uci_get '*'` reads every config, but the values of
secret options (Wi-Fi keys, WireGuard keys, passwords, tokens) come back as `<redacted>`; see
*Safety model*. `exec` is not masked.

A refusal names the uncovered scope and prints the exact `allow` line that would cover it.

An `exec` scope is `argv[0]` taken literally, so a grant for `find` or `awk` looks harmless and
is a root shell: both run other programs, and so do the shells, `env`, `nice`, `flock`,
`timeout`, `xargs`, `tar`, `ssh`, `lua`, `ucode`, `apk` and `opkg`. `allow` refuses such a grant
until you add `--shell-equivalent`, judging by base name so `/usr/bin/../bin/sh` and `/bin/*`
count too; a `ubus_call` grant that can reach `file.exec` is treated the same way.
`openwrt-mcp policies` and `status` mark these grants, which also covers a policy written by
hand. The list is a floor, not a promise: a grant that writes files (`wget`, `cp`, `dd`) or
starts an interpreter that is not on it can still be abused.

### Second factor

Unchanged from upstream: `openwrt-mcp mfa enrol <client>` prints an `otpauth://` URI; then in a
policy `list mfa_tools 'uci_apply'`, `option mfa_window '15m'`. One code opens a time-boxed
window; codes are single-use; unlocks live in memory only.

Wrong codes are limited: in the `config server` section, `option mfa_max_failures '5'` consecutive
wrong codes lock that client out of `mfa_unlock` for `option mfa_lockout '300'` seconds (`'5m'` also
works), doubling on each repeat to one hour. A correct code during the lockout is refused and not
spent. A client with no secret counts the same, so the limit reveals nothing about enrolment, and
the counters are in memory (a restart, `mfa enrol` or a rotated secret clears them). Each wrong code
is audited as `ERROR` and a lockout as `DENIED`; the code itself is never logged. The price: whoever
holds a client's token can keep that client locked out for up to an hour.

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
- **Checked before it reloads.** The dry run runs each service's own checker on the staged config
  where one exists (`fw4 check` for the firewall) and lists only the problems the change *adds*.
  A real apply refuses them unless `force=true`; a config that was already broken can still be
  fixed. dnsmasq, dropbear and the rest have no checker that sees staged changes: they are
  reported "not checked", not "passed".
- **No silent overwrite.** `uci_get` ends with the config's revision. Pass it back as
  `expected_revisions` and the apply is refused with `CONFLICT` if the config changed meanwhile
  (LuCI, another client).
- **The management path is guarded.** A change to the LAN interface or its bridge, the SSH
  listener, or the firewall zone and rule that let SSH in is refused unless the call names a
  `probe` (ping the gateway, resolve a name) or `force=true`. Probes run after the reload and are
  reported with the result; the rollback window defaults to 180 s for such a change. The rule set
  is static (LAN plus whatever dropbear names), so it covers the common layout, not every
  topology.
- **History and restore.** Confirming a change keeps the version of the config from before it
  (newest `history_keep`, default 5, per config, in `/etc/openwrt-mcp/history/`).
  `uci_get history=list` shows them, `history=diff:<id>` compares one with now, and
  `uci_apply restore=<id>` puts one back through the same snapshot, checks and rollback timer.
  Entries contain secrets, like the snapshots: `0600`, masked when shown, and part of a
  `sysupgrade` backup. `option history_keep '0'` turns it off.
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
- **Credentials stay out of the conversation.** `wg_new_client` writes the new client's config
  (private key included) to a root-only file in RAM, beside the socket, and returns the public
  key and the command to run. `openwrt-mcp wg-show <name>` on the router prints the config and
  a QR code in your terminal and deletes the file; an uncollected file goes after 24 hours or at
  the next reboot. Only `reveal=true` puts the key in the result, and so in the model's context
  and the provider's logs. A `sysupgrade` backup is created 0600 before anything is written to it
  and only the newest one is kept. The audit log records arguments and a summary, never tool
  output, and redacts secret-looking fields. The server private key is read from `wg show dump`
  and discarded.
- **Secrets are masked in tool output.** `uci_get`, `uci_apply` (diff and errors), `pkg_config_diff`,
  `pkg_config_resolve`, `uci_confirm`, `uci_rollback`, `system_status` and `ubus_call` keep the shape
  of a line and replace the value of a secret option (`key`, `key1`..`key4`, `psk`, `password`,
  `sae_password`, `passphrase`, `private_key`, `preshared_key`, `token`, `pwd`, anything containing
  `secret`...) with `<redacted>`. The audit log uses the same rule. `exec`, `logread` and the
  diagnostics are not masked, and `wg_new_client` is exempt on purpose. In the `config server`
  section: `list redact_extra 'vendor_blob'` adds names; `option redact_output '0'` turns masking
  off, and is audited. A masked diff does not show what changed in a secret.
- **Router output is untrusted.** Host names, SSIDs, log lines and DNS answers are chosen by other
  devices. Every result has terminal escape sequences, control characters, bidi and zero-width
  characters and invalid UTF-8 removed, and lines are cut at 1024 bytes (not `exec`, `ubus_call`,
  `wg_new_client` or the configuration tools). `network_clients`, `logread` and `net_diag` start with
  an `[untrusted text: ...]` line. That lowers the odds a model obeys such text; it does not remove
  them, so keep write scopes out of sessions that read it.
- **State stays off the web.** The state directory, audit log and socket are refused if they sit
  under `/www`, a `cgi-bin` directory or uhttpd's `home`, even through a symlink.
- **A threat model** is in [SECURITY.md](SECURITY.md).
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
- **WireGuard:** `wg_new_client` with a preshared key (next free address, peer committed to UCI
  and hot-added to the kernel, config + QR, CGNAT endpoint warning), listed, then
  `wg_remove_client` -- `/etc/config/network` back byte-identical, kernel peer gone.
- **Crash recovery:** the daemon `SIGKILL`ed with an unconfirmed apply -> procd respawned it
  after 6 s and it rolled the change back at startup.
- **Refusals:** `exec`, `ubus_call session.list`, out-of-scope `uci_apply` (each naming the
  grant line), any `uci_apply` on the policy config, unauthenticated HTTP (audited).
- **Output safety (1.1.0), on the same board:** `uci_get wireless` and `ubus_call
  network.wireless status` return `<redacted>` for every Wi-Fi `key`, while `ssid`,
  `encryption` and look-alike names such as `wpa_disable_eapol_key_retries` are untouched
  (numbers, booleans and arrays in the JSON reply too). A `uci_apply` dry run that sets a key
  shows it redacted and leaves nothing staged. `network_clients` and `logread` start with the
  untrusted-text marker. Five wrong `mfa_unlock` codes from a client with no secret lock it out
  for 5 minutes (the sixth is refused with a retry time); the audit log records four `ERROR`
  entries then `DENIED`, and none of the submitted codes appear in it. A syslog line written
  with `ubus call log write` that held CSI and OSC sequences, a colour code, BEL and a bidi
  override (all present in the router's own log) came back through `logread` with only the
  text and the tab left, and an over-long line was cut at 1024 bytes with a `[+N bytes]` note.
  The syntax of `uci changes` (`+=`, `-=`, `'\''`, a bare `-path` for a delete) was captured
  from the router and is a test fixture.
- **Reliable changes (1.2.0), on the same board, driven through the daemon's stdio bridge:**
  `fw4 check` sees changes staged in uci (it exits 0 for an invalid value and prints `[!]` lines,
  which is what validation reads): a dry run that sets a bogus zone value reports it as a NEW
  problem, the real apply is refused, and nothing is left staged or snapshotted. A stale
  `expected_revisions` is a `CONFLICT`; the current one passes; one for a config the call does not
  change is refused. A dry run on the LAN interface names the management path, and a real apply
  without a probe is refused with nothing staged. `add_list` of an element already in
  `system.ntp.server` is skipped. On a scratch option in `luci`: an apply with a `ping` and a
  `resolve` probe reports both OK after the reload and arms the rollback; confirming it leaves a
  history entry (`0700` directory, `0600` files); `history=diff` shows what the change added;
  `restore` brings the file back byte-identical with its mode, runs its probe, and leaves an entry
  of its own; an apply with a failing probe reports `PROBE FAILED` with the rollback still armed,
  and `uci_rollback` restores the file byte-identical. `service_control restart` of a daemon
  reports "Settled after" its state.
- **Adoption and credentials (1.3.0), on the same board:** the build was installed with
  `install.sh` and `openwrt-mcp version` reported 1.3.0. `connect doctor` from the Windows PC,
  with its real OpenSSH, passed all seven steps and listed 23 tools; with a key the router does
  not know it stopped at *key accepted*, and with a closed port at *ssh reachable*, each with its
  fix. `connect --write` for Cursor made the key with the PC's own `ssh-keygen`, merged the entry
  into a JSON file, and a second run reported the entry unchanged. `diag` printed the version,
  board, policy shape and audit lines with the SSH client's address as `ip-1` and no audit
  arguments; `--detail` added the masked summaries. `sysupgrade backup` created the archive
  `-rw-------` (4.3 MB, so `sysupgrade -b` keeps the mode of a file that already exists), and the
  second backup removed the first. The daemon held about 10 MB resident right after the restart.
- **Session cleanup (1.3.0), on the same board:** after a daemon restart the stdio bridge
  started on the new build exited at once, and the client's next call opened a fresh session
  without an error; bridges still running the previous build stayed until their client's next
  request. `status` folded 45 expired grants into one line; `prune` removed them, wrote one
  `prune` audit entry, and the daemon reloaded with the live grants only.

Unit and end-to-end tests (real MCP client over in-memory transport and over the bridge
handshake) run on any OS against a fake router: apply/confirm/rollback/timeout, **restart
inside the window**, dry run, refusal on foreign staged edits, list ops, WireGuard
add/list/remove against a captured 25.12 config, client join, log filtering, apk simulation,
`.apk-new` resolution with rollback, preset contents, scope glob semantics.

**Not yet verified on hardware** (covered by the fake-router tests only): `pkg_change` with `commit`,
the LuCI page rendering, the web-root guard on a real `/www` path or symlink, a real power cycle (the
recovery path is the same one the `SIGKILL` test exercises), and keep.d across a real sysupgrade. For
1.2.0 also: a management-path change applied *with* probes (only its refusal without one was run),
a probe failure left to the rollback timer instead of `uci_rollback`, and history across a
sysupgrade. For 1.3.0 also: the `wg_new_client` hand-over and `wg-show` (the test router's `wg0` was
not up, and starting it was not part of the check), `connect --write` against a real Claude Code,
Codex, Claude Desktop, Gemini or VS Code (only the file merge and the command line are tested),
anything on macOS, and the installer's download path on a router (the release workflow has run and
published 1.2.0 and 1.3.0, but `install-router.sh` has not been run against them). The file modes of the WireGuard hand-over are asserted on Linux in CI. Reports from
other boards are welcome.

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
issue. Planned work is in [ROADMAP.md](ROADMAP.md).

**Reporting a bug:** on the router run `openwrt-mcp diag` and paste the output into the issue. It
prints the version, board, daemon state, the shape of the policy and the last 20 audit lines
(`--audit N`), with every IPv4, IPv6 and MAC address, host name, DHCP name, SSID, domain and
WireGuard peer name replaced by a placeholder (`ip-1`, `mac-1`, `host-1`, `ssid-1`) that stays
the same for the same value. Audit arguments are never printed, and the scope, summary and error
text of an entry only with `--detail`, masked the same way. Names are matched against what the
router itself says they are, so read it once before pasting: a name that is only in free text, not
in the router's configuration, is not recognised.

## Licence

MIT -- see [LICENSE](LICENSE). Copyright (c) 2026 Ian Williams (upstream) and Stanislav Chupin
(OpenWrt 25.12 port).
