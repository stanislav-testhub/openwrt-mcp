# Roadmap

Where openwrt-mcp is going after v1.0, and why. Items are grouped into milestones in build order. Each one says
what problem it solves, what ships, and how we will know it works.

Many of these ideas come from reading the history of
[ha-mcp](https://github.com/homeassistant-ai/ha-mcp), an MCP server for Home Assistant: about 150 releases and more
than 2,000 changelog entries in one year. Its fix history shows which problems keep coming back once an agent drives
a real system, so this roadmap tries to pre-empt them rather than rediscover them. The ideas were adapted to a
router, not copied.

Milestones 3 to 7 also draw on three other sources, all from 2026:

- the most-upvoted issues of about twenty widely used MCP servers, such as github-mcp-server, playwright-mcp,
  chrome-devtools-mcp, serena and DesktopCommanderMCP, and of other router and firewall MCP servers;
- the OpenWrt forum's discussion of AI assistants on routers;
- the 2026 MCP specification and its CVE record.

A "Precedent" line names its project. A precedent with no project named comes from ha-mcp.

Nothing here is a promise or a date. Order can change when a real bug says so.

## Principles

These hold for every item below.

1. **Grow tools by mode, not by count.** A new capability becomes an action or mode on an existing tool
   wherever that reads naturally. The tool list stays small. Measured at 1.2.0, it is 23 tools and about 6k
   tokens. Tool-selection accuracy drops somewhere between 10 and 30 tools, depending on the model, and small local
   models drop first. A client that needs fewer tools picks a profile (5.4).
2. **Deny by default stays.** No item may widen what a client can do without an explicit grant. A new write path
   ships with its policy scope, its audit record and a mutation test for its security rule.
3. **Advisory before blocking.** New checks start as warnings in results. A check becomes a gate only when it has
   a way to approve past it. ha-mcp's strict acknowledgment gate broke clients that cached an old schema.
4. **Every write path is covered.** Snapshot, audit, redaction and validation must reach every write path, with a
   test that enumerates the paths. ha-mcp's auto-backup silently skipped some writers, and that was its most
   instructive bug.
5. **Router output is untrusted input.** Host names, SSIDs and log lines are written by other devices, and they
   end up in the model's context.
6. **Small router, small budget.** Results stay bounded, scans have deadlines, and nothing holds a lock while
   waiting on the network.
7. **Verify after write.** A write reports what it re-read, not what it sent. A mismatch is an error. "Reported
   success, changed nothing" is the most common bug in other router MCP servers.
8. **Credentials do not pass through the model by default.** Keys, codes and backups go to the operator's
   terminal, a file on the router or the client's own prompt. Printing them into the result needs an explicit
   flag.
9. **Dependency bumps are gated.** The MCP SDK and other dependencies move only after a green e2e and contract run.
   Users never fetch `latest` at install time. SDK upgrades that changed constructor signatures broke several
   Python servers in place.

Each item that changes a tool schema or a policy needs a `CHANGELOG.md` entry, README *Tools* / *Verified*
updates and a `goldenCalls` entry in `contract_test.go`.

---

## Milestone 1: Output safety (v1.1)

Close the remaining ways secrets and attacker-controlled text reach the model. The code changes are small.

**Status: shipped in 1.1.0** (see `CHANGELOG.md` and the threat model in `SECURITY.md`). Not done from
the list below: the per-policy opt-out in 1.1 (only the global `redact_output` option exists), and
masking of "future search output", since no search tool exists yet. The line cap applies to every tool
except those listed as exempt, which is wider than the four tools named in 1.2.

### 1.1 Redact secrets in tool output

- **Problem.** The audit log redacts secret options, but tool results do not. `uci_get` on a whole `wireless` or
  `network` config returns Wi-Fi keys and WireGuard private keys into the transcript.
- **Ships.** Secret option values are masked in results by default. This covers `key`, `key1`..`key4`, `psk`,
  `password`, `sae_password`, `passphrase`, `private_key`, `preshared_key` and `token`, plus a configurable
  extra list. It applies to `uci_get`, the `uci_apply` dry-run diff, `pkg_config_diff` and future search output.
  The masker reuses the audit log's redaction table, so the two cannot drift apart.
  - `wg_new_client` stays exempt, because showing a fresh key once is its purpose.
  - An operator can opt out with `option redact_output '0'` or a policy flag. Opting out is audited.
- **Done when.** A table test lists each secret-bearing option and every read path. A mutation that removes any
  one entry fails a test.
- **Precedent.** `redact_secrets` and the advisory-driven masker in log and error paths.

### 1.2 Treat router output as untrusted

- **Problem.** DHCP host names, scanned SSIDs, `logread` lines and `iwinfo` strings are controlled by whoever is
  on or near the network. A client called `ignore previous instructions...` lands verbatim in the model's context.
- **Ships.**
  - Control characters and ANSI escapes are stripped.
  - Each field is capped in length.
  - Fields from external sources are labelled in structured output.
  - The tool descriptions for `network_clients`, `logread` and `net_diag` mention this.
- **Done when.** Hostile-input tests feed injection strings, escapes and over-long fields through every listing
  tool.
- **Precedent.** The style guide's rule on interpolating user text, and the `SECURITY.md` threat model.

### 1.3 Written threat model

- **Ships.** A threat model section in `SECURITY.md` covering:
  - who is trusted (the operator, and the client as a principal);
  - the trust boundary (loopback plus SSH or the tunnel);
  - that `exec` is a root shell by design;
  - what the audit log does and does not prove;
  - that rpcd ACLs are not relied on;
  - which kinds of report are in scope.
- **Precedent.** ha-mcp's explicit threat model, which shortens triage.

### 1.4 Guard tests for state paths

- **Ships.** A contract test that no state, snapshot or audit path can resolve under `/www` or a CGI directory.
- **Precedent.** An advisory about backups written to a web-served directory.

### 1.5 Second-factor hardening

- **Ships.** A failed-attempt limiter on `mfa_unlock`: backoff per client, with each failure audited. Codes are
  already single-use, but repeated wrong guesses are not throttled.
- **Done when.** A test proves that the Nth wrong code locks the client out for a period, and that a correct code
  during the lockout is refused.

---

## Milestone 2: Reliable changes (v1.2)

Make `uci_apply` catch mistakes before the reload and prove the result after it.

**Status: shipped in 1.2.0** (see `CHANGELOG.md`). Where the build differs from the text below:

- 2.1: `fw4 check` exits 0 even for an invalid value, so the verdict is its `[!]` lines, compared
  against the same check run before staging. dnsmasq has no check that sees staged changes, and
  dropbear and uhttpd have none: those configs report "not checked".
- 2.2: the revision is a digest of the committed file, not of `uci export`, and
  `expected_revisions` is a `{config: revision}` map, so one call can guard several configs.
- 2.3: the management-path rule set is static (LAN, its bridge, the SSH listener, the zone and
  rule that let SSH in). It does not use the interface the current session arrived on, because the
  bridge's origin address does not reach the tool handlers. Probes are `ping` and `resolve`, each
  a policy scope of its own.
- 2.4: `uci import` writes the file at once instead of staging it, so `restore` replaces the file
  the way `pkg_config_resolve` does and checks it before the reload. History is recorded when a
  change is confirmed (not when it is applied), and by the `wg_*` tools when they commit.
- 2.5: `service_control` goes through rpcd's `rc` object, not procd, and polls that.
- Not built: history in RAM for low-flash boards (the open question below stays open).

### 2.1 Validate before reload

- **Problem.** The dry run shows the diff but does not ask the services whether they accept it.
- **Ships.** The dry run stages the change in a temporary overlay and runs each affected service's own checker,
  where one exists:
  - `fw4 check` for firewall;
  - `dnsmasq --test` for DHCP and DNS;
  - a syntax check for dropbear and uhttpd where available.

  Results are returned as `validation` in the dry-run output. A real apply refuses on a hard failure unless
  `force=true`.
- **Done when.** Fake tests show the checker is called for each config family, and a broken firewall rule fails
  in the dry run, not after the reload.
- **Precedent.** Managed YAML edits that check, then back up, then reload.

### 2.2 Revision locking

- **Problem.** Between an agent's `uci_get` and its `uci_apply`, someone may change the same config, in LuCI or
  from another client. Today the apply silently overwrites that change.
- **Ships.** `uci_get` returns a `revision` for each config, a hash of `uci export <config>`. `uci_apply` accepts
  `expected_revision` and refuses with `CONFLICT` if the config has changed. The revision comes from the content,
  so the server keeps no extra state.
- **Precedent.** `config_hash` optimistic locking.

### 2.3 Post-apply probe and lockout detection

- **Problem.** Rollback is armed, but deciding whether the change worked is left to the agent. A change can also
  cut off the session that would confirm it.
- **Ships.**
  - `uci_apply` accepts a `probe` list (ping gateway, resolve a name, reach a LAN host). The probes run after the
    reload and are reported with the result.
  - The server detects when a change touches the management path, and then refuses it or lengthens the rollback
    window. The management path is:
    - the LAN address or interface carrying the current session;
    - the dropbear listen address;
    - firewall input on that zone.
- **Done when.** Tests cover a change to the management interface with the probe failing, and the rollback fires.

### 2.4 Config history and restore

- **Problem.** The pre-apply snapshot is deleted on `uci_confirm`, so there is no way to answer "what did this
  look like before last week's change".
- **Ships.** The last N confirmed snapshots are kept per config (default 5, configurable). `uci_get` gains
  `history=list` and `history=diff:<id>`, and `uci_apply` gains `restore=<id>`, which goes through the normal
  rollback-armed apply. Snapshots
  keep their 0600 mode and are covered by 1.1 when displayed.
- **Done when.** A test enumerates every write path (`uci_apply`, `wg_new_client`, `wg_remove_client`, package
  config resolve) and checks that each one leaves a history entry.
- **Precedent.** Auto-backup before edits, its `diff` action, and the later fix for writers that skipped it.

### 2.5 Poll instead of sleep

- **Ships.** `service_control` polls procd until the service state is stable or a timeout passes, and reports
  which happened, instead of sleeping for a fixed time.
- **Precedent.** The move from fixed waits to `wait`-for-condition helpers.

### 2.6 Write-path parity

- **Ships.** One validator set is shared by `set`, `add`, `add_list` and `del_list`, enforced by a table test.
  `add_list` and `del_list` become idempotent.
- **Precedent.** A bug where update paths lacked the guards that create paths had.

---

## Milestone 3: Easy to adopt (v1.3)

Today the first install needs a Go toolchain on the operator's machine and a hand-written SSH line in each client.
Across popular MCP servers, the most common class of issue is "it does not connect". This milestone fixes both. It
also fixes the catalog-level defects a measurement of `tools/list` found. **It adds no new write path.**

### 3.1 Prebuilt, signed releases

**Status: release workflow done on `main`.** Still open: `install.sh` downloading a release, and the router-side
one-liner.

- **Problem.** There are no GitHub Releases. `install.sh` cross-compiles locally, so an operator without Go stops
  here. The server runs as root, so binaries must be verifiable: supply-chain attacks on MCP servers (typosquatted
  packages, unsigned binaries) are a recurring 2026 incident class.
- **Ships.**
  - A release workflow that builds every target `install.sh` already maps (aarch64, arm v5/v7, mips/mipsel
    softfloat, mips64/mips64el, x86, x86-64, riscv64).
  - Checksums, an SBOM, and build provenance (GitHub artifact attestations).
  - `install.sh` downloads and verifies the matching release when no Go toolchain is present. Building from source
    stays as the developer path.
  - The README leads with the release install and states the footprint (binary size, RSS) and "no telemetry,
    nothing leaves the LAN".
- **Done when.** A fresh router installs from a release with no Go on the client, and the verification step fails
  on a tampered binary.
- **Precedent.** codebase-memory-mcp: a single static binary, one-line install, provenance and scanning badges.
  Issue trackers of other servers ask for exactly this ("please tag releases", "Linux ARM64 builds").

### 3.2 `connect` and `doctor`

- **Problem.** The stdio bridge needs a dedicated key, an `authorize-key` line on the router and a client config
  entry. Each client stores that entry differently, and Windows and WSL add their own quoting and path problems.
- **Ships.**
  - `openwrt-mcp connect --client claude-code|claude-desktop|cursor|vscode|codex|gemini` on the operator's machine:
    - generates the key;
    - prints the `authorize-key` line to run on the router;
    - writes the client config, with SSH keep-alive set.
  - `openwrt-mcp connect doctor` checks, in order:
    - SSH reachability;
    - the host key;
    - the forced command;
    - the daemon socket;
    - `initialize`;
    - `tools/list`.

    Each failure prints one concrete fix.
  - Windows hygiene tests, moved here from *Later*: UTF-8 throughout, CRLF in scripts, paths with spaces, and WSL.
- **Done when.** `doctor` names the failing step for each fault injected in a test: wrong key, missing forced
  command, daemon stopped, socket disabled.
- **Precedent.** codebase-memory-mcp configures dozens of agents automatically. "Failed to connect" and "No tools"
  issues dominate the trackers of serena, chrome-devtools-mcp and playwright-mcp, and many of them come from WSL
  and Windows paths.

### 3.3 Schema portability

- **Problem.** Five optional slice fields are emitted as `"type": ["null", "array"]`: `uci_apply.changes`, its
  `values`, `uci_apply.probe`, `pkg_change.packages` and `exec.argv`. Type arrays, `$ref`, `$dynamicRef` and
  untyped properties break some model and client schema paths. Other servers' trackers show 400s from Gemini, a
  "missing properties" error from OpenAI, "invalid JSON parameters" from VS Code, and Cursor's limit of 60
  characters on the combined server and tool name.
- **Ships.**
  - Plain `"type": "array"` for those fields.
  - A contract test over the whole `tools/list`. It checks that:
    - every property has a single `type`;
    - there is no `$ref`, `$defs` or `$dynamicRef`, and no top-level `anyOf` or `oneOf`;
    - every object has `properties`;
    - `openwrt` plus the tool name fits 60 characters.
- **Done when.** The test fails on today's schema and passes after the fix.

### 3.4 Accurate annotations

**Status: done on `main`, not yet released** (`TestToolTitlesAndHints` pins the table).

- **Problem.** No tool has a `title`, and `openWorldHint` is unset everywhere. The spec default is `true`, so every
  tool claims to reach the open world. Clients use these hints to decide what to auto-approve.
- **Ships.** `title` on every tool. `openWorldHint` set explicitly: false for closed-world router tools, true for
  `net_diag` and `pkg_query search`. `destructiveHint` and `idempotentHint` reviewed. A contract test pins the
  table.

### 3.5 Description budget

- **Problem.** Measured on 1.2.0: `tools/list` is 23 tools and 21.1 KB, about 6k tokens. `uci_apply` alone is
  4.6 KB, 22% of it.
  - Most descriptions end with policy scope syntax. That text is for the operator, and every denial already prints
    the exact `allow` line.
  - Bloated or human-oriented descriptions are a top complaint about MCP servers in general.
  - Descriptions that name tools that don't exist teach models wrong calls.
- **Ships.**
  - Scope syntax moves to denials and the README.
  - The advanced `uci_apply` modes (`restore`, `probe`, history) move into their parameter descriptions.
  - `contract_test.go` fails above a total ceiling (18 KB) and above a per-tool cap.
  - A test checks that every tool name mentioned in a description or the README exists.
  - `tests/mcp_eval` proves tool selection does not regress.
- **Precedent.** DesktopCommanderMCP ("descriptions written for humans, too long"); firecrawl-mcp-server
  (descriptions that teach a wrong calling convention, and a documented tool that is never listed).

### 3.6 Credentials stay off the transcript

- **Problem.** Two outputs put credentials into the model's context, and from there into the provider's logs:
  - `wg_new_client` returns the private key, the preshared key and a half-block QR code. The QR is about 2-3k
    tokens of block glyphs per call and often renders badly.
  - `mfa_unlock` makes the operator type a TOTP code into the chat for the model to pass on.

  Sending keys to a cloud model is the first privacy objection OpenWrt users raise against AI assistants.
  Separately, `sysupgrade backup` leaves a tarball holding secrets in `/tmp` (RAM) with the default umask, and
  repeated calls pile up.
- **Ships.**
  - `wg_new_client` writes `/tmp/wg-<name>.conf` (0600) by default. It returns the path, the public key and a
    one-line command for the operator, for example `openwrt-mcp wg-show <name>` on the router, which prints the
    config and the QR in the operator's own terminal. `reveal=true` keeps today's output.
  - Backups are written 0600. The tool keeps only the newest archive it made, or lists older ones as outstanding
    in `system_status`.
  - The TOTP code moves to elicitation in 6.1. `mfa_unlock` stays as the fallback for clients without
    elicitation.
- **Done when.** A test shows no private key or PSK in a default `wg_new_client` result, and `reveal=true` restores
  it. Backup files are 0600.

### 3.7 Shell-equivalent `exec` grants

- **Problem.** The `exec` scope is the literal `argv[0]`. A grant for any of these commands is a root shell, but
  doesn't look like one:
  - shells and wrappers: `sh`, `ash`, `busybox`, `env`, `nice`, `flock`;
  - commands that run other commands: `find`, `awk`, `sed`, `xargs`, `tar`, `ssh`;
  - interpreters: `lua`, `ucode`;
  - `apk` and `opkg` (package scripts), and `ubus` where `file.exec` is reachable.

  A later fix in another MCP server shows the pattern: an absolute path got past its command blocklist.
- **Ships.**
  - `allow` warns on a shell-equivalent `argv[0]`, judged by basename, and requires `--shell-equivalent` to grant it.
  - `policies` marks such grants.
  - The list lives in one table with a mutation test.
  - This is advisory first (Principle 3). 6.2's deny floor can later make it a gate.
- **Done when.** Every listed name, given bare or as an absolute path, triggers the warning. Removing any entry
  fails a test.
- **Precedent.** CVE-2025-11490 (DesktopCommanderMCP, blocklist bypass by absolute path). GTFOBins.

### 3.8 Prompts

- **Ships.** MCP prompts for the common jobs: `router-health`, `who-is-online`, `secure-my-router`, `wifi-doctor`
  and `upgrade-plan`. Each is a short recipe that names the tools to call. They cost nothing until used.
- **Precedent.** Other servers' users ask for "example prompts as a resource" and for prompting guidance.

### 3.9 Sanitised diagnostic bundle

- **Ships.** `openwrt-mcp diag` prints the version, the board, the policy shape and the last N audit entries, with
  IPs, MACs, SSIDs and host names masked. The output is ready to paste into a GitHub issue.
- **Precedent.** ha-mcp's built-in issue-report tool, and unifi-mcp's sanitised support bundles.

### 3.10 Registry entry and SDK update

- **Ships.**
  - A `server.json` for the official MCP Registry.
  - go-sdk moves to the release that negotiates protocol 2026-07-28, which 6.1 and 5.5 need. The bump is gated by
    Principle 9.

### 3.11 Measured token cost

- **Ships.** A reproducible task set: "who is on my Wi-Fi", "why is the WAN down", "add and remove a static
  lease". It measures tokens and calls through openwrt-mcp against the same task done with raw SSH and shell
  commands. The README states the result. It extends `tests/mcp_eval`.
- **Done when.** The README figure can be regenerated from the repository. Numbers are measured, never estimated.

---

## Milestone 4: Diagnostics (v1.4)

Read-only value: the questions operators actually ask, answered in few tokens.

### 4.1 Log summary and baseline diff

- **Problem.** After a restart-triggering change, the useful question is "what is new in the log", not "show me
  500 lines".
- **Ships.** New `logread` modes:
  - `mode=summary`: distinct normalised messages with count, first and last time and worst severity, grouped by
    process.
  - `baseline=save`: returns a token.
  - `baseline=<token>`: returns only the messages not seen at baseline time.
  - Newest-first ordering as an option.
- **Done when.** Golden tests on recorded logs, and a fuzz test on the normaliser.
- **Precedent.** ha-mcp's structured log summary and log order toggle.

### 4.2 Health findings

- **Ships.** `system_status mode=doctor` returns a severity-ranked list of findings:
  - a radio down;
  - an interface up with no address;
  - a service enabled but not running;
  - conntrack near its limit;
  - NTP not synced;
  - overlay nearly full;
  - pending `.apk-new` files;
  - a reboot needed after a kernel or kmod update;
  - a failing upstream DNS.

  Each finding carries a suggested next tool call and a link to the relevant OpenWrt wiki page.
- **Precedent.** ha-mcp's health tool (dead entities, repairs). OpenWrt forum users ask that AI help follows
  OpenWrt's own way of doing things and links to the documentation.

### 4.3 Security audit

- **Problem.** The first objection OpenWrt users raise to AI-assisted configuration: changes that look fine but are
  quietly insecure, and that a non-expert cannot check.
- **Ships.** `system_status mode=audit`, a separate list from 4.2. Each finding has a severity, a wiki link and a
  suggested `uci_apply` dry run. It checks for:
  - ports and zones open to WAN;
  - dropbear on WAN, or password authentication on;
  - LuCI reachable from WAN;
  - UPnP on;
  - WPS on;
  - open, WEP or TKIP SSIDs;
  - no root password;
  - `apk audit` findings;
  - WireGuard peers with no handshake for a long time.
- **Done when.** Each finding has a fixture that triggers it and one that does not.

### 4.4 Wi-Fi diagnostics

- **Ships.**
  - `net_diag wifi_scan.<radio>`: neighbouring networks.
  - `net_diag wifi_survey.<radio>`: channel utilisation, plus a channel and width recommendation that states its
    reasons.
  - Per-client signal, retries and rates in `network_clients`.
  - The scan output is untrusted input (Principle 5): SSIDs are written by strangers.

### 4.5 Per-client traffic

- **Ships.**
  - `network_clients fields=usage`: per-client totals for today, the week and the month, from nlbwmon when it is
    installed.
  - A `net_diag` action samples rx/tx deltas per interface or client over N seconds (capped), and lists the top
    conntrack talkers.

### 4.6 Wake-on-LAN

- **Ships.** `net_diag wol.<mac>`, using `etherwake` when it is installed.

### 4.7 Projection, pagination and a truncation contract

- **Problem.** The global cap keeps results bounded, but a cut result does not say how to get the rest. Responses
  too big for the context are among the most-upvoted complaints about popular MCP servers.
- **Ships.**
  - `fields`, `limit`, `offset` and `detail` (`brief` / `full`) on `network_clients`, `pkg_query`, `uci_get` and
    `system_status`.
  - Every capped result ends with one machine-readable line, such as
    `[truncated: 412 more lines; call again with offset=200]`.
  - A per-call `max_lines` up to the global cap.
- **Done when.** A test enumerates every tool and proves no result is cut without the marker.
- **Precedent.** playwright-mcp ("snapshot too long, add pagination", "limit the size of each tool's output");
  unity-mcp (a 13k-token response).

### 4.8 Structured errors

- **Ships.** Every error result carries a stable `code` and a `suggestions` list:
  - `POLICY_DENIED`;
  - `ROLLBACK_PENDING`;
  - `VALIDATION`;
  - `NOT_FOUND`;
  - `CONFLICT`;
  - `TIMEOUT`;
  - `MFA_REQUIRED`.

  Schema-validation failures are rewritten into actionable text. Today's denial message, which prints the exact
  `allow` command, is the model to follow.

### 4.9 Verify after write

- **Problem.** "Reported success, wrote nothing" is a common bug class across router and firewall MCP servers. In
  MikroTik, pfSense and UniFi servers, writes reported success while the device ignored them.
- **Ships.** Every write path re-reads what it changed and reports a mismatch as an error (Principle 7).
- **Done when.** A table test enumerates every write path and injects a backend that accepts and ignores the write.

### 4.10 Works with local models

- **Problem.** Operators who keep keys away from cloud providers run local models, and small models degrade with
  catalog size sooner than large ones.
- **Ships.** `tests/mcp_eval` runs against at least one local model served by Ollama or LM Studio. The README
  carries a "works with" table built from those runs.

---

## Milestone 5: Reach and resilience (v1.5)

### 5.1 opkg, 24.10 and derived firmware

- **Problem.** 25.12 dominates vanilla OpenWrt upgrades. But 24.10 and the firmware derived from it still ship
  opkg and are widely deployed: vendor firmware such as GL.iNet, and community builds such as ImmortalWrt. Users
  have asked whether the server works on GL.iNet 4.x with 24.10.
- **Ships.**
  - A package-manager layer behind `pkg_query`, `pkg_change` and `pkg_config_*`: apk and opkg, with
    `-opkg` / `.apk-new` conffiles.
  - fw3/iptables awareness in `firewall_show`.
  - Capability flags in `system_status`.
  - A documented support matrix.
- **Done when.** The fake-backed tests run for both package managers, and the 7.1 real-target CI runs one 24.10
  image.

### 5.2 Add-on adapters

- **Ships.** `service_list detail=<service>` returns a defined, read-mostly status for popular add-ons when they are
  installed:
  - adblock and adblock-fast ("why is this domain blocked");
  - AdGuard Home and https-dns-proxy;
  - mwan3, pbr and ddns;
  - Tailscale;
  - common proxy and VPN clients.

  Adapters show only for installed packages, so the tool list stays flat (Principle 1). Each adapter is one small
  read with a schema and a fixture.

### 5.3 CLI and skill transport

- **Problem.** For agents with a shell, a CLI plus a short skill file costs almost nothing until it is used. That
  is why several large MCP servers now ship a CLI next to the server; playwright-mcp's measured saving is about 4x.
- **Ships.**
  - `openwrt-mcp call <tool> '<json>'` over SSH. It goes **through the daemon** under the same client identity,
    policy, audit, redaction and rollback. It is another transport, never a second path to `uci` or `exec`.
  - `call <tool> --help` prints the schema on demand.
  - A bundled `SKILL.md`.
- **Done when.** The e2e tests run the same golden calls over stdio and over `call`, with identical audit records.

### 5.4 Client-chosen tool profile

*Replaces "policy-aware tool list".*

- **Problem.** Small models and tight contexts want fewer tools. Hiding tools the client holds no grant for would
  break the denial flow: today a denial prints the exact `allow` line, the operator runs it, and the next call
  works without reconnecting. A hidden tool can't be denied helpfully, and clients handle mid-session catalog
  changes badly (stale catalogs, `Unknown tool`, pagination ignored).
- **Ships.** The client chooses its catalog at session start: `stdio --toolset diag|config|pkg|wg` and
  `--read-only`. Read-only overrides every other setting. Every tool stays listed by default, and grants do not
  change the catalog.
- **Precedent.** github-mcp-server's toolsets and `--read-only`; chrome-devtools-mcp's `--slim`.

### 5.5 Structured output

*Replaces the `format=json` option.*

- **Ships.** An `outputSchema` per tool, with the data in `structuredContent` and the existing text table kept in
  `content`. Many clients forward only `content` to the model, and text tables read better than raw JSON. Schemas
  are sent only to clients that negotiate a protocol version that has them.
- **Precedent.** github-mcp-server gates structured content on the negotiated version.

### 5.6 Session resilience

- **Problem.** Routers reboot (scheduled reboots, upgrades, power cuts) and SSH sessions drop. Stale sessions and
  silent reconnect failures are a common complaint in other servers' trackers.
- **Ships.**
  - Configs generated by 3.2 set SSH keep-alive.
  - A call made while the daemon is starting returns `TIMEOUT` with a retry hint instead of hanging.
  - `status` shows the last disconnect reason.
  - The README documents reconnecting after a reboot.

### 5.7 Cancellation, deadlines and workload limits

- **Ships.**
  - `notifications/cancelled` kills the child process.
  - Every tool has a deadline, and a timeout returns partial output with `code=TIMEOUT`.
  - A global cap on in-flight calls, and caps on long scans (`traceroute`, large `logread`), on top of the existing
    per-client rate ceiling.
- **Done when.** An e2e test cancels a long `traceroute` and asserts that the process is gone.

### 5.8 Progress for long operations

- **Ships.** MCP progress notifications for `pkg_change` commit, `sysupgrade` test and `traceroute`, and the Tasks
  extension where the client supports it.
- **Not included.** The rollback countdown. A progress notification needs a request in flight, and none exists
  after `uci_apply` returns, so the countdown appears in results and in `system_status`.

### 5.9 Advisory warnings in dry runs

- **Ships.** The `uci_apply` dry run returns `warnings`, with no new tool, and each warning links to the wiki.
  Examples:
  - the change touches the address or interface this session uses;
  - it opens a port to WAN;
  - it sets zone input `ACCEPT` on WAN;
  - it enables dropbear password auth;
  - it disables the radio the client is on;
  - it stages `encryption=none` on an existing SSID;
  - it references an interface name that does not exist, for example a case mismatch;
  - it renames or deletes a section that other configs still reference.

  An optional bundled guide is exposed as an MCP resource. Warnings stay advisory: blocking is the job of 6.2.
- **Precedent.** ha-mcp's reactive best-practice warnings and bundled skills as resources.

### 5.10 Cross-config references

- **Ships.** A `uci_get` search mode that finds every use of a value or section name across configs. It knows the
  reference fields in firewall (`network`, `src`, `dest`), dhcp (`interface`), wireless (`network`) and common
  add-ons such as sqm and mwan3 when installed. 5.9 uses it for rename and delete warnings.
- **Precedent.** ha-mcp's dependency-graph search, used before renaming.

### 5.11 Translated documentation

- **Ships.** `README.zh-CN.md` and `README.ru.md`. Much of the OpenWrt community writes in those languages. Tool
  output stays English (see Non-goals).

---

## Milestone 6: Operate (v2.0)

Starts with a design note in `docs/`, because approval interacts with policies and the second factor.

### 6.1 Per-call approval

- **Problem.** The TOTP window approves everything the client's grants allow for its whole duration. There is no
  way to say "this one `exec`, with these arguments, yes".
- **Ships.**
  - Policies can mark a tool or scope `approve`.
  - **Elicitation first.** For clients that negotiate it (protocol 2026-07-28, multi round-trip requests), a matching
    call returns `input_required`. The client asks the human, whom the model cannot answer for. The TOTP prompt of
    MFA-gated tools moves to the same mechanism.
  - **Out of band** for high-risk scopes, and for clients without elicitation:
    - a matching call returns `pending` with an id at once, without blocking;
    - the operator decides with `openwrt-mcp approve|deny <id>`, a LuCI button, or a webhook for external
      notifiers;
    - the agent retries the identical call to consume the approval.
  - The pending record is bound to a hash of the canonical arguments. It is used once, and it expires.
  - **No new PIN.** Where a second factor is wanted, the existing TOTP factor and its limiter (1.5) are reused.
    Another hashed secret would add storage and recovery paths without adding a factor.
- **Done when.**
  - A test proves an approval is consumed exactly once under concurrent identical calls.
  - A changed argument does not match.
  - An expired approval is refused.
  - Elicitation and out-of-band produce the same audit record.
- **Precedent.** ha-mcp's Tool Security Policies (approval gating, decision announcements) and its fix for
  approvals consumed twice by concurrent calls.

### 6.2 Argument predicates and a deny floor

- **Problem.** Scope globs limit which names a call touches, never which values it writes.
- **Ships.** Rules can match on argument values: `eq`, `in`, `regex`, `exists`. Examples:
  - `wireless.*.disabled` only `0` or `1`;
  - never `dropbear.*.PasswordAuth=on`;
  - never zone input `ACCEPT` on WAN.

  A built-in deny floor applies that no grant can lift. It extends today's guard against writing the policy
  config, and can turn 3.7's warning into a gate. The semantics for combining several rules are defined up front
  and covered by mutation tests.
- **Precedent.** ha-mcp had to rework AND-within-a-rule into ANY-match after release. Getting this right first is
  cheaper.

### 6.3 Per-device access control

- **Ships.** `network_clients action=block|allow|schedule` for one device:
  - block or pause its internet access;
  - allow only within time windows ("no internet after 22:00").

  Each action compiles to fw4 rules (`src_mac`, `start_time`, `weekdays`) and goes through the normal
  rollback-armed apply. The scope is `client.<mac>`. Kicking a Wi-Fi client (`hostapd del_client`) is a separate
  write scope.
- **Done when.** Golden tests show the generated rules for each action, and a mutation test shows a block cannot
  leak to another MAC.

### 6.4 Upgrade planner

- **Ships.**
  - **Within a release.** `pkg_change upgrade` in simulate mode reports:
    - version changes;
    - kernel or kmod changes, which mean a reboot;
    - services that will restart;
    - predicted conffiles;
    - files the package would overwrite that were changed or replaced locally, such as self-built binaries.
  - **Across releases.** `sysupgrade action=plan` lists the user-installed packages (world minus defaults). It
    checks which exist in the target release, previews the Attended Sysupgrade request, and lists config files at
    risk.
  - Flashing stays manual (see Non-goals).
- **Precedent.** "Lost my packages after sysupgrade" is one of the oldest recurring OpenWrt forum topics.

### 6.5 Managed files

- **Problem.** Anything outside UCI needs `exec`, which is a root shell. That includes crontabs, `dnsmasq.d`
  snippets, `sysupgrade.conf`, hosts files and block lists. It is the main reason operators grant more than they
  want to. Generic file tools are also the riskiest kind: path traversal is a large share of 2026 MCP CVEs.
- **Ships.**
  - **Typed kinds first**: crontab, `dnsmasq.d/*.conf`, hosts files and `sysupgrade.conf`. Each kind has a
    validator (`sh -n`, the crontab format, the dnsmasq syntax) and a service hook after the write (for example a
    cron restart).
  - A generic path-glob scope exists, but is **empty by default**.
  - Every path is canonicalised before the policy check (symlinks resolved, `..` rejected, no-follow opens), and
    the checker is fuzzed.
  - Atomic writes that keep mode and owner.
  - A history snapshot (2.4).
  - Output redaction (1.1).
  - A deny floor covering `/etc/shadow`, private keys, `/etc/config/openwrt-mcp` and `/etc/openwrt-mcp/`.
- **Depends on.** 1.1, 2.4 and 6.2. It ships only once they exist.
- **Precedent.** ha-mcp's managed YAML editing with an allow-list and a deny floor; path-traversal CVEs in other MCP
  servers.

### 6.6 Interactive views

- **Ships.** Opt-in MCP Apps views for the client table, the security audit and pending approvals. Text stays the
  default, and nothing opens unless the client asks for it.
- **Precedent.** serena's users asked for its dashboard *not* to open by default.

---

## Milestone 7: Scale and ground truth (v2.x)

### 7.1 Real-target end-to-end tests

- **Problem.** `fake_test.go` cannot judge real `uci`, `ubus`, `apk` and `fw4` output, reload behaviour or a
  rollback restore.
- **Ships.** CI boots the OpenWrt 25.12 x86-64 rootfs in a container or QEMU, then runs the e2e client against
  it. The image version is pinned and bumped by a dependency bot. A 24.10 image covers 5.1. Fakes stay for fast
  unit tests.
- **Precedent.** A pinned real-system container that became ha-mcp's main safety net.

### 7.2 Agent acceptance stories

- **Ships.** Scripted tasks run by an agent against 7.1 and scored on outcome, tool choice and token use. Example
  tasks:
  - add a static lease, verify it, roll it back;
  - open and then close a port;
  - add and remove a WireGuard peer.

  This extends `tests/mcp_eval` and 3.11.
- **Precedent.** ha-mcp's UAT/BAT acceptance framework.

### 7.3 Several routers

- **Problem.** Many OpenWrt homes run a main router and dumb access points. "Several instances" is a top request
  in other servers' trackers (ida-pro-mcp, chrome-devtools-mcp, and per-call profile and region in awslabs/mcp).
- **Ships.** `openwrt-mcp hub` on the operator's machine. It multiplexes several SSH stdio sessions behind one MCP
  server, and calls take a `router` argument. Reads may fan out across routers; writes always target exactly one.
  Policy and audit stay on each router.

### 7.4 Events

- **Ships.** MCP resource subscriptions on router events: a new device joined, WAN down, a WireGuard handshake, a
  service crash. They are fed by `ubus listen` and hotplug into a bounded ring buffer.

### 7.5 Metrics history

- **Ships.** `system_status history=24h` reads collectd RRD data when luci-app-statistics is installed: load,
  temperature, traffic.

### 7.6 VLAN view

- **Ships.** `uci_get view=vlan_matrix`: a port × VLAN table built from `bridge-vlan` sections, for DSA setups.

### 7.7 Bufferbloat and SQM

- **Ships.** A bounded latency-under-load test in `net_diag`. It is open-world, so it is annotated as such. A
  `tune-sqm` prompt then proposes cake settings through a `uci_apply` dry run.

---

## Later: delivery and operator experience

- **Update check.** `openwrt-mcp version --check` against GitHub releases, shown by `status`. Then
  `install.sh upgrade`.
- **Packaging.** An `apk` package or feed for 25.12.
- **LuCI control page.** Per-tool enable or disable, a read-only switch, pending approvals (6.1), a redacted audit
  tail and the policy list.
- **PR template.** A checklist with a red-first regression test, a `goldenCalls` entry and a mutation run for
  security rules.

Dropped from this list:

- **The `.mcpb` desktop bundle.** It would have to ship an SSH client, and desktop extensions have proven fragile
  on Windows. `connect` (3.2) covers Claude Desktop along with the other clients.
- **Windows hygiene tests.** They moved to 3.2.

---

## Non-goals

These are deliberately not planned, with the reason for each.

| Idea | Why not |
|---|---|
| Search-based tool discovery or call proxies | Pays off above about 50 tools. The catalog is about 6k tokens (measured, 3.5), and clients increasingly defer MCP tools behind their own tool search. Principle 1 keeps it small. |
| Hundreds of fine-grained tools with meta-tools | The large catalogs other servers carry need index and execute meta-tools. Modes on existing tools avoid that. |
| A code sandbox or custom-tool runner | `exec` already exists as the explicit, auditable escape hatch. A sandbox adds attack surface without being a real boundary. |
| OAuth / OIDC, internet-facing HTTP | The daemon is loopback-only behind SSH or a tunnel, by design: it is root on a network device. Remote access goes over the operator's own VPN (WireGuard, Tailscale). Revisit when there are repeated requests for web or phone clients, which need a public HTTPS endpoint. |
| Flashing firmware | `sysupgrade` validates and backs up, but never flashes. Flashing is the one action with no rollback. 6.4 plans the upgrade; a human runs it. |
| Localised tool output | An operator tool with technical output, and models read English best. Documentation translations are planned (5.11). |

## Open questions

- 2.4: snapshot size on small-flash devices. UCI is small, but package config snapshots may not be. Should
  history move to RAM with a size cap on low-flash boards?
- 3.6: should `wg_new_client` also offer a one-time LuCI download link, or are a file on the router and the
  operator's own terminal enough?
- 5.1: how far should support for derived firmware go? Vendor firmware can patch `uci`, `fw4` or rpcd. Should
  the line be "OpenWrt 24.10+ userland", tested in CI, with anything else best effort?
- 7.1: container rootfs or full QEMU image. The container cannot exercise netifd and wireless, while QEMU is
  slower in CI.
- 7.3: should the hub hold SSH sessions open, or connect per call? Open sessions are faster, but they hide router
  reboots (5.6).

Answered since the first version of this roadmap:

- *Should the server hide tools from clients that never refresh their catalog?* No. See 5.4.
- *Should a pending approval be possible inside the MCP session?* Yes, through elicitation, without a PIN. See 6.1.

Feedback and proposals are welcome as issues. See [CONTRIBUTING.md](CONTRIBUTING.md).
