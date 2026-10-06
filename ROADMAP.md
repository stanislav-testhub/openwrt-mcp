# Roadmap

Where openwrt-mcp is going after v1.0, and why. Items are grouped into milestones in build order. Each one says
what problem it solves, what ships, and how we will know it works.

Many of these ideas come from reading the history of
[ha-mcp](https://github.com/homeassistant-ai/ha-mcp), an MCP server for Home Assistant: about 150 releases and more
than 2,000 changelog entries in one year. Its fix history shows which problems keep coming back once an agent drives
a real system, so this roadmap tries to pre-empt them rather than rediscover them. Feature names in the
"Precedent" lines refer to ha-mcp. The ideas were adapted to a router, not copied.

Nothing here is a promise or a date. Order can change when a real bug says so.

## Principles

These hold for every item below.

1. **Grow tools by mode, not by count.** A new capability becomes an action or mode on an existing tool
   wherever that reads naturally. The tool list stays small: it is about 20 tools today, which is below the range
   where models start choosing tools badly.
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

## Milestone 3: Diagnostics that save tokens (v1.3)

### 3.1 Log summary and baseline diff

- **Problem.** After a restart-triggering change, the useful question is "what is new in the log", not "show me
  500 lines".
- **Ships.** New `logread` modes:
  - `mode=summary`: distinct normalised messages with count, first and last time and worst severity, grouped by
    process.
  - `baseline=save`: returns a token.
  - `baseline=<token>`: returns only the messages not seen at baseline time.
  - Newest-first ordering as an option.
- **Done when.** Golden tests on recorded logs, and a fuzz test on the normaliser.
- **Precedent.** The structured log summary and the log order toggle.

### 3.2 Health findings

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

  Each finding carries a suggested next tool call.
- **Precedent.** The health tool's dead-entity and repairs sections.

### 3.3 Upgrade impact report

- **Ships.** `pkg_change upgrade` in simulate mode reports:
  - version changes;
  - kernel or kmod changes, which mean a reboot;
  - services that will restart;
  - predicted `.apk-new` files;
  - files the package would overwrite that were changed or replaced locally, such as self-built binaries.
- **Precedent.** The pre-update release-notes check.

### 3.4 Projection, pagination, JSON

- **Ships.** `fields`, `limit`, `offset` and `detail` (`brief` / `full`) on `network_clients`, `pkg_query`,
  `uci_get` and `system_status`. `format=json` sits next to the current text tables. The global result cap stays
  as a backstop.
- **Precedent.** `fields=` projection, offset pagination and detail levels.

### 3.5 Progress notifications

- **Ships.** MCP progress notifications for slow operations, so clients do not time out silently:
  - `pkg_change` commit;
  - `sysupgrade` test;
  - `traceroute`;
  - the rollback countdown.

### 3.6 Traffic sampling

- **Ships.** A `net_diag` action that samples rx/tx deltas per interface or client over N seconds (capped), and
  lists the top conntrack talkers.

---

## Milestone 4: Tool-surface quality (v1.4)

### 4.1 Structured errors

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

### 4.2 Policy-aware tool list

- **Problem.** Every client sees every tool, including ones it can never call. The model wastes calls and context
  on them.
- **Ships.** `tools/list` hides tools for which the client holds no grant. A `notifications/tools/list_changed`
  is sent when policies reload. The README tells operators to reconnect clients that ignore the notification.
- **Precedent.** Read-only mode and per-tool enable or disable. Clients kept stale catalogs after setting changes
  and got `Unknown tool` errors.

### 4.3 Accurate annotations

- **Ships.** `title` is set on every tool, and `openWorldHint` explicitly: false for closed-world router tools,
  true for `net_diag` and `pkg_query search`. `destructive` and `idempotent` are reviewed. A contract test pins
  the table.

### 4.4 Description budget

- **Ships.** `contract_test.go` measures the serialized `tools/list` size and fails above a ceiling. Descriptions
  are trimmed to what the model needs at call time. `tests/mcp_eval` keeps proving that tool selection does not
  regress.
- **Precedent.** Repeated description-trimming passes once the catalog cost became visible.

### 4.5 Advisory warnings in dry runs

- **Ships.** The `uci_apply` dry run returns `warnings`, with no new tool. Examples:
  - the change touches the address or interface this session uses;
  - it opens a port to WAN;
  - it sets zone input `ACCEPT` on WAN;
  - it enables dropbear password auth;
  - it disables the radio the client is on;
  - it references an interface name that does not exist, for example a case mismatch;
  - it renames or deletes a section that other configs still reference.

  An optional bundled guide is exposed as an MCP resource. Warnings stay advisory: blocking is the job of 5.1.
- **Precedent.** Reactive best-practice warnings and bundled skills as resources.

### 4.6 Cross-config references

- **Ships.** A `uci_get` search mode that finds every use of a value or section name across configs. It knows the
  reference fields in firewall (`network`, `src`, `dest`), dhcp (`interface`), wireless (`network`) and common
  add-ons such as sqm and mwan3 when installed. 4.5 uses it for rename and delete warnings.
- **Precedent.** Dependency-graph search, used before renaming.

### 4.7 Sanitised diagnostic bundle

- **Ships.** `openwrt-mcp diag` prints the version, the board, the policy shape and the last N audit entries,
  with IPs, MACs, SSIDs and host names masked. The output is ready to paste into a GitHub issue.
- **Precedent.** The built-in issue-report tool.

---

## Milestone 5: Fine-grained approval (v1.5)

Starts with a design note in `docs/`, because it interacts with policies and the second factor.

### 5.1 Per-call approval

- **Problem.** The TOTP window approves everything the client's grants allow for its whole duration. There is no
  way to say "this one `exec`, with these arguments, yes".
- **Ships.**
  - Policies can mark a tool or scope `approve`. A matching call returns `pending` with an id at once, without
    blocking.
  - The pending record is bound to a hash of the canonical arguments. It is used once, and it expires.
  - The operator decides with `openwrt-mcp approve|deny <id>`, a LuCI button, or a webhook for external
    notifiers.
  - The agent retries the identical call to consume the approval.
  - An optional approval PIN is stored hashed, apart from the policy file, with the same limiter as 1.5.
- **Done when.**
  - A test proves an approval is consumed exactly once under concurrent identical calls.
  - A changed argument does not match.
  - An expired approval is refused.
- **Precedent.** Tool Security Policies with approval gating, decision PIN, approval announcements, and a fix for
  approvals consumed twice by concurrent calls.

### 5.2 Argument predicates and a deny floor

- **Problem.** Scope globs limit which names a call touches, never which values it writes.
- **Ships.** Rules can match on argument values: `eq`, `in`, `regex`, `exists`. Examples:
  - `wireless.*.disabled` only `0` or `1`;
  - never `dropbear.*.PasswordAuth=on`;
  - never zone input `ACCEPT` on WAN.

  A built-in deny floor applies that no grant can lift. It extends today's guard against writing the policy
  config. The semantics for combining several rules are defined up front and covered by mutation tests.
- **Precedent.** ha-mcp had to rework AND-within-a-rule into ANY-match after release. Getting this right first is
  cheaper.

### 5.3 Workload limits

- **Ships.** A global cap on in-flight calls, a deadline per tool, and caps on long scans (`traceroute`, large
  `logread`), on top of the existing per-client rate ceiling.

---

## Milestone 6: Managed files and ground truth (v2.0)

### 6.1 Managed file tools

- **Problem.** Anything outside UCI needs `exec`, which is a root shell. That includes crontabs, `dnsmasq.d`
  snippets, `sysupgrade.conf`, hosts files and block lists. It is the main reason operators grant more than they
  want to.
- **Ships.** `file_read` and `file_write` with:
  - path-glob scopes;
  - atomic writes that keep mode and owner;
  - a history snapshot (2.4);
  - a validator by type (`sh -n`, the crontab format, `dnsmasq --test`);
  - a service hook after the write (for example a cron restart);
  - output redaction (1.1);
  - a deny floor covering `/etc/shadow`, private keys, `/etc/config/openwrt-mcp` and `/etc/openwrt-mcp/`.
- **Depends on.** 1.1, 2.4 and 5.2. It ships only once they exist.
- **Precedent.** Managed YAML editing with an allow-list and a deny floor.

### 6.2 Real-target end-to-end tests

- **Problem.** `fake_test.go` cannot judge real `uci`, `ubus`, `apk` and `fw4` output, reload behaviour or a
  rollback restore.
- **Ships.** CI boots the OpenWrt 25.12 x86-64 rootfs in a container or QEMU, then runs the e2e client against
  it. The image version is pinned and bumped by a dependency bot. Fakes stay for fast unit tests.
- **Precedent.** A pinned real-system container that became ha-mcp's main safety net.

### 6.3 Agent acceptance stories

- **Ships.** Scripted tasks run by an agent against 6.2 and scored on outcome, tool choice and token use. Example
  tasks:
  - add a static lease, verify it, roll it back;
  - open and then close a port;
  - add and remove a WireGuard peer.

  This extends `tests/mcp_eval`.
- **Precedent.** The UAT/BAT acceptance framework.

---

## Later: delivery and operator experience

- **Update check.** `openwrt-mcp version --check` against GitHub releases, shown by `status`. Then
  `install.sh upgrade`.
- **Packaging.** An `apk` package or feed for 25.12. An `.mcpb` bundle or small desktop wrapper that opens the
  SSH stdio bridge.
- **LuCI control page.** Per-tool enable or disable, a read-only switch, pending approvals (5.1), a redacted audit
  tail and the policy list.
- **Windows hygiene tests.** UTF-8 throughout, CRLF in `install.sh` and uploaded scripts, and quoting of paths
  with spaces under Git Bash.
- **PR template.** A checklist with a red-first regression test, a `goldenCalls` entry and a mutation run for
  security rules.

---

## Non-goals

These are deliberately not planned, with the reason for each.

| Idea | Why not |
|---|---|
| Search-based tool discovery or call proxies | Pays off above about 50 tools. Principle 1 keeps the count small. |
| A code sandbox or custom-tool runner | `exec` already exists as the explicit, auditable escape hatch. A sandbox adds attack surface without being a real boundary. |
| OAuth / OIDC, internet-facing HTTP | The daemon is loopback-only behind SSH or a tunnel, by design. Revisit only if remote exposure becomes a goal. |
| Localisation | An operator tool with technical output. Not worth the upkeep yet. |

## Open questions

- 2.4: snapshot size on small-flash devices. UCI is small, but package config snapshots may not be. Should
  history move to RAM with a size cap on low-flash boards?
- 4.2: client support for `tools/list_changed` varies. Should the server hide tools, or list them with a
  "not granted" note, for clients that never refresh?
- 5.1: should a pending approval also be possible from inside the MCP session, with a PIN typed by the operator,
  or only out of band?
- 6.2: container rootfs or full QEMU image. The container cannot exercise netifd and wireless, while QEMU is
  slower in CI.

Feedback and proposals are welcome as issues. See [CONTRIBUTING.md](CONTRIBUTING.md).
