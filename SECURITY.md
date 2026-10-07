# Security policy

openwrt-mcp runs as root on a router and exposes its configuration to an AI agent, so security
reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead:
*Security* tab -> *Report a vulnerability* on this repository. Include the OpenWrt release,
the openwrt-mcp version (`openwrt-mcp version`), and steps to reproduce.

You should get an answer within a week. Fixes are released as a new version with a
CHANGELOG entry that credits the reporter unless you prefer otherwise.

## Threat model

This section says what the daemon defends, against whom, and where it stops. It describes the
current release; the CHANGELOG says when each control arrived.

### What is protected

- **Control of the router.** Whatever a client may do is what its policy grants, and nothing else.
- **Secrets in the configuration:** Wi-Fi keys, WireGuard private and preshared keys, tokens and
  passwords in `/etc/config/*`.
- **The policy file** (`/etc/config/openwrt-mcp`): it decides what every client may do.
- **The audit log** as a record of what was asked and what happened.

### Who is trusted

| Party | Trust |
|---|---|
| The operator: root on the router, running `openwrt-mcp allow`, `pair`, `mfa enrol` | Fully. Policy changes happen only there. |
| An MCP client holding a grant | To the extent of its grant, and no further. Identity is the SSH key bound to the stdio bridge, or the bearer token. |
| The model behind the client | **Not trusted.** It reads text that others write, and it can be steered by it. The policy is written for a model that has been talked into something. |
| Devices on the network, remote hosts, whoever sends packets | **Untrusted sources of text:** host names, SSIDs, log lines, DNS answers. |
| A local process on the router | Can reach `127.0.0.1`, so it can be refused but not ignored: HTTP needs a token even from loopback. |
| Anyone with a root shell on the router | Out of scope. They can edit the policy, the state and the audit log directly. |

### Boundaries

- **stdio bridge:** an SSH forced command (`openwrt-mcp authorize-key`) runs `openwrt-mcp stdio`,
  which talks to the daemon over a unix socket, mode `0600` in a `0700` directory, so only root can
  reach it. The client name asserted on that socket is only as good as the SSH key bound to it.
- **HTTP:** loopback only (the daemon refuses any other address), a bearer token on every request
  with no loopback auto-trust, SHA-256 digests stored rather than tokens, and an `Origin` check
  against browsers. Reach it over `ssh -L`.
- **No shell.** Every command is an argv. Names, targets and paths that could be read as options
  are refused, and UCI names are validated against UCI's grammar so a scope cannot be bent onto
  another key.

### Authorisation

Deny by default. A policy names a client, tools, scope globs, a calls-per-minute ceiling and an
expiry. `uci_apply` and `pkg_config_resolve` refuse the policy file whatever the grant, so a
client cannot write itself a wider policy. Every committing tool refuses to run on top of someone
else's uncommitted edit, and `uci_apply` arms a rollback timer whose snapshot is on flash.

Limits you must accept:

- **`exec` is a root shell by design,** and so is `ubus_call` on a broad object. Grant them for a
  working session, not for good. `@operator` includes writes to `dropbear`, `rpcd` and `uhttpd`.
  An `exec` grant for `sh`, `find`, `awk`, `env`, `ssh`, `apk` or any other program that runs
  programs is the same shell under a harmless name, so `allow` refuses it without
  `--shell-equivalent`, judging by base name and by glob, and `policies` and `status` mark such
  grants. The list is a floor: a grant that writes files, or starts an interpreter not on it, is
  not caught.
- **rpcd ACLs are not relied on.** They do not bind a root process on the local ubus socket.
- **The policy is advisory if the agent can also run `ssh root@router`.** Deny that in the client,
  or keep the root key out of its reach.
- **The rate limit is per process.** A daemon restart resets it.

### Audit log

It records every call and its outcome (`OK`, `DENIED`, `ERROR`): time, client, tool, scope and
arguments, with secret-named values masked, and a short summary or error text (240 bytes,
sanitised, masked). The file is `0600` in a `0700` directory and rotates to one older generation.

It does **not** record what a tool returned, and it is not tamper-evident: root can edit it, and
nothing signs it or ships it elsewhere. Treat it as a record for an honest operator, not as
evidence against a root attacker.

### Output safety

Everything a tool returns goes through one path: sanitise, mask, bound, label.

- **Secrets are masked** in `uci_get`, `uci_apply` (the staged diff and error texts),
  `pkg_config_diff`, `pkg_config_resolve`, `uci_confirm`, `uci_rollback`, `system_status` and
  `ubus_call`. The value of any option named `key`, `key1`..`key4`, `psk`, `password`,
  `sae_password`, `passphrase`, `private_key`, `preshared_key`, `token`, `pwd` (or containing
  `secret`, `credential`, `apikey` and the like) becomes `<redacted>`; the option and the line
  keep their shape. The audit log and the masker share one rule. `redact_extra` adds names.
- **Not masked, on purpose:** `exec` (a root shell can read any file anyway), `logread`,
  `firewall_show` and the diagnostics, which carry no configuration values or are free text;
  and `wg_new_client` with `reveal=true`, whose job is then to hand the operator the new client's
  private key. Treat that output as a credential: show it to the operator and do not store it. By
  default the key is not in the result at all: the config goes to a `0600` file in a `0700`
  directory in RAM beside the socket, created with `O_EXCL`, and the operator collects it with
  `openwrt-mcp wg-show`, which deletes it. An uncollected file is swept after 24 hours and lost
  at reboot. A `sysupgrade` backup is created `0600` before it is written, and the tool keeps
  only the newest archive it made. A model that is told to run `wg_new_client` therefore never
  sees the key unless it also sets `reveal`, and a policy cannot yet tell the two apart.
- **Known gaps in masking:** a masked diff hides *what* changed in a secret; matching by substring
  also hides options such as `wpa_psk_file`; a secret in free text (a log line, a `description`)
  is not recognised. `option redact_output '0'` turns masking off; it is audited as a system
  event, at startup and on config reload.
- **Untrusted text.** Terminal escape sequences, control characters, bidirectional and zero-width
  format characters and invalid UTF-8 are removed from every result, and from the audit summary.
  Lines are cut at 1024 bytes for every tool except `exec`, `wg_new_client`, `ubus_call` and the
  configuration tools. A result over 64 KB is cut with a visible notice, errors included. The
  results of `network_clients`, `logread` and `net_diag` start with `[untrusted text: ...]`.
- **What that does not do.** The marker lowers the chance that a model obeys a host name that
  says "ignore your instructions"; it does not stop it. Stripping format characters also breaks
  emoji sequences that use a zero-width joiner. The controls that hold are the policy, and not
  granting write scopes in the same session that reads untrusted text.

### State at rest

The state directory (`/etc/openwrt-mcp`) holds token digests, TOTP secrets (raw, since TOTP is
symmetric), the pending-apply record and, while an apply is unconfirmed, a full copy of every
config it touches, secrets included. Files are `0600`, directories `0700`; a snapshot is deleted
on a successful rollback and kept after a failed one. On confirm it becomes a **history entry**:
the version of the config from before the change, kept with the newest `history_keep` (default 5,
`0` turns history off) per config under `/etc/openwrt-mcp/history/`. The `wg_*` tools record the
file just before they commit. History entries are whole config files, secrets included, so they
are held to the same modes, are masked when shown through `uci_get history=diff`, and travel in a
`sysupgrade` backup like the rest of the state directory. These files are as sensitive as
`/etc/config` itself.

The state directory, the audit log and the socket are checked against the web root: a path under
`/www`, under any `cgi-bin` directory or under uhttpd's configured `home`, directly or through a
symlink, is refused. `-state` there stops the command; an `audit` or `socket` option there is
ignored with a log line and keeps its default.

### Change safety

`uci_apply` adds checks that narrow what a mistaken or manipulated call can do. None widens what a
grant allows, except where stated.

- **Validation before reload.** Where a service has a checker that sees staged changes (`fw4 check`
  for the firewall), a real apply is refused if the change adds a problem the config did not have;
  `force=true` overrides, and the rollback timer still applies. A config with no such checker is
  reported "not checked", never "passed".
- **Revisions.** `uci_get` prints a revision (a digest of the committed file) and
  `expected_revisions` makes `uci_apply` refuse a config that changed in between. It prevents
  overwriting someone else's edit; it is not an integrity check, because the caller supplies it.
- **Management path.** A change to the LAN interface or its bridge, the SSH listener, or the
  firewall zone and rule that let SSH in is refused unless the call names a probe (or `force=true`).
  The rule set is static and covers the common layout; a router managed through an unusual
  interface should not rely on it.
- **Probes** make the router ping or resolve a name on the caller's behalf, which a grant on
  `uci_apply` alone never allowed. Each probe target is therefore its own policy scope,
  `probe.<kind>.<target>`; `*` covers them, `<config>.*` does not.
- **Restore** replaces a whole config, so its scope is the whole-config key `<config>`, which
  `<config>.*` does not cover. It runs the same snapshot, rollback timer and checks as any apply.

### Second factor

`mfa_tools` in a policy makes listed tools require a TOTP code (`mfa_unlock`). Codes are
single-use; a window stays open for `mfa_window`; unlocks live in memory. After
`mfa_max_failures` (default 5) wrong codes in a row a client is locked out for `mfa_lockout`
(default 5 minutes), doubling on each repeat to one hour; a correct code during the lockout is
refused and not spent; an unenrolled client is counted the same, so the limiter reveals nothing
about enrolment. The counters are in memory: a daemon restart, re-enrolment or a rotated secret
clears them.

The trade-off is deliberate: **whoever holds a client's token or key can lock the operator out of
`mfa_unlock` for up to an hour** by sending wrong codes. The alternative is unlimited guessing.
The second factor does not protect against root.

## Scope of reports

In scope: anything that lets an MCP client act outside the policies granted to it -- scope or
tool bypasses, command or option injection through tool arguments, secrets reaching the audit
log or a masked tool's output, control or escape sequences reaching a result, a way around the
second-factor limiter, a state, audit or socket path that ends up web-served, a rollback that
does not restore, the stdio bridge accepting a client it should not.

Out of scope: an agent using exactly the permissions you granted (a broad `exec` or `ubus_call`
grant *is* a root shell, as documented); an agent following an instruction injected through
untrusted text, within its grant; the gaps listed above under masking and untrusted text; the
lockout trade-off; access by someone who already has a root login on the router.

## Supported versions

Only the latest release is supported.
