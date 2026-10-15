# Design note: approve from the router (v1.6)

Status: implemented on branch `v1.6` (8.1 to 8.10), not yet run on a real router. Roadmap entry: [Milestone 8](../ROADMAP.md#milestone-8-approve-from-the-router-v16).

## Why

Today every grant needs a root shell on the router:

```sh
ssh root@192.168.1.1
openwrt-mcp allow claude-code @operator 2h
```

Pairing a new client needs one more SSH step (`openwrt-mcp authorize-key`). For a router owner who does not use SSH,
that is where adoption stops. The agent also stalls: it gets a denial, prints an `allow` line, and waits for a human
who has to open a terminal, log in and paste it.

The goal of v1.6 is that a permission request **appears where the owner already looks** (LuCI), **one click**
answers it, and **the waiting call continues** without the agent retrying. Responsibility stays with the owner:
every grant is explicit, narrow by default, time-limited, audited and revocable.

## What changes for the owner

1. The agent calls a tool it has no grant for.
2. Within one LuCI poll, the request shows at the top of *Services → MCP Server* and on the *Status → Overview* page:

   ```
   ⚠ claude-code asks for: Apply UCI change (writes)
     scope   wireless.default_radio1.disabled
     args    set wireless.default_radio1.disabled=1
     waiting 41 s
     [ Allow for 1 hour ▾ ]  [ this exact scope ▾ ]  [ Deny ]
   ```

3. The owner clicks **Allow**. The held call continues and the agent gets its result. Nothing to copy, no SSH.

If nobody answers in time, the agent gets the usual `POLICY_DENIED` with the request id and where to approve it. The
request stays open for a while, and a retry after approval works.

## Trust model

**A LuCI administrator is already root.** LuCI's own pages (System → Startup, Scheduled Tasks, SSH keys, Software)
let its admin run anything. A grant button in LuCI gives no *human* more power than they had.

The rule "issuing grants stays on the command line" (ROADMAP, *Later*) protected against **agents**: nothing an agent
can reach may widen what an agent may do. v1.6 keeps that property, but enforces it with an explicit, tested deny
floor (8.1) instead of by having no write path. This is the only principle that changes, and it changes in the
README, `SECURITY.md` and the ROADMAP together.

### Paths an agent could use to approve itself (closed by 8.1)

| Path | Why it works today | Floor in 8.1 |
|---|---|---|
| `ubus_call openwrt-mcp.decide` | `ubus_call` runs `ubus` as root, which bypasses rpcd's session ACLs. Only the policy scope gates it, and `*` would match. | `ubus_call` never reaches the objects `openwrt-mcp`, `session`, `file`, `rpc-sys`, and never `uci` writes to `openwrt-mcp` or `rpcd`. No grant lifts this, `@all` included. |
| `exec openwrt-mcp allow …` | `exec` scope is argv[0]; `openwrt-mcp` is not in `shellEquivalentPrograms`. | `exec` refuses the binary and its rpcd plugin by basename and by path. |
| `uci_apply` on `rpcd` | `isPolicyFile` guards only `/etc/config/openwrt-mcp`. An agent with `@operator` could add an rpcd login and then approve itself through LuCI. | The guard (`uci_apply`, history `restore`, `pkg_config_resolve use_new`) also covers `/etc/config/rpcd`. |
| Social engineering | If the card showed agent-written text, the agent would write what the owner reads. | The request card shows only facts the daemon derived (tool title, risk badge, exact scope, redacted arguments), no agent text. |
| Request flooding | Many prompts train a reflex click ("MFA fatigue"). | Dedupe, at most 5 open requests per client and 50 in all, per-client rate limit, expiry. |

What the floor does **not** claim: a client that already holds `exec sh` (or `@all`) is root and can do anything,
including editing files the floor protects. That is stated in `SECURITY.md` today (`exec` is a root shell by design)
and stays true. The floor guarantees that **no grant short of a root shell** can be turned into a wider grant.

### The LuCI side

- Approvals go through an rpcd plugin with its own ACL (8.3), never a shared token. LuCI's JSON-RPC carries the
  session id in the request body, so a cross-site page cannot forge a call.
- Read and write are separate ACL groups. A LuCI user with read-only access sees requests but no buttons.
- The page never shows a secret. Arguments come from the same redaction as the audit log.
- `system_status mode=audit` (4.3) already flags LuCI reachable from WAN. While *Permit all* is active or requests
  are open, that finding is raised to `high`.

## Design

### Requests (8.2)

A denial today is a line in `audit.jsonl` with no id. v1.6 turns it into a **request** record:

| Field | Source |
|---|---|
| `id` | random, 8 hex characters |
| `client`, `tool` | the session and the call |
| `scope` | the exact scope the policy check failed on (`config.go`), not one the agent names |
| `args` | redacted, capped at 512 bytes, the same text the audit log holds |
| `args_hash` | SHA-256 of the canonical arguments |
| `created`, `expires` | now, now + `request_ttl` |
| `state` | `open` → `allowed` / `denied` / `expired` |

- **Dedupe**: an open request with the same client, tool and scope is reused; its `last_seen` is updated.
- **Caps**: 5 open per client, 50 in all. Over the cap, the call is denied as today with no new request.
- **Storage**: in daemon memory, mirrored to `/var/run/openwrt-mcp/requests.json` (0600, atomic rename) so the rpcd
  plugin can read it. RAM only: a reboot clears requests, which is the right outcome.
- **Decisions are claims**: the rpcd plugin marks a request decided under a lock; a second decision on the same id
  is refused ("already allowed"). This is the precedent from ha-mcp's double-consumption fix.
- **Audit**: `request` (created), `decide` (actor, decision, grant written) and `expire` events.

**Held calls.** With `option request_wait '60'` (seconds, 0 to 300, 0 = today's behaviour) a denied call does not
return at once. It waits, re-checking the policy once a second, until:

- a grant now covers it → the call runs normally, and its result notes `approved in LuCI after 23 s`;
- the request is denied → `POLICY_DENIED`, `denied by the operator`;
- the wait ends → `POLICY_DENIED` with the request id, where to approve, and the CLI line as fallback:

  ```
  denied: no policy grants uci_apply to "claude-code"
    approve: LuCI → Services → MCP Server (request 7f3a9c01, open 10 min), then call again
    or run:  openwrt-mcp allow claude-code uci_apply 'wireless.default_radio1.disabled' 60m
  [code: POLICY_DENIED]
  ```

The held call counts against the in-flight cap (`limits.go`), honours cancellation (5.7), and, when the client sent a
progress token, sends progress notifications so the client does not time out (5.8 lands in v1.7; until then the
default wait stays well under common client timeouts).

Re-checking the policy, instead of waiting for a "decision" message, keeps one source of truth: the grant in
`/etc/config/openwrt-mcp`. The daemon already re-reads it on mtime change, and the CLI `allow` releases a held call
the same way the LuCI button does.

**No agent text on the card.** A "reason" field would mean an extra argument on every tool schema, and it is the
one thing on the card the agent controls. v1.6 shows none: the owner sees what the call does, not what the agent
says about it. If a later version adds one, it is labelled "written by the agent", sanitised by the 1.2 rules and
capped at 200 characters.

### Grant breadth

The **Allow** button writes the narrowest grant by default: the tool, on the exact scope that failed. A select widens
it, from narrowest to widest:

1. this exact scope (default), e.g. `uci_apply` on `wireless.default_radio1.disabled`;
2. this tool on the scope's family, e.g. `wireless.*`;
3. this tool on every scope;
4. the `@operator` preset.

Durations: 15 min, **1 hour** (default), 8 hours, 1 day, 7 days. "Never" is available only on the *Permissions* tab,
not in the request card. Every grant is written with `appendPolicy` and `replaceExpired`, the same code as the CLI,
so the shell-equivalent check (3.7) applies: a request for `exec sh` shows the root-shell warning and needs a
second confirmation.

### rpcd plugin (8.3)

`/usr/libexec/rpcd/openwrt-mcp` is a two-line wrapper: `exec /usr/bin/openwrt-mcp rpcd "$@"`. The Go binary
implements the rpcd exec-plugin protocol (`list` prints the method signatures; `call <method>` reads JSON on stdin).
Logic stays in Go, shared with the CLI and tested there.

| Method | ACL | Does |
|---|---|---|
| `status` | read | what `status --json` returns today, plus requests, permit-all state and client list |
| `requests` | read | open and recently decided requests |
| `decide` `{id, decision, breadth, duration}` | write | claims the request; on `allow` writes the grant |
| `revoke` `{client, index \| all}` | write | removes grant blocks (narrows only) |
| `revoke_tools` `{client, tools}` | write | takes single tools out of the client's blocks, keeping each block's scopes and expiry (a preset writes one block for many abilities; the page's per-ability switch needs this). Narrows only |
| `grant_preset` `{client, preset, duration}` | write | `@readonly`, `@operator` |
| `permit_all` `{client, duration, confirm}` | write | see 8.6 |
| `end_permit_all` `{client}` | write | removes the `@all` blocks |
| `pair` `{client, pubkey, preset}` | write | optional, 8.7 |
| `settings` / `set_settings` | read / write | request wait and TTL, optional channels |

The ACL file splits into `luci-app-openwrt-mcp` (read) and `luci-app-openwrt-mcp-write`. The page drops `fs.exec`
of `status --json`, so the old exec ACL line goes.

Open question: whether rpcd passes the LuCI user name to an exec plugin. If it does, the audit actor is
`luci:<user>`; if not, it is `luci`.

### LuCI page (8.4)

*Services → MCP Server*, built with LuCI's own tabs and widgets, so it follows the active theme and dark mode.

**Always on top, above the tabs** (rendered only when there is something to show):

- **Requests**: one card per open request, newest first, with the countdown of a held call. Several requests from one
  client get an "Allow all N" button that uses the narrowest breadth for each.
- **Permit all active**: a red banner, "claude-code has full root access until 14:30 — [End now]".
- **Rollback pending**: today's `uci_apply` deadline, now as a countdown.

**Tabs:**

| Tab | Holds |
|---|---|
| Overview | daemon state and version, transports, clients (SSH keys from `authorized_keys`, HTTP tokens, last seen from the audit log) |
| Permissions | per client: preset buttons (Read-only, Operator), then tools in groups, then a red **Permit all** section last |
| Activity | the audit log with client, tool and outcome filters and a text search |
| Settings | request wait and TTL; optional channels, each with its harm notice; MFA state (read only: enrolment stays on the CLI) |
| Clients | pairing (8.7, hidden unless enabled) |

**Tool groups on *Permissions*.** Taken from ha-mcp's settings page: a group header with "*n*/*m* granted", rows with a
risk badge, and a note on why a row cannot be changed. Groups and badges come from the tool registry (`registry.go`
titles and annotations), so the page and the server cannot drift:

| Group | Tools | Badge |
|---|---|---|
| Diagnostics | `system_status`, `logread`, `network_clients`, `firewall_show`, `service_list`, `net_diag`, `wg_list_clients` | read |
| Configuration | `uci_get` (read), `uci_apply`, `uci_confirm`, `uci_rollback` | writes, rollback-armed |
| Packages | `pkg_query` (read), `pkg_config_diff` (read), `pkg_change`, `pkg_config_resolve` | writes |
| VPN | `wg_new_client`, `wg_remove_client` | writes, shows keys |
| System | `service_control`, `sysupgrade` | writes |
| Raw access | `exec`, `ubus_call` beyond the read list | **root shell** |

Each row shows the scopes granted and the expiry, with **Revoke**. Granting a single tool from this tab is allowed
(it is the owner acting, not answering an agent) and uses the same breadth and duration selects.

Enhancements over ha-mcp:

- requests sit **on the page the owner already has open**, and on Overview, not only on a settings tab;
- the held call continues by itself; ha-mcp makes the agent call again;
- the default grant is the narrowest one, with widening as a deliberate choice;
- *Permit all* exists but is time-capped and loud; ha-mcp has no such mode;
- no three-step enablement (ha-mcp #1990): requests are on as soon as v1.6 is installed, with `request_wait '0'` as
  the only switch.

### Overview widget (8.5)

`/www/luci-static/resources/view/status/include/15_openwrt-mcp.js`, using the same rpcd methods. LuCI hides an
include whose `render()` returns `null`, so the widget shows only when there are open requests, *Permit all* is
active or a rollback is pending. It is polled with the rest of Overview. Each request row has **Allow** (narrowest
breadth, 1 hour), **Deny** and **Open** (the full page). Precedent for buttons there: the Wi-Fi include's
*Disconnect*.

### Permit all (8.6)

- **What it grants**: every tool, every scope, including `exec` and `ubus_call '*'`. That is a root shell, and the
  page says so in those words.
- **What it does not lift**: the deny floor (8.1), the audit log, rollback on `uci_apply`, redaction, the rate
  limit. Second factors are set per grant and the `@all` block carries none, so permit all is **refused for a client
  that has one enrolled** (CLI and LuCI): grant that client its tools by hand with `mfa_tools`.
- **Duration**: 15 min, **1 hour** (default), 4 hours, 24 hours at most. There is no "never".
- **Confirmation**: a checkbox ("I understand this gives claude-code root access to this router") and typing the
  client name. The CLI equivalent needs `--shell-equivalent`.
- **Warning text**, shown before the checkbox:

  > Not recommended. For the next hour, the agent can do anything root can: change or break Wi-Fi, firewall and
  > network settings (and lock you out), read every password and key on the router, install or remove software, and
  > run any program. Mistakes are not always reversible: only `uci_apply` changes roll back. Prefer approving
  > requests one by one.

- **While active**: the red banner on the MCP page and on Overview, with **End now**; `system_status` lists it under
  *outstanding*; the audit log marks every call a permit-all grant authorised with `"via":"permit-all"`.
  The banner follows the *shape* of a grant (every gated tool on `*`), not a label, so a hand-written grant of the
  same shape shows it too, including one with no expiry (shown as "with no end").
- **Shape**: `@all` in `permitall.go` (not in the `presets` map, so `grant_preset` cannot reach it), so the CLI (`openwrt-mcp allow claude-code @all 1h --shell-equivalent`)
  and LuCI write identical blocks, and *End now* removes exactly those.

### Optional channels (off by default)

Each one is a switch on *Settings*. Next to each switch, and in the README, is a short notice saying why it is off
and how it can harm you.

| Channel | What it does | Why it is off by default |
|---|---|---|
| **Push hook** (8.8) | Each new request fires the ubus event `openwrt-mcp.request` and runs executables in `/etc/openwrt-mcp/hooks.d/` with the request as JSON on stdin (fields from the table above, already redacted). Users wire Telegram, ntfy or Home Assistant. | Request details (client, tool, scope, redacted arguments) leave the router for a third-party service. A hook runs as root: a broken or hostile hook script is a root process. Approving from a notification is not part of this; the notification links to LuCI. |
| **Pair from LuCI** (8.7) | *Clients* tab: paste the public key that `openwrt-mcp connect` prints, name the client, pick a starting preset (default Read-only). Writes the same forced-command line as `authorize-key`. | Anyone who can log in to LuCI can add a key that reaches the router over SSH. The key is limited to the MCP bridge, but its grants are whatever you give it. |
| **Approve in chat** (8.9) | Optional per-client list (`chat_approve_client`); empty means every client that negotiates elicitation. The held call is answered in the client's own prompt ("Allow uci_apply on wireless.default_radio1.disabled for 1 hour?"): exact scope only, 15 minutes, 1 hour or 8 hours, never a root-shell tool. | The client relays your answer. A client, an extension or an agent that auto-answers prompts would grant itself. Use it only with clients you trust to show the prompt to you. Never offered for *Permit all* or for root-shell tools. Shares the request record with per-call approval (6.1). |

## Build order and done-when

Each item ships with its policy scope, audit record and mutation tests for its security rule (Principle 2).

| Item | Done when |
|---|---|
| 8.1 Deny floor | A table test enumerates every write path and every floor entry, each refused under `@operator` and `@all`; removing any entry fails a mutation test. **Ships first; 8.3 and later depend on it.** |
| 8.2 Requests and held calls | Concurrent identical calls consume one decision exactly once; a hold ends on allow, deny, timeout and cancellation; caps and expiry hold under a race test; the in-flight cap counts held calls. |
| 8.3 rpcd plugin | `list` matches the ACL file (test); each method has a golden test; a call without the write ACL is refused by rpcd on a real router. |
| 8.4 LuCI page | Groups and badges are generated from the registry (test fails if a tool has no group); hardware run: request appears, Allow releases the held call. |
| 8.5 Overview widget | Hidden with nothing pending; shown within one poll of a request; buttons work. |
| 8.6 Permit all | `@all` refuses "never" and anything over 24 h; expiry removes it; the floor still refuses under it; banner present on both pages. |
| 8.7–8.9 Optional channels | Off after install; each switch audited; each harm notice present (test on the settings schema). |
| 8.10 Docs | (screenshots pending a hardware run) README "Approve from LuCI" section with screenshots; `SECURITY.md` trust boundary and floor; ROADMAP *Later* bullet and the old "grants stay on the CLI" sentence revised. |

## Files touched (expected)

- Go: `requests.go` (new), `rpcd.go` (new), `config.go` (denial with request id), `tools.go` (held call),
  `presets.go` (`@all`), `shellequiv.go` (binary and plugin), `rollback.go` and `tools_pkg.go` (guard covers `rpcd`),
  `registry.go` (ubus object floor, groups), `status.go` (requests and permit-all in the report).
- Router files: `files/usr/libexec/rpcd/openwrt-mcp`, `files/usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json`
  (read/write split), `files/www/luci-static/resources/view/openwrt-mcp/status.js` (rework),
  `files/www/luci-static/resources/view/status/include/15_openwrt-mcp.js` (new), `files/etc/config/openwrt-mcp`
  (new options, commented).
- Install: `install-router.sh`, `install-router_test.sh`, `files/lib/upgrade/keep.d/openwrt-mcp`, the uninstall list
  in `install.sh`. New files must appear in all four.

## Verification

- `go vet ./... && go test ./...`, the contract test (`goldenCalls`) for the changed denial text, and mutation runs on
  the floor table and request matching.
- `install-router_test.sh` covers the new files on install, upgrade and uninstall.
- On a real router:
  1. a client with no grant calls `uci_apply` (dry run); the request appears on the MCP page and on Overview;
  2. **Allow** releases the held call, which returns its normal result;
  3. **Deny**, a wait that runs out, and request expiry each give the documented result;
  4. *Permit all* for 15 min; expiry removes it and the banner goes;
  5. under `@operator` and under `@all`, `ubus_call openwrt-mcp.decide`, `exec openwrt-mcp` and `uci_apply` on
     `rpcd` are all refused;
  6. a LuCI user with only the read ACL sees requests but no buttons.

## Open questions

- Default `request_wait`: 60 s is below the tool timeouts of the clients we know, but some clients cut off sooner.
  Should `connect` write a matching client timeout?
- Does rpcd hand the LuCI user name to an exec plugin? It decides the audit actor.
- Should the request card offer "Allow and remember for this tool" (widen breadth 3) as a one-click option, or keep
  widening behind the select?
- Should the Overview widget be removable per user (LuCI lets users hide Overview sections), or always shown while
  *Permit all* is active?
