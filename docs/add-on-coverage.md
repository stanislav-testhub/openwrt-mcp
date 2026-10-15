# Design note: add-on coverage (v1.7 to v1.9)

Status: proposal. Roadmap entry: [Milestone 9](../ROADMAP.md#milestone-9-add-on-coverage-v17-to-v19).

## Why

The core tools cover what every OpenWrt router has: UCI, fw4, netifd, wireless, packages, logs. But most enthusiasts
install OpenWrt *for* its add-ons: an ad blocker, a second WAN, a VPN with policy routing, a NAS share, a captive portal
on a travel router. Those are also where their questions are:

| The owner asks | Today the agent has to | With an adapter |
|---|---|---|
| "Why is this site blocked?" | know which of four blockers runs, where its lists live, how to grep them | `service_list detail=adblock query=example.com` |
| "Is my failover working?" | parse `mwan3 status` free text | one table: interface, tracking, online/offline, policies |
| "Which ports did UPnP open, and for whom?" | find the lease file, decode it | leases with port, protocol, client, age |
| "Did my dynamic DNS update?" | read per-section run files and logs | registered IP vs WAN IP, last update, last error |
| "Why does my TV bypass the VPN?" | know pbr, mwan3, podkop and tailscale all use fwmarks | `net_diag action=path src=<mac> dest=<host>` |
| "Is the UPS on battery?" | know NUT's `upsc` | charge, runtime, status, last transfer |

1.5 shipped the framework and three adapters (tailscale, AdGuard Home, podkop). This note plans the rest: which
add-ons, in which order, what each adapter does beyond a status read, and how each one is verified on a real router.

## Principles applied

The roadmap's principles hold. How they bind this work:

1. **No new tools.** Everything below is a mode or parameter on `service_list`, `service_control`, `uci_apply`,
   `system_status` and `net_diag`. The catalog grows by two optional parameters, measured as in 3.11.
2. **Installed only.** An adapter appears only when the add-on's init script exists. A router with no add-ons sees
   no change, not even in tool descriptions: `service_list` names the adapters that apply *on this router*.
3. **Reads first.** Every adapter ships its status read before any verb. A verb ships only with its policy scope,
   audit record, verify-after-write and a mutation test (Principle 2).
4. **Configuration changes go through `uci_apply`.** An add-on that keeps its settings in UCI gets no write path of
   its own. The adapter contributes reference fields and dry-run warnings instead. Verbs exist only for what UCI
   cannot express: refresh a list, force an update, unban an address.
5. **Credentials never print.** Add-ons are full of them: DDNS passwords, VPN keys, tunnel tokens, RPC secrets, proxy
   links. Adapters print fixed fields extracted by name, never a config file or raw output (the rule from
   `adapters.go`), and declare the UCI options that hold secrets so `uci_get` masks them too.
6. **Third-party text is untrusted.** UPnP descriptions, captive-portal client names, proxy node names from a
   subscription and Samba user names are written by other devices or other people. They are clipped, sanitised and
   marked.
7. **An adapter never fails the call.** "Installed but disabled", "enabled but not running", "running but its
   lists failed to download" and "output not recognised" are all statuses, not errors.

## The adapter contract, version 2

Today an adapter is a service name, an untrusted-text label and a `read` function. Version 2 adds optional layers.
Each adapter implements only those that make sense for it, and the registry test checks every declared layer.

```go
type adapter struct {
	service   string
	untrusted string               // third-party text in the output, "" if none
	reads     []argv               // every command the adapter may run, declared for tests and capture
	read      func(ctx) string     // L1 status (exists)
	query     *adapterQuery        // L2 one bounded lookup: kind (domain|ip|mac|iface|name) and func
	verbs     []adapterVerb        // L3 typed operations: name, arg kind, risk class, argv, verify
	refs      []refField           // L4 UCI fields that name other sections (feeds 5.10 and 5.9)
	secrets   []string             // L4 UCI options that hold credentials (feeds redaction)
	warn      func(live, staged) []warning // L4 dry-run warnings specific to this add-on
	findings  func(ctx) []finding  // L5 health and security findings (feeds 4.2 and 4.3)
	minVer    string               // oldest add-on version the parser was checked against
}
```

| Layer | Surface | What it adds | Policy |
|---|---|---|---|
| L1 status | `service_list detail=<svc>` | version, running state, the add-on's own health, counts | read (exists) |
| L2 query | `service_list detail=<svc> query=<value>` | one lookup: is this domain blocked, is this IP banned, which policy matches this client | read; the value is validated by kind before any argv is built |
| L3 verbs | `service_control name=<svc> action=<verb> arg=<value>` | refresh lists, force an update, unban, pause | scope `<svc>.<verb>`, the grammar service actions already use |
| L4 config knowledge | `uci_apply` dry run, `uci_get refs=` and masking | reference fields, add-on warnings, secret options | none new |
| L5 findings | `system_status mode=doctor` / `mode=audit` | stale lists, failed updates, services exposed to WAN | read |

**Verbs carry a risk class.** `routine` verbs (refresh a list, force a DDNS update, rescan) join the `@operator`
preset. `disruptive` verbs (pause blocking, take a WAN member down, kick captive-portal clients) need an explicit grant
and are listed in the deny-floor review of 6.2. A verb never takes free text: its argument has a kind, and the kind's
validator runs before the argv is built.

**Version drift.** Add-ons change their output between releases. Each parser checks the shape it expects and, when
it does not match, reports `output not recognised (adblock 4.4.1; checked up to 4.3.x)` instead of guessing.
`minVer` and the highest checked version are printed in the README table.

**Files that are not UCI.** Some add-ons keep allowlists in plain files (`/etc/adblock/adblock.allowlist`,
`/etc/banip/banip.allowlist`). Editing those is 6.5 (managed files), as a typed kind with a validator. Until 6.5
ships, the adapter reads them (counts, and whether a given value is listed) but does not write them.

## Cross-add-on views

The hardest questions span several add-ons. These are modes on existing tools, built from what the adapters
already read.

- **DNS path** (`net_diag action=dns_path`). Who answers a client's DNS: dnsmasq, then its forwarders (AdGuard Home,
  https-dns-proxy, stubby, unbound, smartdns, nextdns, a proxy's DNS), with the blocker attached at each hop.
  With `query=<domain>` it follows one name: which hop answered, and whether a blocker rewrote it. Conflicts become
  findings: two blockers enabled, two daemons claiming port 53, dnsmasq forwarding to a resolver that is stopped.
- **Traffic path** (`net_diag action=path src=<mac|ip> dest=<host|ip>`). Which way one client's traffic to one
  destination goes: pbr policy, mwan3 policy, podkop or another proxy, tailscale exit node, WireGuard, plain WAN. It
  reads `ip rule`, the nft mark rules and each adapter's policy table; it does not send traffic.
- **Mark map** (part of the path view and a doctor finding). Which fwmark bits each add-on uses: mwan3, pbr,
  tailscale, podkop, sing-box based proxies. Overlapping masks are the most common reason two routing add-ons break
  each other silently, and nothing on the router reports it.
- **Exposure** (enriches the 4.3 security audit). What is reachable from WAN: fw4 redirects, UPnP leases, and add-on
  listeners bound to all addresses (ttyd, Samba, transmission RPC, the AdGuard Home UI, mosquitto, frps dashboards),
  each with whether it requires authentication.

## Which add-ons, and why

Selection uses four signals, in this order:

1. **Installs**, where any are measured (see *Evidence*).
2. **Activity.** Issues and pull requests in `openwrt/packages`, long forum support threads, recurring "why"
   questions; for community feeds, GitHub stars and forum threads in English, Chinese and Russian.
3. **Risk.** Add-ons that open ports or route traffic get priority, because the audit should see them.
4. **Verifiability.** It can run on the verification router (below), or a fixture can be captured honestly.

Package names below were checked against the 25.12 `aarch64_cortex-a53` index on 2026-10-15.

### Evidence

OpenWrt has no popcon and no runtime telemetry, and the download servers' logs are not published. A June 2026 RFC on
openwrt-devel proposes a public dashboard from server-side aggregates, per-package downloads included; until something
like it exists, these are the signals, snapshot 2026-10-15.

**Installs: the Attended Sysupgrade server.** For each image it builds, ASU counts the packages the request adds on top
of the target's and the device profile's defaults (`asu/build.py`). Requests from LuCI Attended Sysupgrade and `owut`
carry the router's installed package list, so this is the closest thing to an install count that exists. Limits: a
30-day window, at most the top 100 per query (`asu/routers/stats.py`), dependencies count too, and only routers that
upgrade through ASU are seen. On 25.12 and across all branches, the top 100 is all base packages and LuCI. Smaller
branches show deeper lists:

| Branch (largest count) | Add-ons and tools in the top 100 |
|---|---|
| 24.10 (4,805) | dnsmasq-full 846, nano 693, tcpdump 660, usbutils 637, htop 625, luci-app-ttyd 625, iperf3 582, openssh-sftp-server 556, luci-app-sqm 539, ip-full 531, wireguard-tools 451 |
| SNAPSHOT (5,345) | luci-app-statistics 1,220, htop 1,122, dnsmasq-full 1,118, tcpdump 944, iperf3 907, luci-app-sqm 872, luci-app-irqbalance 802 |
| 23.05 (1,112) | lldpd 210, luci-app-watchcat 202, luci-app-statistics 111, luci-app-ttyd 111, wireguard-tools 100, luci-app-lldpd 89, luci-app-sqm 89, iperf3 88, tcpdump 86, htop 83 |
| 22.03 (389) | wireguard-tools 44, dnsmasq-full 42, iperf3 42, irqbalance 31, ddns-scripts-noip 27, luci-i18n-upnp-zh-cn 25 |

No branch's top 100 contains adblock, adblock-fast, banIP, mwan3, pbr, https-dns-proxy, AdGuard Home or a VPN client.
Their place in the waves comes from activity, not installs. To refresh:
`curl 'https://sysupgrade.openwrt.org/api/v1/top-packages?branch=24.10&n=100'` (also on
[sysupgrade.openwrt.org/stats](https://sysupgrade.openwrt.org/stats)).

**Activity: issues and pull requests in `openwrt/packages`** whose title names the package. This counts version bumps
as well as bug reports, so it measures how much happens around a package, not how many people run it. sqm-scripts is
undercounted because its titles say "sqm". Packages kept in the main `openwrt/openwrt` repository (lldpd, usteer,
qosify) count low or zero here.

| Issues and PRs (title match) | Packages |
|---|---|
| 300 and more | adblock 602, ddns-scripts 530, mwan3 406, unbound 301 |
| 100 to 299 | https-dns-proxy 259, nextdns 252, strongswan 234, collectd 177, acme 176, openvpn 171, samba4 163, transmission 153, adblock-fast 148, travelmate 134, tailscale 132, adguardhome 129, tor 128, sing-box 116, pbr 112, miniupnpd 112, zerotier 111 |
| 50 to 99 | banip 99, netbird 99, xray-core 99, stubby 92, aria2 83, nut 82, keepalived 80, ksmbd 79, dawn 74, watchcat 64, mosquitto 56, frp 54, cloudflared 52, minidlna 50 |
| under 50 | sqm-scripts 45, ttyd 45, iperf3 44, usteer 33, v2raya 32, irqbalance 25, smartdns 23, wifischedule 23, nlbwmon 23, vnstat 20, hd-idle 9, opennds 2, qosify 0 |

**Community feeds: GitHub stars.** AdGuard Home 37.4k (also in the official feed), OpenClash 27.8k, zapret 16.3k,
v2rayA 15.7k, passwall 10.0k, nikki 5.4k, passwall2 3.7k, podkop 2.2k, youtubeUnblock 1.6k, zapret-openwrt 1.4k,
homeproxy 1.1k, adblock-lean 0.6k. Stars measure interest, not installs.

**What the evidence changed.**

- sqm-scripts and ttyd moved into wave 1: both are in the top 100 of three branches, and ttyd is a root shell that the
  exposure view must see.
- luci-app-statistics (collectd) became a wave 2 adapter, taking over roadmap 7.5.
- watchcat stays in wave 2; irqbalance becomes a wave 2 doctor finding; lldpd joins wave 3.
- iperf3 and tcpdump, in the top 100 of every branch with room for add-ons, became their own item (*Diagnostic
  tools*), because they are tools the agent runs, not services to report on.
- dnsmasq-full, near the top of 24.10 and SNAPSHOT, is what pbr, adblock-fast and podkop need for nftsets: a doctor
  finding flags an add-on that needs it when plain dnsmasq is installed.
- Wave 4 is ordered by stars.

### Wave 1 (v1.7): DNS, filtering and exposure

Ships with the 5b carry-overs: the six deferred adapters, banIP and UPnP for the security audit, and the two services
with the most measured installs (sqm-scripts, ttyd).

| Add-on | L1 status | L2 query | L3 verbs | L5 findings | Rig |
|---|---|---|---|---|---|
| adblock | version, backend, blocked domains, sources ok/failed, last run | domain: blocked by which list, allowlisted | `refresh` (routine), `suspend`/`resume` (disruptive) | lists not refreshed in 7 days, a source failed, backend mismatch | B |
| adblock-fast | same fields from its ubus service data | domain | `refresh`, `pause` | same, plus dnsmasq instance mismatch | B |
| banip | feeds active, element counts, last run, allow/block list sizes | ip: which feed or list matches | `refresh`, `unban ip` (via `banip` search and set delete) | feeds stale, WAN ifaces not detected, LAN range in a block feed | A |
| https-dns-proxy | instances, listen ports, provider host (no path, no token), dnsmasq wiring | — | — | dnsmasq not forwarding to it, bootstrap DNS unset | B |
| mwan3 | interfaces (online, tracking, track IPs ok), policies and their members, rules | ip or mac: which rule and policy match | `ifup`/`ifdown` member (disruptive) | member offline, all members of a policy down, track IP is the gateway | C |
| pbr | status, policies, interfaces, resolver mode, fw mask | src and dest: matching policy | `reload` | mark mask overlaps another add-on, policy names a missing interface | B |
| ddns | per section: domain, provider, registered IP, WAN IP, last update, last error | — | `update <section>` (routine) | registered IP differs from WAN IP, WAN is behind CGNAT (100.64/10), updates failing | A |
| upnp (miniupnpd) | enabled, external interface, secure mode, leases (port, proto, client, description) | — | `delete <lease>` (routine) | secure mode off, a lease for a host with no DHCP lease, UPnP behind CGNAT (cannot work) | A |
| sqm-scripts | per interface: qdisc, rates, script, live drops and backlog from `tc -s` | — | — | flow offloading enabled (bypasses shaping), rate above the WAN link | A |
| ttyd | interface, port, credential set (never the credential) | — | — | bound to WAN, no credential | A |

Cross views in this wave: **DNS path** and **exposure**.

### Wave 2 (v1.8): resolvers, QoS, VPN and remote access

| Add-on | L1 status | L2 / L3 | L5 findings | Rig |
|---|---|---|---|---|
| unbound | running, mode (with or without dnsmasq), cache stats via `unbound-control` when installed | query domain (cache or resolve) | dnssec failures, port clash with dnsmasq | B |
| stubby, smartdns, nextdns | upstreams (host only), listen port, running; nextdns profile masked | — | not in the DNS path | B |
| luci-app-statistics (collectd) | plugins enabled, data directory (RAM or disk), last write; `history=24h` reads RRD for load, temperature, traffic (was roadmap 7.5) | — | RRD in RAM only (lost on reboot), plugin enabled with no data | A |
| irqbalance | enabled, running, IRQ spread across CPUs | — | NIC IRQs all on one CPU under load | A |
| qosify | interfaces, classes, counters | — | sqm and qosify both on one interface | B |
| watchcat | mode per section, targets, last action | — | periodic reboot configured, ping target is the gateway | B |
| travelmate | uplink, station state, captive-portal state, last scan | `rescan` (routine) | no uplink, radio shared with an AP at a fixed channel | C |
| openvpn | instances, role, state from the status file when configured, last error | — | auth failures in log, client with `redirect-gateway` and no kill switch | A |
| zerotier | node id (public), networks: status, assigned IPs, route count | — | network not authorized, zone not in firewall | C |
| netbird | management connection, peers online, routes | — | not logged in, setup key in UCI (flag, never print) | C |
| strongswan | connections, SAs up/down, rekey times | — | proposals with weak ciphers | C |
| cloudflared | running, connector count, last error; token masked | — | token in world-readable file | C |
| frpc / frps | proxies and their state through the admin API on loopback | — | frps dashboard or token-less frps on WAN | C |

Cross view in this wave: **traffic path** with the **mark map** (pbr, mwan3, podkop, tailscale, WireGuard).

### Wave 3 (v1.9): Wi-Fi, clients and the home server

| Add-on | L1 status | L2 / L3 | L5 findings | Rig |
|---|---|---|---|---|
| usteer / dawn | nodes seen, clients and their steering state | query mac | both installed and enabled | C (needs a second AP for steering) |
| wifischedule | schedules per radio, next on/off | — | schedule disables the radio the management path uses | A |
| opennds | gateway state, clients authenticated/preauth (names untrusted) | `deauth <mac>` (disruptive) | portal on the LAN zone instead of a guest zone | B |
| nlbwmon | extends the existing `net_diag action=usage`: protocol split, query mac | query mac | database on RAM only (lost on reboot) | A |
| lldpd | neighbours per port: system name, port, VLANs, capabilities (names untrusted) | query port | lldpd sending on WAN | A |
| vnstat2 | per interface: today, month, top days | — | interface not tracked, database on RAM | A |
| samba4 / ksmbd | shares, guest access, interfaces bound, open sessions | — | guest-writable share, bound to WAN | A |
| transmission | running, RPC bind and whitelist, auth on, active torrents count | — | RPC without auth on all addresses | A |
| minidlna, aria2 | running, media dirs or RPC bind, secret masked | — | RPC without secret | A |
| hd-idle | disks and idle timers | — | disk listed that is not present | C (USB disk) |
| nut | UPS status (online, on battery), charge, runtime, last transfer | — | on battery, low runtime, driver not connected | C (UPS) |
| acme | certificates: domain, issuer, expiry, last renewal result | `renew <domain>` (routine) | expires in under 14 days, renewal failing | A |
| mosquitto | listeners, TLS, anonymous access, client count | — | anonymous on a non-loopback listener | A |
| keepalived | VRRP instances, state, priority | — | split brain (two masters seen in log) | C (second router) |
| tor | bootstrap progress, transparent proxy ports, bridges in use (masked) | — | SOCKS port on a non-loopback address | A |

### Wave 4 (best effort): proxy and censorship-circumvention stacks

The largest communities outside the official feeds, especially in Chinese and Russian. They ship from their own
feeds, change fast and hold the most credentials. Adapters here are status-only (L1, L4 secrets, L5), marked "best
effort" in the README, and dropped rather than kept broken when upstream changes.

In order of GitHub stars:

| Add-on | Feed | L1 status | Notes |
|---|---|---|---|
| OpenClash | community | running, core version, mode, selected node per group | Clash API on loopback |
| zapret | community | running, queue numbers, strategy name, nft rules present | DPI bypass; only presence and wiring |
| v2rayA | official | running, core, proxy mode, connected node name (untrusted) | local API on loopback |
| passwall, passwall2 | community | running, main node (name only), shunt rules count, DNS mode | node links never printed |
| nikki (mihomo) | community | running, mode, selected node per group (names untrusted), rule count | external controller on loopback, secret masked |
| podkop | community | shipped in 1.5 | — |
| youtubeUnblock | community | running, queue number, nft rules present | DPI bypass |
| homeproxy | community (ImmortalWrt) | running, routing mode, node count, DNS strategy | sing-box based, shares the mark map |

Every adapter in this wave also feeds the **mark map** and **DNS path**, because these stacks are the usual cause of
"two add-ons fighting".

### Diagnostic tools

iperf3 and tcpdump are in the measured top 100 of every branch that has room for add-ons. They are not services to
report on but tools the agent would run, so they become `net_diag` modes, offered only when the binary is installed:

- `action=throughput target=<host>`: iperf3 against a LAN host running a server, or the router as a short-lived server
  for a LAN client. Bounded duration (at most 10 s) and annotated open-world. Answers "is it the Wi-Fi or the WAN".
- `action=capture iface=<dev> filter=<expr>`: tcpdump, capped by time and packet count, summarised (top talkers,
  protocols, DNS names asked, TCP resets). The raw pcap never enters the transcript; an optional file on the router is
  for the operator. The filter is parsed against an allow-list of BPF primitives, never passed through as text.

Both need a grant (`net_diag.throughput`, `net_diag.capture`): capture reads other people's traffic.

## Scenario prompts

Adapters answer questions. Prompts (3.8) give the agent a safe path for the common setups, built only from existing
tools: check `pkg_query`, simulate `pkg_change`, stage with a `uci_apply` dry run, apply with rollback, verify with the
adapter, confirm.

- `block-ads`: pick a blocker that fits the router's RAM and the existing DNS path; warn if another blocker is on.
- `multi-wan`: mwan3 with tracking on each member, then a failover test the owner triggers.
- `vpn-policy-routing`: pbr or podkop for chosen clients or domains, with the mark map checked first.
- `expose-service-safely`: a port forward or a tunnel (cloudflared, frpc) instead of UPnP, with the exposure view
  before and after.
- `remote-access`: WireGuard (exists), Tailscale, ZeroTier or NetBird, compared for the owner's case.

## Verification

### The rig

The verification router is a GL.iNet GL-MT6000 (1 GB RAM, 8 GB eMMC, `aarch64_cortex-a53`) running 25.12. It has the
room to keep every wave 1 to 3 package installed at once. Running them all at once is another matter: several
compete for the same port, hook or fwmark, and the router is also somebody's home network. So each add-on gets a rig
class:

- **A, always on.** Passive or self-contained; safe to leave enabled (ddns, upnp, banip, nlbwmon, vnstat, sqm,
  samba, acme). Verified continuously.
- **B, test window.** Installed and left disabled; enabled one at a time in a scheduled window because it takes over
  DNS, routing or a radio (adblock vs adblock-fast vs AdGuard Home, pbr vs another policy router, every proxy stack).
  The window script stops the conflicting service, enables the add-on, runs the checks, and restores the previous
  state through `cbak` snapshots and `uci_apply` rollback.
- **C, extra hardware or an account.** A second WAN (mwan3), a second AP (usteer, dawn), a USB disk (hd-idle), a UPS
  (nut), a second router (keepalived), or a cloud account (zerotier, netbird, cloudflared). Until the hardware is
  there, these ship from fixtures and say "fixture-tested" in the README, not "verified".

Before each wave, a RAM and flash budget check (`system_status` before and after installing the wave) is recorded in
the PR. Every new listening service is checked by the exposure view itself, which is also its first test.

### What "verified" means for one adapter

1. **States from fixtures.** Fake-backed tests cover not installed, installed and disabled, enabled and running,
   enabled but crashed, running with a failed sub-part (a list that did not download, a tracking IP down), and
   unrecognised output. Each state is one fixture.
2. **Fixtures from the real commands.** Because an adapter declares `reads`, a capture helper (`make capture
   SVC=adblock ROUTER=...`) runs exactly those argv on a router and saves the outputs. Captures are scrubbed before
   commit: private addresses rewritten to `192.168.1.x`, host names and MACs replaced, secrets removed, and a test
   rejects fixtures that still contain an RFC 1918 address outside `192.168.1.0/24` or a known secret pattern.
   Captures from a real home network are never committed raw.
3. **Query and verbs.** Mutation tests for each validator (a domain that is really a flag, an IP with a shell
   character), each verb's scope, and the verify step (a verb that "succeeds" without changing state must fail).
4. **Real router.** The adapter runs on the rig in each state it can reach there, and the README table records the
   add-on version and "GL-MT6000, 25.12", as for the 1.5 adapters.
5. **24.10 and opkg.** CI's real-target job installs each wave's official-feed packages in the 24.10 and 25.12
   rootfs containers and runs detection, UCI parsing and the installed-but-not-running path. Daemons that need
   netifd or wireless are not started there.
6. **Budget.** The tool-description size (3.11) is measured before and after each wave. Adapters must not change it;
   only the two new parameters may.

## Build order and done-when

1. **Contract v2** (`adapters.go`): the struct above, the registry test that checks each declared layer, the
   `query` parameter on `service_list`, `arg` and adapter verbs on `service_control`, verbs in presets by risk class.
   Done when the three 1.5 adapters run on it unchanged and the catalog grows by at most the two parameters.
2. **Capture helper and the fixture scrubber**, with its rejecting test.
3. **Wave 1**, then the DNS path and exposure views.
4. **Wave 2**, then the traffic path and mark map.
5. **Wave 3**, then the scenario prompts.
6. **Wave 4**, best effort, any time after step 1. **Diagnostic tools** likewise; they need no adapter.
7. **Contributor guide**: "Adding an adapter" in `CONTRIBUTING.md`, with a template file, the checklist above, and
   the rule that an adapter PR includes a scrubbed capture.

Each wave is done when every adapter in it is either verified on the rig or marked fixture-tested with the reason,
the README add-on table is updated, and the wave's findings appear in `system_status mode=doctor`/`audit` on the
rig.

## Files touched (expected)

- `adapters.go` (contract v2, registry), `adapter_<svc>.go` and `adapter_<svc>_test.go` per add-on.
- `tools_system.go` (`service_list query`, `service_control` verbs), `presets.go` (verb risk classes).
- `refs.go`, `warnings.go`, `redact_output.go` (reference fields, warnings and secret options from adapters).
- `health.go`, `securityaudit.go` (adapter findings), `diag.go` / `tools_net.go` (DNS path, traffic path, mark map).
- `prompts.go` (scenario prompts), `testdata/addons/<svc>/` (fixtures), `Makefile` (capture), `realtarget_test.go`.
- `README.md` add-on table, `CONTRIBUTING.md`, `CHANGELOG.md`.

## Open questions

- Should verbs on files (adblock and banIP allowlists) wait for 6.5, or ship earlier as narrowly typed verbs (`allow
  <domain>`) with their own validator? Waiting keeps one file-write path; shipping early answers the most common
  ad-blocker request.
- Wave 4 adapters read credentials-heavy configs from feeds the project does not control. Is status-only enough, or
  should they stay out of the default build and be enabled with a build tag?
- How many adapters before `service_list`'s "available here" line needs paging? A router rarely has more than ten
  add-ons, but a rig with every wave installed will have forty.
- Can the rig's test windows run unattended (a scheduled window with automatic restore), or does each need the owner
  present because it interrupts DNS for the household?
