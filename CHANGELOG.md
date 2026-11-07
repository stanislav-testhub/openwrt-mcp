# Changelog

## Unreleased

Fixed
- **Grants from several approvals add up.** A call was refused unless one policy covered all its scopes, so a section
  grant and its option grants approved separately never let `uci_apply` through, while the page, which checks each
  request on its own, showed the request as already allowed and drew no card. A call now passes when every scope is
  covered by some live policy of the client for that tool.

Added
- **`option profile 'small'` and `option toolsets`** (ROADMAP 10.6, 10.7). `small` fills in `idle_exit 5`, `listen ''`, `memory_limit 16`, `audit_max_mb 1`, `history_keep 3` and `toolsets 'diag config'` for every option the config leaves unset; explicit options win, an unknown profile name is logged and ignored. `option toolsets` caps the catalogue of every client on the bridge, `call` and HTTP; a client's `--toolset` can only narrow it, `exec` is not listed under a cap, and the core tools stay. Measured with every tool granted: 24 tools and 27.8 KB of `tools/list` become 15 tools and 18.5 KB under `diag config`.
- `audit_max_mb`, when unset, is at most 1/32 of the filesystem holding the audit log (at least 1, at most 16), so a 16 MB flash no longer takes up to 32 MB of log. An explicit value is never clamped.
- The diagnostic bundle has a `fit` line (RAM, size of the audit log's filesystem, profile, toolset cap) and suggests the `small` profile under 256 MiB RAM; `install-router.sh` prints the same fit and the suggestion, and still refuses when the binary does not fit (now covered by `install-router_test.sh`).
- **`request_access`: ask for several grants at once.** A client that runs its calls one after another showed the owner one
  card at a time, each held until it was answered. `request_access wants=['uci_apply wireless.radio1.channel', 'pkg_change add.usteer']`
  opens every request first, without waiting (ungated, grants nothing, same caps and rate limit as a refused call), so LuCI shows
  them under one "Allow all N" row; the real calls then find their requests answered. The "Allow all" row now has a duration
  choice (15 minutes, 1 hour, 8 hours) instead of 15 minutes only. The catalogue grows by 636 bytes (budget raised, documented).
- LuCI: the Status › Overview widget offers the same duration choice (15 minutes, 1 hour, 8 hours) beside Allow, not 15 minutes only.
- `system_status` prints the daemon's resident and peak memory (ROADMAP 10.1); `footprint_test.go` fails when the stripped mipsle-softfloat binary (12.98 MB measured) or our start-up heap (2.56 MB measured, 10.2 lowers it) passes its budget.
- `bench/footprint.sh` measures VmRSS, VmHWM and RssAnon of an idle daemon, one bridge and the daemon after initialize, tools/list and system_status. Measured on the 25.12.6 x86 VM (stripped amd64 binary, 11.9 MB): daemon idle 13.0 MB resident (4.5 MB anonymous), bridge 12.7 MB (4.4 MB anonymous), daemon after the calls 17.9 MB (7.7 MB anonymous). There is no MIPS emulator on the build server, so mipsle itself is not measured.
- Start-up: the ~100 package-level regexps compile on first use (`lazyRegexp`), so every bridge and `call` starts without them. Our start-up heap fell from 2.56 MB to 55 KB (budget now 100 KB). On the 25.12.6 VM the anonymous memory of an idle daemon fell from 4.5 to 1.6 MB, of a bridge from 4.4 to 1.5 MB, and of the daemon after the calls from 7.7 to 6.0 MB. A pattern that fails to compile now panics at first use; `TestLazyRegexpsCompile` compiles them all.
- `option memory_limit '<MiB>'` sets the daemon's soft memory limit (8 to 4096; unset keeps today's behaviour). With 16 set, the 25.12.6 VM daemon peaked at 9.7 MB anonymous memory after system_status, pkg_query installed, firewall_show, logread 2000 lines and service_list (without the limit: 8.0 to 9.7 MB, so the limit does not bind there). VmHWM reads about 10 MB higher because it counts the mapped binary. `bench/footprint.sh` takes `MEMLIMIT=<MiB>` and runs those calls.
- `option listen ''` turns the HTTP listener off; the daemon then serves the stdio socket alone. `status`, `doctor` and the running check use the socket in that case, `pair` warns that the token has nothing to open, and the daemon refuses to start with both `listen` and `socket` empty. Tests cover the empty value and an MCP session over the socket alone.
- `option idle_exit '<minutes>'` (default 0, resident) makes the daemon stop itself through procd when unused, and the stdio bridge or `call` start it again. It stays up while a session is open, a `uci_apply` is armed, a request waits for the operator, the HTTP listener is on, or the last use is younger than the setting; each condition has its own test and a mutation run. `status` and `doctor` say "stopped (starts on demand)". Checked on the 25.12.6 VM with `idle_exit 1`: the daemon exited about 52 s after its last use, and a bridge started it again and had the first reply in 0.27 s (x86; MIPS not measured). A bridge that connects in the few milliseconds between the last check and the stop gets a closed connection and must retry.
- **One approval request per call, not one per scope.** When a client holds a tool but some scopes of a call are uncovered, the refusal and
  the request named only the first one, so a call with several (a `uci_apply` touching two configs) needed one request, one wait and one tap
  for each. It now names every scope no policy covers, in one request and one `allow` line. A new request also replaces the client's older open
  requests for the same tool whose scopes it covers, so the operator's page does not collect cards that expire unanswered.
- **Structured output for `uci_get`, `logread` and `exec`, masking-aware.** These tools can carry secrets, so their `structuredContent` is
  never built from the raw output: it is parsed from the text after sanitising, masking and bounding (`presentBody`), so it shows exactly what
  the text shows. `uci_get` returns `entries` (`key`, `value`) and `notes` (the revision line); `logread` returns `lines` (`time`, `level`,
  `text`); `exec` returns `lines`. The catalogue budget rises by 409 bytes (27,140) and `uci_get`'s own to 1,790; item objects are left loose.
  A test puts a Wi-Fi key through `uci_get` and checks it is absent from the data.
- **passwall and passwall2 run and carry traffic; a stack with rules but no process is flagged.** Started from the unpacked project packages on
  25.12.6 (`dns_shunt dnsmasq`, `chinadns-ng` absent; the node is chosen by the global option `node`, not `tcp_node`), each sent a LAN client's
  request through a socks node (`301`; `000` with the node stopped). passwall2 needs `coreutils-nohup` (25.12's BusyBox has no `nohup`); without
  it, its nft rules load, xray never starts and DNS is redirected to nothing. Every proxy stack's detail now says so when its rules are loaded and
  none of its processes runs.
- **homeproxy carries traffic; its detail no longer shows an old failure.** With sing-box 1.12.22 in place of the feed's 1.13, homeproxy 26.298 on
  25.12.6 started and a LAN client reached `1.1.1.1` through its socks node (`301` with the node up, `000` with it stopped). The log still held the
  earlier 1.13 failure and the detail printed it for a running service; a `started.` line after an error now clears it. Also learned: the 24.10
  feed has no `kmod-veth`, so a client namespace needs the 25.12 VM.
- **pbr warns when mwan3 is active too.** Checked with a real second uplink (a veth pair into a namespace acting as the upstream, 25.12.6): with
  mwan3 stopped, a pbr policy sent a LAN client out of wan2 and the request reached the upstream; with mwan3 running the same request timed out,
  because mwan3's fwmark rules (priority 2001, plus its blackhole/unreachable rules) are checked before pbr's (29997 and up). The pbr detail now
  says so, from `ip -4 rule show`. Also fixed: the reader skipped this check when pbr had no procd *running* instance (it never has one).
- **`usage` (nlbwmon) checked against a real database.** A LAN client downloaded 20 MB through the router; the per-client totals, the
  per-protocol view of `src=` (a `null` layer7 reads as `other`) and the period list parse as written. No code change; the real output is now a test.
- **frpc and frps show whether they are connected.** frpc reports `connection to the server` (an established TCP connection to its server port, or
  why it has none: the client keeps running and retrying while its server is down), frps reports `clients connected` on its bind port. Both read
  `/proc/net/tcp` and `tcp6`; checked on 25.12.6 with frp 0.66.0 client and server on one router, then with the server stopped.
- **Wave 4 finished on both releases.** passwall2 26.11.3 (unpacked like passwall: stock layout read, 2 nodes, 8 shunt rules) and v2rayA
  (official feeds: 2.2.7.3 on 24.10.8, a newer build on 25.12.6, running with the stock config) were added; the whole of wave 4 also ran on
  24.10.8 from the projects' ipk files: youtubeUnblock, nikki, zapret, OpenClash (needs `dnsmasq-full` in place of `dnsmasq`) and passwall
  and passwall2 unpacked. The adapters read the same layouts there. homeproxy 26.187 **starts** on 24.10.8 with the feed's sing-box 1.12.22,
  so the 25.12 failure is sing-box 1.13 against homeproxy's generated config, not homeproxy itself. Real traffic: on 25.12.6 nikki sent
  `1.1.1.1` through a shadowsocks server (sing-box on loopback, run as a uid nikki exempts, or its own output loops until `too many open
  files`): `curl` got `301` with the server up and nothing (`000`) with it stopped. OpenClash (mihomo core, fake-ip) and v2rayA
  (Xray, transparent mode, node imported through its API) carried the same kind of request on 25.12.6, each with the same server-up/server-down
  control. What a router owner must know, seen while doing it: the proxy server on the same box has to be exempt from the redirect (OpenClash:
  group 65534; v2rayA: socket mark 0x80, which needs root), and a running openNDS silently drops redirected LAN traffic. Not done: traffic
  through homeproxy, passwall and passwall2.
- **Fix: the v2rayA API address was always `not set`.** The wave 4 reader printed a config value only if it looked like a version string
  (no `:`), so `0.0.0.0:2017` never passed. Options named `address` now accept a host:port shape (letters, digits, `.`, `:`, `[`, `]`, `-`).
  Found by the first capture of a real v2rayA config. Note the stock value listens on all addresses.
- **Wave 4 run from the projects' own packages (25.12.6 VM, x86_64; unsigned, installed with `--allow-untrusted` on the isolated VM).**
  nikki 2026.10.10 with mihomo-meta 1.19.32, OpenClash 0.48.002 (mihomo copied in as its core), zapret v72.13 (nfqws) and youtubeUnblock 1.3.1
  ran with local profiles and stock configs; the adapters' guesses from source (process names, `inet nikki` and `inet zapret`, the chains in
  `inet fw4`, option names) all held, and the stock configs' secrets (nikki API secret and web password, OpenClash dashboard password,
  subscription URLs) stayed out of the detail. passwall 26.11.3 was unpacked only: its dependencies (chinadns-ng, tcping and others) are not
  in the official feed; only the config layout (`@global[0]`, nodes, shunt rules) was checked. Not covered: passwall2, v2rayA, real proxy
  traffic through any of them, the same stacks on 24.10.
- **homeproxy: the detail says why it stopped.** luci-app-homeproxy 26.298 (ImmortalWrt feed) does not start on 25.12.6: it writes inbound
  fields that sing-box 1.13.21 from the official feed removed (`legacy inbound fields ... removed in sing-box 1.13.0`), and the service stops
  at once. The only trace is `/var/run/homeproxy/homeproxy.log`, so the detail now prints its last `Error:` line and sing-box's last
  `FATAL` line (control characters dropped, marked untrusted). Capture `homeproxy-failing`.
- **youtubeUnblock on a real install.** 1.3.1 from the project's release (x86_64 apk) on 25.12.6: the chain `youtubeUnblock` is in `inet fw4` as
  the source said, the section is named `youtubeUnblock`, the queue counted packets. Without `kmod-nft-queue` the daemon exits at once
  (`mnl_cb_run: Operation not permitted`); the package does not pull that module in. Capture `youtubeunblock-running`.
- **NetBird next to mwan3 (found on the 24.10.8 VM).** The 0.59.13 client could not reach its management server: `connect: invalid argument`.
  strace showed every `connect` to port 443 returning EINVAL right after `SO_MARK 0x1bd00`; NetBird marks its own control-plane sockets with
  that value, and mwan3's rule `fwmark 0x3d00/0x3f00 blackhole` (its default mask) matches it. With the two mwan3 rules removed the daemon
  reached the server (a dummy setup key was refused, as it should be). The `netbird` detail now warns when a routing rule that discards
  packets (`blackhole`, `unreachable`, `prohibit`) matches 0x1bd00 (capture `netbird-mwan3`, two tests).
- **samba4 with a real login.** samba4 4.22.7 ran on the 25.12.6 VM (root grown to 3 GB; the old 98 MB root could not hold it) with one share
  that lists a user (`users`, `guest_ok 'no'`): a login with the right password listed the share, a wrong one got `NT_STATUS_LOGON_FAILURE`.
  The adapter reads the config only and says `login required, writable`; the generated `smb.conf` has `valid users` and `guest ok = no` for it
  (capture `samba4-login`). The user's name and hash stay out of the detail.
- **ZeroTier and NetBird with a real peer.** ZeroTier 1.16.2 on the 25.12.6 VM joined a private network served by a local controller (the
  `zerotier/zerotier` container, 1.14.2): `OK` with an address, then `ACCESS_DENIED` after the controller withdrew the authorization (the client
  keeps its old address; the adapter lists it as it is). The OpenWrt build has no controller of its own, so the controller ran in a container.
  NetBird status taken from a 0.82.0 client connected to a cloud account (`netbird-connected`); the parser reads the same text on every
  platform. The 0.59.13 client from the 24.10 feed could not start on the VM: `dial tcp ...:443: connect: invalid argument` (the cause was not
  found), so the OpenWrt package itself was not run connected.
- **travelmate reads its own state.** The adapter used to print only the config (enabled, captive check, uplink count). It now reads the runtime
  file travelmate writes and prints its status and version, the uplink in use (radio, SSID marked untrusted, interface), `last run`, a warning
  when the uplink's subnet equals the LAN's (travelmate itself complains about that) and one when the internet check fails (`net nok`). The
  file differs per release: 2.2.1 on 24.10 writes `/tmp/trm_runtime.json` and `travelmate_version`, 2.4.9 on 25.12 writes
  `/var/run/travelmate/travelmate.runtime.json` and `backend_ver`; both are read. Seen on both VMs with a real WPA2 association to a
  virtual (hwsim) access point and a DHCP lease (`travelmate-connected`, `travelmate-2512`). A stub `sta` section whose SSID equals the
  `uplink` is what makes travelmate act; without it the process runs and scans nothing.
- **usteer and DAWN with a peer, ZeroTier on a real network.** Two OpenWrt VMs on one network, each with a virtual `mac80211_hwsim` radio and
  its own access point (`owlab-roam`, 5 GHz): the 24.10.8 VM (usteer 2022.08, DAWN 2023.05) sees the 25.12.6 VM's node and AP as a remote
  host and tracks the client associated to it (`usteer-peer`, `dawn-peer` captures: one client, two APs, two hearing-map rows). The reverse direction showed no peer (the packets reach the 25.12.6 VM; why it ignores them was not looked into,
  the different versions are the likely cause), so both views come from the 24.10.8 host. Hwsim radios now start under hostapd: the cause earlier was
  `/etc/capabilities/wpad.json` (ujail), not the radio.
  - DAWN `network view` and `hearing map` counted SSIDs (the top-level keys), so two access points showed as "1 entry". They now read
    "network view: 2 access points on 1 SSID (1 local)" and "hearing map: N clients heard".
  - ZeroTier on a real 25.12.6 VM (1.16.2): a joined network the controller does not answer (`NOT_FOUND`, empty name, no address) is listed. The
    package's stock `earth` network (8056c2e21c000001) is no longer served, and this build has no local controller (`/controller` is 404),
    so an `OK` network with an address is still fixture-tested only.
- **Exposure, mark owners, structured status, wave 4 checked.**
  - `wan-exposure` now lists UPnP mappings next to the forwards and, for each reachable port, the process behind it (inode in `/proc/net`
    matched to `/proc/<pid>/fd`) and whether it asks for a login (dropbear, uhttpd, ttyd, smbd/ksmbd, transmission, aria2, mosquitto,
    miniupnpd, dnsmasq). The finding is high when a reachable listener accepts clients with no login.
  - `net_diag action=path` reads `nft -t list ruleset` and names the add-on behind each fwmark (mwan3, pbr, tailscale, podkop, wave 4
    tables): bits, written values, and warnings for a shared value, partly overlapping bits and a whole-mark write. Taken from a real
    mwan3 2.12.0 and pbr 1.2.2 ruleset (25.12.6 VM, `nft-marks`); mwan3's MARK value is hidden by iptables-nft, so only its mask shows.
    tailscale and podkop forms were read off a real GL-MT6000 ruleset and rewritten by hand for the tests: podkop's whole-mark write
    with `counter` after it, its `podkop_remark` chain inside fw4, an exact `meta mark 0x...` match and the OR form were not recognised
    before; a partial bit overlap is now reported only when the written values can collide.
  - `net_diag action=path` names the nftables rules that write a mark and can catch the given client: its address, the target and the incoming
    interface are evaluated against each rule, a rule in a chain reached by `jump` or `goto` takes its callers' verdict, and named sets are
    asked with `nft get element`. Ports, protocols and connection state are not evaluated; mwan3's marks stay hidden by iptables-nft.
  - `pkg_query action=installed|upgradable` returns `structuredContent` too (name, version, upgradable_from, total); the other actions stay text. Catalogue budget 26450 to 26720 for it. `firewall_show`, `uci_get`, `exec` and `logread` stay text: structured content bypasses the output masking, and nft rulesets and configs carry free text.
  - `net_diag action=usage src=<client IP or MAC>` breaks one client's nlbwmon totals down by layer7 protocol (share, RX, TX; the ten largest). Column names checked against nlbwmon's source; not run against a real nlbwmon database (the VM has no space for the package, and the router wrapper refuses `nlbw`).
  - Two more wave 2 doctor findings: `dns-resolver-bypassed` (stubby or smartdns enabled while dnsmasq forwards nothing to its port; skipped when unbound fronts the path, smartdns redirects port 53 itself or listens on 53) and `watchcat-short-reboot` (a `ping_reboot` rule with a period under 5 minutes).
  - `net_diag action=throughput` and `action=capture` were run for the first time against real iperf3 and tcpdump 4.99 (25.12.6 VM, through the stdio bridge). One bug: DNS replies were counted as "other" in the capture summary; now they count as DNS.
  - `net_diag action=dns_path` names the process behind a dnsmasq upstream no add-on claims (from /proc), which covers the DNS port of
    the wave 4 proxy stacks without a port table.
  - `system_status` (status mode) and `service_list` (listing) return `structuredContent` too; the text stays. The Tasks extension waits
    for go-sdk (v1.8.0 has none).
  - Wave 4 adapters compared with the projects' own default configs and init scripts: passwall2 reads `remote_dns_protocol` (it has no
    `dns_mode`), nikki reads its nft table. README add-on table lists the version checked for each.
  - youtubeUnblock was read from the `openwrt` branch of its repository: it has no nft table of its own (a chain `youtubeUnblock` in `inet fw4`), and its UCI
    section is `youtubeUnblock.youtubeUnblock` (`conf_strat`, `queue_num`, `packet_mark`) with one `section` per profile; the adapter now reads those. OpenClash's
    `dashboard_password` and `config_subscribe` were confirmed in its init script and LuCI model.

- **Last tails of waves 2 and 3.**
  - `system_status history=1h|6h|24h|7d` (ROADMAP 7.5): load, CPU, memory, temperatures and the five busiest interfaces from collectd's
    RRD files, as now, average and maximum, a trend of 6 to 8 slices and the volume an interface carried. Needs luci-app-statistics
    (it depends on `rrdtool`, which the adapter runs as `rrdtool fetch` on paths it listed itself); says what is missing when the data
    is not there, and when collectd has covered only part of the window. Own scope `history`. Checked on a 25.12.6 VM with collectd
    5.12 and rrdtool 1.0.50, but with only minutes of data: a full day was not seen.
  - `service_control name=ddns action=update`: removes `<rundir>/<section>.update` of each enabled service and restarts the updaters, because
    the updater skips a send while the address equals what DNS returns and the last send is younger than `force_interval`, and a restart alone
    does not change that (read from the 25.12.6 `dynamic_dns_updater.sh`; not run against a provider). Routine. pbr and miniupnpd get no verb:
    `reload`/`restart` already cover pbr.
  - `service_control name=miniupnpd action=unmap arg=tcp:PORT|udp:PORT`: removes one UPnP mapping by its external port. miniupnpd has no
    command line for it, so the verb drops the line from the lease file, restarts the daemon (which rebuilds its rules from that file) and reads
    the file back; a mapping that is still there is reported as a failure. Routine. A client that renews its mapping creates it again. Run on
    a 25.12.6 VM against miniupnpd 2.3.9 with a LAN client made with `upnpc`: the nft rule and the `upnpc -l` entry went, the other mapping stayed.
  - Peer and login states on the 25.12.6 VM (all against real packages, no outside accounts), three adapters changed by what they showed:
    - `openvpn` now reads the status file of each enabled instance (OpenVPN 2.7.8): connected clients with name, virtual address, traffic and
      start time (client names marked as untrusted, public addresses left out), or the tunnel counters on a client.
    - `frpc`, `frps` and the audit finding `frps-open` read the section `common`; the stock config of frp 0.66.0 has no `main`, so the adapters
      reported "server not set" and the finding fired on a server that had a token. Proxies are now listed (type, local and remote port).
    - `swanctl` (strongSwan 6.0.7): per IKE SA its state and age, per child SA its state and traffic, and a configured connection that has
      no SA now (from `swanctl --list-conns`). The tunnel was two charon daemons in network namespaces over a veth pair; over the VM's bridge
      IKE packets did not reach the responder, and why was not found.
    - Not done: the libvirt VM has no Tailscale, NetBird or ZeroTier account, samba4 does not fit the VM's 98 MB root and its adapter reads
      shares from the config only, and frp client to server was not connected (the adapters read config, not tunnels).
  - usteer and DAWN with a real radio: the host's RTL8852BE (rtw89) was passed through to the 24.10.8 VM (libvirt `hostdev`, returned to the
    host when the VM stops), hostapd ran one 5 GHz AP and a phone associated. Both adapters printed the real node, the client count and the
    hearing map without addresses; captured as `usteer-ap` and `dawn-ap`. Two things were not seen: a second AP or peer (the card allows one AP
    on one channel), and steering itself. On that VM hostapd under `ujail` never registered on ubus (the cause of the earlier hwsim failure
    on 25.12): removing `/etc/capabilities/wpad.json` fixed it. The 2.4 GHz AP was not visible to the phone at 5 dBm or at 17 dBm; 5 GHz was.
  - pbr checked with a second uplink on the 25.12.6 VM (eth2 as `wan2`): a route table and mark for it, a policy for one LAN client via `wan2`
    and `ip route get` with that mark left through eth2; the adapter lists all three gateways and `query` finds the policy. Captured as
    `pbr-two-uplinks`. Packet forwarding past the host NAT was not seen.
  - Audit finding `wan-exposure` (info): the listening ports reachable from the internet (sockets on every address from `/proc/net` crossed
    with WAN rules and the open-zone case), the port forwards and rules into the LAN, the ports bound to every address but held back by the
    firewall, and rules that accept a port nothing listens on. Silent when nothing is reachable. Custom nft rules and upstream NAT are not seen.
  - Doctor finding `irq-one-cpu` (info): on a multi-core router with at least 100,000 device interrupts, one CPU handles 90% or more of them
    and irqbalance is not running. Timers and IPIs are left out. The thresholds are a judgement, not measured on a router.
  - Adapters `usteer`, `dawn` and `opennds` (status only). usteer: active policies from the effective config, nodes, peers and a client count
    (never client addresses). DAWN: discovery mode, encryption, hostapd presence; warns when the shipped key is in use. openNDS: `ndsctl
    status`, FAS host without its path. `shared_key` and `faskey` joined the secret option names (audit log, output masking, capture scrubber).
    Run on a 25.12.6 VM: usteer and DAWN idle (the hwsim radios would not come up under hostapd, so no AP and no peer), openNDS with no clients.
    What usteer and DAWN print with clients uses field names from their documentation and has not been seen on a router.
- **Add-on verbs on `service_control` (ROADMAP 9.1, L3).** New parameter `arg`. Verbs: `adblock` refresh/suspend/resume, `adblock-fast`
  refresh/pause/resume, `banip` refresh and `unban <ip>`, `mwan3` ifup/ifdown `<interface>`. Scope `<service>.<verb>`. Routine verbs are in
  `@operator`; disruptive ones are left out of the preset (it now lists service_control scopes instead of `*`) and need a named grant.
  Arguments are validated by kind (IP, or an interface present in the mwan3 config) before any command runs. `unban` deletes the address
  from each active set holding it and fails if it is still there afterwards. Each detail ends with a `service_control verbs:` line.
- **Doctor findings for the wave 1 add-ons left over:** `adblock-broken` (adblock error or paused, adblock-fast error codes),
  `banip-no-wan`, `hdp-bypassed` (https-dns-proxy running while its dnsmasq management is off and no forwarder points at it) and
  `pbr-errors`. Only for installed, boot-enabled add-ons.
- **Wave 4, best effort (ROADMAP 9.6):** status-only adapters for `openclash`, `zapret`, `v2raya`, `passwall`, `passwall2`, `nikki`,
  `youtubeUnblock` and `homeproxy` (podkop shipped in 1.5). Running processes, whether the stack's nft table is loaded, a few
  fixed config flags and node or subscription counts. Node names, links, subscription URLs and secrets are never read into the
  output. Built from each project's documented layout and not run against the projects; to be dropped rather than patched
  if upstream changes.
- **Wave 3 adapters, second batch:** `wifischedule`, `vnstat`, `hd-idle`, `keepalived` (configured state only), `lldpd` (ports with a
  neighbour; neighbour names not printed) and `nlbwmon` (database path, RAM or flash). Doctor finding `stats-db-in-ram`.
- **Five more prompts (ROADMAP 3.8, 9.5):** `block-ads`, `multi-wan`, `vpn-policy-routing`, `expose-service-safely`, `remote-access`.
  Text only, read tools only, each ends in a proposal. Tests keep them inside the `@readonly` preset.
- **Wave 3 adapters, first batch (ROADMAP 9.5):** `samba4`, `ksmbd` (shares, guest access, writable), `transmission`, `aria2`,
  `minidlna`, `mosquitto` and `tor` (only known directives of their config files), `acme` (days left per certificate, from
  `openssl x509 -enddate` on a path built from a validated domain) and `nut-monitor` (four UPS fields via `upsc`).
  Passwords, RPC secrets and bridge lines are never printed. Findings: audit `smb-guest-writable`, `rpc-open`,
  `mosquitto-anonymous`; doctor `acme-expiring`.
- **Wave 2 adapters, second batch:** `strongswan` (as `ipsec`/`swanctl`: IKE and child SA counts), `cloudflared`, `frpc`, `frps`
  and `collectd` (luci-app-statistics: data directory, RAM or flash, enabled plugins). Tokens and passwords show only as "set".
  Audit finding `frps-open`: frps enabled with no token.
- **Wave 2 doctor findings:** `sqm-qosify-both` (two shapers on one interface), `unbound-port-clash` (unbound and dnsmasq both on port 53),
  `dns-two-blockers` (adblock, adblock-fast or simple-adblock enabled together). Only for installed add-ons.
- **Wave 2 resolvers (ROADMAP 9.4): `service_list detail=unbound|stubby|smartdns`.** Listen port, upstream hosts (never URLs or
  pinsets), DNSSEC mode, cache statistics when `unbound-control` answers, and whether dnsmasq forwards to the resolver.
  Fixture-tested, not yet run on hardware.
- **Wave 2 adapters from config and one fixed read:** `watchcat`, `openvpn`, `nextdns`, `qosify`, `travelmate`, `zerotier`
  (`zerotier-cli listnetworks`, network names not printed) and `netbird` (`netbird status`, five known fields only).
  Key files, auth files, profile ids and SSIDs are never printed. Fixture-tested.
- **`net_diag action=dns_path`.** Who answers DNS, hop by hop: dnsmasq, its forwarders matched to the add-on that owns
  each local port, and the enabled blockers. Warns on more than one blocker and on two daemons wanting port 53.
- **`net_diag action=path src=<client IP|MAC> target=<IPv4>`.** The client's neighbour entry, the kernel's unmarked route,
  the fwmark **mark map** from `ip rule` (warns when two masks share bits) and the pbr policies naming the client.
  It does not simulate which mark nftables would set. New parameter: `src`.
- **Add-on findings in `system_status mode=doctor` and `mode=audit` (ROADMAP 9.1, L5).** Only for installed add-ons.
  Audit: `ttyd-open` (a shell with no login: no credential and not `/bin/login`; high on every interface, medium on one),
  `upnp-insecure-mode`. Doctor: `sqm-offload`, `ddns-stale`, `ddns-cgnat`, `mwan3-iface-offline`, `mwan3-policy-down`.
  A check that cannot read its add-on (mwan3 not running) is listed under "not checked", not as a finding.

Fixed
- The ttyd status no longer calls a default luci-app-ttyd instance (`command /bin/login`) an open shell: login asks for the
  system password. It says "system login prompt".

Added
- **First run on a real OpenWrt (ROADMAP 9.7, 24.10.8 x86 VM; banip 1.5.6-r7, adblock-fast 1.2.4-r4, mwan3 2.11.16-r5, sqm-scripts 1.6.0, tcpdump 4.99.5, iperf3 3.22).**
  The adapters, verbs, doctor, audit, `capture` and `throughput` ran against the real packages (`go test -tags realtarget`,
  `realtarget_addons_test.go`). What it found and what changed:
  - banIP 1.5 writes its status to `/var/run/banip_runtime.json`, not the path the adapter assumed, and names its version `version`:
    the adapter, `query`, `unban` and the doctor read the real file first (the old path stays as a fallback).
  - A disabled banIP says "disabled" and no longer warns about missing WAN interfaces; `banip refresh` on a disabled banIP explains why it
    cannot run instead of "exit status 1".
  - adblock-fast that has never run has empty service data: it says so, not "output not recognised".
  - The doctor flagged `mwan3-policy-down` (high) on a stock mwan3 install, for a policy of a disabled second uplink that no rule uses. It
    now looks at policies a rule uses.
  - Confirmed as written: adblock-fast status and error codes, the mwan3 interface and policy status, the mwan3 ifup/ifdown verbs,
    adblock-fast refresh, sqm queue listing, tcpdump line parsing, iperf3 `-J` output in both directions.
  - `make capture` lost every command after the first (ssh read the manifest from stdin), put ssh warnings into captures and mangled JSON
    arguments; fixed. Scrubbed captures are under `testdata/captured/` and drive `captured_test.go`.
  - Second pass (adblock 4.4.2, pbr 1.2.2-r20, ddns-scripts 2.8.2, miniupnpd-nftables 2.3.9, https-dns-proxy 2026.05.06): all five adapters
    answer on the real packages. miniupnpd creates its lease file with the first mapping, so a quiet LAN said "lease file not readable"; it now
    says "none (no lease file yet)". https-dns-proxy keeps `listen_addr` in its global section, which the adapter now falls back to.
    pbr and https-dns-proxy captures are in `testdata/captured/`.
  - Third pass, banIP and adblock-fast really running (the VM got DNS by pointing https-dns-proxy at a resolver IP, since the host drops
    UDP DNS from the VM net). adblock-fast loaded 239,581 domains and banIP 1.5.6 ran with the doh and tor feeds. `query` and `unban` hit
    real data. One bug: adblock-fast writes `server=/name/#` for a name it lets through, and `query` reported it as blocked. It now counts only
    `server=/name/` with no upstream. `unban` of an address inside an interval range works (nft splits the range). `banip refresh` returns while
    banIP is still reloading, so the status read right after it can be the previous run's. Captures of both running states are in `testdata/captured/`.
  - Fourth pass, waves 2 and 3 from the official feed, installed in batches on the VM (stock config; the disk is small, so each batch was
    removed before the next): acme, aria2, collectd, hd-idle, keepalived, ksmbd, lldpd, minidlna, mosquitto, nlbwmon, qosify, stubby,
    swanctl, travelmate, vnstat, watchcat, wifischedule; openvpn, smartdns, tor, transmission, unbound, zerotier; frpc, frps, nextdns,
    tailscale (NeedsLogin), cloudflared, netbird. All answer with plausible, readable status; the one thing found: collectd without
    luci-app-statistics said "luci_statistics config unreadable", now it says the config is absent and collectd uses `/etc/collectd.conf`.
  - Fifth pass, **OpenWrt 25.12.6 (apk)** on the `openwrt-2512` VM (fixed to boot with the same OVMF pflash change as 2410): wave 1 and the
    wave 2/3 batch above installed with apk and run. banIP 1.9.1 and adblock-fast ran for real. What it found:
    - banIP 1.9 is enabled at boot, registers a procd instance and exits 1 with "banIP is disabled" until `ban_enabled` is set: the doctor
      reported `service-crashed` (medium) for it. It no longer does while `ban_enabled` is off.
    - banIP 1.9 keeps its version in `backend_ver` (`frontend_ver` is empty): the status line shows it.
    - adblock-fast on 25.12 ships all 16 list sources with `enabled=0`; a first start fails with `errorNothingToDo`. The adapter said
      "16 list sources configured"; it now says how many are enabled and that none means nothing to download.
    - Confirmed unchanged on apk: the banIP runtime path (`/var/run/banIP/banIP.runtime.json`), `query` and `unban`, mwan3, pbr, ddns,
      https-dns-proxy, UPnP, sqm and the 17 wave 2/3 adapters above; the audit and doctor read `apk` correctly (`apk-new`).
  - Sixth pass, 24.10.8 VM, **classic adblock 4.4.2-r4 after a real run** (adguard feed, 187,749 domains). It was wrong in two places:
    - The status read `/var/run/adblock/adblock.runtime.json`; adblock 4.4 writes `/var/run/adb_runtime.json` and keeps its version in
      `adblock_version`. On a real router `service_list detail=adblock` said "has not run since boot" even after a run, and the audit's
      `adblock-broken` check never saw the status. Both paths are read now.
    - `query` looked for the list at `/tmp/adb_list.overall` and expected `server=/name/` lines. The list is in dnsmasq's conf dir (named
      in the runtime file's `run_directories`) and holds `local=/name/` lines. Both are read now; a name is reported as blocked.
  - Seventh pass, 24.10.8 VM, the three tails from the earlier lists, each with a real state (captures in `testdata/captured/`):
    - **UPnP:** a real mapping made with `upnpc` (miniupnpc 2.2.8). miniupnpd refuses mappings while the WAN address is private
      ("Port forwarding is impossible"), so the VM got `external_ip` set to a public-looking address. The adapter lists it correctly; no change.
    - **ddns:** a real update (ddns-scripts 2.8.2, custom `update_url` to a receiver on the VM; `upd_privateip` is needed for a private
      address). The adapter showed the right state. Only a comment was wrong: `<section>.ip` holds the DNS answer for `lookup_host`
      (empty when it does not resolve), not what the provider was told; the adapter's wording and the stale check were already right.
    - **pbr:** a policy via `wan` built a real nft rule and mark chain. A policy via `wg0` (no gateway) made pbr report
      `errorPolicyUnknownInterface` with the policy name only in `info`, which the adapter does not print; the policy list now says
      "pbr has no gateway for this interface, so the policy is not applied" on the policy that names it.
  - GL-MT6000 (25.12.6, the live router; read-only through the MCP, the running build is older than this tree): `podkop` 0.7.22, `tailscale`
    1.104.1 (running, 2 peers offline), AdGuard Home and `ttyd` answered correctly; the doctor found `tor` down. The cause was not an adapter
    fault: `DataDirectory /srv/tor` and no `/srv` on the router.
  - Eighth pass, this tree deployed to the GL-MT6000 (25.12.6, read-only checks afterwards): samba4 (3 shares, login required), collectd,
    nlbwmon (database in RAM: the doctor's `stats-db-in-ram` finding is right), tor (TransPort/DNSPort on the TorNet bridge), transmission,
    lldpd and the audit's new checks answered on real data. One fault: `/etc/config/mwan3` outlived the package, so the doctor listed
    "not checked: mwan3 (... Not found)". A missing `mwan3` ubus object now means "not installed" and is skipped silently.
  Not verified: a pbr policy that routes a client's traffic out of a second uplink, the states that need a
    peer or a login (a tailscale peer that is online, netbird, zerotier, openvpn, strongSwan, frp, a Wi-Fi uplink for travelmate), samba4, nut, the wave 4 proxies (homeproxy, nikki, openclash, passwall, podkop, zapret, youtubeUnblock: not in the official
    feed; podkop is verified on the GL-MT6000), a login to samba4 or a client on transmission.
- **`query=<ip>` for pbr and mwan3 (ROADMAP 9.1 tail).** `service_list detail=pbr query=1.2.3.4` lists the policies whose `src_addr` or
  `dest_addr` hold the address (single addresses, CIDRs, `!` negation, space or comma lists) with their interface, protocol and ports;
  entries that are names, sets or MACs are counted as "not evaluated". `detail=mwan3 query=...` names the first rule whose `dest_ip` or
  `src_ip` holds it, the rule's policy and the policy's members now, and counts the rules that select by port only. It reads the uci rules,
  not the kernel's decision. Tested on the real pbr policies and the stock mwan3 rules from the VMs.
- **README add-on table** now says where each add-on was verified (GL-MT6000, 24.10.8 VM, 25.12.6 VM, stock config or a real state).
- **Structured output (ROADMAP 5.5), first two tools.** `network_clients` and `wg_list_clients` declare an `outputSchema` and return the
  same rows as `structuredContent` next to the unchanged text table (`content`). Clients get the data for the page the text shows; host
  names, SSIDs and peer names are sanitised as in the text. WireGuard rows carry the full public key (public data) and never a
  private or preshared key. An error result carries no structured content. A tool hands its data over with `setStructured`; any other
  tool is text only. The catalogue grows by 1,142 bytes (budget raised to 25,600). Not done: the schemas are sent to every client, not
  only to those that negotiated a version with them, and `system_status` and `service_list` are still text.
- **Progress for long operations (ROADMAP 5.8).** A client that sends a `progressToken` gets a `notifications/progress` every 5 s while
  `pkg_change` (commit=true), `sysupgrade` (test, check) and `net_diag` (traceroute, throughput, capture) run, saying how long the call
  has been going. None of these knows a percentage, so there is no total. No token, or any other call: nothing is sent, and the
  heartbeat ends with the call. The catalogue does not change. The Tasks extension is not built.
- **`net_diag action=throughput` and `action=capture` (ROADMAP 9.8).** `throughput` runs `iperf3 -c <target> -J` once up and once down
  (3 s each by default, 5 s at most) and reports Mbit/s and retransmits; a server error is shown as the line's result. `capture`
  runs `tcpdump` on one interface (it must exist in `/proc/net/dev`) with `-c 2000`, a 128-byte snap length and a deadline of at most
  10 s, and returns a summary: packet count, protocols, TCP resets, top senders by bytes, DNS names asked (untrusted text, as before).
  A raw packet never enters the transcript. The filter is checked word by word against `host net port portrange src dst tcp udp icmp
  icmp6 ip ip6 arp and or not` plus numbers, addresses and CIDR networks; parentheses, byte offsets, names and options are refused.
  A missing binary is reported by name. Neither action is in `@readonly` or `@operator` (those presets now list the other net_diag
  actions instead of `*`), so each needs a grant such as `capture.br-lan` or `throughput.*`. The catalogue grows by `filter` and the
  two actions (+196 bytes; budgets raised to 24,400, 13,130 and 1,900 for net_diag).
- **Fixture capture and scrubbing (ROADMAP 9.2).** `make capture SVC=banip ROUTER=root@...` runs the read-only commands listed in
  `testdata/capture/<svc>.cmds` on a router, pipes each output through `openwrt-mcp scrub` (built only with `-tags capture`, so the
  router binary does not grow) and saves it under `testdata/captured/<svc>/`. The scrubber rewrites addresses outside
  `192.168.1.0/24` to stable stand-ins (private to `192.168.1.100+`, public to `198.51.100.x`, IPv6 to `2001:db8::n`), MACs to
  `02:00:00:00:00:nn`, listed host names, WireGuard-shaped keys, bearer tokens and secret UCI options; it refuses to write a result that
  still fails the hygiene check. Two tests: manifests may name read-only commands only, and every checked-in file under `testdata/`
  holds no private address outside the lab subnet, no unlisted MAC and no key-shaped value. Known limit: a four-part version string
  such as `1.2.3.4` is taken for an address. No real capture exists yet; the existing adapter fixtures stay marked synthetic.
- **`service_list detail=NAME query=VALUE` (ROADMAP 9.1, query layer).** One bounded lookup per add-on, validated by kind before
  anything runs. adblock-fast: `query=<domain>` says whether the name (or a parent domain) is in the loaded block list and in
  which one, or whether `allowed_domain` exempts it. banIP: `query=<ip>` asks each active set of the address's family
  (`nft get element`) and names the sets that hold it. Neither prints list contents. The catalogue grows by this one parameter
  (+42 bytes, budget raised to 23,950). adblock (classic) answers `query=<domain>` too: it scans the merged list `/tmp/adb_list.overall` and the allowlist file; the path is from memory of the package, fixture-tested only.
- **Add-on status, wave 1 (ROADMAP 9.3, first part).** `service_list detail=NAME` now also reads adblock, adblock-fast, banIP,
  ddns, https-dns-proxy, miniupnpd, mwan3, pbr, sqm and ttyd when installed. Read-only, fixed fields only: ttyd's credential,
  ddns passwords and update URLs, https-dns-proxy resolver paths, pbr's policy addresses and adblock-fast's list URLs never
  print. Findings are lines of the detail for now (ttyd on every interface without a login, UPnP secure mode off, ddns record
  stale or behind CGNAT, sqm with flow offloading, a mwan3 policy with no member online, banIP with no WAN interface). No new
  tool or parameter; the catalogue size is unchanged. These adapters are **fixture-tested** from the add-ons' upstream sources,
  not yet verified on a router. Not in this step: the `query` and verb layers (9.1), DNS path and exposure views, doctor and
  audit findings, banIP and UPnP verbs.
- LuCI: when one assistant has two or more requests waiting, a row above the cards offers **Allow all N for 15 minutes** and
  **Deny all N**. Each request gets the same narrow grant its own button would write, and one Undo takes the whole answer back.
  A request for full control (a root shell) never joins; it keeps its own card and confirmation. This is the "Allow all N"
  button the design note (`docs/luci-approvals.md`) already described. Before, a batch of calls (for example `pkg_config_resolve`
  on nine files) meant nine separate taps.

Fixed
- Approve in chat: a declined prompt no longer denies the request for good. Some clients answer the prompt with *decline*
  without showing it, which left nothing to approve in LuCI and made the refusal look like a human decision. The call is still
  refused at once, but the request stays open, and the refusal names the request and where to approve it (LuCI or the CLI).
  Only a refusal made in LuCI or by the CLI is final.

## 1.6.0 -- Approve from the router

An agent that hits a missing grant no longer waits for someone to open a shell: the request shows in LuCI, one click
answers it, and the held call continues. Run end to end on a real OpenWrt 25.12.5 router (GL-MT6000, including the LuCI
phone layout) and on 24.10.8 (x86/64 VM): install, every tool,
approvals from LuCI (rendered in headless Chromium: Overview, Permissions, Activity, Settings, the Status widget, the
root-shell confirmation box), rpcd refusing a write call for a read-only login, and the widget appearing only while a
request is pending (see README, *Approve from LuCI*).

Added
- **Approval requests and held calls (ROADMAP 8.2).** A refused call records a request (client, tool, exact scope,
  redacted arguments, all derived by the daemon). With `request_wait` (default 300 s, 0 to 600; 0 refuses at once) the
  call is held and continues when a grant covers it. Requests are deduplicated, capped (5 per client, 50 in all), expire
  after `request_ttl` and live in RAM.
- **Deny floor (8.1).** Whatever the grant (`@operator` and `@all` included), an agent cannot widen its own access:
  `ubus_call` to `openwrt-mcp`, `session`, `file` and `rpc-sys`, `uci` writes to the `openwrt-mcp` and `rpcd` configs,
  and `exec` or writes on the daemon's binary, policy, rpcd plugin and ACL, LuCI page, init script, `etc/dropbear` and
  request state are refused.
- **LuCI page and rpcd plugin (8.3, 8.4).** *Services -> MCP Server*: Overview, Permissions (abilities in groups with
  a risk badge, Revoke, per-tool limits), Activity (audit log with filters), Settings. Reads need the read ACL, writes
  need `luci-app-openwrt-mcp-write`. Write methods include `decide`, `grant`, `revoke`, `revoke_tools` and `set_settings`.
- **Status -> Overview widget (8.5).** Shows pending requests and appears only while something is pending.
- **Permit all (8.6).** Grants a client every tool on every scope, root shell included: 24 h cap, typed client name,
  refused for a client with a second factor, red banner with End now, calls marked `"via":"permit-all"` in the audit
  log. CLI: `openwrt-mcp allow CLIENT @all 1h --shell-equivalent`.
- **Optional channels, off by default, each audited (8.7 to 8.9).**
  - `pairing`: a Clients tab that writes the same forced-command line as `authorize-key`.
  - `push_hook`: a new request fires the ubus event `openwrt-mcp.request` and runs the executables in
    `/etc/openwrt-mcp/hooks.d/` (10 s limit; group/world-writable and non-executable files are skipped).
  - `chat_approve` and `list chat_approve_client`: the request is also shown in the client's own prompt (MCP
    elicitation); exact scope, 15 m, 1 h or 8 h, never for a root-shell tool.
- `docs/luci-approvals.md`, README *Approve from LuCI* and SECURITY trust-boundary text.

Not included: "Allow once" (the shortest grant is 15 minutes), Pause/Resume, and a push web-address field; the server
has no support for them yet.

Fixed
- With stdin already at EOF, `openwrt-mcp` could swallow a refused command's message instead of reporting it.
- `openwrt-mcp allow` and `revoke` (including presets and `@all`) now write `grant` and `revoke` audit rows, as the LuCI path does.
- `allow` refuses a comma in a scope: scopes are separated by spaces, so `'wireless.*,network.*'` was stored as one pattern that matched nothing. The check runs before an expired grant is replaced.
- LuCI Permissions: a tool's custom limit takes several names separated by spaces, as the CLI does, so a tool with more than one limit can be edited and saved (the `grant` call accepts them; commas and quotes are still refused).
- LuCI Settings no longer jumps the scroll position when a switch is ticked.
- The package tools name only the package manager the router runs: titles read "Query packages (apk)" and "Review new package configs (.apk-new)" on 25.12, and "(opkg)" and "(-opkg)" on 24.10, and their descriptions no longer say "apk; opkg on 24.10". The generated skill file keeps the plain titles.
- LuCI Status › Overview: the widget no longer repeats the "MCP Server" title, and its Open MCP Server button text is centered.
- LuCI Activity: the service's own records (a connection opening, a request held, answered or expired) read as sentences instead of `asked to use "request"`, each row's Show raw button sits at the right edge of its cell, and each filter keeps its label with its field, with Search filling the rest of the row.
- LuCI: with one assistant there is no Assistant picker on Permissions and no Assistant filter on Activity, and its id is shown only when there are several. On a phone, Show raw sits on its own line in every Activity row, and the custom limit editor keeps each label with its field.
- LuCI: on a phone the tables' header row is hidden in every theme (a later rule used to show it as a stray box).
- LuCI Permissions: the custom limit field now shows, per tool, what a limit looks like (for example `network.lan wireless.*`) and that limits are separated by spaces.
- `allow` also refuses a placeholder scope (`<`, `>`, `{`, `}`), such as a copied `<service>.restart`.
- `mfa status` says when an enrolled client has no policy with `mfa_tools`, so nothing is gated; the README explains that only a config policy is gated.
- `uci_apply` no longer prints "Verified: 0 of N change(s) match" when every change is on a section addressed by position; it says "Not verified".
- **24.10 WireGuard.** `wg_new_client` and `wg_remove_client` returned `NOT_APPLIED` on stock 24.10: its netifd handler has no
  `renew` action (the call succeeds and does nothing) and `reload_config` does not touch peers, so the peer reached the
  interface only at the next `ifup`. Where the handler has no `renew` the interface is now brought up again with `ifup`,
  for the writer and for a rollback alike (25.12 keeps its in-place `renew`). On 24.10 this restarts the tunnel sessions
  of every peer for a moment. Run on a 24.10.8 VM: add, remove, confirm and rollback of both.
- `network_clients` on 24.10: BusyBox's `ip` has no `-j`, so the neighbour table was lost and the note carried BusyBox's
  whole usage text. It reads the plain `ip neigh show` then, and a failure is one line.
- `pkg_config_resolve use_new` on `/etc/config/NAME` kept the old copy as `NAME.pre-opkg-new` / `NAME.pre-apk-new` in
  `/etc/config`, where `reload_config` and `uci` treat it as a package and print "uci: Invalid argument" on every
  reload. It is now the hidden `.NAME.pre-opkg-new` (or `.pre-apk-new`).
- `install-router.sh` left `/etc/config/openwrt-mcp.default` when the installed config differed from the shipped one;
  `reload_config` printed "uci: Entry not found" for it on every change, into `uci_apply`, `wg_*` and `pkg_*` results.
  The shipped copy is now `/etc/openwrt-mcp/config.default`, and an older `.default` in `/etc/config` is removed.
- AdGuard Home adapter: the 24.10 package names the config file in `adguardhome.config.config` (`/etc/adguardhome.yaml`),
  not `config_file`; both options are read.
- A refusal to change the policy or rpcd config through `uci_apply`, `restore` or `pkg_config_resolve` carries
  `POLICY_DENIED`, not `FAILED`. `system_status` names the router's own new-config suffix, not `.apk-new` on opkg.
- Tests: three bridge and chat tests raced the removal of their temp directory (the session's closing audit record was
  written after the test returned) and failed about every other run; they now wait for it, and `install.sh`'s test gate
  no longer fails at random.

## 1.5.0 -- Reach and resilience

Reach routers the 25.12-only server could not, run it from a plain shell, let a client ask for less than its grants allow,
and survive the things a router does (reboots, restarts, dropped sessions). The one behaviour change to know about: adding
or removing a WireGuard peer is now a normal rollback-armed change (see Changed).

Added
- **opkg and 24.10 (ROADMAP 5.1).** The package tools use `opkg` when the router has no `apk` (`pkg_query`, `pkg_change`,
  `pkg_config_diff`, `pkg_config_resolve`, the doctor's new-defaults and kernel checks). `system_status` shows
  `packages: apk|opkg; firewall: fw4|fw3`.
  - New doctor finding `opkg-new-pending` (the apk one stays `apk-new-pending`); the audit skips the package check on opkg.
  - `firewall_show` on an fw3 router: `ruleset` and `rendered`; other views are refused with a reason.
  - CI: a `real-target` job runs the package and uci tools in the openwrt/rootfs 24.10 and 25.12 containers.
  - Catalogue budget raised from 23,500 to 23,650 bytes (prose 12,450 to 12,650) for the descriptions that now name both managers.
- **`openwrt-mcp call` and a skill file (ROADMAP 5.3).** `ssh ROUTER call TOOL '{json}'` runs one tool and prints its text:
  no MCP client needed. `call --list` names the tools of the session, `call TOOL --help` prints a tool's schema. It runs
  through the same server as an MCP session, so policy, audit, redaction and rollback are the existing path. A refusal goes
  to stderr with the `allow` line, exit status 1. `skills/openwrt-mcp/SKILL.md` is generated from the catalogue
  (`UPDATE_SKILL=1 go test -run TestSkillFileIsCurrent`).
- **Client-chosen tool profile (ROADMAP 5.4).** `--read-only` and `--toolset diag,config,pkg,wg` narrow one session: read-only
  is the `@readonly` preset intersected with the client's grants; a toolset lists only its tools (`system_status` is always
  there, `exec` is in none). It is enforced when a tool is called, not only in `tools/list`. `connect --read-only` and
  `connect --toolset` write the profile into the client entry (after `--`, because OpenSSH reads `--read-only` as its own option).
- **Entry grammar.** The words after the forced command (`SSH_ORIGINAL_COMMAND`) are parsed by the daemon against an
  allow-list: `--toolset`, `--read-only` and `call`, with a length cap and no control characters, never through a shell.
  Anything else is refused and audited. Existing `authorized_keys` lines keep working.
- **Deadlines and a workload cap (ROADMAP 5.7).** Each tool has a deadline above its own waits; at most 8 calls run at once,
  the rest queue for up to 30 s and then get a `busy` refusal (audited DENIED, code `TIMEOUT`). `uci_confirm`, `uci_rollback`
  and `mfa_unlock` never queue. A cancelled call kills the command it started and is audited as `cancelled by the client`; a
  deadline hit as `<tool> hit its <limit>`.
- **Session resilience (ROADMAP 5.6).**
  - The bridge waits up to 10 s for the daemon's socket (reboot, upgrade, crash) instead of failing on the first refused dial,
    and ends with `[code: TIMEOUT; next: ... wait a few seconds and retry]` when it gives up.
  - Audit: a `stdio session closed after <duration>: <reason>` line per stdio session and a `daemon started` line per start.
  - `status` (text and `--json` `last_disconnect`) shows the last disconnect and its reason; a session still open when the
    daemon started again is reported as cut by the restart.
- **Add-on status (ROADMAP 5.2).** `service_list` takes `detail=<service>`: a read-only status for installed add-ons
  (tailscale, AdGuard Home, podkop). The list ends with the names that apply on the router. Scope `<service>.detail`. Fixed
  fields only, no credentials. Catalogue budget raised from 22,100 to 22,300 bytes (prose 11,500 to 11,550): one parameter
  serves every adapter, instead of a tool per add-on. The other six adapters (adblock, adblock-fast, https-dns-proxy, mwan3,
  pbr, ddns) are in 1.6.
- **Cross-config references (ROADMAP 5.10).** `uci_get` takes `refs=<name>`: finds what defines an interface, zone, device,
  radio or mwan3 member/policy of that name and every reference field in network, firewall, dhcp, wireless, sqm and mwan3
  that uses it. `config` narrows the search (and is optional with `refs`). Scope `refs`. Catalogue budget raised from 23,650
  to 23,900 bytes (prose 12,650 to 12,875); `uci_get` gets a per-tool budget of 1,650 bytes.
- **Warnings in a dry run (ROADMAP 5.9).** `uci_apply` dry run lists `warnings from this change`: the audit's firewall, SSH,
  LuCI, UPnP and Wi-Fi checks run on the live and on the staged configuration, and only what the change adds is reported, with
  the audit's next steps and wiki pages. Two new findings: `ref-removed` / `ref-unknown` (a deleted, renamed or misspelled name
  that other sections still use, with a case-mismatch hint) and `radio-in-use` (the change turns off the Wi-Fi network this
  session is connected through). A real apply reads no warnings.
- **The management path follows the session.** The stdio and `call` bridges send the client address from `SSH_CLIENT`, the daemon
  resolves it with `ip route get`, and the interface it leaves by is treated like the LAN, so a session over a WireGuard tunnel
  is protected by the probe and `force` rules too. A WireGuard interface's `addresses`, `listen_port` and `private_key` are
  management options.

Changed
- **`wg_new_client` with `reveal=true` has its own scope**, `wireguard.<iface>.reveal` (`wireguard.reveal` without an
  interface), so a policy can allow the tool without ever putting the private key in the conversation. A grant for
  `wireguard.<iface>` alone no longer covers `reveal=true`; `wireguard.*`, `*` and the presets are unchanged.
- **`wg_new_client` and `wg_remove_client` no longer hot-add or hot-remove with `wg set`.** They save the peer in the network
  config through the standard rollback path (snapshot, armed rollback, reload, read-back) and need `uci_confirm` within 90 s;
  otherwise the change is reverted (a new client's key file is deleted too).
  - netifd loads the peer; if it has not after a short wait, the interface is asked to renew (`ubus call network.interface.X
    renew`), and a rollback does the same.
  - A commit that fails restores the snapshot and reverts the staged edit. One apply can be pending at a time
    (`ROLLBACK_PENDING`); staged `network` edits are refused (`CONFLICT`).
  - Removal refuses the peer the session arrives through unless `force=true`. A peer that only the running interface knows is
    still removed with `wg set` (no rollback possible).
- Busy and deadline refusals carry `TIMEOUT`, toolset and read-only refusals `POLICY_DENIED`.
- `wg_remove_client` deletes the removed peer's uncollected client config (it holds the private key) instead of leaving it
  for the 24 h sweep.
- A command the daemon refuses (`--toolset bogus`) now ends the bridge with `command refused: <reason>`, not
  `daemon closed the connection`, which read like a crash.

Tests
- The write-path table covers both `wg_*` tools. Every item was mutation-tested (80 to 90 mutants per item, survivors killed or
  explained as equivalent); `FuzzParseEntry` and the adapter parsers were fuzzed.

## 1.4.0 -- Diagnose

Answer "is it healthy, is it exposed, what is going on" in a few calls, and check that a change landed.
Nothing here adds a way to change the router: the new modes are read-only, and the existing write tools
now read back what they wrote.

Added
- **Verify after write (ROADMAP 4.9).** A write the router accepts and then does not keep is
  `NOT_APPLIED`, a new error code, instead of a success the caller has no reason to doubt. Each
  write path reads back what it changed:
  - **`uci_apply`:** after the commit and before any service is reloaded, each config is re-read
    with `uci show` and every change is compared with what the batch must have left. The last
    write to a key wins; a `set` to the empty string means unset; `add_list`, `del_list` and
    `set_list` are checked against the list (order included); `create` against the section type;
    `delete` against absence. A difference returns `NOT_APPLIED` with the keys, reloads nothing and
    leaves the rollback armed; the message names `uci_rollback` and says not to confirm. A
    success says `Verified: re-read dhcp after commit, 3 of 3 change(s) match.`
  - Sections addressed by position (`@rule[3]`) or by a generated name (`cfg0a1b2c`) are not
    compared, because an earlier add or delete in the same batch moves them. The result counts
    them. The value of a secret option (`key`, `private_key`, `psk`, `password`, ...) is never
    printed in a mismatch.
  - **`wg_new_client`:** after the commit the peer is looked up by its public key, with its name
    and address, before anything touches the running interface. After `wg set` it must be on the
    interface. A failed hot-add stays the note it was (the interface may simply be down); a
    `wg set` that exits 0 and leaves no peer is `NOT_APPLIED`, and the client's config file is
    kept for `openwrt-mcp wg-show`.
  - **`wg_remove_client`:** the peer must be gone from `wg show` before the config is deleted
    (otherwise a live peer would be listed nowhere), and the section must be gone after the commit.
  - **`pkg_change`:** after an `add` or `del` with `commit=true`, `/etc/apk/world` must list the
    package, or no longer list it. Version constraints and repository tags in the file are
    ignored; `upgrade` is not checked because it changes versions, not what was asked for.
  - A read-back that cannot run is not a failed write: the result says `Not verified:` and why.
  - `TestEveryWritePathVerifiesAfterWrite` lists every tool that is not read-only. Each one runs
    against a backend that accepts the write and keeps none of it and must answer
    `NOT_APPLIED`, or is exempt with a written reason (`uci_confirm`, `uci_rollback`,
    `pkg_config_resolve`, `sysupgrade`, `exec`, `ubus_call`, `mfa_unlock`). A tool added later
    fails the test until it is in one list.
- **`net_diag` wifi_survey, traffic and usage; airtime in `network_clients` (ROADMAP 4.4, 4.5).**
  All read-only, so the existing `net_diag` grants cover them without widening.
  - **`wifi_survey[.<device>]`:** per radio, busy, rx and tx airtime and noise for the channels the
    radio has stayed on for at least 10 s, from `iwinfo survey`. The driver only keeps real figures
    for the channel it is on (every other channel holds the milliseconds of a boot-time scan), so
    the result says the rest are not measured and **does not recommend a channel**: that needs an
    active scan, which moves the radio off its channel and is not read-only. The noise byte is a
    signed dBm value read as unsigned (170 is -86 dBm). One survey per radio, however many SSIDs
    share it.
  - **`traffic[.<interface>]`:** `/proc/net/dev` sampled twice (`count` seconds, default 3, max 10),
    rates per interface (loopback and idle interfaces left out, a counter that went backwards
    counts as no traffic), and the top five sources in the conntrack table. Sources are ranked by
    bytes when the kernel counts them (`nf_conntrack_acct`), otherwise by connections, and it
    says which. The source is the original direction's, so through NAT it is the LAN client.
  - **`usage[.<YYYY-MM-DD>]`:** nlbwmon's totals per device (summed over its addresses), the 25
    largest, with the accounting periods it has. nlbwmon keeps a period per month by default, so
    this is "this month", not "today" or "this week". Without nlbwmon the error names the package
    and `pkg_change` as the way to install it.
  - **`network_clients`:** an `AIR` column, each Wi-Fi client's share of its radio's airtime
    (receive plus transmit, from `hostapd`). A dash when hostapd does not report it. Retries are
    not here: neither `iwinfo` nor `hostapd` exposes them.
  - **Not in this release:** the active neighbour scan and the channel recommendation that would
    need it, and Wake-on-LAN. Both change what the radio or the LAN does, so as `net_diag` actions
    they would silently reach every stored `net_diag '*'` grant.
  - `net_diag` and its untrusted-text label now also cover host names (leases).
  - Tool catalogue: 23,254 bytes; `net_diag` may be 1,700 bytes (was 1,500); the budgets move to
    23,300 and 12,300.
- **`system_status mode=doctor` and `mode=audit` (ROADMAP 4.2, 4.3).** Two ranked lists of
  findings, severity first (`high`, `medium`, `low`, `info`), advisory only: nothing is changed.
  Each finding has a stable id, a message, the evidence, a next read-only call and an OpenWrt
  wiki link (every link was opened and read for content before it went in; the wiki answers 200
  for pages that do not exist). Each list ends with what was checked, what could not be
  (`not checked: radios (ubus ...)`), and where a check sees only part of the picture.
  - **Doctor:** `radio-down`, `iface-no-address`, `iface-error`, `service-crashed`,
    `conntrack-high` (80%, high at 95%), `overlay-full` and `tmp-full` (10% free, high at 5%),
    `apk-new-pending`, `ntp-unsynced`, `clock-unset`, `reboot-needed`.
    - A service counts as crashed only when procd has it with instances, none running and a
      non-zero exit code. `rc list` alone cannot tell a stopped daemon from a one-shot init
      script that ran and exited. On the router this was developed against, `rc list` shows 24
      of 45 enabled scripts as stopped: mostly one-shots, and one (AdGuard Home) that procd
      shows running. A daemon that is enabled but was never started has no procd instance and
      is not reported; the result says so on its `limits:` line.
    - NTP is asked of chrony (`chronyc -c tracking`) when it is installed. Otherwise only
      "was the clock ever set" is checked, and the limits line says so.
  - **Audit:** `wan-zone-input-accept`, `wan-zone-forward-accept`, `wan-port-open`,
    `wan-forward-open`, `wan-redirect`, `ssh-wan`, `luci-wan`, `ssh-password-auth`,
    `luci-all-addresses`, `upnp-on`, `wps-on`, `ssid-open`, `ssid-wep`, `ssid-weak-cipher`,
    `ssid-wpa1`, `root-no-password`, `apk-audit-modified`, `wg-stale-peer`.
    - The internet-facing zones are the ones named `wan*` and the ones holding an interface
      with a default route. The stock DHCP, ICMP and IGMP rules are not reported. An
      explicit SSH or web-interface port is reported as `ssh-wan` or `luci-wan` only when the
      service listens on every address.
    - The root password is checked by reading whether its field in `/etc/shadow` is empty.
      The hash is never stored or shown, and an error never carries file contents.
    - `apk audit` changes under `etc/`, `tmp/`, `var/`, `overlay/`, `root/` and `mnt/` are
      configuration, not tampering, and are ignored; a changed or removed file elsewhere is
      reported.
  - **Not in this release:** the upstream-DNS check (it needs an active probe, which would
    make `system_status` leave the router) and a "reboot needed after a kmod update" beyond the
    kernel version.
  - **Scopes.** `doctor` and `audit` are scopes of `system_status`. A `*` grant, which is what
    both presets give, covers them; a grant for one of them does not cover the other, and the
    denial prints the exact `allow` line. Plain `system_status` is unchanged.
  - **Untrusted text.** `system_status` now carries the untrusted-text label and says so in its
    description, because audit findings quote SSIDs. They are quoted, cut to 32 bytes and kept
    to one line.
  - Tests: a healthy router that raises nothing, one fixture per finding that triggers it and
    one per boundary that must not (one below, at and one above each threshold), the
    not-checked path, ranking, a test that every next step names a real tool and every link is
    in the verified list, the read-only command oracle over everything the two modes run, and
    27 mutation rows.
  - Tool catalogue: 22,967 bytes; the budget moves to 23,000 and the prose budget to 12,050.
- **`logread mode=summary` and baselines (ROADMAP 4.1).** After a change the useful question is
  "what is new in the log", not "show me 500 lines".
  - `mode=summary` collapses the filtered log to its distinct messages, grouped by process
    (worst severity first, then busiest). Each row has the severity, a count, the first and last
    time and the message with MACs, IPv4/IPv6 addresses, clock times, hex ids, durations and
    numbers replaced by `<mac>`, `<ip>`, `<time>`, `<hex>`, `<dur>` and `<n>`. A duration is
    digits and a unit that stand alone (`90s`, `12h`, `8d7h34m`): an uptime in a periodic message
    would otherwise make every occurrence a new message in a baseline diff, which the first
    check on a router showed. A number that is part of a name
    (`phy0-ap1`, `eth1`) is kept, so two radios are never merged. `lines` limits the messages
    and `offset` pages through them.
  - `baseline=save` returns an 8-hex-digit token for the messages in the log now.
    `baseline=<token>` returns only the messages that were not there (in either mode, with the
    same filters), headed `since baseline <token>: N of M distinct messages are new`.
  - A baseline is a set of 64-bit fingerprints, no log text, in the daemon's memory. At most 8
    are kept, least recently used first. A daemon restart, the Monday reboot included, drops
    them; an unknown token is `NOT_FOUND` and says to save a new one. Nothing is written to disk.
  - Tests: a synthetic sample log (`testdata/logread_sample.txt`, documentation addresses
    only), a table of normaliser cases, a fuzz test (idempotent, bounded growth, valid UTF-8
    stays valid), and the baseline rules (new-only, numbers do not make a message new, least
    recently used eviction, no log text held).
  - Tool catalogue: 22,707 bytes; the budget moves to 22,750 and the prose budget to 11,850.

Changed
- **Three prompts use the new modes (ROADMAP 3.8 follow-up).** `router-health` starts from
  `system_status mode=doctor` and `logread mode=summary`; `secure-my-router` from
  `system_status mode=audit` and confirms each lead with the call it names; `wifi-doctor` from
  `net_diag wifi_survey` and the `AIR` column. A new test checks that every `tool with mode=x` or
  `action=x` in a recipe is a value that tool's schema documents. All of it stays inside `@readonly`.
- **`service_control` fails when the final state contradicts the action.** It was a trailing
  `Note:` on a success; it is now `NOT_APPLIED` for `stop` that leaves the service running and
  for `enable` or `disable` that leave the flag unchanged. For `start`, `restart` and `reload`
  it is an error only when procd has an instance of the service and none is running, because a
  one-shot init script (the firewall, say) always reports "stopped" and must not fail; there it
  stays a note. A caller that tested `err == nil` after a `stop` now sees the failure.
- **Every error result ends with a code (ROADMAP 4.8).**
  - The last line is `[code: X]`, with X one of `POLICY_DENIED`, `MFA_REQUIRED`,
    `ROLLBACK_PENDING`, `VALIDATION`, `NOT_FOUND`, `CONFLICT`, `NOT_APPLIED`, `TIMEOUT` or
    `FAILED` (anything else). A client can branch on it without parsing prose. `TIMEOUT` adds `next: retry once,
    then narrow the request`.
  - The message above it is unchanged, so the denial text still prints the exact `allow` line,
    and `CONFLICT:` still starts its message. The audit log's outcome is unchanged.
  - A code survives wrapping (`%w`) and `errors.Join`. A lockout after bad TOTP codes reports
    `POLICY_DENIED`.
  - Not covered: arguments the MCP SDK rejects before a tool runs (wrong type, missing
    required field) come back as the SDK words them.
- **One shape for "this result was cut" (ROADMAP 4.7).**
  - Whenever a result is cut, its last line is `[truncated: <what>; <how to get the rest>]`
    (for an error result, the line before `[code: X]`). It replaces three different notices:
    the byte cap's `[TRUNCATED: ...]`, the ubus pruner's `[pruned: ...]` and `logread`'s leading
    `[N matching lines, showing the last M]`.
  - A line cut to 1024 bytes keeps its inline `...[+N bytes]` and now also adds
    `[truncated: N line(s) cut at 1024 bytes; ...]` at the end.
  - `TestNoToolCutsAResultWithoutTheNotice` runs every golden call against a backend that
    answers with 300 KB of long lines and fails on a cut result without the notice.
- **Paging on the three tools whose results grow.** `logread`, `network_clients` and
  `pkg_query` take `offset`, and a cut result names the next value:
  `[truncated: 20 older matching lines omitted; call again with offset=10]`.
  - `logread` counts back from the newest line, so `offset` skips the newest N matching lines.
  - `network_clients` returns 100 rows a page and `pkg_query` 200 lines. The totals
    (`N client(s)`, `(N packages)`) stay on every page.
  - Tool catalogue: 22,444 bytes (was 22,086); the budget moves to 22,500 and the prose budget
    to 11,700 for the three `offset` fields. No tool was added.

## 1.3.0 -- Easy to adopt

Install from a release, set a client up with one command, a smaller and portable tool catalogue, and
no credentials in the conversation. Nothing here adds a way to change the router.

Changed
- **Tool titles and hints (ROADMAP 3.4).**
  - Every tool now has a display `title`, set both at the top level and in `annotations.title`
    for older clients.
  - Every tool states `openWorldHint` explicitly; the spec default is `true`, so every tool
    used to claim it. It is `true` for the seven tools that can reach past the router:
    - `net_diag`;
    - `uci_apply`, whose probes ping and resolve;
    - `pkg_query`, whose `refresh` runs `apk update`;
    - `pkg_change`;
    - `sysupgrade`, whose `check` runs `owut`;
    - `ubus_call`;
    - `exec`.
  - `wg_remove_client` is now marked idempotent: removing the same peer again changes nothing.
  - A contract test pins the title and the four hints of every tool.
- **Expired grants no longer pile up.**
  - `allow` replaces the client's expired grant with the same tools and scopes instead of
    adding another block, so a daily `allow claude-code @operator 2h` keeps four blocks, not
    four more each day.
  - `status` folds expired grants into one count line; `status --all` lists them. `--json` is
    unchanged and still carries every grant with its `expired` flag.
  - Expired grants were already ignored when authorising, so this is cleanup, not security.
- **MCP Go SDK 1.6.1 to 1.8.0 (ROADMAP 3.10).**
  - It still negotiates `2026-07-28` at most; nothing here narrows the protocol versions.
  - `tools/list` differs from 1.6.1 only in annotations: `readOnlyHint` and `idempotentHint` are
    now sent when `false` instead of being left out. Their meaning is unchanged, because
    `false` is the spec default. Input schemas and descriptions are byte for byte the same.
  - We set none of the `MCPGODEBUG` flags the SDK removed in 1.8.0. The HTTP Origin check is
    ours (`server.go`), not the SDK's, and its test passes unchanged.
  - The per-frame cap on inbound messages is 16 MiB by default; requests are a few hundred
    bytes, so it never applies.
- **Portable input schemas (ROADMAP 3.3).**
  - Five optional or nested slices were advertised as `"type": ["null","array"]`:
    `uci_apply.changes`, its `values`, `uci_apply.probe`, `pkg_change.packages` and `exec.argv`.
    They are now a plain `"type": "array"`. Type arrays break Gemini's OpenAPI subset and
    older VS Code.
  - A call that sends `null` for one of them (OpenAI-style clients do, for "not set") is still
    accepted and treated as omitted. Members the schema declares are dropped when null before
    validation; free-form objects such as `ubus_call.args` keep their nulls.
  - `TestToolSchemasArePortable` fails on a type array, `$ref`/`$defs`/`$dynamicRef`, a
    top-level `anyOf`/`oneOf`/`allOf`, a bare `{"type":"object"}`, or a server plus tool name
    over 60 characters. `ubus_call.args` and `uci_apply.expected_revisions` are free-form maps
    on purpose and pass because they state `additionalProperties`.
- **Smaller tool descriptions (ROADMAP 3.5).**
  - `tools/list` went from 23,731 to 21,982 bytes (23 tools; 22,086 once `wg_new_client`
    gained `reveal` below). The text for operators is gone
    from the descriptions: the "Policy scope: ..." sentences, `exec`'s warning about broad
    grants, and the `uci_apply` paragraphs that repeated its own parameter descriptions
    (ops, `probe`, `restore`, `expected_revisions`). A refusal already prints the exact
    scope to grant, and the README *Tools* table lists the scope syntax.
  - `uci_get` no longer says its output "includes secrets such as Wi-Fi keys": they are masked
    by default, so the sentence told a model the wrong thing.
  - `TestCatalogueStaysWithinBudget` fails above 22,100 bytes in total, above 11,500 bytes of
    descriptions, or above 1.5 KB for one tool (4 KB for `uci_apply`).
  - The limit is not the 18 KB ROADMAP 3.5 first named. That figure was set before 3.4's
    titles and hints and the SDK's explicit `false` hints, which together add about 2 KB that
    no description edit can remove; reaching it would have cut about 38% of all prose.
  - `TestDocsOnlyNameToolsThatExist` fails when a description, the server instructions or the
    README name a tool-like identifier that is not a tool.
- **Credentials stay off the transcript (ROADMAP 3.6). Behaviour change.**
  - `wg_new_client` no longer returns the client's private key, preshared key or QR code. It
    writes the config to a file the owner alone can read, in RAM beside the daemon socket
    (`/var/run/openwrt-mcp/wg/<name>.conf`), and returns the public key and the command
    `openwrt-mcp wg-show '<name>'`. The roadmap named `/tmp`, which any local user can write
    into; the runtime directory is `0700`, and the file is created with `O_EXCL`, so it never
    replaces a file or follows a planted symlink.
  - `reveal=true` restores the old result, key and QR included, and writes no file. Use it
    only when the key may enter the conversation and the provider's logs.
  - The file is created before the peer is committed, and removed again if anything after
    that fails; a name that already has a waiting file is refused. Files nobody collected are
    swept after 24 hours (at the next `wg_new_client`) and vanish at reboot.
  - `openwrt-mcp wg-show <name> [--keep]`, run on the router, prints the config and the QR
    code in the operator's own terminal and deletes the file.
  - `sysupgrade action=backup` creates the archive `0600` before `sysupgrade` writes into it
    (it used to take the default umask), refuses to replace an existing file, treats an empty
    archive as a failure, and removes the archives this tool made earlier. Only files named
    exactly like its own (`backup-<host>-<date>-<time>.tar.gz`) are removed, and only
    regular files; the result says how many went.
  - `mfa_unlock` is unchanged: the operator still types the code into the chat. Moving it to
    elicitation is ROADMAP 6.1.
- **Shell-equivalent `exec` grants need a flag (ROADMAP 3.7).**
  - `openwrt-mcp allow <client> exec <programs> <duration>` now refuses a grant that lets the
    client run a program that runs other programs, and says so. Add `--shell-equivalent` to
    grant it anyway; the grant is made and a warning is printed.
  - The list: `sh ash bash dash busybox env nice flock timeout nohup setsid chroot su watch time
    start-stop-daemon taskset ionice chrt find awk sed xargs tar ssh dbclient lua ucode apk
    opkg ubus`. The roadmap named the first dozen; the rest are BusyBox wrappers and shells of
    the same class. A test pins the list, so adding a name is a recorded decision.
  - Names are judged by base name, so `sh`, `/bin/sh` and `/usr/bin/../bin/sh` are the same
    grant, and by glob: `*`, `s*`, `?sh` and `/bin/*` can reach a listed program and count.
  - A `ubus_call` grant that can reach `file.exec` (`file.*`, `*`, ...) counts too.
  - `policies` prints `shell-equivalent: ...` under such a grant, `status` marks it, and
    `status --json` carries `shell_equivalent` (additive; empty grants omit it). That also
    covers a policy file written by hand, which the `allow` gate never sees.
  - Existing grants are not changed or revoked.

Fixed
- **The stdio bridge outlived the daemon (ROADMAP 5.6).** After a daemon restart, each
  `openwrt-mcp stdio` process stayed alive until its client's next request, blocked reading
  stdin. It now exits as soon as the daemon closes the socket, with "daemon closed the
  connection" on stderr.

Added
- **`openwrt-mcp prune [--older-than <duration>]`** deletes expired grants, writes one
  `prune` line to the audit log when it removes any, and refuses a negative age (that would
  reach live grants). Comments, the server section and other blocks are kept byte for byte.
- **Release workflow (ROADMAP 3.1).**
  - A pushed `vX.Y.Z` tag builds all ten router architectures. Each archive holds the binary
    and the `files/` payload.
  - The workflow writes `SHA256SUMS`, attests the build (`gh attestation verify`), and
    publishes a GitHub Release with the CHANGELOG section as notes.
  - It refuses a tag that disagrees with `main.go`.
  - CI now also cross-builds `mips64` and `mips64le`, which `install.sh` already supported.
- **Install without Go (ROADMAP 3.1).**
  - `install-router.sh` runs on the router and is published with every release. It downloads
    the archive for the router's architecture, checks it against `SHA256SUMS`, refuses on a
    mismatch, checks the overlay has room, then installs.
  - `install.sh` now hands its own payload to the same script, so there is one install
    procedure.
  - `install.sh install --release [vX.Y.Z]` has the router fetch a release instead of
    building one. It is also the fallback when no Go toolchain is found.
  - `install-router_test.sh` exercises the download and verification against a local mirror
    in CI. It covers: latest, a pinned version, a malformed version, a missing architecture,
    a missing `SHA256SUMS`, and an archive swapped for another architecture.
  - CI checks that `install.sh`, `install-router.sh` and the release workflow list the same
    architectures.
- **`openwrt-mcp connect` and `connect doctor` (ROADMAP 3.2).** They run on the operator's PC.
  - `connect --client claude-code|claude-desktop|codex|cursor|gemini|vscode --host <router>`:
    - makes an ed25519 key with the PC's `ssh-keygen` if there is none (never overwrites);
    - prints the two commands to run on the router (`authorize-key`, `allow ... @readonly 30d`),
      built from `<type> <base64>` of the public key only, because the key's comment is free text
      that would otherwise end up inside a pasted command;
    - shows the client entry, and with `--write` adds it: Claude Code and Codex through their own
      `mcp add`, Claude Desktop, Cursor, Gemini CLI and VS Code by merging one `openwrt` entry into
      their JSON file. Other servers are kept, an existing different `openwrt` entry needs
      `--replace`, the original file is kept once as `<file>.before-openwrt-mcp`, the write goes
      through a temp file and a rename, and a file that is not plain JSON (VS Code allows comments)
      is left alone with the snippet printed.
    - the entry is `ssh` plus an argument list (`-T -i KEY -p PORT -o BatchMode=yes -o
      IdentitiesOnly=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 user@host`), so no
      quoting depends on the OS; the commands printed for a human are quoted for POSIX shells or
      for Windows.
    - `--host`, `--user`, `--name`, `--key` and `--port` are validated before anything is made, so a
      value cannot become an `ssh` option.
  - `connect doctor` starts the same `ssh` command a client would and speaks MCP over it. Steps,
    in order: SSH reachable, host key (unknown, or changed), key accepted, forced command, daemon
    socket, `initialize`, `tools/list`. It stops at the first failure and prints one fix. A test
    drives it with a stand-in `ssh` for each fault: wrong key, key file too open or missing,
    missing forced command, stopped daemon, disabled socket, unknown and changed host key,
    unresolvable and refused and timed-out hosts, an empty tool list.
  - Claude Desktop is Windows and macOS only; elsewhere `--file` names the config. Under WSL,
    `connect` warns that a Windows-side client uses the Windows `ssh` and `~/.ssh`.
  - The binary needs nothing OS-specific, and CI now builds and vets it for Windows and macOS.
    Releases carry `windows_amd64`, `windows_arm64`, `darwin_amd64` and `darwin_arm64` archives
    (a zip for Windows) with the binary and the licence, checksummed and attested like the rest.
- **MCP prompts (ROADMAP 3.8).** `router-health`, `who-is-online`, `secure-my-router`,
  `wifi-doctor` and `upgrade-plan`: short recipes that name the tools to call and end in a report
  or a proposal. They are text only, so no policy applies and nothing is audited. A test checks that
  every tool they name exists (the ghost-tool test now reads them too) and that every call they
  make is one `@readonly` allows, including the `ubus_call` objects and `sysupgrade` actions, so a
  read-only client can follow them to the end. Where a step would need more (`uci_apply`, the
  `sysupgrade` backup), the recipe stops at a proposal.
- **`openwrt-mcp diag` (ROADMAP 3.9).** A bundle to paste into a bug report: version, Go and OS,
  board and kernel (from `ubus`), daemon and bridge state, settings, the shape of every policy
  (tools, scopes, rate, expiry, shell-equivalent marker) and the last `--audit N` (default 20)
  audit lines.
  - Every IPv4 (leading-zero spellings too), IPv6 and MAC address becomes `ip-N` or `mac-N`, except
    loopback and the unspecified address. Host names, DHCP names (static and leased), SSIDs, the
    domain and WireGuard peer names become `host-N`, `ssid-N`, `domain-N`, `peer-N`, matched
    case-insensitively on whole words. They are read from `system`, `dhcp`, `wireless` and
    `network` and the lease file; only those options are kept, so keys in the same output are read
    and dropped. The same value always gets the same placeholder.
  - Client names stay only if they name a program (`claude-code`, `cursor`, ...); any other
    becomes `client-N`. The factory host name `OpenWrt` is not a name worth hiding and is left alone.
  - Audit arguments are never printed. The scope, summary and error of an entry appear only with
    `--detail`, masked like everything else.
  - The test generates addresses and names in the contexts a log has them in and fails if any
    survives; a whole-command test builds a router with private names in its UCI, policy and audit
    log and checks the default and `--detail` output for leaks.
- **Registry entry and README (ROADMAP 3.10, 3.1).**
  - `server.json` for the official MCP Registry, name `io.github.stanislav-testhub/openwrt-mcp`.
    It names the repository and no package: the registry's package types are for software you
    install where the client runs. A test checks the name, the 100-character description limit and
    that its version equals the binary's. Publishing is left to the operator.
  - The README states what the server does with the network (nothing of its own: no telemetry, no
    outbound connection; the tools that make the router reach out are the ones annotated
    `openWorldHint`), the binary sizes per architecture, and how it differs from the other OpenWrt
    MCP servers, from their READMEs.

## 1.2.0 -- Reliable changes

Closes ROADMAP milestone 2 (items 2.1 to 2.6). No tool is added: every item is a parameter or a
mode of an existing tool.

Added
- **Validation before reload (2.1).** `uci_apply` runs each config's own checker before staging
  (the baseline) and after (the candidate) and reports `validation` in the dry run. For the
  firewall that is `fw4 check`. Measured on the router: it sees changes staged in `/tmp/.uci`, but
  it exits 0 even for an invalid value and only prints `[!]` lines for what it will ignore, so the
  verdict is those lines, compared as counted lines with section indexes normalised (a warning
  that merely moved is not new). A real apply is refused when the candidate has a problem the
  baseline did not, unless `force=true`; a config that was already broken can still be fixed.
  Configs without a checker (dnsmasq has none that sees staged changes: `dnsmasq --test` reads a
  file generated at service start) are reported "not checked".
- **Revision locking (2.2).** `uci_get` ends with `# revision of <config>: <12 hex>`, the digest of
  the committed file, even for a narrowed read. `uci_apply` takes `expected_revisions`
  (`{config: revision}`) and refuses with `CONFLICT` if a config changed since; a revision for a
  config the call does not change, or one that is not 12 hex digits, is an error rather than
  ignored. Dry runs print the revisions to pass; applies print the new ones.
- **Probes and management-path detection (2.3).** `probe` (up to 5 of `{kind: ping|resolve, target,
  server?}`) runs after the reload, each retried for `probe_wait` seconds (default 15, max 60) and
  never longer than half the rollback window. A failed probe is reported and the change stays
  armed: the timer undoes it, as for a caller that lost its connection. The staging lock is
  released before probes run. A change to the LAN interface or its bridge, the SSH listener, or
  the firewall zone and rule that let SSH in is refused unless it names a probe or `force=true`,
  and its default rollback window is 180 s. The rule set is static: it does not know which
  interface the current session arrived on, because the stdio bridge's origin address does not
  reach the tool handlers (a session-aware rule is future work).
- **History and restore (2.4).** Confirming a change keeps the config as it was before, per config,
  newest `history_keep` (default 5, `0` off, at most 20), under `/etc/openwrt-mcp/history/` with
  `0600` files. `uci_get history=list` and `history=diff:<id>` read them; `uci_apply restore=<id>`
  puts one back through the same snapshot, checks, rollback timer and probes. `uci import` writes
  the file at once (measured), so a restore replaces the file as `pkg_config_resolve` does, and
  runs the checkers on the installed file before anything reloads; its dry run shows the settings
  diff only. A rolled-back change leaves no entry. `wg_new_client` and `wg_remove_client`, which
  commit without a rollback, record the file just before they commit.
- **Polling instead of sleeping (2.5).** `service_control` reads the state every 500 ms until it
  has been the same for three reads, or `wait` seconds (default 10, max 60) pass, and says which
  happened. It also notes a final state that contradicts the action (a service still running after
  `stop`).
- **Write-path parity (2.6).** `add_list` skips an element already in the list: libuci appends a
  duplicate (measured). `del_list` of a missing element already succeeds as a no-op (measured), and
  a test pins it. `set_list` now refuses an empty element like `add_list` and `del_list` did, and
  one table test runs every option-writing op against the same hostile names and values.

Security
- A probe has the router ping or resolve a name for the caller, which a grant on `uci_apply` never
  allowed, so each probe target is a policy scope of its own, `probe.<kind>.<target>`. Targets
  that could read as an option are refused. A restore replaces a whole config, so its scope is
  `<config>`, which `<config>.*` does not cover.
- History entries hold whole config files, secrets included. They get the snapshots' protection
  (`0700` directory, `0600` files, state-path guard), are masked when shown, and are in
  `sysupgrade` backups because `keep.d` keeps the whole state directory.

Changed
- `uci_apply`'s `changes` is optional in the schema (a restore has none).
- `wg_new_client` and `wg_remove_client` take the calling client's name, for the history entry.

Verified
- On the GL-MT6000 (OpenWrt 25.12.5), through the daemon's stdio bridge: every refusal and dry-run
  behaviour above, a real apply with probes then confirm, history list/diff, a byte-identical
  restore, a failing probe followed by `uci_rollback`, and a `service_control` restart (see the
  README *Verified* section). Not run on hardware: a management-path change applied with probes,
  a failed probe left to the rollback timer, and history across a `sysupgrade`.
- The mutation harness has 57 rows for the new rules; all but two (the `0600`/`0700` modes of the
  history files and directory, which need Linux to observe) are killed, and those modes were
  confirmed on the router. `-race` and the description eval were not run locally.

Not done
- Out of scope: the `wg_*` tools still commit with no snapshot or rollback. History in RAM for
  low-flash boards (ROADMAP open question) is not built.

## 1.1.0 -- Output safety

Closes ROADMAP milestone 1 (items 1.1 to 1.5), and carries the fixes found by a test-coverage
audit (schema-driven hostile-input test, fuzzing, mutation analysis).

Added
- `SECURITY.md` has a written threat model (ROADMAP 1.3): what is protected, who is trusted, the
  boundaries, what the audit log does and does not prove, what output safety does and does not
  do, the second-factor trade-off, and what is in scope for a report.
- Config options in the `config server` section: `mfa_max_failures`, `mfa_lockout`,
  `redact_output`, `redact_extra` (see below). No tool is added or changed in its schema.

Security
- `firewall_show` (family, table, chain), `uci_get` (config), `ubus_list` (filter) and
  `ubus_call` (object, method) accepted values starting with `-`, which reached `nft`, `uci`
  and `ubus` as options. Refused now, and the validators for nft names and UCI config names
  no longer allow a leading `-`.
- The audit log recorded the value of a secret option set through `uci_apply`
  (`{"option":"key","value":"<wifi password>"}`), contrary to the README. A secret-named
  option (`key`, `key1..4`, `psk`, `password`, `private_key`, `preshared_key`, ...) now hides
  its `value`/`values`.
- The HTTP `Origin` check trimmed the header by hand, so `http://localhost:80@evil.example` read
  as `localhost`. It parses a URL now, refuses userinfo, paths and fragments, and accepts
  `http://[::1]`.
- `openwrt-mcp allow` wrote the client name and scopes between single quotes without checking
  them; a quote or newline could corrupt the policy file. The client name must now be one the
  stdio bridge accepts, and scopes may not contain quotes.
- `authorize-key` refuses control characters in the key comment.
- State paths can no longer sit in a web-served location (ROADMAP 1.4). The state directory
  (tokens, MFA secrets, rollback snapshots), the audit log and the socket are checked, with
  symlinks followed, against `/www`, any `cgi-bin` directory and the uhttpd `home` and
  `cgi_prefix`. `-state` in such a place makes every command refuse to run; an `audit` or
  `socket` option there is ignored with a log line and keeps its default. Every state path is
  now built in `statepaths.go`, and a test fails if one is built anywhere else.
- `mfa_unlock` had no failed-attempt limit (ROADMAP 1.5). Five consecutive wrong codes now lock
  that client out for 5 minutes, doubling on each repeat to one hour; success, re-enrolment
  and a rotated secret clear it. A correct code during the lockout is refused and not
  consumed. A client with no secret is counted the same, so the limiter is no enrolment
  oracle. A lockout audits as `DENIED`, each wrong code as `ERROR`. Options `mfa_max_failures`
  and `mfa_lockout`. The state is in memory, so a daemon restart clears it. Trade-off: whoever
  holds a client's token can lock the operator out of `mfa_unlock` for up to an hour.
- Tool output hid nothing (ROADMAP 1.1). `uci_get`, `uci_apply` (the staged diff, and errors that
  echo someone else's staged edit), `pkg_config_diff`, `pkg_config_resolve`, `uci_confirm`,
  `uci_rollback`, `system_status` and `ubus_call` now keep the shape of a line and drop the
  value of a secret option: `key`, `key1..4`, `psk`, `password`, `sae_password`, `passphrase`,
  `private_key`, `preshared_key`, `token`, `pwd` and the other names the audit log already
  hid, in `uci show`, `uci changes`, `uci export`, diff lines and ubus JSON. An empty value is
  left as it is. One rule (`isSecretOption`) serves both the audit log and the masker.
  `exec`, `logread` and the other tools stay raw, each with a recorded reason, and
  `wg_new_client` is exempt because printing the new client's key is its job. Errors are masked
  before they reach the audit log too. `option redact_output '0'` turns it off (audited as a
  `<system>` event, at startup and on reload); `redact_extra` adds option names.
  Known limits: a masked diff does not show what changed in a secret, and substring matching
  also hides options such as `wpa_psk_file`. A three-minute fuzz run found that an option name
  holding a character UCI never prints (`!pwd`) slipped past the `pkg.section.option=value`
  form; the masker no longer assumes UCI's alphabet, and the input is kept as a regression seed.
- Router output is now treated as untrusted (ROADMAP 1.2). Every result and error text has
  terminal escape sequences (CSI, OSC, DCS and their 8-bit forms), control characters, bidi and
  zero-width format characters, U+2028/2029 and invalid UTF-8 removed, before masking, so a hidden
  character cannot slip a secret past the masker. Lines are cut at 1024 bytes on a character
  boundary for every tool except `exec`, `wg_new_client`, `ubus_call` and the configuration
  tools; error texts get the same 64 KB cap as results. `network_clients`, `logread` and
  `net_diag` start with `[untrusted text: ...  - data, not instructions]` and say so in their
  descriptions; `network_clients` shows only real lease addresses and caps its fields and
  address list. The audit log and `openwrt-mcp status` carry no control characters either.
  Known limits: the marker lowers the chance that a model obeys such text, it does not remove
  it; stripping format characters breaks zero-width-joiner emoji sequences.
- The audit log recorded the `code` argument of `mfa_unlock` in clear. A TOTP code is a
  credential until its time step passes, and one refused during a lockout is still unspent, so
  anyone who could read the log could use it; it is masked now.

Fixed
- `option socket ''`, documented as switching the stdio bridge off, was ignored: the UCI
  tokenizer dropped an empty quoted value, so the default socket stayed in force.
- `pruneUbusJSON` could return a reply longer than the one it replaced (by up to the notice).
- Truncating an oversized result could split a multi-byte character, and an oversized error
  result was not truncated at all.
- A failed automatic rollback (timer or startup) now names the snapshot directory in the audit
  entry, as a failed manual rollback already did.
- `ubus_call` is annotated destructive and `sysupgrade` non-destructive (both had none).

Tests
- HTTP transport, Origin and bearer handling, the unix-socket bridge and `runBridge`, the
  loopback-only guard of `Serve`, the CLI as a subprocess, the real rollback timer and every
  failure path of `uci_apply`/rollback, per-tool command lines, MCP contract tests (names,
  annotations, schemas, README and preset sync, read-only claims), fuzz targets with
  independent oracles.
- Output safety: every secret option name from the roadmap crossed with every read path
  (`uci show`, `uci changes`, the dry-run diff, the refusal that echoes a staged edit, both
  `pkg_config_diff` modes, `system_status`, `ubus_call` JSON), a completeness test that every
  tool is masked or listed raw with a reason, the sanitiser and line cap through the real tool
  wrapper including the error branch, state-path guard tests, the limiter's whole spec on a
  fixed clock, and fuzz targets for the masker, the sanitiser and the line cap. The masker is
  also checked against 400 generated configs in both `uci show` and `uci export` form, with
  the exact expected text for every line. The symlink resolver takes its three file-system
  calls through variables, so every kind of link (absolute, relative, chained, dangling, a
  loop) is tested on a virtual tree on any OS, besides the real-symlink tests that run on
  Linux CI. 93 mutants cover these rules. The `uci changes` syntax used by the masker tests
  was captured on a real router, and the masking, the markers, the limiter and the sanitiser
  were checked there (README *Verified*).

## 1.0.0 -- OpenWrt 25.12 port

Retargeted from GL.iNet firmware 4.x (OpenWrt 21.02, opkg) to stock OpenWrt 25.12 (apk,
fw4/nftables). Verified against a GL-MT6000 on 25.12.5.

Security
- `uci_apply` and `pkg_config_resolve` refuse the openwrt-mcp policy config, whatever the
  grant. Before this, a client holding `uci_apply` on `*` (the `@operator` preset) could add
  itself a policy with `exec` on `*` and confirm it.

Removed
- GL.iNet oui-httpd page, menu and i18n; `gl_ddns`/`wireguard_server` WireGuard model;
  `.ipk` packaging (`mkipk.sh`, `install-ipk`); GL-specific docs and findings.

Changed
- Rollback snapshots live on flash under the state directory and the pending record is written
  before commit, so a reboot inside the window rolls back at the next start. Restore is atomic
  per file and forces `config.change` events when `reload_config` has no checksums.
- Reload runs `/sbin/reload_config` synchronously instead of rpcd's asynchronous method.
- Scope globs treat `[` `]` literally (`firewall.@rule[3].*`); previously `[0]` was a character
  class and a grant written exactly as its scope did not match it.
- Commands run through a replaceable runner; the test suite runs on any OS.
- WireGuard: stock `network.<iface>` + `wireguard_<iface>` peers; endpoint from `ddns`, else the
  default-route interface with a CGNAT/private-address warning; optional PSK.

Added
- stdio transport: `openwrt-mcp stdio --client X` bridges an SSH session into a root-only unix
  socket; `authorize-key` binds a dedicated key to it with a forced command.
- `uci_apply`: `add_list`, `del_list`, `set_list`, `dry_run`, staged-change output, UCI name
  validation; `uci_rollback`.
- Tools: `system_status`, `network_clients`, `firewall_show`, `net_diag`, `service_list`,
  `service_control`, `pkg_query`, `pkg_change`, `pkg_config_diff`, `pkg_config_resolve`,
  `sysupgrade`, `wg_list_clients`, `wg_remove_client`. `logread` filters the whole buffer and
  gains regex and since-minutes.
- CLI: `allow <client> @readonly|@operator <dur>`, `revoke <client>`, `authorize-key`.
- LuCI status page (Services -> MCP Server), read-only via one rpcd exec ACL.
- `install.sh` (build for the router's arch, install, uninstall) and keep.d coverage for
  everything installed. MCP server instructions and tool annotations.


## v0.5.0

**Issue a WireGuard client and show a QR to scan it**, plus `uci_get` to read configuration
without a root shell.

### Added

- `wg_new_client` -- issues a WireGuard client for the router's VPN server: generates a
  keypair, allocates the next free tunnel address, writes a peer the vendor UI still lists,
  and returns the config together with a UTF-8 QR code. Adding a client by hand is three
  fiddly steps and then a config has to reach a phone; transcription is what actually goes
  wrong, so the QR sits next to the text.

  It hot-adds the peer with `wg set` rather than restarting the interface -- a restart drops
  every established session, a poor trade for adding one client. If the running interface
  cannot be identified the peer is still committed and the output says so. It prefers the
  router's dynamic-DNS name over its WAN address for `Endpoint`, since a dynamic address
  baked into a client config stops working at the next reconnect. A full subnet is an error,
  never a recycled address: two devices sharing one tunnel address breaks whichever connects
  second, and it fails silently.

  The tool returns a new private key. It never reaches `audit.jsonl`, which records arguments
  and a summary but not tool output, and `wg pubkey` reads the key on stdin so it is never in
  argv where `/proc` would expose it. It does land in the caller's context, so issue one
  client per device and consider gating the tool behind `mfa_tools`.

- `uci_get` -- read current UCI configuration (via `uci show`) through the same policy gate
  as every other tool. Closes the read gap: an agent can inspect state before an `uci_apply`
  without being granted `exec` (a root shell) or a broad ubus `uci.*` scope just to look. Its
  policy scope mirrors `uci_apply` (`<config>[.<section>[.<option>]]`), so one grant reasons
  about reads and writes symmetrically.

### Fixed

- `wg_new_client` names the server field that is actually absent. A section with an address
  and port but no keypair -- a VPN server that was never set up -- reported "missing
  address_v4, public_key or port", sending you to check all three. It now names only what is
  missing and, when there is no keypair at all, says the server has probably never been
  configured.

## v0.4.0

**An optional TOTP second factor for the tools that can change or read anything.** Opt-in per
policy — absent means off, so every existing configuration behaves exactly as before.

### Added

- `mfa_tools` and `mfa_window` on a policy. Naming a tool there additionally requires an
  unexpired TOTP unlock; `'*'` covers every tool the policy grants.
- `openwrt-mcp mfa enrol <client>` prints a QR-scannable `otpauth://` URI once, and
  `openwrt-mcp mfa status` shows who is enrolled and what is gated.
- An `mfa_unlock` tool taking a 6-digit code.

### Why a window rather than a code per call

A broad grant plus a stolen bearer token is root on the router. The token is something the
workstation has; a TOTP code is something the operator has, elsewhere.

But an agent works in bursts, and a control that demands six digits per call gets switched
off — a control too annoying to leave on protects nothing. So one code opens a time-boxed
window and the gated tools work normally until it lapses, the way `sudo` does.

### Decisions worth knowing

- `mfa_unlock` is itself ungated, or satisfying the factor would deadlock behind the factor.
  Safe because it grants nothing without a valid current code.
- The check runs **after** authorisation, so an unauthorised caller learns nothing about which
  tools are gated.
- Unenrolled and wrong-code fail with identical text; distinguishing them tells an attacker
  which clients are worth attacking.
- Codes are single-use. Without that a code is good for its whole ~90-second acceptance span.
- Unlocks live in memory only, so a restart re-locks everything.
- `mfa_tools` naming a tool the policy does not grant is rejected at load — a typo would
  otherwise sit there looking like protection.
- The secret is stored recoverably, because TOTP is symmetric, unlike bearer tokens which are
  kept only as digests. Hence mode 0600, and `enrol` is CLI-only. **Run it yourself**: a
  secret that passes through anyone else is not a second factor.

### Fixed before release

- A freshly enrolled client was rejected with "invalid code" on a **running** daemon. The
  secret file was read once at startup, and `mfa enrol` is a separate process writing it, so
  enrolment silently needed a restart. It now reloads on change, the way `allow` already did.
  Rotating a secret closes any window opened under the old one.
- The `otpauth://` account now names the router (`claude-code@GL-BE14000`). Without it, two
  routers produce identical authenticator entries and the only way to pair them up is trying
  each code against each router — which is precisely how this was found.

### Verified

End to end on hardware: `exec` denied, a real code unlocked for 15m, `exec` worked, the same
code was refused as replayed, and `ubus_call` — not listed in `mfa_tools` — was unaffected
throughout.

76 tests. TOTP is checked against RFC 6238's own vectors, because a hand-rolled
implementation that is subtly wrong still agrees with itself: enrolment and unlock would
match while no real authenticator app could produce an accepted code. Nine mutations all
killed, including gate-always-allows, accepts-any-code, replay-removed, window-never-expires,
reload-removed and 0600→0644.

## v0.3.2

**Fixes a bug that hid the status page on any router not in "router" net mode.** Worth
upgrading if you run GL.iNet firmware and the page never appeared.

### Fixed

- `menu.d/openwrt-mcp.json` declared `show_mode: ["router"]`, copied from AdGuard Home
  without checking whether it applied. It does not: openwrt-mcp exposes `ubus` and `uci`,
  which exist in every net mode, so there is no mode in which the daemon runs but its status
  page should be invisible. The key is now omitted, matching `plugins`, and the page appears
  in every mode.

Found by installing on a second device — a Slate 7 Pro (GL-BE10000) running firmware 4.8.4
in **ap** mode. Everything worked except the visible part: the package installed, the RPC
answered, `ui.get_menu_list` returned the entry and the view was served, but the nav had no
item. AdGuard Home, Tailscale and ZeroTier were missing too — all declaring
`show_mode: ["router"]` — so the SPA was faithfully honouring a declaration that was wrong.

### Verified

The published `.ipk` installed unchanged on the Slate 7 Pro: different SoC (mt7987 vs
mt7988), different firmware (4.8.4 vs 4.9.0), same `aarch64_cortex-a53`. Auth matrix, scope
gate, response pruning, the RPC module and its access gate all behaved as on the Flint 4, and
the page now renders in both router and ap mode.

## v0.3.1

Documentation only — **no functional change from v0.3.0**, so there is no reason to upgrade
unless you want the version string to match. The binary differs only in that string.

- README now leads with a screenshot of the MCP Server page in GL.iNet's admin panel,
  captured from a real Flint 4 rather than mocked up.
- The screenshot shows the recommended *narrow* grant, and its audit tail includes a genuine
  refusal — `ubus_call` on `dnsmasq.metrics` denied against scopes covering `network.*`,
  `iwinfo.*`, `system.*` and `gl-clients.*`, with the `allow` line that would cover it. An
  earlier capture showed `scope: *`, which contradicted the README's own advice to start
  narrow.

## v0.3.0

A status page inside the router's own web UI, under **Applications → MCP Server**: daemon
state, paired clients, standing policies and the recent audit tail. Read-only.

### Added

- `openwrt-mcp status [--json] [--audit N]` — daemon state, pairings, grants and recent
  audit entries. `--json` is what the web UI consumes.
- An oui-httpd RPC module at `/usr/lib/oui-httpd/rpc/openwrt-mcp` exposing
  `openwrt-mcp.status`, plus the view and menu entry the GL.iNet SPA loads.

### Why the UI is read-only

`pair`, `allow` and `unpair` stay command-line only, so nothing reachable over the network
can widen a grant — the same property that keeps them out of the MCP tool list. The page
shows and explains grants; it never issues them.

Status is a CLI subcommand rather than a second HTTP endpoint for the same reason. The
daemon's only listener is loopback and reachability is explicitly not treated as identity,
so a second HTTP surface would mean either exposing policy and audit data to every process
on the router, or storing a bearer token on the router for the UI to present. oui-httpd
already runs as root and can read the state directory anyway, so a CLI read grants its
caller nothing new.

### Notes for anyone building a GL.iNet view

No GL.iNet SDK or bundler is needed. The SPA fetches a view as text, `eval`s it, and uses
the resulting value as the route component, so a plain IIFE returning a Vue 2 options object
is sufficient. The shipped views' `module.exports=…` form works only because a direct `eval`
inherits the enclosing webpack wrapper's scope. Vue is 2.6.12, so render functions avoid
needing a template compiler at eval time.

`running` in the report asks `/health` and requires the daemon to identify itself, rather
than just dialling the port — 8730 is an ordinary port for something else to hold, and an
`ssh -L` answers it happily.

## v0.2.0

First release with a downloadable package. The `.ipk` on the release page installs without a
Go toolchain or the OpenWrt SDK.

Verified on a GL.iNet Flint 4 (GL-BE14000), OpenWrt 21.02-SNAPSHOT / GL firmware 4.9.0.

### It installs on someone else's machine now

`v0.1.0` could not be installed by anyone but the author:

- `Makefile` hardcoded `GO ?= /usr/local/go/bin/go`, so Go from apt, brew or asdf failed
  with `make: *** Error 127` on the first command.
- The `files/` tree — the procd init script and the default UCI config — had **never been
  committed**. An unanchored `.gitignore` pattern swallowed it, so a fresh clone could not
  run `make install` at all.
- SSH key auth was assumed but never documented, while `make install` pipes over
  non-interactive ssh and a factory router has no `authorized_keys`.
- `$TOK` appeared in the connect instructions and was never defined.

### Added

- `.ipk` packaging. The daemon survives a firmware upgrade via `/lib/upgrade/keep.d`, and
  `/etc/config/openwrt-mcp` is a conffile so upgrades never clobber live policies.
- `uci_apply` creates and deletes whole sections, not just options. A change with `type` and
  no `option` creates a named section; `delete` with no `option` removes one. Adding a static
  lease or a firewall rule is now one rollback-armed call rather than a root shell.
  Section-level changes take the scope `<config>.<section>`, distinct from
  `<config>.<section>.<option>`.
- Response pruning for oversized ubus replies. `gl-clients list` measured 100,587 bytes on a
  49-client network; replies over 8 KB now have arrays capped at 16 elements, pruned from the
  decoded tree so the result stays valid JSON. That call is now 43,676 bytes.
- CI: vet, tests, cross-build, and assertions that the package contains the four files the
  router needs and declares its conffile.

### Fixed

- `make install` failed with `ETXTBSY` on every install after the first — `cat >` cannot
  overwrite a running executable. It now writes a sidecar and renames.
- Pruning no longer touches replies small enough to read whole. The first version capped a
  17-element list in 196 bytes (`iwinfo devices`), discarded a real interface and made the
  reply longer.

### Documented

Findings from the Flint 4 `gl-*` surface, including why `gl_screen.*` should not be granted
(its ubus `set` bypasses the Lua validation layer and corrupts the value type) and that the
screen passcode is stored in plaintext under `/tmp`.

### Known limitations

The `.ipk` targets `opkg`. Stock OpenWrt 24.10+ moved to `apk` and is untested; GL.iNet
firmware 4.x is opkg-based, so this does not affect the Flint range.

## v0.1.0

Initial implementation: resident MCP server under procd, six generic tools over `ubus`/`uci`,
bearer auth, standing policies with deny-by-default, audit log, and `uci_apply` rollback.
Written against a GL.iNet Flint 2.
