# Design note: small routers and resource footprint

Status: proposal. Roadmap entry: [Milestone 10](../ROADMAP.md#milestone-10-small-routers-v20-prep).

## Why

openwrt-mcp was built and verified on a 1 GB arm64 Filogic router with gigabytes of flash. Most OpenWrt routers in
use are much smaller: 128 MB of RAM, 16 MB of NOR flash, a MIPS 24Kc/1004Kc or Cortex-A7 CPU. The project has
never measured what it costs on such a device. Milestone 9 adds many adapters, so the code only grows from here.

The goal is to lower what openwrt-mcp costs in **tokens, flash and RAM** without dropping a feature, and to let small
routers choose a smaller footprint. Every saving is measured, never estimated, and every budget is enforced by a test,
like the catalogue budget of 3.5.

## Baseline

Measured on 2026-10-15 at 1.5.0, Go 1.27.1, `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`. The commands are in the
appendix.

| What | Value |
|---|---|
| Binary, arm64 / armv7 / mips and mipsle softfloat | 10.1 / 10.6 / 11.9 MB |
| The same compressed, xz -9 / gzip -9 (close to the flash cost on jffs2-lzma / ubifs) | 2.8 / 3.8 MB |
| Size floors (mipsle): a go-sdk stdio server with one tool / a bare net/http server / stdlib JSON + exec + regexp | 8.8 / 7.5 / 4.0 MB |
| Code by package (arm64 text) | crypto 703 KB, third-party 600 KB, our code 567 KB, runtime 471 KB, encoding 382 KB, net/http 247 KB |
| Daemon (`serve`) RSS, idle | 14.7 MB: 5.8 MB anonymous + 9.0 MB file-backed |
| Each SSH session's `stdio` bridge RSS | 10.4 MB: 3.0 MB anonymous + 7.3 MB file-backed, shared with the daemon |
| Process start (every bridge and every `call`) | 105 package inits, 1.3 MB of heap. Our package alone: 1.08 MB, 13.5k allocations, 48 package-level `regexp.MustCompile` |
| `tools/list` | 23 tools, at most 23.9 KB (about 6–7k tokens), enforced by `contract_test.go` |
| State directory on flash | 277 KB in use, worst case **32 MB** (see below) |

### What the numbers say

- **The SDK sets the floor, not our code.** The MCP Go SDK links net/http, crypto/tls, oauth2 and jsonschema whatever
  we use from it: 8.8 MB of the 11.9 MB. All our optional features together are about 3 MB raw and under 1 MB
  compressed.
- **Unused code costs flash, not RAM.** Linux loads binary pages on demand and shares them between processes. A tool
  nobody calls costs almost no RAM. RAM goes to the resident daemon, to each session's bridge and to start-up
  initialisation.
- **On a 128 MB router the real cost is RAM.** About 15 MB stays resident whether or not an agent is connected, plus
  about 3 MB of anonymous memory per session, on a device with roughly 60–80 MB free after boot. Flash fits (about
  3–4.5 MB compressed against 5–9 MB of free overlay), but tightly.
- **The audit log can fill a small flash.** `audit_max_mb` defaults to 16 and rotation keeps one older generation, so
  audit can take 32 MB. That was sized for eMMC. On a 16 MB NOR router it fills the overlay. This is a bug.
- **Tokens are already managed.** The catalogue has a byte budget, clients choose `--toolset` and `--read-only`, and
  agents with a shell can use `call` with the bundled skill. Two levers are left: a server-side catalogue cap for small
  routers, and keeping structured output (5.5) from doubling result size.

## Device classes

| Class | Typical hardware | Plan |
|---|---|---|
| A: 256 MB RAM or more, NAND or eMMC | Filogic, IPQ807x, x86 | `full`, today's behaviour and the default |
| B: 128 MB RAM, 16 MB NOR | ath79, ramips mt7621, Cortex-A7 boards | the target of this milestone: the `small` profile |
| C: 64 MB RAM or 8 MB flash and below | older ath79 and ramips | not supported. A Go binary is at least 4 MB, and OpenWrt itself warns about 8/64 devices |

## Should users install only the tools they need?

Two ways to do that were considered.

**Build-time editions** (core / full / lite binaries cut with build tags): **no.** Removing every optional tool saves
under 1 MB of compressed flash and almost no RAM, because unused code is never paged in. Each edition multiplies the
CI matrix, release artifacts, contract tests and support questions ("which edition do you run?"). The SDK floor stays
whatever we remove.

**Runtime profiles**: **yes.** There is one binary everywhere. A UCI option `profile 'full'|'small'` picks resource
defaults (resident or on-demand daemon, HTTP listener, memory limit, audit and history caps). An operator-level
toolset cap (`option toolsets`) gives the "mandatory core plus chosen toolsets" catalogue. It reuses the partition
`profile.go` already has: `coreTools` (`system_status`, `mfa_unlock`) plus the `diag`, `config`, `pkg` and `wg`
toolsets. The policy engine, audit, redaction and rollback are core and never optional.

## Plan

The milestone ships after Milestone 9's add-on waves, before Milestone 6. 10.1 therefore measures the post-M9 binary
as its baseline. Until then, M9 grows the code without a size gate, so each adapter should stay one small file, as 9.1
already asks.

### 10.1 Footprint budget

Measure first, then hold the line.

- A test or CI step fails when the stripped mipsle-softfloat binary (the largest target) grows past its measured size
  plus a small slack, or when our package's start-up heap (from `GODEBUG=inittrace=1`) grows past its budget.
- The real-target CI job (`realtarget_test.go`, `-test.run ^TestReal`) records VmRSS and VmHWM of `serve` when idle and
  after the golden calls, and of one bridge. It logs the result bytes of each golden call, in the style of 3.11.
- `system_status` gains one line: daemon RSS and free overlay.
- **Done when** raising any limit needs a reason in the commit, the same rule as the catalogue budget, and the README
  table is regenerated from CI output.

### 10.2 Lazy start-up

- Package-level regexps and anything else built at start move behind `sync.OnceValue` or into their function. Only
  `entry.go`'s two patterns sit on the bridge path. `tools_system.go` compiles a regexp on every call; `strings.Map`
  replaces it. Duplicate patterns are merged: the SSH-key patterns in `connect.go` and `presets.go`, and the MAC and
  IPv4 patterns in `diag.go` and `logsummary.go`.
- The `stdio` and `call` paths build no tool registry and no schema. Schemas are already built lazily, per client.
- **Done when** our package's start-up heap is under 100 KB (from 1.08 MB), the bridge's anonymous RSS drops by about
  1 MB on the real target, and the full suite and golden calls are unchanged. Start time on a MIPS target is measured
  and stated.

### 10.3 Memory limit

- `option memory_limit '<MiB>'` sets `debug.SetMemoryLimit` in `serve`. When it is unset, Go's default applies. There is
  no GOGC option: one knob is enough.
- **Done when** the heaviest bounded calls (`logread`, package lists, per-client traffic) stay under a 16 MiB high-water
  mark on the real target with the limit set, and the option is documented next to `audit_max_mb`.

### 10.4 Optional HTTP listener

- `option listen ''` turns the TCP listener off. Today it always binds `127.0.0.1:8730`. `status`, `doctor`, `connect`
  and the LuCI page say "HTTP off". SSH-only users get less attack surface, and 10.5 needs it.
- **Done when** a config test covers the empty value and the e2e suite passes over the socket with HTTP off.

### 10.5 On-demand daemon

- `option idle_exit '<minutes>'`, where `0` (the `full` default) keeps today's resident daemon.
- The daemon stops itself only when all of these hold: no open session, no armed rollback, no held request
  (Milestone 8), HTTP off, and idle for that long. It stops through procd (`/etc/init.d/openwrt-mcp stop`), so procd
  still respawns it after a crash.
- A bridge or `call` that finds no socket runs `/etc/init.d/openwrt-mcp start`, then uses the existing dial retry
  (`dialDaemon` in `sessions.go`, 10 s).
- Boot still starts the daemon once, so a rollback armed before a reboot is recovered. Then it idles out.
- **Done when** a test shows that each keep-alive condition alone keeps the daemon up, a mutation run covers the
  condition list, idle RAM is zero on the real target, and the cold first-call latency on MIPS is measured and stated
  in the README.

### 10.6 The `small` profile and an install fit check

- **A fix for everyone, not tied to a profile:** when `audit_max_mb` is unset, its default is clamped to 1/32 of the
  overlay size. Large overlays keep 16 MB. Audit plus its rotated copy can then never take more than 1/16 of flash.
- `option profile 'small'` means `idle_exit 5`, `listen ''`, `memory_limit 16`, `audit_max_mb 1`, `history_keep 3`
  and `toolsets 'diag config'`. Any option set explicitly wins over the profile.
- `install.sh` and `install-router.sh` read MemTotal and free overlay. Under 256 MB of RAM they suggest `small`. They
  refuse to install when free overlay is less than the compressed binary plus a margin, and print both numbers.
  `doctor` reports the same fit.
- **Done when** `install-router_test.sh` covers fit and no-fit, and the e2e suite runs under `small` on a class-B
  router or with emulated limits.

### 10.7 Operator toolset cap

- `option toolsets 'diag config'` is intersected with the client's `--toolset` in `profile.go`
  (`sessionProfile.inToolsets`). It is static configuration, so 5.4's rule holds: the catalogue is fixed for a session
  and never depends on grants. A call outside the cap gets the existing "not available in this session" line, which
  will also name the UCI option.
- **Done when** `TestToolsetTablePartitionsEveryTool` still passes and the catalogue size under `small` is measured and
  stated.

### 10.8 Compaction without losing anything

The reuse sweep found about 250–300 lines that repeat existing helpers, about 2% of 14.4k non-test lines. The value is
fewer copies of security-critical code (principle 4), not bytes. Each item is a refactor with no change in behaviour:

1. **The armed-write sequence is written five times**: `uci_apply`, history `restore`, `pkg_config_resolve`,
   `wg_new_client` and `wg_remove_client` each repeat snapshot, revert on failure, commit, read back, reload and notice.
   Extract `undoNow`, `stillArmed` and a `stageOrRevert` closure. `pkg_config_resolve` moves onto `preflight`,
   `installConfig` and `armedNotice`. About 60 lines; medium risk, so a mutation run on the rollback rules is required.
2. **`runDiag` rebuilds `runStatus`** (policy list, expired count, audit tail). Render the masked `statusReport`
   instead. About 35 lines.
3. **Wireless and neighbour queries are written three times** (`tools_net.go`, `trafficdiag.go`, `warnings.go`; `ip
   neigh` parsed as text in one place and as JSON in another; `wifiUp` twice). One `iwinfoClients` and one
   `neighbours(ctx)`. About 30 lines.
4. **Six string-cutting helpers** (`truncate`, `trunc`, `cutRunes`, `clip`, `short`, the cap loops) become one `cutAt`.
   About 25 lines.
5. **Standard library replacements**: `slices.Sorted(maps.Keys(m))`, `slices.Contains`, `cmp.Or`, `rand.Text()`, and
   the `crypto/rand.Read` error checks that cannot fire since Go 1.24. About 30 lines.
6. **Calls that bypass existing helpers**: `boardLine` → `runJSON`; `systemStatus` → the `snapshot` getters; two JSON
   encoder helpers → one; the `operator` preset built from `readonly`'s list. About 35 lines.
7. **Regexp hygiene**, shared with 10.2.

Small fixes found along the way change behaviour, so each is its own commit with a failing test first. They are not
counted as compaction:

- one JSON secret walker for the audit log and tool output (the audit log then also masks bare `key` options);
- one `writeAtomic` on top of `writeSynced` for the six temp-file-and-rename sites, which adds fsync to the token,
  MFA and policy writes;
- the audit summary cut can split a UTF-8 character; `harvestNames` misses UCI list values.

Kept on purpose:

- `miniyaml.go`: the AdGuard Home adapter needs it, and the standard library has no YAML parser;
- go-qrcode and image/png: about 70 KB of symbols for the `wg_new_client` QR code;
- the security audit, health and dry-run warnings: they already share the findings framework.

- **Done when** golden calls, contract tests and mutation suites are unchanged, and each item reports its line count
  and text-size change.

### 10.9 Structured output must not double result tokens

This is a constraint on 5.5, not separate work.

- `outputSchema` counts inside the catalogue budget.
- The compact text stays in `content`. `structuredContent` goes only to clients that negotiate it.
- The result bytes of each golden call (10.1) must not grow for clients that read only text.

## Not planned

| Idea | Why not |
|---|---|
| Build-time editions per tool | Under 1 MB of compressed flash and almost no RAM saved, since unused code is never paged in. Each edition multiplies CI, releases and support. Runtime toolsets already cut the tokens. |
| UPX or other self-decompressing binaries | Each process decompresses the whole binary into anonymous memory, so the daemon and the bridges no longer share pages: RAM use goes up. Overlay filesystems already compress. |
| Replacing the MCP SDK with an in-house layer | It would save 4–5 MB raw (8.8 MB floor down to about 4 MB), but we would lose the SDK's spec tracking (elicitation for Milestone 8 and 6.1, progress, tasks, structured output) and principle 9's gated upgrades. Revisit if class-B users report that it does not fit after Milestone 10. |
| A separate tiny bridge binary | Adds flash. Its gain (about 2 MB of anonymous memory per session) is mostly what 10.2 already gets. |
| Removing explicit `false` hints and `additionalProperties` from the catalogue | 1–2 KB, through an SDK compatibility switch (`MCPGODEBUG=hintomitempty`) that may go away. Strict clients rely on `additionalProperties`. |

## Appendix: how the baseline was measured

```sh
# binary sizes (repeat for GOARCH=arm GOARM=7, mips/mipsle GOMIPS=softfloat)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o owm.arm64 .
xz -9 -c owm.arm64 | wc -c; gzip -9 -c owm.arm64 | wc -c

# size by package: build without -s -w, then sum symbol sizes by package path
go tool nm -size owm.arm64.full

# start-up cost
GODEBUG=inittrace=1 ./openwrt-mcp version 2>&1 | grep '^init'

# RSS on the router
grep -E '^(VmRSS|VmHWM|RssAnon|RssFile)' /proc/$(pidof -s openwrt-mcp)/status
```

The size floors come from three throwaway programs built for mipsle softfloat: a go-sdk stdio server with one tool,
a net/http server that runs one command, and a stdin JSON loop with `os/exec`, `regexp` and a unix socket dial.
