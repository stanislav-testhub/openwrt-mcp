# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you open a pull request

```sh
go vet ./...
go test ./...
gofmt -l .          # must print nothing
sh -n install.sh files/etc/init.d/openwrt-mcp
```

The tests need no router: `fake_test.go` replaces the command runner and the filesystem root,
so they run on Linux, macOS and Windows. CI additionally runs `go test -race` and
cross-compiles every supported architecture.

## Guidelines

- **Target stock OpenWrt 25.12+.** No `opkg`, `iptables`, vendor firmware paths or
  21.02-era workarounds. If a feature needs a package that is not in a default image, detect
  it and say what to install.
- **No shell.** Commands are argv slices passed to `run`/`runJSON`; validate every name that
  ends up in an argv, and refuse values that start with `-`.
- **Every new tool** needs a scope that a policy can grant narrowly, an annotation
  (`annRead`, `annIdem`, `annDest`, `annDestIdem` or `annWrite`), a title in `toolTitles`
  (and an entry in `openWorldTools` if it can reach past the router), a place in the
  `@readonly` or `@operator` preset (or a reason it is in neither), a row in the README tool
  table and tests against `fakeRouter`. Keep its description to what a model needs to call it
  (the refusal already prints the scope to grant), and stay inside the budget that
  `TestCatalogueStaysWithinBudget` pins; raising it needs a reason in the commit.
- **Changes that write configuration** go through the snapshot / arm / confirm path in
  `rollback.go`, never a bare `uci commit`.
- **Fixtures must not contain real data.** Use `192.168.1.x`, `10.x`, `aa:bb:cc:...` MACs,
  `example.com` hosts and placeholder keys. Never paste output from your own router unedited.
- Scripts that run on the router are POSIX `sh` for BusyBox ash, with LF line endings
  (`.gitattributes` enforces this).

Please describe what you tested on real hardware (board, OpenWrt release) in the PR.

## Adding an adapter

An adapter answers `service_list detail=<service>` for one add-on package. The tool list stays flat:
adapters are rows in a table, not tools.

1. **Write `read(ctx) string`** (a new `adapter_<name>.go`, or a row in `wave4` in `adapter_wave4.go`
   for a status-only proxy stack). Read only: commands are argv built by the code, never from the
   caller. Print fixed fields by name; never echo a config file or a command's output, because those
   hold keys, node links and tokens. An add-on that does not answer is a status line, not an error.
2. **Register it** in `adapters` in `adapters.go`, sorted by service name. The name is the init script
   (`/etc/init.d/<name>`); the "available here" line follows from it. Set `untrusted` when the output
   carries text someone else chose (a peer's host name, a lease description): clip it, pass it through
   `sanitizeText`, and name it there. Add a `query` only for a bounded lookup (a domain or an IP).
3. **Read the upstream project, not memory.** Take option names, runtime files and nft table names from the
   package's default config and init script, and say in the README row which version you checked.
   An adapter built from docs only is marked "source-checked", one run on a router "verified".
4. **Capture real output** when you can run the package: list the read-only commands in
   `testdata/capture/<service>.cmds` (a test keeps the file read-only and rejects anything that writes),
   run `ROUTER=root@host ./capture.sh <service> [host,names,to,hide]`, and read every file in
   `testdata/captured/<service>/` before committing. Test against the capture in `captured_test.go`-style
   tests; add a synthetic fixture only for states you could not produce, and say so in the test.
5. **Add findings** only for a state that is wrong whatever the operator intended. A finding is a
   `check*` function in `findings_addons.go` registered in `healthFindings` (`health.go`, the doctor) or in `auditFindings` (`securityaudit.go`), with a
   `findingHints` entry that names the tool to call next. Add the README row and a CHANGELOG line.
6. **Wire the shared views** if the add-on listens for DNS (`dnsOwners` in `netpath.go`), marks packets
   (`markowners.go`) or opens a port (`securityexposure_auth.go`). Otherwise `dns_path` still names the
   process behind an unclaimed local port, and the exposure view lists it without a login note.

## Releasing (maintainers)

1. Set `version` in `main.go` and in `server.json` to `X.Y.Z` (a test checks that they match).
2. Rename `## Unreleased` in `CHANGELOG.md` to `## X.Y.Z -- <name>`.
3. Commit, tag `vX.Y.Z` and push the tag.

The `release` workflow then:

- refuses a tag that does not match `main.go`, or a version with no CHANGELOG section;
- runs the tests;
- builds every architecture `install.sh` supports and packs each binary with `files/`;
- writes `SHA256SUMS` and attests the build;
- publishes the release with that CHANGELOG section as notes.

To release a tag that already exists, run the workflow by hand with the tag as input.
