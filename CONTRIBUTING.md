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
