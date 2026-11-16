#!/bin/sh
# install.sh upgrade, against a fake ssh: it must install only when the router says a newer release exists (or
# cannot say), and never when the router is current or cannot reach GitHub.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/ssh" <<'FAKE'
#!/bin/sh
# Last argument is the remote command. `sh -s` is the installer being fed; anything else is the version check.
for a; do last=$a; done
case "$last" in
	*"version --check"*) printf '%s\n' "$FAKE_OUT"; exit "${FAKE_RC:-0}" ;;
	*) cat >/dev/null; : > "$FAKE_MARK" ;;
esac
FAKE
chmod +x "$tmp/ssh"

run() { # run <rc> <output> -> sets $rc and whether the installer ran in $installed
	rm -f "$tmp/mark"
	rc=0
	PATH="$tmp:$PATH" FAKE_RC=$1 FAKE_OUT=$2 FAKE_MARK="$tmp/mark" sh "$here/install.sh" upgrade >"$tmp/out" 2>&1 || rc=$?
	if [ -e "$tmp/mark" ]; then installed=yes; else installed=no; fi
}
fail() { echo "FAIL: $1" >&2; cat "$tmp/out" >&2; exit 1; }

run 0 "openwrt-mcp 1.7.0
up to date (latest release v1.7.0)"
[ "$rc" = 0 ] && [ "$installed" = no ] || fail "current router must not be reinstalled"

run 0 "openwrt-mcp 1.7.0
newer release: v1.8.0 (you run 1.7.0)"
[ "$rc" = 0 ] && [ "$installed" = yes ] || fail "newer release must be installed"

run 0 "openwrt-mcp 1.7.0"
[ "$rc" = 0 ] && [ "$installed" = yes ] || fail "a daemon that cannot check must get the latest release"

run 1 "openwrt-mcp 1.8.0
could not check for a newer release: no route to host"
[ "$rc" != 0 ] && [ "$installed" = no ] || fail "a failed check must not install, and must fail"
grep -q 'could not ask' "$tmp/out" || fail "a failed check must say so"
echo "install.sh upgrade: ok"
