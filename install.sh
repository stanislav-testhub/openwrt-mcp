#!/bin/sh
# Build openwrt-mcp on this machine and install it on an OpenWrt 25.12 router over SSH.
#
#   ROUTER=root@192.168.1.1 [SSH_PORT=22] [SSH_KEY=~/.ssh/id_ed25519] ./install.sh install
#   ./install.sh uninstall [--purge]      stop, disable and remove (--purge: also config + state)
#   ./install.sh build                    cross-compile only, for the router's architecture
#   ./install.sh stage                    copy the binary to /tmp/openwrt-mcp on the router, nothing else
#
# Why a script and not a package: OpenWrt 25.12 installs .apk (apk-tools 3, ADB format), which
# needs the SDK or a host apk-tools with `mkpkg` to build and signs against the distribution
# keys -- the router's own apk has no mkpkg. The binary is CGO_ENABLED=0 static Go, so a plain
# file install loses nothing: /etc/config is preserved by sysupgrade, and the shipped
# /lib/upgrade/keep.d entry carries the rest across a firmware flash.
#
# Works from Linux, macOS and Git Bash on Windows (it needs go, ssh and tar on PATH). Nothing
# is needed on the router beyond what 25.12 ships.
set -eu

ROUTER=${ROUTER:-root@192.168.1.1}
SSH_PORT=${SSH_PORT:-22}
GO=${GO:-go}
SRC=$(cd "$(dirname "$0")" && pwd)

ssh_r() {
	# shellcheck disable=SC2086
	ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p "$SSH_PORT" ${SSH_KEY:+-i "$SSH_KEY"} "$ROUTER" "$@"
}

# Map the router's package architecture to a Go target. DISTRIB_ARCH is more precise than
# uname -m, which says "mips" for both endiannesses.
go_target() {
	arch=$(ssh_r '. /etc/openwrt_release; echo "$DISTRIB_ARCH"')
	case "$arch" in
		aarch64_*)        echo "GOARCH=arm64" ;;
		x86_64)           echo "GOARCH=amd64" ;;
		i386_*)           echo "GOARCH=386" ;;
		arm_cortex-a7*|arm_cortex-a9*|arm_cortex-a15*) echo "GOARCH=arm GOARM=7" ;;
		arm_*)            echo "GOARCH=arm GOARM=5" ;;
		mipsel_*)         echo "GOARCH=mipsle GOMIPS=softfloat" ;;
		mips_*)           echo "GOARCH=mips GOMIPS=softfloat" ;;
		mips64el_*)       echo "GOARCH=mips64le" ;;
		mips64_*)         echo "GOARCH=mips64" ;;
		riscv64_*)        echo "GOARCH=riscv64" ;;
		*) echo "unsupported router architecture '$arch'" >&2; exit 1 ;;
	esac
}

build() {
	target=$(go_target)
	echo "building for $target ($(ssh_r 'uname -m'))" >&2
	(cd "$SRC" && $GO vet ./... && $GO test ./...)
	# shellcheck disable=SC2086
	(cd "$SRC" && env CGO_ENABLED=0 GOOS=linux $target $GO build -trimpath -ldflags="-s -w" -o "$SRC/openwrt-mcp.bin" .)
	echo "$SRC/openwrt-mcp.bin"
}

payload() {
	stage=$(mktemp -d)
	mkdir -p "$stage/usr/bin"
	cp "$SRC/openwrt-mcp.bin" "$stage/usr/bin/openwrt-mcp"
	(cd "$SRC/files" && tar -cf - .) | (cd "$stage" && tar -xf -)
	(cd "$stage" && tar -czf - .)
	rm -rf "$stage"
}

install_remote() {
	payload | ssh_r 'rm -rf /tmp/openwrt-mcp-inst && mkdir -p /tmp/openwrt-mcp-inst && tar -xzf - -C /tmp/openwrt-mcp-inst'
	ssh_r "FORCE=${FORCE:-0} sh -s" <<'EOF'
set -e
S=/tmp/openwrt-mcp-inst
if [ -s /etc/openwrt-mcp/pending.json ] && [ "$FORCE" != 1 ]; then
	echo "refusing: a uci_apply awaits confirmation, and restarting the daemon would roll it back." >&2
	echo "confirm or roll it back first, or rerun with FORCE=1." >&2
	rm -rf "$S"; exit 1
fi
put() { # src dst mode -- write beside, then rename: a running binary cannot be overwritten
	mkdir -p "$(dirname "$2")"
	cp "$S/$1" "$2.new" && chmod "$3" "$2.new" && mv "$2.new" "$2"
}
put usr/bin/openwrt-mcp /usr/bin/openwrt-mcp 0755
put etc/init.d/openwrt-mcp /etc/init.d/openwrt-mcp 0755
if [ -f /etc/config/openwrt-mcp ]; then
	cmp -s "$S/etc/config/openwrt-mcp" /etc/config/openwrt-mcp || cp "$S/etc/config/openwrt-mcp" /etc/config/openwrt-mcp.default
else
	put etc/config/openwrt-mcp /etc/config/openwrt-mcp 0600
fi
put lib/upgrade/keep.d/openwrt-mcp /lib/upgrade/keep.d/openwrt-mcp 0644
put usr/share/luci/menu.d/luci-app-openwrt-mcp.json /usr/share/luci/menu.d/luci-app-openwrt-mcp.json 0644
put usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json /usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json 0644
put www/luci-static/resources/view/openwrt-mcp/status.js /www/luci-static/resources/view/openwrt-mcp/status.js 0644
mkdir -p /etc/openwrt-mcp && chmod 0700 /etc/openwrt-mcp
rm -rf "$S"

/etc/init.d/openwrt-mcp enable
/etc/init.d/openwrt-mcp restart
rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null || true
/etc/init.d/rpcd reload
sleep 1
openwrt-mcp version
openwrt-mcp status --audit 0
EOF
}

case "${1:-}" in
	build)
		build ;;
	stage)
		build >/dev/null
		ssh_r 'cat > /tmp/openwrt-mcp.new && chmod +x /tmp/openwrt-mcp.new && mv /tmp/openwrt-mcp.new /tmp/openwrt-mcp' < "$SRC/openwrt-mcp.bin"
		echo "staged at $ROUTER:/tmp/openwrt-mcp (not installed, gone after reboot)" ;;
	install)
		build >/dev/null
		install_remote ;;
	uninstall)
		ssh_r "PURGE=$([ "${2:-}" = --purge ] && echo 1 || echo 0) sh -s" <<'EOF'
[ -x /etc/init.d/openwrt-mcp ] && { /etc/init.d/openwrt-mcp stop; /etc/init.d/openwrt-mcp disable; }
rm -f /usr/bin/openwrt-mcp /etc/init.d/openwrt-mcp /lib/upgrade/keep.d/openwrt-mcp \
	/usr/share/luci/menu.d/luci-app-openwrt-mcp.json /usr/share/rpcd/acl.d/luci-app-openwrt-mcp.json
rm -rf /www/luci-static/resources/view/openwrt-mcp /var/run/openwrt-mcp
rm -f /tmp/luci-indexcache*; /etc/init.d/rpcd reload
sed -i '/openwrt-mcp stdio --client/d' /etc/dropbear/authorized_keys 2>/dev/null || true
if [ "$PURGE" = 1 ]; then
	rm -rf /etc/openwrt-mcp /etc/config/openwrt-mcp /etc/config/openwrt-mcp.default
	echo "removed, including policies, tokens, MFA secrets and the audit log"
else
	echo "removed; kept /etc/config/openwrt-mcp and /etc/openwrt-mcp (use --purge to delete)"
fi
EOF
		;;
	*)
		sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
		exit 2 ;;
esac
