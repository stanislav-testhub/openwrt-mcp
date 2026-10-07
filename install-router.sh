#!/bin/sh
# Install or upgrade openwrt-mcp on this router. Run it ON the router (OpenWrt 25.12+); it
# needs nothing beyond a default image (wget is uclient-fetch, with ca-bundle).
#
#   wget -O /tmp/install-router.sh https://github.com/stanislav-testhub/openwrt-mcp/releases/latest/download/install-router.sh
#   sh /tmp/install-router.sh
#
#   VERSION=v1.2.0 sh install-router.sh   a given release instead of the latest
#   FORCE=1 sh install-router.sh          restart even though a uci_apply awaits confirmation
#
# It downloads the archive for this router's architecture and the release's SHA256SUMS,
# refuses on a checksum mismatch, then installs. install.sh runs it too, with PAYLOAD=<dir>
# naming a payload it built and unpacked there, so there is one install procedure.
set -eu

REPO=stanislav-testhub/openwrt-mcp
RELEASES=${RELEASES:-https://github.com/$REPO/releases}
S=${PAYLOAD:-/tmp/openwrt-mcp-inst}
FORCE=${FORCE:-0}

die() {
	echo "install-router: $*" >&2
	rm -rf "$S"
	exit 1
}

# The release archive label for this router. Keep in step with go_target in install.sh and
# the target list in .github/workflows/release.yml (CI compares them).
arch_label() {
	# shellcheck disable=SC1091
	. /etc/openwrt_release
	case "$DISTRIB_ARCH" in
		aarch64_*)        echo arm64 ;;
		x86_64)           echo amd64 ;;
		i386_*)           echo 386 ;;
		arm_cortex-a7*|arm_cortex-a9*|arm_cortex-a15*) echo armv7 ;;
		arm_*)            echo armv5 ;;
		mipsel_*)         echo mipsle_softfloat ;;
		mips_*)           echo mips_softfloat ;;
		mips64el_*)       echo mips64le ;;
		mips64_*)         echo mips64 ;;
		riscv64_*)        echo riscv64 ;;
		*) die "unsupported router architecture '$DISTRIB_ARCH'" ;;
	esac
}

# fetch_release LABEL: download and verify the archive for LABEL, unpack it into $S.
fetch_release() {
	case "${VERSION:-}" in
		"") sums_url=$RELEASES/latest/download/SHA256SUMS ;;
		v[0-9]*.[0-9]*.[0-9]*) sums_url=$RELEASES/download/$VERSION/SHA256SUMS ;;
		*) die "VERSION must look like v1.2.3, not '$VERSION'" ;;
	esac
	rm -rf "$S" && mkdir -p "$S/dl"
	wget -q -O "$S/dl/SHA256SUMS" "$sums_url" || die "download failed: $sums_url"
	file=$(grep -o "openwrt-mcp_[0-9.]*_linux_$1\.tar\.gz" "$S/dl/SHA256SUMS" | head -n 1) || true
	[ -n "$file" ] || die "the release has no archive for '$1'"
	ver=${file#openwrt-mcp_}
	ver=${ver%%_*}
	wget -q -O "$S/dl/$file" "$RELEASES/download/v$ver/$file" || die "download failed: $file"
	# "hash  file" (text mode) or "hash *file" (binary mode); sha256sum -c reads both.
	sum=$(grep -E "^[0-9a-f]{64} [ *]$file\$" "$S/dl/SHA256SUMS") || die "SHA256SUMS has no line for $file"
	(cd "$S/dl" && echo "$sum" | sha256sum -c - >/dev/null) || die "checksum mismatch for $file: not installing"
	tar -xzf "$S/dl/$file" -C "$S" || die "cannot unpack $file"
	rm -rf "$S/dl"
	echo "verified $file"
}

install_payload() {
	[ -f "$S/usr/bin/openwrt-mcp" ] || die "no binary in $S"
	# The binary is written beside the running one before the rename, so its size must fit.
	need=$(($(wc -c < "$S/usr/bin/openwrt-mcp") / 1024 + 256))
	avail=$(df -Pk /usr/bin | awk 'NR == 2 { print $4 }')
	[ "$avail" -ge "$need" ] || die "not enough space: $need KiB needed on /usr/bin's filesystem, $avail KiB free"

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
}

main() {
	if [ -s /etc/openwrt-mcp/pending.json ] && [ "$FORCE" != 1 ]; then
		echo "refusing: a uci_apply awaits confirmation, and restarting the daemon would roll it back." >&2
		die "confirm or roll it back first, or rerun with FORCE=1."
	fi
	if [ -z "${PAYLOAD:-}" ]; then
		label=$(arch_label) || exit 1
		fetch_release "$label"
	fi
	install_payload
}

# Tests source this file with INSTALL_ROUTER_LIB=1 to call the functions on their own.
[ -n "${INSTALL_ROUTER_LIB:-}" ] || main
