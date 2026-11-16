#!/bin/sh
# Build the apk (v3) package for one architecture from a release archive.
#   build.sh APKTOOLS ARCHIVE APK_ARCH OUT.apk
# APKTOOLS  apk-tools 3 with mkpkg (Alpine's `apk`; the router's apk has none)
# ARCHIVE   openwrt-mcp_X.Y.Z_linux_<label>.tar.gz from the release (binary + files/ payload)
# APK_ARCH  the router's DISTRIB_ARCH, e.g. x86_64 or aarch64_cortex-a53
# The version comes from the archive name. No signature: sign the feed index, or install with
# --allow-untrusted for a single file.
set -eu
# Files must be owned by root in the package, so run this as root: in an Alpine container it is
#   docker run --rm -v "$PWD:/w" -w /w alpine:3.23 sh packaging/apk/build.sh apk dist/X.tar.gz ARCH dist/X.apk
[ "$(id -u)" = 0 ] || { echo "run as root (owners go into the package)" >&2; exit 2; }
[ $# -eq 4 ] || { sed -n '2,8p' "$0" >&2; exit 2; }
apk=$1 archive=$2 arch=$3 out=$4
here=$(cd "$(dirname "$0")" && pwd)
ver=$(basename "$archive" | sed -n 's/^openwrt-mcp_\([0-9][0-9.]*\)_linux_.*\.tar\.gz$/\1/p')
[ -n "$ver" ] || { echo "cannot read the version from $archive" >&2; exit 2; }
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
tar -xzf "$archive" -C "$stage"
# apk protects everything under /etc by itself (an edited file stays, the new one lands as .apk-new).
chmod 0600 "$stage/etc/config/openwrt-mcp"
"$apk" mkpkg \
	--info "name:openwrt-mcp" \
	--info "version:$ver-r1" \
	--info "arch:$arch" \
	--info "description:MCP server for OpenWrt: policies, audited tools, approval from LuCI" \
	--info "url:https://github.com/stanislav-testhub/openwrt-mcp" \
	--info "license:MIT" \
	--script "post-install:$here/post-install" \
	--script "post-upgrade:$here/post-install" \
	--script "pre-deinstall:$here/pre-deinstall" \
	--files "$stage" --output "$out"
