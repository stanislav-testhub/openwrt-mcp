#!/bin/bash
# Tests install-router.sh's download and verification (fetch_release) against a local mirror of
# a release, served over HTTP. The installing half needs a router; this half does not.
# Expected values follow the release layout (latest/download/<f>, download/vX.Y.Z/<f>) and the
# script's documented refusals, not its code. Needs bash, curl, tar, sha256sum and python3.
#
#   bash install-router_test.sh            SCRIPT=<other copy> to test a modified installer
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${SCRIPT:-$HERE/install-router.sh}
PY=$(command -v python3 || command -v python)
T=$(mktemp -d)
M=$T/mirror
mkdir -p "$M/download/v1.2.0" "$M/latest/download" "$T/shim"

# One archive per label: the real payload tree, and a stand-in binary that names its label,
# so an archive swapped for another architecture is detectable.
for label in arm64 amd64 mipsle_softfloat; do
	stage=$T/pack
	rm -rf "$stage" && mkdir -p "$stage/usr/bin"
	(cd "$HERE/files" && tar -cf - .) | (cd "$stage" && tar -xf -)
	printf '\177ELF %s\n' "$label" > "$stage/usr/bin/openwrt-mcp"
	tar -C "$stage" -czf "$M/download/v1.2.0/openwrt-mcp_1.2.0_linux_$label.tar.gz" .
done
rm -rf "$T/pack"
(cd "$M/download/v1.2.0" && sha256sum -- *.tar.gz > SHA256SUMS)
# Both line formats sha256sum writes: text mode ("hash  file") and, for mipsle, binary mode
# ("hash *file"). Normalised here because sha256sum picks the mode by platform.
sed -i -e 's/ [ *]openwrt-mcp_/  openwrt-mcp_/' -e 's/  \(openwrt-mcp_[0-9.]*_linux_mipsle_softfloat\)/ *\1/' \
	"$M/download/v1.2.0/SHA256SUMS"
cp "$M/download/v1.2.0/SHA256SUMS" "$M/latest/download/"

# The router's wget is uclient-fetch: -q -O FILE URL.
cat > "$T/shim/wget" <<'EOF'
#!/bin/sh
while [ $# -gt 1 ]; do case "$1" in -q) shift ;; -O) out=$2; shift 2 ;; *) break ;; esac; done
curl -fs -o "$out" "$1"
EOF
chmod +x "$T/shim/wget"

PORT=$("$PY" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
"$PY" -m http.server "$PORT" --bind 127.0.0.1 --directory "$M" >/dev/null 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$T"' EXIT
for _ in $(seq 30); do curl -fs "http://127.0.0.1:$PORT/latest/download/SHA256SUMS" >/dev/null && break; sleep 0.2; done

pass=0 fail=0
check() { if [ "$1" = "$2" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL $3: got [$1] want [$2]"; fi; }

# fetch STAGE LABEL [VAR=value...]: run fetch_release in its own shell, print its exit status.
# The script sets -e, so the status is taken with && / || rather than $? after the call.
fetch() {
	stage=$1 label=$2
	shift 2
	(
		export PATH="$T/shim:$PATH" RELEASES=${RELEASES:-http://127.0.0.1:$PORT} INSTALL_ROUTER_LIB=1 "$@"
		# shellcheck disable=SC1090
		. "$SCRIPT"
		S=$stage
		(fetch_release "$label") >"$T/out" 2>&1 && echo 0 || echo $?
	)
}

st=$(fetch "$T/s1" mipsle_softfloat)
check "$st" 0 "latest: exit status"
check "$(cat "$T/out")" "verified openwrt-mcp_1.2.0_linux_mipsle_softfloat.tar.gz" "latest: message"
check "$(cat "$T/s1/usr/bin/openwrt-mcp" 2>/dev/null)" "$(printf '\177ELF mipsle_softfloat')" "latest: the binary for this label"
check "$([ -f "$T/s1/etc/init.d/openwrt-mcp" ] && [ ! -e "$T/s1/dl" ] && echo ok)" ok "latest: payload unpacked, downloads gone"

st=$(fetch "$T/s2" arm64 VERSION=v1.2.0)
check "$st" 0 "pinned version: exit status"
check "$(cat "$T/out")" "verified openwrt-mcp_1.2.0_linux_arm64.tar.gz" "pinned version: message"

st=$(fetch "$T/s3" arm64 VERSION=v1.2)
check "$st" 1 "malformed VERSION: refused"
check "$(cat "$T/out")" "install-router: VERSION must look like v1.2.3, not 'v1.2'" "malformed VERSION: message"

st=$(fetch "$T/s4" sparc)
check "$st" 1 "no archive for the label: refused"
check "$(cat "$T/out")" "install-router: the release has no archive for 'sparc'" "no archive for the label: message"
check "$([ -e "$T/s4" ] && echo left || echo gone)" gone "no archive for the label: stage removed"

st=$(RELEASES=http://127.0.0.1:$PORT/nope fetch "$T/s5" amd64)
check "$st" 1 "no SHA256SUMS: refused"
check "$(tail -n 1 "$T/out")" "install-router: download failed: http://127.0.0.1:$PORT/nope/latest/download/SHA256SUMS" "no SHA256SUMS: message"

# A valid archive for another architecture, put in place after SHA256SUMS was written.
cp "$M/download/v1.2.0/openwrt-mcp_1.2.0_linux_arm64.tar.gz" "$M/download/v1.2.0/openwrt-mcp_1.2.0_linux_amd64.tar.gz"
st=$(fetch "$T/s6" amd64)
check "$st" 1 "swapped archive: refused"
check "$(tail -n 1 "$T/out")" "install-router: checksum mismatch for openwrt-mcp_1.2.0_linux_amd64.tar.gz: not installing" "swapped archive: message"
check "$([ -e "$T/s6" ] && echo left || echo gone)" gone "swapped archive: nothing left to install"

echo "install-router: $pass passed, $fail failed"
[ "$fail" = 0 ]
