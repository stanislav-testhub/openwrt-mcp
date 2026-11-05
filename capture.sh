#!/bin/sh
# Capture the outputs an add-on adapter reads from a real router, scrubbed, as fixtures
# (ROADMAP 9.2). Usage:
#   ROUTER=root@192.168.1.1 [SSH_PORT=22] [SSH_KEY=...] ./capture.sh SERVICE [host,names,to,hide]
# Runs exactly the read-only commands in testdata/capture/SERVICE.cmds (a test keeps that file
# read-only), pipes each output through `openwrt-mcp scrub` and writes
# testdata/captured/SERVICE/NN.txt. Review the files before committing: the scrubber removes
# addresses, MACs, the host names you list and the usual secret shapes, not everything.
set -eu
svc=${1:?service name}
hosts=${2:-}
ROUTER=${ROUTER:?set ROUTER=root@host}
list="testdata/capture/$svc.cmds"
[ -f "$list" ] || { echo "no $list" >&2; exit 2; }
go build -tags capture -o /tmp/openwrt-mcp-scrub . || exit 1
out="testdata/captured/$svc"
mkdir -p "$out"
n=0
while IFS= read -r cmd; do
	case "$cmd" in ''|'#'*) continue ;; esac
	n=$((n + 1))
	f=$(printf '%s/%02d.txt' "$out" "$n")
	{ printf '# %s\n' "$cmd"
	  ssh -o BatchMode=yes -p "${SSH_PORT:-22}" ${SSH_KEY:+-i "$SSH_KEY"} "$ROUTER" "$cmd" 2>&1 \
		| /tmp/openwrt-mcp-scrub scrub -hosts "$hosts"
	} > "$f" || { echo "scrub refused $f; remove it and look at the command" >&2; rm -f "$f"; exit 1; }
	echo "wrote $f"
done < "$list"
