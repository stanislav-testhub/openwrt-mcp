#!/bin/sh
# footprint of an idle daemon, after calls, and of one bridge. Needs /tmp/owm.
# Usage: copy the binary to /tmp/owm on a test router or VM, then: sh footprint.sh (ROADMAP 10.1).
# Prints VmRSS, VmHWM and RssAnon of the idle daemon, of one bridge, and of the daemon after the calls. Uses its own config and state under /tmp/fp.
D=/tmp/fp; rm -rf $D; mkdir -p $D/state
printf "config server\n\toption listen '127.0.0.1:18730'\n\toption socket '$D/mcp.sock'\n\toption audit '$D/audit.jsonl'\n" > $D/config
O="/tmp/owm -config $D/config -state $D/state"
mem() { grep -E '^(VmRSS|VmHWM|RssAnon)' /proc/$1/status | tr -s ' \t\n' ' '; echo; }
$O serve >$D/serve.log 2>&1 & S=$!
n=0; while [ ! -S $D/mcp.sock ] && [ $n -lt 10 ]; do sleep 1; n=$((n+1)); done
echo "daemon idle:        $(mem $S)"
$O allow fp @readonly 1h >/dev/null
# one bridge: initialize, list tools, call system_status, kept open briefly
( printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fp","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/initialized"}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"system_status","arguments":{}}}'; sleep 3 ) | $O stdio --client fp >$D/bridge.out 2>$D/bridge.err &
sleep 2
B=$(pgrep -f "owm .*stdio --client fp" | head -1)
echo "bridge (1 session): $(mem $B)"
echo "daemon after calls: $(mem $S)"
echo "bridge replies: $(grep -c result $D/bridge.out)"
sleep 2
kill $S 2>/dev/null
