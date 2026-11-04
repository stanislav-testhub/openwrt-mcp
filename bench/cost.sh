#!/bin/sh
# Measured cost of three everyday tasks: through openwrt-mcp and through raw SSH shell commands.
# ROADMAP 3.11. It counts calls and the bytes the model would read and write (what it sends plus what
# comes back). It does not count tokens: that needs a tokenizer or a live model, and a figure here is
# never an estimate.
#
# Run it only against a disposable OpenWrt (a VM or a spare router), never a router people use:
# task 2 adds a second WAN (a bridge no DHCP server answers on) and removes it again, task 3 adds
# and removes a static lease.
#
#   RAW='ssh -i rootkey root@target' MCP='ssh -T -i mcpkey root@target' sh bench/cost.sh
#
# RAW is an ssh command that gives a root shell. MCP is the forced-command ssh line of a client that
# holds @operator (openwrt-mcp allow <client> @operator 1h). Both are word-split, so keep them simple.
# The fixture is synthetic: six DHCP leases and neighbours on br-lan, written to /tmp on the target.
set -eu

: "${RAW:?set RAW to an ssh command with a root shell on the target}"
: "${MCP:?set MCP to the forced-command ssh line of an @operator client}"
LAN_DEV=${LAN_DEV:-br-lan}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
calls=0 out_total=0 in_total=0
rows=

# raw CMD: one shell call. Counts the command and its output.
raw() {
	calls=$((calls + 1))
	in_total=$((in_total + $(printf '%s' "$1" | wc -c)))
	$RAW "$1" >"$tmp/o" 2>&1 || true
	out_total=$((out_total + $(wc -c <"$tmp/o")))
}
# mcp TOOL JSON: one tool call. Counts the tool name, the arguments and the reply (stdout and stderr).
mcp() {
	calls=$((calls + 1))
	in_total=$((in_total + $(printf '%s%s' "$1" "$2" | wc -c)))
	$MCP call "$1" "$2" >"$tmp/o" 2>&1 || true
	out_total=$((out_total + $(wc -c <"$tmp/o")))
	LAST=$tmp/o
}
row() { # NAME
	rows="$rows$(printf '%-34s %5d %9d %9d' "$1" "$calls" "$in_total" "$out_total")
"
	calls=0 out_total=0 in_total=0
}

# ---- fixture
now=$(date +%s)
$RAW "i=0; : >/tmp/dhcp.leases; while [ \$i -lt 6 ]; do i=\$((i+1)); echo \"\$((${now}+3600)) 02:00:00:00:00:0\$i 192.168.1.\$((100+i)) host\$i 01:02:00:00:00:00:0\$i\" >>/tmp/dhcp.leases; ip neigh replace 192.168.1.\$((100+i)) lladdr 02:00:00:00:00:0\$i dev $LAN_DEV nud reachable; done"

# ---- tool catalogue: what an MCP client loads once per session
{
	printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bench","version":"0"}}}'
	printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
	printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
	sleep 4
} | $MCP >"$tmp/list" 2>/dev/null || true
catalogue=$(grep '"id":2' "$tmp/list" | head -n1 | wc -c)

# ---- task 1: who is on my network
mcp network_clients '{}'
row "1 clients      openwrt-mcp"
raw 'cat /tmp/dhcp.leases; ip neigh show'
row "1 clients      raw ssh"

# ---- task 2: why is the second WAN down (DHCP gets no answer)
$RAW "ip link add name bench0 type bridge; ip link set bench0 up; uci set network.benchwan=interface; uci set network.benchwan.proto=dhcp; uci set network.benchwan.device=bench0; uci commit network; ifup benchwan"
$RAW "n=0; while [ \$n -lt 20 ] && ! logread | grep -q 'benchwan.*udhcpc\|udhcpc.*bench0'; do n=\$((n+1)); sleep 1; done"
mcp system_status '{}'
mcp logread '{"mode":"summary","since_minutes":30}'
row "2 wan down     openwrt-mcp"
raw 'ifstatus benchwan'
raw 'ip route show; ip addr show dev bench0'
raw 'logread | tail -n 30'
row "2 wan down     raw ssh"
$RAW "ifdown benchwan; uci delete network.benchwan; uci commit network; ip link del bench0"

# ---- task 3: add a static lease, then remove it (the MCP side follows the tool's own advice:
# dry run, apply, confirm; the raw side commits and verifies in one call each way)
lease='{"changes":[{"config":"dhcp","section":"bench","op":"create","type":"host"},{"config":"dhcp","section":"bench","option":"mac","value":"02:00:00:00:00:99"},{"config":"dhcp","section":"bench","option":"ip","value":"192.168.1.199"}]}'
mcp uci_apply "$(printf '%s' "$lease" | sed 's/^{/{"dry_run":true,/')"
mcp uci_apply "$lease"
tok=$(sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' "$LAST" | head -n1)
mcp uci_confirm "{\"token\":\"$tok\"}"
mcp uci_apply '{"changes":[{"config":"dhcp","section":"bench","op":"delete"}]}'
tok=$(sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' "$LAST" | head -n1)
mcp uci_confirm "{\"token\":\"$tok\"}"
row "3 lease add+del openwrt-mcp"
raw 'uci add dhcp host >/dev/null; uci rename dhcp.@host[-1]=bench; uci set dhcp.bench.mac=02:00:00:00:00:99; uci set dhcp.bench.ip=192.168.1.199; uci commit dhcp; /etc/init.d/dnsmasq reload; uci show dhcp.bench'
raw 'uci delete dhcp.bench; uci commit dhcp; /etc/init.d/dnsmasq reload; uci show dhcp | grep -c bench'
row "3 lease add+del raw ssh"

$RAW "rm -f /tmp/dhcp.leases"

printf '%-34s %5s %9s %9s\n' task calls sent received
printf '%s' "$rows"
printf 'tool catalogue (tools/list reply, loaded once per MCP session): %d bytes\n' "$catalogue"
