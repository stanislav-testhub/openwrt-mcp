#!/bin/bash
# Runs the example push hooks against a local stand-in for Telegram and ntfy, with uci and
# jsonfilter replaced by shims, so no router, token or network is involved. Needs bash, curl and python3.
#   bash examples/hooks/hooks_test.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'kill $SRV 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/shim"
cat > "$T/shim/uci" <<'S'
#!/bin/sh
[ "$1" = -q ] && shift
[ "$1" = get ] || exit 1
case "$2" in
*.telegram_bot_token) [ -n "${T_TOKEN-}" ] && echo "$T_TOKEN" ;;
*.telegram_chat_id)   [ -n "${T_CHAT-}" ] && echo "$T_CHAT" ;;
*.ntfy_url)           [ -n "${T_NTFY-}" ] && echo "$T_NTFY" ;;
esac
exit 0
S
cat > "$T/shim/jsonfilter" <<'S'
#!/usr/bin/env python3
import json, sys
k = sys.argv[2].lstrip("@.")
v = json.load(sys.stdin).get(k)
if v is not None: print(v)
S
chmod +x "$T/shim/"*
cat > "$T/srv.py" <<'S'
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        open(sys.argv[2], "a").write(json.dumps({"path": self.path, "title": self.headers.get("Title"), "body": body}) + "\n")
        self.send_response(500 if "fail" in self.path else 200); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
S
LOG=$T/log; : > "$LOG"
python3 "$T/srv.py" 18999 "$LOG" & SRV=$!
for i in 1 2 3 4 5 6 7 8 9 10; do curl -s -o /dev/null http://127.0.0.1:18999/ -X POST && break; sleep 0.3; done
: > "$LOG"
REQ='{"event":"request","id":"abc123","client":"claude-server","tool":"uci_apply","scope":"network","args":"x","expires":"2026-11-08T10:00:00Z"}'
pass=0; failn=0
ok() { if eval "$2"; then pass=$((pass+1)); else failn=$((failn+1)); echo "FAIL: $1"; fi; }
export PATH="$T/shim:$PATH" TELEGRAM_API=http://127.0.0.1:18999

T_TOKEN=123:SECRETTOKEN T_CHAT=42 sh "$HERE/telegram" <<<"$REQ"; rc=$?
ok "telegram: delivered, exit 0" '[ $rc = 0 ]'
ok "telegram: bot path carries the token" 'grep -q "/bot123:SECRETTOKEN/sendMessage" "$LOG"'
dec() { python3 -c 'import json,sys,urllib.parse as u;[print(u.unquote_plus(json.loads(l)["body"])) for l in open(sys.argv[1])]' "$LOG"; }
ok "telegram: names client, tool and scope" 'dec | grep -q "claude-server asks for uci_apply on network"'
ok "telegram: chat id sent" 'grep -q "chat_id=42" "$LOG"'
ok "telegram: points at LuCI, request id included" 'dec | grep -q "abc123" && dec | grep -q "LuCI"'
ok "telegram: the token never reaches the message body" '! dec | grep -q SECRETTOKEN'

sh "$HERE/telegram" <<<"$REQ" 2>/dev/null; rc=$?
ok "telegram: no credentials -> exit 3" '[ $rc = 3 ]'

T_TOKEN=fail:x T_CHAT=42 sh "$HERE/telegram" <<<"$REQ"; rc=$?
ok "telegram: HTTP 500 is a failure" '[ $rc != 0 ]'

: > "$LOG"
T_NTFY=http://127.0.0.1:18999/topic-xyz sh "$HERE/ntfy" <<<"$REQ"; rc=$?
ok "ntfy: delivered, exit 0" '[ $rc = 0 ]'
ok "ntfy: posted to the topic with a title" 'grep -q "/topic-xyz" "$LOG" && grep -q "openwrt-mcp request" "$LOG"'
ok "ntfy: names client and tool" 'grep -q "claude-server asks for uci_apply on network" "$LOG"'
sh "$HERE/ntfy" <<<"$REQ" 2>/dev/null; rc=$?
ok "ntfy: no topic -> exit 3" '[ $rc = 3 ]'
echo "$pass passed, $failn failed"; [ $failn = 0 ]
