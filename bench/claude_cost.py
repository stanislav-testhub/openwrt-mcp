#!/usr/bin/env python3
"""What a tool catalogue costs a Claude model, and whether the model still picks the right tool (ROADMAP 3.11).

It needs the `claude` CLI signed in (a subscription is enough: no API key, and none is read). Nothing here touches a
router: bench/stub_mcp.py serves a recorded tools/list and answers every call with a fixed line.

  OWM_CATALOGUE_OUT=/tmp/catalogue.json go test -run TestDumpCatalogue .     # record the catalogue
  python3 bench/claude_cost.py cost   /tmp/catalogue.json
  python3 bench/claude_cost.py select /tmp/catalogue.json

cost    runs the same one-word prompt twice per model, with the server and without it; the difference in input
        tokens is what the catalogue (names, descriptions, input schemas) adds to every conversation. The count
        comes from the usage the API reports for the real run, in the model's own tokenizer, so it is measured.
select  gives 29 plain requests (bench/select_questions.json) to the model with only the catalogue's tools, and
        checks the first tool it calls, as bench/select_eval.py does for DeepSeek.

Env: MODELS (default "claude-haiku-5-5,claude-sonnet-5-5"), RUNS (cost: default 2). `claude` is run without
CLAUDECODE and ANTHROPIC_API_KEY so that a run started from inside a Claude Code session uses its own login, and with
ENABLE_TOOL_SEARCH=false so every tool is in the context, not looked up on demand. Built-in tools are turned off.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from select_eval import matches  # noqa: E402

MODELS = os.environ.get("MODELS", "claude-haiku-5-5,claude-sonnet-5-5").split(",")
RUNS = int(os.environ.get("RUNS", "2"))
PREFIX = "mcp__openwrt__"


def claude(args, cwd):
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "ANTHROPIC_API_KEY")}
    env["ENABLE_TOOL_SEARCH"] = "false"
    p = subprocess.run(["claude", "-p"] + args + ["--strict-mcp-config", "--tools", "", "--no-session-persistence"],
                       cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    return p.stdout


def config(tmp, catalogue):
    with_path = os.path.join(tmp, "with.json")
    without_path = os.path.join(tmp, "without.json")
    with open(with_path, "w") as f:
        json.dump({"mcpServers": {"openwrt": {"command": sys.executable,
                                              "args": [os.path.join(HERE, "stub_mcp.py"), os.path.abspath(catalogue)]}}}, f)
    with open(without_path, "w") as f:
        json.dump({"mcpServers": {}}, f)
    return with_path, without_path


def total_input(out):
    u = json.loads(out)["usage"]
    return u["input_tokens"] + u["cache_creation_input_tokens"] + u["cache_read_input_tokens"]


def cost(catalogue):
    tools = json.load(open(catalogue))
    print("%d tools, %d bytes as tools/list sends them" % (len(tools), sum(len(json.dumps(t, separators=(",", ":"))) for t in tools)))
    with tempfile.TemporaryDirectory() as tmp:
        w, wo = config(tmp, catalogue)
        for model in MODELS:
            deltas = []
            for _ in range(RUNS):
                a = total_input(claude(["Reply with the single word ok.", "--model", model, "--output-format", "json", "--mcp-config", w], tmp))
                b = total_input(claude(["Reply with the single word ok.", "--model", model, "--output-format", "json", "--mcp-config", wo], tmp))
                deltas.append((a, b, a - b))
            print("%-20s with %s, without %s, catalogue adds %s input tokens" % (
                model, "/".join(str(d[0]) for d in deltas), "/".join(str(d[1]) for d in deltas), "/".join(str(d[2]) for d in deltas)))


def first_tool(out):
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "assistant":
            for c in e["message"]["content"]:
                if c.get("type") == "tool_use":
                    return c["name"].removeprefix(PREFIX), c.get("input", {})
    return None, {}


def select(catalogue):
    qs = json.load(open(os.path.join(HERE, "select_questions.json")))
    with tempfile.TemporaryDirectory() as tmp:
        w, _ = config(tmp, catalogue)
        for model in MODELS:
            tool_ok = arg_ok = 0
            misses = []
            for q in qs:
                got, args = first_tool(claude([q["q"], "--model", model, "--output-format", "stream-json", "--verbose", "--max-turns", "1",
                                               "--mcp-config", w, "--allowedTools", "mcp__openwrt"], tmp))
                t = got == q["tool"]
                a = t and matches(q.get("args", {}), args)
                tool_ok += t
                arg_ok += a
                if not a:
                    misses.append((q["q"], q["tool"], got, args if t else ""))
            print("%-20s right tool %d/%d, right args %d/%d" % (model, tool_ok, len(qs), arg_ok, len(qs)))
            for q, want, got, args in misses:
                print("  MISS %r wanted %s, got %s %s" % (q, want, got, json.dumps(args) if args else ""))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("cost", "select"):
        sys.exit(__doc__)
    {"cost": cost, "select": select}[sys.argv[1]](sys.argv[2])
