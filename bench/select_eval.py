#!/usr/bin/env python3
"""Tool-selection check: does a model pick the right openwrt-mcp tool (and the key argument) for a plain request?

Compares tools/list catalogues, for example the same server before and after a description trim (ROADMAP 3.5/3.11).
It measures what the catalogue's words do to the choice, not how well a given model reasons. The numbers belong to
the model used and say nothing about another one. The questions are synthetic: no address, name or key of a real network.

  DEEPSEEK_KEY_FILE=path python3 bench/select_eval.py NAME=catalogue.json [NAME=catalogue.json ...]

A catalogue is the JSON array `tools/list` returns under "tools". The key is read from the file and never printed.
Env: MODEL (default deepseek-flash), RUNS (default 1), BASE (default https://api.deepseek.com).
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("BASE", "https://api.deepseek.com")
MODEL = os.environ.get("MODEL", "deepseek-flash")
RUNS = int(os.environ.get("RUNS", "1"))
SYSTEM = "You operate one OpenWrt router through the tools given. Answer each request by calling the single best tool."


def key():
    with open(os.environ["DEEPSEEK_KEY_FILE"]) as f:
        return f.read().strip()


def call(k, tools, question):
    body = {"model": MODEL, "temperature": 0, "tool_choice": "auto",
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}],
            "tools": [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""),
                                                        "parameters": t["inputSchema"]}} for t in tools]}
    req = urllib.request.Request(BASE + "/chat/completions", json.dumps(body).encode(),
                                 {"Authorization": "Bearer " + k, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        res = json.load(r)
    msg = res["choices"][0]["message"]
    calls = msg.get("tool_calls") or []
    usage = res.get("usage", {})
    if not calls:
        return None, {}, usage
    fn = calls[0]["function"]
    try:
        args = json.loads(fn.get("arguments") or "{}")
    except ValueError:
        args = {}
    return fn["name"], args, usage


def matches(want, args):
    for k, v in want.items():
        got = args.get(k)
        if isinstance(v, str):
            if not isinstance(got, str) or v.lower() not in got.lower():
                return False
        elif got != v:
            return False
    return True


def main():
    sets = [a.split("=", 1) for a in sys.argv[1:]]
    if not sets:
        sys.exit(__doc__)
    k = key()
    qs = json.load(open(os.path.join(HERE, "select_questions.json")))
    results = {}
    for name, path in sets:
        tools = json.load(open(path))
        tool_ok = arg_ok = n = prompt = 0
        misses = []
        for q in qs:
            for _ in range(RUNS):
                n += 1
                got, args, usage = call(k, tools, q["q"])
                prompt += usage.get("prompt_tokens", 0)
                t = got == q["tool"]
                a = t and matches(q.get("args", {}), args)
                tool_ok += t
                arg_ok += a
                if not a:
                    misses.append((q["q"], q["tool"], got, args if t else ""))
        results[name] = (tool_ok, arg_ok, n, prompt // max(1, n), misses)
    print("%-10s %12s %12s %14s" % ("catalogue", "right tool", "right args", "prompt tokens"))
    for name, (t, a, n, p, _) in results.items():
        print("%-10s %9d/%-3d %9d/%-3d %14d" % (name, t, n, a, n, p))
    for name, (_, _, _, _, misses) in results.items():
        for q, want, got, args in misses:
            print("MISS %s: %r wanted %s, got %s %s" % (name, q, want, got, json.dumps(args) if args else ""))


main()
