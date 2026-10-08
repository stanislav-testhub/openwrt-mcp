package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultCmdTimeout = 30 * time.Second

// cmdRunner executes argv directly -- never through a shell -- so there is no quoting or
// injection surface regardless of what the model puts in the arguments. It is a variable so
// tests can stand in a fake router: the tools are then exercised end to end on a workstation
// that has no ubus, uci, apk or wg, on any OS.
var cmdRunner = execRunner

func execRunner(ctx context.Context, stdin *string, argv []string) (string, string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(*stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// run executes argv with the given timeout and returns stdout, followed by stderr if any.
func run(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
	return runWith(ctx, timeout, nil, argv...)
}

// runStdin is run() with input piped in. It exists for key material (`wg pubkey`,
// `wg set ... preshared-key /dev/stdin`): passing a secret as an argv element would expose
// it in /proc to every process on the box for the lifetime of the call.
func runStdin(ctx context.Context, timeout time.Duration, stdin string, argv ...string) (string, error) {
	return runWith(ctx, timeout, &stdin, argv...)
}

func runWith(ctx context.Context, timeout time.Duration, stdin *string, argv ...string) (string, error) {
	if timeout <= 0 {
		timeout = defaultCmdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, errOut, err := cmdRunner(ctx, stdin, argv)
	if e := strings.TrimSpace(errOut); e != "" {
		if out != "" {
			out += "\n"
		}
		out += e
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, withCode(codeTimeout, fmt.Errorf("timed out after %s", timeout))
	}
	return out, err
}

// runJSON runs argv and decodes its stdout as JSON into v.
func runJSON(ctx context.Context, v any, argv ...string) error {
	out, err := run(ctx, defaultCmdTimeout, argv...)
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(argv, " "), err, strings.TrimSpace(out))
	}
	if err := json.Unmarshal([]byte(out), v); err != nil {
		return fmt.Errorf("%s: unexpected output: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// sysRoot prefixes every file the tools read or write directly (leases, /proc, /sys,
// /etc/config, *.apk-new). "/" on the router; a fixture tree in tests.
var sysRoot = "/"

func sysPath(p string) string {
	if sysRoot == "/" {
		return p
	}
	return filepath.Join(sysRoot, filepath.FromSlash(p))
}

func readSys(p string) (string, error) {
	b, err := os.ReadFile(sysPath(p))
	return string(b), err
}

// maxResultBytes caps what any tool may return. A tool result lands in an agent's context
// window, so an unbounded one is a denial of service against the thing calling it. This is
// the backstop for output no structural pruning understands -- exec, logread, ubus replies
// that are one enormous object rather than long arrays.
const maxResultBytes = 64 << 10

func textResult(s string) *mcp.CallToolResult {
	if strings.TrimSpace(s) == "" {
		s = "(no output)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: capBytes(s, maxResultBytes)}}}
}

// errResultCoded is an error result that ends with its code line (errcode.go). Bounded like a
// result, since an error that carries a command's whole output can flood a context window just
// as well; the line is part of the bound, so nothing can cut it off.
func errResultCoded(s, line string) *mcp.CallToolResult {
	text := capBytes(s, maxResultBytes-len(line)-1) + "\n" + line
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// maxArrayElems is how many elements of a long array survive pruning.
const maxArrayElems = 16

// pruner collapses long arrays in a decoded ubus reply, counting what it drops so the
// caller can tell "nothing to prune" from "pruned to nothing".
//
// The motivating case: per-client time series (hostapd airtime, luci-rpc host hints on a
// busy network) where a single reply runs to 100 KB of numbers that answer no question
// anyone asked. Pruning the decoded tree rather than truncating the string keeps the result
// parseable, which is the entire point.
type pruner struct {
	maxElems int
	dropped  int
}

func (p *pruner) walk(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = p.walk(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = p.walk(e)
		}
		if len(t) > p.maxElems {
			n := len(t) - p.maxElems
			p.dropped += n
			// Full slice expression: never write the marker into the caller's backing array.
			return append(t[:p.maxElems:p.maxElems], fmt.Sprintf("...+%d more", n))
		}
		return t
	}
	return v
}

// pruneMinBytes is the size below which a reply is returned whole, however long its arrays.
//
// Not every array is a time series. `ubus call iwinfo devices` on a many-SSID router returns
// a list of interface names in a couple of hundred bytes: capping that at 16 discards a real
// interface and, once the notice is added, makes the reply longer. Pruning has to earn its
// data loss, and on a reply small enough to read whole it never can.
const pruneMinBytes = 8 << 10

// pruneUbusJSON shortens long arrays in a ubus reply. Non-JSON output (ubus error text),
// small replies, and replies with nothing to prune are returned untouched, so the common
// case is byte-for-byte what ubus printed.
func pruneUbusJSON(out string) string {
	if len(out) < pruneMinBytes {
		return out
	}
	var v any
	if json.Unmarshal([]byte(out), &v) != nil {
		return out
	}
	p := &pruner{maxElems: maxArrayElems}
	pruned := p.walk(v)
	if p.dropped == 0 {
		return out
	}
	b, err := json.MarshalIndent(pruned, "", "\t")
	if err != nil {
		return out
	}
	res := fmt.Sprintf("%s\n\n%s", b, truncNotice(fmt.Sprintf("%d array element(s) dropped", p.dropped),
		fmt.Sprintf("arrays capped at %d, %d -> %d bytes; use a narrower ubus method for the full series",
			maxArrayElems, len(out), len(b))))
	// Belt and braces: re-indenting and the notice itself can outweigh what pruning saved.
	if len(res) >= len(out) {
		return out
	}
	return res
}

// mfaGate returns a refusal, or "" if the call may proceed. Named rather than inlined in the
// tool wrapper so a test can drive it: a second factor that is never actually consulted is
// exactly the kind of control that looks present and protects nothing.
func (s *Server) mfaGate(p *Policy, client, tool string, now time.Time) string {
	if p == nil || !p.NeedsMFA(tool) {
		return ""
	}
	if _, open := s.mfa.UnlockedUntil(client, now); open {
		return ""
	}
	return fmt.Sprintf("denied: %s requires a second factor for %q\n"+
		"  call mfa_unlock with a current 6-digit code from your authenticator; "+
		"it stays unlocked for %s", tool, client, p.MFAWindow)
}

// maskOutput applies the redaction rule for one tool, with the config as it is now.
func (s *Server) maskOutput(tool string, in any, out string) string {
	c := s.cfg()
	return maskForTool(tool, in, out, c.RedactExtra, c.RedactOutput)
}

// presentOutput is the one path every tool result and error text takes to the caller:
// sanitise, then mask, then bound, then label. Sanitising comes first so that a control or
// zero-width character inside an option name cannot hide a secret line from the masker; the
// marker comes last so that nothing can cut it off.
func (s *Server) presentOutput(tool string, in any, text string) string {
	text = sanitizeText(text)
	text = s.maskOutput(tool, in, text)
	if _, uncapped := uncappedTools[tool]; !uncapped {
		var cut int
		if text, cut = capLinesN(text, maxLineBytes); cut > 0 {
			text += "\n" + truncNotice(fmt.Sprintf("%d line(s) cut at %d bytes", cut, maxLineBytes),
				"narrow the request or filter the output")
		}
	}
	return labelUntrusted(tool, text)
}

// noteRedaction records, as a system event, that output redaction was switched on or off by
// the config file. Running unredacted is the operator's call, but it must leave a trace.
func (s *Server) noteRedaction(on bool, why string) {
	state := "ENABLED"
	if !on {
		state = "DISABLED"
	}
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<system>", Tool: "redact_output", Outcome: OutcomeOK,
		Summary: "tool output redaction " + state + ": " + why})
}

// mfaUnlock is the mfa_unlock handler, named and given the clock so a test can drive it. It
// applies the configured failed-attempt limit before every attempt: the config can change
// under a running daemon, and the store outlives each version of it.
func (s *Server) mfaUnlock(client, code string, now time.Time) (string, string, error) {
	cfg := s.cfg()
	s.mfa.SetLimit(cfg.MFAMaxFailures, cfg.MFALockout)
	window := defaultMFAWindow
	// Use the window from any policy that names this client, so a policy saying
	// 5m is not silently stretched to the default.
	for _, p := range cfg.Policies {
		if p.Client == client && p.Enabled && len(p.MFATools) > 0 {
			window = p.MFAWindow
			break
		}
	}
	until, err := s.mfa.Unlock(client, code, window, now)
	if err != nil {
		// Returned as an error so a wrong code audits as ERROR, distinct from a policy DENIED.
		// A lockout is a *LockoutError, which addTool records as DENIED: that one is a decision.
		return "", "mfa_unlock", err
	}
	return fmt.Sprintf("Unlocked until %s (%s).", until.Format(time.RFC3339), window), "mfa_unlock", nil
}

// ungatedTools need no policy. ubus_list is introspection only -- method names and argument
// types, never configuration data -- and without it an agent cannot discover what to ask
// for. mfa_unlock is how you satisfy the second factor, so gating it would be a deadlock;
// without a valid current code it does nothing but record a failed attempt.
var ungatedTools = map[string]bool{"ubus_list": true, "mfa_unlock": true}

// addTool registers one tool behind the shared policy+audit gate.
//
// scopeOf derives the policy scope strings from the typed input; fn does the work and
// returns (output, summary, error). Neither can bypass the gate: authorisation happens
// in this wrapper, before fn is ever called.
func addTool[In any](s *Server, srv *mcp.Server, client, name, desc string, ann *mcp.ToolAnnotations,
	scopeOf func(In) []string,
	fn func(context.Context, In) (string, string, error),
) {
	a := *ann // the presets are shared; the title and openWorldHint belong to this tool
	a.Title = toolTitles[name]
	a.OpenWorldHint = ptr(openWorldTools[name])
	schema := inputSchema[In]()
	srv.AddReceivingMiddleware(omitNulls(name, schema))
	mcp.AddTool(srv, &mcp.Tool{Name: name, Title: a.Title, Description: desc, Annotations: &a, InputSchema: schema},
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			started := time.Now()
			scopes := scopeOf(in)
			ev := AuditEvent{Time: nowISO(), Client: client, Tool: name, Scope: strings.Join(scopes, " ")}
			if b, err := json.Marshal(in); err == nil {
				var m any
				if json.Unmarshal(b, &m) == nil {
					ev.Args = m
				}
			}
			finish := func(res *mcp.CallToolResult, outcome Outcome, summary, errMsg string) (*mcp.CallToolResult, any, error) {
				ev.Outcome, ev.Summary, ev.Error = outcome, summary, errMsg
				ev.Duration = time.Since(started).Milliseconds()
				s.audit.Record(ev)
				return res, nil, nil
			}

			if !ungatedTools[name] {
				now := time.Now()
				p, reason := s.cfg().AuthorisePolicy(client, name, scopes, now)
				if p == nil {
					return finish(errResultCoded(reason, codeLine(codePolicyDenied)), OutcomeDenied, "", reason)
				}
				// Second factor, checked after authorisation so an unauthorised caller
				// learns nothing about which tools are MFA-gated.
				if r := s.mfaGate(p, client, name, now); r != "" {
					return finish(errResultCoded(r, codeLine(codeMFARequired)), OutcomeDenied, "", r)
				}
			}

			out, summary, err := fn(ctx, in)
			if err != nil {
				msg := err.Error()
				if out != "" {
					msg += "\n" + out
				}
				// Staged changes are echoed in some error texts, and err.Error() is what the
				// audit log records: both are masked.
				msg = s.presentOutput(name, in, msg)
				errMsg := sanitizeText(s.maskOutput(name, in, err.Error()))
				outcome := OutcomeError
				var lock *LockoutError
				if errors.As(err, &lock) {
					outcome = OutcomeDenied // "we said no", not "it broke"
				}
				return finish(errResultCoded(msg, codeLine(errCode(err))), outcome, summary, errMsg)
			}
			return finish(textResult(s.presentOutput(name, in, out)), OutcomeOK, summary, "")
		})
}

func clampSec(v, def, max int) time.Duration {
	if v <= 0 {
		v = def
	}
	if v > max {
		v = max
	}
	return time.Duration(v) * time.Second
}

func clampInt(v, def, lo, hi int) int {
	if v == 0 {
		v = def
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return v
}

// noScope is the scope function for tools whose policy check is tool-level only.
func noScope[In any](In) []string { return nil }

// Tool annotations: hints to the client, never a security boundary (the policy is). They let
// a client auto-approve reads and ask before writes.
var (
	annRead = &mcp.ToolAnnotations{ReadOnlyHint: true}
	annIdem = &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true}
	annDest = &mcp.ToolAnnotations{DestructiveHint: ptr(true)}
	// annDestIdem: removes something, and a repeat with the same arguments changes nothing more.
	annDestIdem = &mcp.ToolAnnotations{DestructiveHint: ptr(true), IdempotentHint: true}
	// annWrite: changes state (a file in /tmp, say) but cannot destroy anything, and is not
	// idempotent (each call makes a new file).
	annWrite = &mcp.ToolAnnotations{DestructiveHint: ptr(false)}
)

func ptr[T any](v T) *T { return &v }
