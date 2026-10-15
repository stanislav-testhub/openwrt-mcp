package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Approve in chat (docs/luci-approvals.md, 8.9): when a call is refused, the client that made it is
// asked, through MCP elicitation, to approve it. The answer is the same decision LuCI records, on
// the same request, so the two cannot disagree. Off until the owner switches the channel on, and
// then only for clients that negotiated elicitation.
//
// It runs as a multi-round-trip request: the first call returns the question (an input-required
// result), and the client's retry carries the answer. The SDK does the same through a direct
// elicitation for clients on older protocol versions, so nothing here depends on the version.
//
// The client relays the answer, so a client or an agent that answers its own prompts approves
// itself: that is the harm notice. What the channel does not do is widen a grant: chat approves
// only the exact scope that was refused, for at most chatDurations, and never a tool that is a
// root shell (the owner approves those in LuCI with the confirmation box).

// chatDurations are the lengths a chat answer can grant: shorter than LuCI offers.
var chatDurations = []string{"15m", "1h", "8h"}

const (
	chatActor    = "chat"
	chatInputKey = "approve"
)

func chatClientOn(cfg *Config, client string) bool {
	return cfg.ChatApprove && (len(cfg.ChatClients) == 0 || slices.Contains(cfg.ChatClients, client))
}

// supportsElicitation reports whether the client negotiated form elicitation.
func supportsElicitation(sess *mcp.ServerSession) bool {
	if sess == nil {
		return false
	}
	ip := sess.InitializeParams()
	if ip == nil || ip.Capabilities == nil || ip.Capabilities.Elicitation == nil {
		return false
	}
	e := ip.Capabilities.Elicitation
	return e.Form != nil || e.URL == nil // neither set means form, by the spec
}

// chatBlocks is what an accepted prompt would grant, or nil when the request is not one to ask
// about in chat: the channel is off for this client, the client cannot be asked, the scope cannot
// be named exactly, or the tool is a root shell.
func chatBlocks(cfg *Config, sess *mcp.ServerSession, r Request) []presetPolicy {
	if !chatClientOn(cfg, r.Client) || !supportsElicitation(sess) {
		return nil
	}
	blocks, err := planGrant(r, "exact")
	if err != nil {
		return nil
	}
	for _, b := range blocks {
		if len(shellEquivalentNames(b.tools, b.scopes)) > 0 {
			return nil
		}
	}
	return blocks
}

// chatPrompt is the input-required result that asks the client. It names the request and the
// redacted arguments the audit log holds, never the raw ones.
func chatPrompt(r Request) *mcp.CallToolResult {
	msg := fmt.Sprintf("Allow %s to call %s on %s? Request %s on the router. Arguments: %s",
		r.Client, r.Tool, r.Scope, r.ID, r.Args)
	return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{chatInputKey: &mcp.ElicitParams{
		Message: truncate(sanitizeText(msg), 600),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{"duration": map[string]any{
				"type": "string", "title": "Grant lasts", "enum": chatDurations, "default": "1h"}},
		},
	}}}
}

// applyChatAnswer settles the request from the client's answer: accept grants the exact scope,
// decline denies, anything else (a dismissed prompt, a duration this channel does not offer, a
// request already settled in LuCI) leaves the request open.
func (s *Server) applyChatAnswer(r Request, blocks []presetPolicy, ans *mcp.ElicitResult) {
	now := time.Now()
	switch ans.Action {
	case "accept":
		dur, _ := ans.Content["duration"].(string)
		if dur == "" {
			dur = "1h"
		}
		if !slices.Contains(chatDurations, dur) {
			return
		}
		if got, ok := s.requests.Get(r.ID, now); !ok || got.State != reqOpen {
			return // settled elsewhere (LuCI, expiry) while the prompt was open
		}
		if err := writeGrants(s.configPath, r.Client, blocks, dur); err != nil {
			s.chatAudit(r, fmt.Sprintf("%s: the grant could not be written: %v", r.ID, err))
			return
		}
		if _, err := s.requests.Decide(r.ID, true, chatActor, now); err == nil {
			s.chatAudit(r, fmt.Sprintf("%s: %s on %s for %s (exact)", r.ID, r.Tool, r.Scope, dur))
		}
	case "decline":
		s.requests.Decide(r.ID, false, chatActor, now) // the store audits the decision
	}
}

func (s *Server) chatAudit(r Request, summary string) {
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<" + chatActor + ">", Tool: "chat_grant", Scope: r.Scope,
		Outcome: OutcomeOK, Summary: strings.TrimSpace(summary)})
}
