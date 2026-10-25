package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Milestone 8.9. Approve in chat is an optional channel: while a refused call is held, a client that
// negotiated elicitation is asked, and its answer is the same decision LuCI records.

const chatOn = "\toption chat_approve '1'\n"

// chatClient connects a client that answers every prompt with a fixed result, and counts them.
type chatClient struct {
	*mcp.ClientSession
	asked   atomic.Int32
	mu      sync.Mutex
	message string
}

func (c *chatClient) lastMessage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.message
}

// connectChat: a nil answer is a client that does not advertise elicitation.
func connectChat(t *testing.T, s *Server, client string, answer *mcp.ElicitResult) *chatClient {
	t.Helper()
	c := &chatClient{}
	var opts *mcp.ClientOptions
	if answer != nil {
		opts = &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			c.asked.Add(1)
			c.mu.Lock()
			c.message = r.Params.Message
			c.mu.Unlock()
			return answer, nil
		}}
	}
	ct, st := mcp.NewInMemoryTransports()
	if _, err := s.serverFor(client).Connect(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, opts).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	c.ClientSession = cs
	return c
}

func chatServer(t *testing.T, extra string) *Server {
	t.Helper()
	fastPoll(t)
	f := newFakeRouter(t)
	f.on("uci show wireless", "wireless.radio0=wifi-device")
	return testServer(t, "\toption request_wait '5'\n"+extra+uciGrant("c"))
}

func auditFile(t *testing.T, s *Server) string {
	t.Helper()
	b, _ := os.ReadFile(s.cfg().AuditPath)
	return string(b)
}

var (
	accept1h  = &mcp.ElicitResult{Action: "accept", Content: map[string]any{"duration": "1h"}}
	acceptDef = &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}
)

// timedGrants are the grants written for client c with an expiry: what a chat answer creates.
func timedGrants(s *Server) []*Policy {
	var out []*Policy
	for _, p := range s.cfg().Policies {
		if p.Client == "c" && !p.Expires.IsZero() {
			out = append(out, p)
		}
	}
	return out
}

func TestChatApprovalReleasesTheHeldCallWithAnExactTimedGrant(t *testing.T) {
	s := chatServer(t, chatOn)
	c := connectChat(t, s, "c", accept1h)
	res := expectResult(t, callAsync(t, c.ClientSession, context.Background(), "uci_get", uciGetCall), "approved call")
	if res.isErr {
		t.Fatalf("an approved call was refused: %s", res.text)
	}
	if r := s.requests.List(time.Now())[0]; r.State != reqAllowed || r.Decider != "chat" {
		t.Errorf("request = %+v, want allowed by chat", r)
	}
	g := timedGrants(s)
	if len(g) != 1 || len(g[0].Scopes) != 1 || g[0].Scopes[0] != "wireless" {
		t.Fatalf("want one exact grant for wireless, got %+v", g)
	}
	if d := time.Until(g[0].Expires); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("grant lasts %v, want about 1h", d)
	}
	if audit := auditFile(t, s); !strings.Contains(audit, "chat_grant") || !strings.Contains(audit, "allowed by chat") {
		t.Errorf("audit lacks the chat decision:\n%s", audit)
	}
}

func TestChatPromptDefaultsToAnHourAndNamesTheRequestWithoutSecrets(t *testing.T) {
	s := chatServer(t, chatOn+policyFor("c", []string{"uci_apply"}, "network.*"))
	c := connectChat(t, s, "c", acceptDef)
	ch := map[string]any{"op": "set", "config": "wireless", "section": "x", "option": "key", "value": "hunter2-secret"}
	res := expectResult(t, callAsync(t, c.ClientSession, context.Background(), "uci_apply",
		map[string]any{"dry_run": true, "changes": []map[string]any{ch}}), "approved call")
	m := c.lastMessage()
	if !strings.Contains(m, "uci_apply") || !strings.Contains(m, "wireless") || !strings.Contains(m, s.requests.List(time.Now())[0].ID) {
		t.Errorf("prompt does not say what is asked: %q (call: %q)", m, res.text)
	}
	if strings.Contains(m, "hunter2-secret") {
		t.Errorf("a secret reached the prompt: %q", m)
	}
	g := timedGrants(s)
	if len(g) != 1 {
		t.Fatalf("want one grant, got %+v", g)
	}
	if d := time.Until(g[0].Expires); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("default grant lasts %v, want 1h", d)
	}
}

func TestChatDeclineDeniesTheRequestAndTheCall(t *testing.T) {
	s := chatServer(t, chatOn)
	c := connectChat(t, s, "c", &mcp.ElicitResult{Action: "decline"})
	res := expectResult(t, callAsync(t, c.ClientSession, context.Background(), "uci_get", uciGetCall), "declined call")
	if !res.isErr || !strings.Contains(res.text, "denied by the operator") {
		t.Errorf("declined call: %q", res.text)
	}
	if got := s.requests.List(time.Now())[0]; got.State != reqDenied || got.Decider != "chat" {
		t.Errorf("request = %+v", got)
	}
}

// heldStill asserts the call is still waiting, nothing was granted, and one request is open.
func heldStill(t *testing.T, s *Server, c *chatClient, name string, args map[string]any, wantAsked int32) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		// Cancelling ends the held call, and the server then writes its audit line. Leave only
		// once it has, or the write races the removal of the test's temp directory.
		cancel()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			if strings.Contains(auditFile(t, s), "cancelled while waiting for approval") {
				return
			}
		}
		t.Error("the held call never wrote its cancellation to the audit log")
	}()
	expectPending(t, callAsync(t, c.ClientSession, ctx, name, args), name)
	if got := c.asked.Load(); got != wantAsked {
		t.Errorf("asked %d times, want %d", got, wantAsked)
	}
	if g := timedGrants(s); len(g) != 0 {
		t.Errorf("a grant was written: %+v", g)
	}
	if open := s.openRequests(t); len(open) != 1 {
		t.Errorf("%d open requests, want 1 left for LuCI", len(open))
	}
}

func TestChatCancelIsNotAnAnswer(t *testing.T) {
	s := chatServer(t, chatOn)
	heldStill(t, s, connectChat(t, s, "c", &mcp.ElicitResult{Action: "cancel"}), "uci_get", uciGetCall, 1)
}

func TestChatIsOffUnlessSwitchedOn(t *testing.T) {
	s := chatServer(t, "")
	heldStill(t, s, connectChat(t, s, "c", accept1h), "uci_get", uciGetCall, 0)
}

func TestChatOnlyAsksTheNamedClients(t *testing.T) {
	s := chatServer(t, chatOn+"\tlist chat_approve_client 'someone-else'\n")
	heldStill(t, s, connectChat(t, s, "c", accept1h), "uci_get", uciGetCall, 0)
}

func TestChatSkipsAClientThatCannotElicit(t *testing.T) {
	s := chatServer(t, chatOn)
	heldStill(t, s, connectChat(t, s, "c", nil), "uci_get", uciGetCall, 0)
}

// A root-shell tool is approved in LuCI behind the confirmation box, never in chat.
func TestChatNeverAsksForARootShellTool(t *testing.T) {
	s := chatServer(t, chatOn)
	heldStill(t, s, connectChat(t, s, "c", accept1h), "exec", map[string]any{"argv": []string{"sh", "-c", "id"}}, 0)
}

// The SDK client validates the enum before answering, so a rogue client is simulated by handing
// the answer straight to the server: a duration this channel does not offer grants nothing.
func TestChatRefusesADurationItDoesNotOffer(t *testing.T) {
	s := chatServer(t, chatOn)
	r, _ := s.requests.Open(time.Now(), ttl10, "c", "uci_get", "wireless", nil)
	blocks, err := planGrant(r, "exact")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"7d", "never", "9999h", "1h; rm"} {
		s.applyChatAnswer(r, blocks, &mcp.ElicitResult{Action: "accept", Content: map[string]any{"duration": d}})
		if g := timedGrants(s); len(g) != 0 || len(s.openRequests(t)) != 1 {
			t.Fatalf("duration %q wrote %+v, open %d", d, g, len(s.openRequests(t)))
		}
	}
}

func TestChatChannelListedOffWithNotice(t *testing.T) {
	var c channel
	for _, x := range channels {
		if x.Name == "chat" {
			c = x
		}
	}
	if c.Name == "" || c.option != "chat_approve" || !strings.Contains(c.Harm, "answers its own prompts") ||
		!strings.Contains(c.Harm, "root shell") {
		t.Errorf("chat channel = %+v", c)
	}
}

// An answer that arrives after LuCI (or expiry) settled the request must not write a grant.
func TestChatAnswerAfterTheRequestWasSettledGrantsNothing(t *testing.T) {
	s := chatServer(t, chatOn)
	r, _ := s.requests.Open(time.Now(), ttl10, "c", "uci_get", "wireless", nil)
	blocks, _ := planGrant(r, "exact")
	if _, err := s.requests.Decide(r.ID, false, "luci", time.Now()); err != nil {
		t.Fatal(err)
	}
	s.applyChatAnswer(r, blocks, accept1h)
	if g := timedGrants(s); len(g) != 0 {
		t.Errorf("a late answer wrote %+v", g)
	}
	if got, _ := s.requests.Get(r.ID, time.Now()); got.State != reqDenied || got.Decider != "luci" {
		t.Errorf("the settled request changed: %+v", got)
	}
}

// A client that answers without a duration (the server cannot assume it applied the schema
// default) gets the hour the prompt promised, no more.
func TestChatAnswerWithoutADurationGrantsAnHour(t *testing.T) {
	s := chatServer(t, chatOn)
	r, _ := s.requests.Open(time.Now(), ttl10, "c", "uci_get", "wireless", nil)
	blocks, _ := planGrant(r, "exact")
	s.applyChatAnswer(r, blocks, &mcp.ElicitResult{Action: "accept"})
	g := timedGrants(s)
	if len(g) != 1 {
		t.Fatalf("want one grant, got %+v", g)
	}
	if d := time.Until(g[0].Expires); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("grant lasts %v, want 1h", d)
	}
}
