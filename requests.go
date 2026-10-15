package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A refused call becomes a request an operator can approve (docs/luci-approvals.md, 8.2). The
// store holds the requests, the mirror file lets the rpcd plugin (8.3) list them, and a held call
// waits here for the answer. A request carries only what the daemon derived from the call: no
// text the agent wrote, so the owner reads facts, not an argument.

const (
	maxOpenPerClient  = 5
	maxOpenTotal      = 50
	requestRatePerMin = 10 // new requests per client per minute, against reflex-click fatigue
	requestArgsMax    = 512
	// requestKeepClosed is how long a decided or expired request stays listed, so a held call and
	// the operator's page both see the outcome.
	requestKeepClosed = 10 * time.Minute

	defaultRequestTTL = 10 * time.Minute
	minRequestTTL     = time.Minute
	maxRequestTTL     = 24 * time.Hour
	maxRequestWait    = 300 * time.Second
)

// requestsPath is RAM on the router: a reboot clears every request, which is the right outcome.
var requestsPath = "/var/run/openwrt-mcp/requests.json"

// requestPoll is how often a held call re-reads the policy and its request. A variable so tests
// need not wait whole seconds.
var requestPoll = time.Second

type RequestState string

const (
	reqOpen    RequestState = "open"
	reqAllowed RequestState = "allowed"
	reqDenied  RequestState = "denied"
	reqExpired RequestState = "expired"
)

type Request struct {
	ID       string       `json:"id"`
	Client   string       `json:"client"`
	Tool     string       `json:"tool"`
	Scope    string       `json:"scope"`
	Args     string       `json:"args"`
	ArgsHash string       `json:"args_hash"`
	Created  time.Time    `json:"created"`
	Expires  time.Time    `json:"expires"`
	LastSeen time.Time    `json:"last_seen"`
	State    RequestState `json:"state"`
	Decided  time.Time    `json:"decided,omitzero"`
	Decider  string       `json:"decider,omitempty"`
}

type RequestStore struct {
	mu    sync.Mutex
	path  string
	sink  func(AuditEvent)
	onNew func(Request) // called for each newly opened request, with the lock held: it must not block
	byID  map[string]*Request
	made  map[string][]time.Time // creation times per client, for the rate limit
	byKey map[string]string      // client|tool|scope -> id of the open request

	// The mirror as this process last wrote or read it, so adoptLocked re-reads only a file
	// another process (the rpcd plugin) has changed since.
	seenMod  time.Time
	seenSize int64
}

func NewRequestStore(path string, sink func(AuditEvent)) *RequestStore {
	return &RequestStore{path: path, sink: sink, byID: map[string]*Request{},
		made: map[string][]time.Time{}, byKey: map[string]string{}}
}

func requestKey(client, tool, scope string) string { return client + "\x00" + tool + "\x00" + scope }

// Open records a refusal as a request, or returns the open one for the same client, tool and
// scope. ok is false at a cap or the rate limit: the call is then refused as it always was.
func (rs *RequestStore) Open(now time.Time, ttl time.Duration, client, tool, scope string, args any) (Request, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sweepLocked(now)
	if id, ok := rs.byKey[requestKey(client, tool, scope)]; ok {
		r := rs.byID[id]
		r.LastSeen = now // the expiry stays put: repeating a call must not keep a request open
		rs.saveLocked()
		return *r, true
	}
	perClient, total := 0, 0
	for _, r := range rs.byID {
		if r.State == reqOpen {
			total++
			if r.Client == client {
				perClient++
			}
		}
	}
	if perClient >= maxOpenPerClient || total >= maxOpenTotal {
		return Request{}, false
	}
	cut := now.Add(-time.Minute)
	recent := rs.made[client][:0]
	for _, t := range rs.made[client] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= requestRatePerMin {
		rs.made[client] = recent
		return Request{}, false
	}
	rs.made[client] = append(recent, now)

	text, hash := requestArgs(args)
	r := &Request{ID: newRequestID(rs.byID), Client: client, Tool: tool, Scope: scope, Args: text, ArgsHash: hash,
		Created: now, Expires: now.Add(ttl), LastSeen: now, State: reqOpen}
	rs.byID[r.ID] = r
	rs.byKey[requestKey(client, tool, scope)] = r.ID
	rs.emit("request", r, fmt.Sprintf("open %s: %s on %s", r.ID, tool, scope))
	rs.saveLocked()
	if rs.onNew != nil {
		rs.onNew(*r)
	}
	return *r, true
}

// Decide settles an open request once. Concurrent or repeated decisions on the same id lose with
// "already ...": a decision is consumed exactly once.
func (rs *RequestStore) Decide(id string, allow bool, actor string, now time.Time) (Request, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sweepLocked(now)
	r, ok := rs.byID[id]
	if !ok {
		return Request{}, fmt.Errorf("no request %q", id)
	}
	if r.State != reqOpen {
		return *r, fmt.Errorf("request %s is already %s", id, r.State)
	}
	state := reqDenied
	if allow {
		state = reqAllowed
	}
	rs.closeLocked(r, state, actor, now)
	rs.emit("decide", r, fmt.Sprintf("%s %s by %s", r.ID, state, actor))
	rs.saveLocked()
	return *r, nil
}

// Resolve marks an open request allowed because a grant now covers it (the CLI `allow`, or a
// decision whose grant was written first). It is a no-op once the request is settled.
func (rs *RequestStore) Resolve(id, actor string, now time.Time) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sweepLocked(now)
	if r, ok := rs.byID[id]; ok && r.State == reqOpen {
		rs.closeLocked(r, reqAllowed, actor, now)
		rs.emit("decide", r, fmt.Sprintf("%s allowed by %s", r.ID, actor))
		rs.saveLocked()
	}
}

func (rs *RequestStore) Get(id string, now time.Time) (Request, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sweepLocked(now)
	if r, ok := rs.byID[id]; ok {
		return *r, true
	}
	return Request{}, false
}

// List returns every kept request, oldest first.
func (rs *RequestStore) List(now time.Time) []Request {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.sweepLocked(now)
	return rs.listLocked()
}

func (rs *RequestStore) listLocked() []Request {
	out := make([]Request, 0, len(rs.byID))
	for _, r := range rs.byID {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// sweepLocked expires open requests past their time and forgets old closed ones. Every method
// calls it first, so there is no timer and no state that is wrong between calls.
func (rs *RequestStore) sweepLocked(now time.Time) {
	rs.adoptLocked(false)
	changed := false
	for id, r := range rs.byID {
		switch {
		case r.State == reqOpen && now.After(r.Expires):
			rs.closeLocked(r, reqExpired, "", now)
			rs.emit("expire", r, fmt.Sprintf("%s expired unanswered", r.ID))
			changed = true
		case r.State != reqOpen && now.Sub(r.Decided) > requestKeepClosed:
			delete(rs.byID, id)
			changed = true
		}
	}
	if changed {
		rs.saveLocked()
	}
}

func (rs *RequestStore) closeLocked(r *Request, state RequestState, actor string, now time.Time) {
	r.State, r.Decider, r.Decided = state, actor, now
	delete(rs.byKey, requestKey(r.Client, r.Tool, r.Scope))
}

func (rs *RequestStore) emit(kind string, r *Request, summary string) {
	if rs.sink != nil {
		rs.sink(AuditEvent{Time: nowISO(), Client: r.Client, Tool: kind, Scope: r.Scope, Outcome: OutcomeOK, Summary: summary})
	}
}

// saveLocked mirrors the requests for the rpcd plugin: write-and-rename, 0600, under the mirror
// lock and after taking in any decision the plugin wrote, so a save never erases one. A failure is
// logged and otherwise ignored, because a mirror that cannot be written must not stop a call.
func (rs *RequestStore) saveLocked() {
	if rs.path == "" {
		return
	}
	unlock, err := lockMirror(rs.path)
	if err == nil {
		defer unlock()
		rs.adoptLocked(true)
		err = writeMirror(rs.path, rs.listLocked())
	}
	if err != nil {
		log.Printf("openwrt-mcp: cannot write %s: %v", rs.path, err)
		return
	}
	rs.noteMirrorLocked()
}

func (rs *RequestStore) noteMirrorLocked() {
	if fi, err := os.Stat(rs.path); err == nil {
		rs.seenMod, rs.seenSize = fi.ModTime(), fi.Size()
	}
}

// adoptLocked takes in the answers the rpcd plugin wrote to the mirror: a request still open
// here that the file shows settled is closed the same way. force skips the change check, for a
// caller that holds the lock and is about to overwrite the file.
func (rs *RequestStore) adoptLocked(force bool) {
	if rs.path == "" {
		return
	}
	fi, err := os.Stat(rs.path)
	if err != nil || (!force && fi.ModTime().Equal(rs.seenMod) && fi.Size() == rs.seenSize) {
		return
	}
	disk, err := readMirror(rs.path)
	if err != nil {
		return
	}
	for _, d := range disk {
		if r, ok := rs.byID[d.ID]; ok && r.State == reqOpen && d.State != reqOpen {
			rs.closeLocked(r, d.State, d.Decider, d.Decided)
		}
	}
	rs.seenMod, rs.seenSize = fi.ModTime(), fi.Size()
}

// readMirror returns the requests in the mirror file; a missing file holds none.
func readMirror(path string) ([]Request, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Requests []Request `json:"requests"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return doc.Requests, nil
}

func writeMirror(path string, reqs []Request) error {
	if reqs == nil {
		reqs = []Request{}
	}
	b, err := json.MarshalIndent(struct {
		Requests []Request `json:"requests"`
	}{reqs}, "", "\t")
	if err == nil {
		err = os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err == nil {
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, b, privateMode); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	return err
}

// The mirror has two writers in two processes, the daemon and the rpcd plugin, so each change to
// it is a read-modify-write under a lock file. O_EXCL makes taking it atomic; a lock older than
// mirrorLockStale belongs to a process that died and is broken.
const (
	mirrorLockStale = 10 * time.Second
	mirrorLockWait  = 3 * time.Second
)

func lockMirror(path string) (unlock func(), err error) {
	lock := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(mirrorLockWait)
	for {
		f, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateMode)
		if err == nil {
			f.Close()
			return func() { os.Remove(lock) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if fi, serr := os.Stat(lock); serr == nil && time.Since(fi.ModTime()) > mirrorLockStale {
			os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the request mirror is locked by another process")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// requestArgs renders the arguments the way the audit log holds them (redacted), capped, and
// hashes that same text, so the hash never lets a guessed secret be checked.
func requestArgs(args any) (string, string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // "<redacted>" stays readable
	b := []byte(nil)
	if args != nil && enc.Encode(redact(args)) == nil { // map keys come out sorted
		b = bytes.TrimSpace(buf.Bytes())
	}
	sum := sha256.Sum256(b)
	return truncate(sanitizeText(string(b)), requestArgsMax), hex.EncodeToString(sum[:])
}

func newRequestID(taken map[string]*Request) string {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err) // the system has no randomness: nothing safe to do
		}
		if id := hex.EncodeToString(b[:]); taken[id] == nil {
			return id
		}
	}
}

// ---------------------------------------------------------------- held calls

type approval struct {
	p       *Policy
	waited  time.Duration
	reqID   string
	release func()              // the in-flight slot taken while holding; nil when none was
	input   *mcp.CallToolResult // set when the client is asked to approve in chat: returned as is
	denial  string              // set when the call must be refused
	code    string
}

// awaitApproval handles a call the policy refused: it opens (or reuses) a request, and with
// request_wait set holds the call until a grant covers it, the request is denied, or the wait
// ends. A hold takes an in-flight slot, so held calls cannot be used to pile up work.
func (s *Server) awaitApproval(ctx context.Context, sess *mcp.ServerSession, answers mcp.InputResponseMap, client, tool string, scopes []string, reason, missing string, args any) approval {
	deny := func(text string) approval { return approval{denial: text, code: codePolicyDenied} }
	if missing == "" { // a rate limit: more access is not what the call lacks
		return deny(reason)
	}
	cfg := s.cfg()
	ttl := cfg.RequestTTL
	req, ok := s.requests.Open(time.Now(), ttl, client, tool, missing, args)
	if !ok {
		return deny(reason)
	}
	if blocks := chatBlocks(cfg, sess, req); blocks != nil {
		ans, answered := answers[chatInputKey].(*mcp.ElicitResult)
		if !answered {
			return approval{input: chatPrompt(req)}
		}
		s.applyChatAnswer(req, blocks, ans)
		now := time.Now()
		if got, ok := s.requests.Get(req.ID, now); ok && got.State == reqDenied {
			return deny("denied by the operator: request " + req.ID + " was refused")
		}
		if p, _, _ := s.cfg().authorise(client, tool, scopes, now); p != nil {
			return approval{p: p, reqID: req.ID}
		}
	}
	denial := requestHint(reason, req, time.Now())
	if cfg.RequestWait <= 0 {
		return deny(denial)
	}

	var release func()
	if !slotExempt[tool] {
		var refusal string
		if release, refusal = s.acquireSlot(ctx); release == nil {
			return approval{denial: refusal, code: codeTimeout}
		}
	}
	giveUp := func(a approval) approval {
		if release != nil {
			release()
		}
		return a
	}
	started := time.Now()
	timer := time.NewTimer(cfg.RequestWait)
	defer timer.Stop()
	tick := time.NewTicker(requestPoll)
	defer tick.Stop()
	for {
		now := time.Now()
		if got, ok := s.requests.Get(req.ID, now); ok && got.State == reqDenied {
			return giveUp(deny("denied by the operator: request " + req.ID + " was refused"))
		}
		if p, _, _ := s.cfg().authorise(client, tool, scopes, now); p != nil {
			s.requests.Resolve(req.ID, "policy", now)
			return approval{p: p, waited: now.Sub(started), reqID: req.ID, release: release}
		}
		select {
		case <-ctx.Done():
			return giveUp(deny("cancelled while waiting for approval of request " + req.ID))
		case <-timer.C:
			// The request stays open: a retry after approval works.
			return giveUp(deny(denial))
		case <-tick.C:
		}
	}
}

// requestHint adds where to approve the request, after the first line of the usual refusal,
// which keeps its CLI fallback.
func requestHint(reason string, r Request, now time.Time) string {
	mins := max(1, int((r.Expires.Sub(now)+time.Minute-1)/time.Minute))
	hint := fmt.Sprintf("  approve: LuCI → Services → MCP Server (request %s, open %d min), then call again", r.ID, mins)
	first, rest, found := strings.Cut(reason, "\n")
	if !found {
		return reason + "\n" + hint
	}
	return first + "\n" + hint + "\n" + rest
}
