package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------- helpers

const initializeRPC = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
	`"capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`

// policyFor renders one `config policy` block.
func policyFor(client string, tools []string, scopes ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "config policy\n\toption client '%s'\n", client)
	for _, t := range tools {
		fmt.Fprintf(&b, "\tlist tools '%s'\n", t)
	}
	for _, s := range scopes {
		fmt.Fprintf(&b, "\tlist scopes '%s'\n", s)
	}
	return b.String()
}

// headerRT stamps fixed headers on every request, the way a real MCP client configured
// with a bearer token does.
type headerRT struct{ h map[string]string }

func (r headerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, v := range r.h {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func startHTTP(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// postInitialize sends a raw JSON-RPC initialize and returns the response, closed.
func postInitialize(t *testing.T, url string, headers map[string]string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/mcp", strings.NewReader(initializeRPC))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func auditEvents(t *testing.T, s *Server) []AuditEvent {
	t.Helper()
	b, err := os.ReadFile(s.cfg().AuditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line is not JSON: %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

// shortSocketPath keeps the path under the ~104-byte sun_path limit on every OS.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// Forward slashes: listenSocket splits the path with package path, which only knows '/'.
	return filepath.ToSlash(filepath.Join(dir, "run", "m.sock"))
}

// ---------------------------------------------------------------- http: bearer token

func TestHTTPRefusesAnythingButAValidBearerToken(t *testing.T) {
	f := newFakeRouter(t)
	s := testServer(t, "")
	tok, err := s.tokens.Mint("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	ts := startHTTP(t, s)

	rejected := []struct{ name, auth string }{
		{"no header", ""},
		{"empty bearer", "Bearer "},
		{"unknown token", "Bearer not-a-token"},
		{"token plus a trailing byte", "Bearer " + tok + "x"},
		{"token minus a trailing byte", "Bearer " + tok[:len(tok)-1]},
		{"token with a leading byte", "Bearer x" + tok},
		{"other scheme", "Basic " + tok},
	}
	for _, c := range rejected {
		hdr := map[string]string{}
		if c.auth != "" {
			hdr["Authorization"] = c.auth
		}
		code, h, body := postInitialize(t, ts.URL, hdr)
		if code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", c.name, code)
		}
		if !strings.Contains(h.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: 401 without a Bearer challenge: %v", c.name, h)
		}
		if strings.Contains(body, "serverInfo") {
			t.Errorf("%s: an initialize answer leaked to an unauthenticated caller: %s", c.name, body)
		}
	}

	if code, _, body := postInitialize(t, ts.URL, map[string]string{"Authorization": "Bearer " + tok}); code != http.StatusOK ||
		!strings.Contains(body, "openwrt-mcp") {
		t.Errorf("valid token: status %d body %.200s", code, body)
	}

	// Every refusal is on the record, attributed to nobody; the one success is not a denial.
	var denied int
	for _, ev := range auditEvents(t, s) {
		if ev.Client == "<unauthenticated>" && ev.Outcome == OutcomeDenied {
			denied++
		}
	}
	if denied != len(rejected) {
		t.Errorf("%d unauthenticated denials audited, want %d", denied, len(rejected))
	}
	if f.allCalls() != "" {
		t.Errorf("an unauthenticated request ran commands:\n%s", f.allCalls())
	}
}

func TestHTTPTokenRevokedByTheCLIStopsWorkingWithoutARestart(t *testing.T) {
	s := testServer(t, "")
	tok, err := s.tokens.Mint("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	ts := startHTTP(t, s)
	hdr := map[string]string{"Authorization": "Bearer " + tok}
	if code, _, _ := postInitialize(t, ts.URL, hdr); code != http.StatusOK {
		t.Fatalf("fresh token refused: %d", code)
	}

	// `openwrt-mcp unpair` is a separate process with its own TokenStore over the same file.
	cli, err := LoadTokens(s.tokens.path)
	if err != nil {
		t.Fatal(err)
	}
	if n := cli.Revoke("claude-code"); n != 1 {
		t.Fatalf("revoked %d tokens, want 1", n)
	}
	// Pin a distinct mtime: the daemon notices a change by mtime, and a filesystem with coarse
	// timestamps could otherwise hand both writes the same one.
	later := time.Now().Add(5 * time.Second)
	if err := os.Chtimes(s.tokens.path, later, later); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := postInitialize(t, ts.URL, hdr); code != http.StatusUnauthorized {
		t.Errorf("a revoked token still works: %d", code)
	}
}

func TestHTTPIdentityComesFromTheTokenNotFromClientInfo(t *testing.T) {
	f := newFakeRouter(t)
	f.on("logread", "Tue Sep 30 12:00:00 2026 daemon.info x: hello")
	s := testServer(t, policyFor("alice", []string{"logread"}, "*"))
	alice, _ := s.tokens.Mint("alice")
	mallory, _ := s.tokens.Mint("mallory")
	ts := startHTTP(t, s)

	call := func(token string) (string, bool) {
		t.Helper()
		tr := &mcp.StreamableClientTransport{
			Endpoint:             ts.URL + "/mcp",
			HTTPClient:           &http.Client{Transport: headerRT{map[string]string{"Authorization": "Bearer " + token}}},
			DisableStandaloneSSE: true,
			MaxRetries:           -1,
		}
		// Both callers introduce themselves as "alice"; only one holds her token.
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "alice", Version: "0"}, nil).Connect(context.Background(), tr, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		return callText(t, cs, "logread", nil)
	}

	if out, isErr := call(alice); isErr || !strings.Contains(out, "hello") {
		t.Errorf("alice with her own token: err=%v %s", isErr, out)
	}
	out, isErr := call(mallory)
	if !isErr || !strings.Contains(out, `no policy grants logread to "mallory"`) {
		t.Errorf("mallory posing as alice was not refused as mallory: err=%v %s", isErr, out)
	}
	var sawMallory bool
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "logread" && ev.Client == "mallory" && ev.Outcome == OutcomeDenied {
			sawMallory = true
		}
		if ev.Tool == "logread" && ev.Client == "alice" && ev.Outcome == OutcomeDenied {
			t.Errorf("a denial was attributed to alice: %+v", ev)
		}
	}
	if !sawMallory {
		t.Error("mallory's denied call is not in the audit log under her own name")
	}
}

// ---------------------------------------------------------------- http: browser defence

func TestHTTPOriginMustBeLoopback(t *testing.T) {
	s := testServer(t, "")
	tok, _ := s.tokens.Mint("claude-code")
	ts := startHTTP(t, s)

	for origin, wantOK := range map[string]bool{
		"http://localhost:8730":            true,
		"https://localhost":                true,
		"http://127.0.0.1:8730":            true,
		"http://127.1.2.3:80":              true,
		"http://[::1]:8730":                true,
		"http://[::1]":                     true,
		"http://evil.example":              false,
		"https://evil.example:8730":        false,
		"null":                             false,
		"http://localhost.evil.example":    false,
		"http://127.0.0.1.evil.example":    false,
		"http://localhost:80@evil.example": false, // userinfo: the host is evil.example
		"http://127.0.0.1:80@evil.example": false,
		"http://evil.example:80@localhost": false, // userinfo before a loopback-looking tail
		"http://192.168.1.1":               false,
		"http://notlocalhost":              false, // ends in "localhost" but is another host
		"http://evil.localhost:8730":       false,
		"http://xlocalhost":                false,
		"http://localhost.":                false,
		"file://":                          false,
	} {
		code, _, _ := postInitialize(t, ts.URL, map[string]string{"Authorization": "Bearer " + tok, "Origin": origin})
		if wantOK && code != http.StatusOK {
			t.Errorf("origin %q refused with %d", origin, code)
		}
		if !wantOK && code != http.StatusForbidden {
			t.Errorf("origin %q gave %d, want 403 (a page on that origin must not drive the router)", origin, code)
		}
	}

	// A non-browser client sends no Origin and is judged by its token alone.
	if code, _, _ := postInitialize(t, ts.URL, map[string]string{"Authorization": "Bearer " + tok}); code != http.StatusOK {
		t.Errorf("no Origin header: %d", code)
	}
}

func TestIsLoopbackOriginAgreesWithNetURLOnWhoTheHostIs(t *testing.T) {
	// A differential check against the standard parser: whatever isLoopbackOrigin accepts,
	// url.Parse must agree names a loopback host and carries no userinfo to hide behind.
	for _, o := range []string{
		"http://localhost:80@evil.example", "http://127.0.0.1:1@evil.example", "https://localhost:443#@evil.example",
		"http://localhost/@evil.example", "http://localhost\\@evil.example", "http://[::1]:80@evil.example",
	} {
		if isLoopbackOrigin(o) {
			t.Errorf("isLoopbackOrigin(%q) = true; the real host is not loopback", o)
		}
	}
}

func TestHealthIsPublicOnLoopbackAndRevealsNothingSensitive(t *testing.T) {
	s := testServer(t, policyFor("claude-code", []string{"logread"}, "*"))
	tok, _ := s.tokens.Mint("paired-client")
	ts := startHTTP(t, s)

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "openwrt-mcp "+version+" ok") {
		t.Errorf("health: %d %q", resp.StatusCode, body)
	}
	for _, secret := range []string{"claude-code", "paired-client", tok, "logread", s.configPath} {
		if strings.Contains(body, secret) {
			t.Errorf("/health leaks %q: %s", secret, body)
		}
	}
	for _, p := range []string{"/", "/nope", "/mcp/extra"} {
		r, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode == http.StatusOK {
			t.Errorf("GET %s answered 200 without a token", p)
		}
	}
}

// ---------------------------------------------------------------- serve: loopback only

func TestServeRefusesToBindAnythingButALoopbackIP(t *testing.T) {
	for _, listen := range []string{
		"0.0.0.0:8730", "192.168.1.1:8730", ":8730", "[::]:8730", "[fe80::1]:8730",
		"example.com:80", "localhost:8730", // names are not accepted: only a literal loopback IP
		"8730", "127.0.0.1", // not host:port
	} {
		s := testServer(t, "config server\n\toption listen '"+listen+"'\n")
		// If the guard regresses, Serve binds and blocks forever. Run it aside so that shows up
		// as a failed assertion in seconds rather than a hung test run (the goroutine is left
		// to die with the process).
		res := make(chan error, 1)
		go func() { res <- s.Serve() }()
		select {
		case err := <-res:
			if err == nil {
				t.Errorf("Serve accepted listen %q", listen)
			} else if !strings.Contains(err.Error(), "loopback") && !strings.Contains(err.Error(), "bad listen") {
				t.Errorf("listen %q: error does not say why: %v", listen, err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("Serve accepted listen %q and is serving on it: a root-equivalent RPC surface on a routable address", listen)
		}
	}
}

func TestServeBindsLoopbackAndAnswersHealth(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := testServer(t, "config server\n\toption listen '"+addr+"'\n")
	errc := make(chan error, 1)
	go func() { errc <- s.Serve() }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/health")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "ok") {
				t.Fatalf("health: %d %s", resp.StatusCode, b)
			}
			return
		}
		select {
		case err := <-errc:
			t.Fatalf("Serve returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon never came up on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------------------------------------------------------------- unix socket bridge

func listenTestSocket(t *testing.T, s *Server) string {
	t.Helper()
	sock := shortSocketPath(t)
	ln, err := s.listenSocket(sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	done := make(chan struct{})
	go func() { s.serveSocket(ln); close(done) }()
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("serveSocket did not stop after its listener closed")
		}
	})
	return sock
}

func TestSocketBridgeSpeaksMCPOverARealUnixSocket(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, `{"client":"claude-code","origin":"ssh from 192.0.2.7"}`+"\n"+initializeRPC+"\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, `"serverInfo"`) {
		t.Fatalf("no initialize answer over the socket: %v %q", err, line)
	}
}

func TestListenSocketReplacesAStaleSocketAndLocksTheDirectory(t *testing.T) {
	s := testServer(t, "")
	sock := shortSocketPath(t)
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte("stale"), 0o644); err != nil { // what a crashed run leaves behind
		t.Fatal(err)
	}
	ln, err := s.listenSocket(sock)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	defer ln.Close()

	if runtime.GOOS != "windows" { // Windows has no unix modes
		st, _ := os.Stat(sock)
		dir, _ := os.Stat(filepath.Dir(sock))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("socket mode %o, want 600: any local user could otherwise speak as any client", st.Mode().Perm())
		}
		if dir.Mode().Perm() != 0o700 {
			t.Errorf("socket directory mode %o, want 700", dir.Mode().Perm())
		}
	}
}

func TestBridgeRefusesAnOversizedOrSilentHandshake(t *testing.T) {
	s := testServer(t, "")
	srvSide, cliSide := net.Pipe()
	done := make(chan struct{})
	go func() { s.handleBridge(srvSide); close(done) }()
	go func() { // 70 KiB with no newline: larger than the 64 KiB handshake buffer
		cliSide.Write([]byte(strings.Repeat("a", 70<<10)))
		cliSide.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleBridge did not give up on an endless handshake line")
	}
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "session" {
			t.Errorf("a session was opened for a garbage handshake: %+v", ev)
		}
	}
}

func TestClientNameBoundaries(t *testing.T) {
	for name, want := range map[string]bool{
		"a":                     true,
		strings.Repeat("a", 63): true,
		strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false,
		"":                      false,
		"claude-code":           true,
		"a.b_c-d":               true,
		"a b":                   false,
		"a/b":                   false,
		`a"b`:                   false,
		"a'b":                   false,
		"a\nb":                  false,
		"é":                     false,
		`c",command="sh`:        false,
		"a;b":                   false,
		"$(id)":                 false,
	} {
		if got := reClientName.MatchString(name); got != want {
			t.Errorf("reClientName(%q) = %v, want %v", name, got, want)
		}
	}
}

// ---------------------------------------------------------------- the stdio subcommand

func swapStdio(t *testing.T) (stdinW *os.File, stdoutR *os.File) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	t.Cleanup(func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		inR.Close()
		outW.Close()
		outR.Close()
	})
	return inW, outR
}

func TestRunBridgeCarriesMCPBothWaysAndEndsWhenStdinCloses(t *testing.T) {
	s := testServer(t, "")
	sock := listenTestSocket(t, s)
	stdinW, stdoutR := swapStdio(t)
	t.Setenv("SSH_CLIENT", "192.0.2.7 51234 22")

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- runBridge(sock, "claude-code") }()

	if _, err := io.WriteString(stdinW, initializeRPC+"\n"); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdoutR).ReadString('\n')
		got <- line
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, `"serverInfo"`) {
			t.Fatalf("stdout did not carry the initialize answer: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer on stdout")
	}

	stdinW.Close() // the MCP client went away
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runBridge: %v", err)
		}
		if d := time.Since(start); d > 4*time.Second {
			t.Errorf("runBridge needed %s to notice stdin closing: the half-close is not reaching the daemon", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runBridge never returned after stdin closed")
	}

	var origin string
	for _, ev := range auditEvents(t, s) {
		if ev.Tool == "session" {
			origin = ev.Summary
		}
	}
	if !strings.Contains(origin, "ssh from 192.0.2.7") {
		t.Errorf("the session was not audited with its SSH origin: %q", origin)
	}
}

func TestRunBridgeFailsClearly(t *testing.T) {
	if err := runBridge("/nonexistent/m.sock", "../etc"); err == nil || !strings.Contains(err.Error(), "bad client name") {
		t.Errorf("bad client name: %v", err)
	}
	err := runBridge(filepath.Join(t.TempDir(), "absent.sock"), "claude-code")
	if err == nil || !strings.Contains(err.Error(), "daemon not reachable") {
		t.Errorf("missing daemon: %v", err)
	}
}

// ---------------------------------------------------------------- concurrency

// These assert the contract (one server per client; whole audit lines) and are meant to be
// run with -race, which CI does and a cgo-less Windows workstation cannot.

func TestServerForReturnsOneServerPerClientUnderContention(t *testing.T) {
	s := testServer(t, "")
	const workers = 64
	start := make(chan struct{})
	got := make([]*mcp.Server, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			got[i] = s.serverFor("shared")
		}(i)
	}
	close(start)
	wg.Wait()
	for i, g := range got {
		if g == nil || g != got[0] {
			t.Fatalf("worker %d got a different server: two handlers for one client would split its pending state", i)
		}
	}
	if s.serverFor("other") == got[0] {
		t.Error("two clients share one server, so one could act with the other's identity")
	}
}

func TestAuditRecordsStayWholeLinesUnderContention(t *testing.T) {
	a := NewAuditor(filepath.Join(t.TempDir(), "audit.jsonl"), 16)
	const workers, each = 32, 25
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < each; i++ {
				a.Record(AuditEvent{Time: nowISO(), Client: "c", Tool: "t", Outcome: OutcomeOK,
					Summary: fmt.Sprintf("w%d-i%d %s", w, i, strings.Repeat("x", 200))})
			}
		}(w)
	}
	close(start)
	wg.Wait()

	b, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("interleaved or torn audit line: %v\n%q", err, line)
		}
		seen[strings.Fields(ev.Summary)[0]] = true
	}
	if len(seen) != workers*each {
		t.Errorf("%d distinct records on disk, want %d: events were lost", len(seen), workers*each)
	}
}

// ---------------------------------------------------------------- policy hot reload

func TestConfigReloadFailsSafeOnABrokenFileAndFollowsLaterEdits(t *testing.T) {
	s := testServer(t, policyFor("c", []string{"logread"}, "*"))
	touch := func(body string, n int) {
		t.Helper()
		if err := os.WriteFile(s.configPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		// A distinct, increasing mtime per edit: the daemon reloads on mtime change, and two
		// edits inside one timestamp tick would otherwise look like no edit.
		at := time.Now().Add(time.Duration(n) * 10 * time.Second)
		if err := os.Chtimes(s.configPath, at, at); err != nil {
			t.Fatal(err)
		}
	}
	allowed := func() bool {
		ok, _ := s.cfg().Authorise("c", "logread", nil, time.Now())
		return ok
	}
	header := "config server\n\toption socket ''\n"

	if !allowed() {
		t.Fatal("precondition: the grant should apply")
	}
	// A policy with no client does not parse. Keeping the old grants is the safe reading of an
	// operator's typo mid-edit; so is NOT silently dropping them (that would look like a bug).
	touch(header+"config policy\n\tlist tools 'logread'\n", 1)
	if !allowed() {
		t.Error("a syntax error in the policy file dropped working grants")
	}
	// A valid edit that removes the grant takes effect without a restart.
	touch(header, 2)
	if allowed() {
		t.Error("revoking the grant in the file did not take effect: access outlived its policy")
	}
	// And a later good edit grants again.
	touch(header+policyFor("c", []string{"logread"}, "*"), 3)
	if !allowed() {
		t.Error("a later valid edit was not picked up")
	}
}

func TestConfigReloadUnderConcurrentCalls(t *testing.T) {
	// A generous rate limit: eight spinning goroutines would otherwise trip the default 60/min
	// and look like a refused grant.
	s := testServer(t, policyFor("c", []string{"logread"}, "*")+"\toption max_per_min '1000000'\n")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if ok, _ := s.cfg().Authorise("c", "logread", nil, time.Now()); !ok {
					t.Error("a grant that never changed was refused while another goroutine reloaded")
					return
				}
			}
		}()
	}
	for n := 1; n <= 20; n++ { // rewrite the same grant with new mtimes: every cfg() call may reload
		at := time.Now().Add(time.Duration(n) * time.Minute)
		_ = os.Chtimes(s.configPath, at, at)
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
