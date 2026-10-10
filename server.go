package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	configPath string
	statePath  string
	audit      *Auditor
	mfa        *MFAStore
	tokens     *TokenStore

	applyMu sync.Mutex // serialises uci staging: /tmp/.uci is shared by every uci user
	histMu  sync.Mutex // serialises writes to the config history

	mu      sync.RWMutex
	config  *Config
	cfgTime time.Time
	servers map[string]*mcp.Server // per authenticated client name
	pending map[string]*pendingApply

	slots chan struct{} // one entry per running tool call, capacity inflightLimit (limits.go)
}

// cfg returns the current policy set, re-reading the config file when it has changed on
// disk so that `openwrt-mcp allow` and hand edits take effect without a restart. A file
// that fails to parse is ignored and the previous good config is kept -- a syntax error
// must not silently drop every policy (which would fail closed and look like a bug) nor
// leave a half-parsed one in place.
func (s *Server) cfg() *Config {
	if st, err := os.Stat(s.configPath); err == nil {
		s.mu.RLock()
		stale := !st.ModTime().Equal(s.cfgTime)
		s.mu.RUnlock()
		if stale {
			if fresh, err := LoadConfig(s.configPath); err == nil {
				s.mu.Lock()
				was := s.config
				s.config, s.cfgTime = fresh, st.ModTime()
				s.mu.Unlock()
				if was != nil && was.RedactOutput != fresh.RedactOutput {
					s.noteRedaction(fresh.RedactOutput, "config file changed")
				}
				log.Printf("openwrt-mcp: reloaded config (%d policies)", len(fresh.Policies))
			} else {
				s.mu.Lock()
				s.cfgTime = st.ModTime() // don't retry the same broken file every call
				s.mu.Unlock()
				log.Printf("openwrt-mcp: config reload failed, keeping previous policies: %v", err)
			}
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func NewServer(configPath, statePath string) (*Server, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	if err := checkStatePaths(statePath, cfg); err != nil {
		return nil, err
	}
	mfa, err := LoadMFA(mfaPath(statePath))
	if err != nil {
		return nil, err
	}
	tokens, err := LoadTokens(tokensPath(statePath))
	if err != nil {
		return nil, err
	}
	s := &Server{
		configPath: configPath,
		statePath:  statePath,
		mfa:        mfa,
		config:     cfg,
		tokens:     tokens,
		audit:      NewAuditor(cfg.AuditPath, cfg.AuditMaxMB),
		servers:    map[string]*mcp.Server{},
		pending:    map[string]*pendingApply{},
		slots:      make(chan struct{}, inflightLimit),
	}
	if !cfg.RedactOutput {
		s.noteRedaction(false, "option redact_output '0' at startup")
	}
	s.recoverPending()
	return s, nil
}

// serverFor returns the MCP server for one client name, building it on first use. Every
// tool handler is closed over that name, so identity is fixed when the connection is
// authenticated and can never be spoofed by a tool argument or a self-asserted clientInfo.
func (s *Server) serverFor(client string) *mcp.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv, ok := s.servers[client]; ok {
		return srv
	}
	srv := s.newServerForClient(client)
	s.servers[client] = srv
	return srv
}

// ---------------------------------------------------------------- http (bearer token)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.authenticate(mcp.NewStreamableHTTPHandler(s.getServer, nil)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// A service that will tell you what it is and where it came from is worth keeping.
		fmt.Fprintf(w, "openwrt-mcp %s ok\nsource: %s\n", version, sourceURL)
	})
	return mux
}

// authenticate enforces the bearer token on every request. There is deliberately no
// loopback auto-trust: any process on the router can reach 127.0.0.1, and an `ssh -R`
// can make remote traffic arrive there too, so reachability is never treated as proof
// of identity.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser defence: a page in a local browser must not be able to drive the router.
		if o := r.Header.Get("Origin"); o != "" && !isLoopbackOrigin(o) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if _, ok := s.tokens.Resolve(strings.TrimSpace(raw)); !ok {
			s.audit.Record(AuditEvent{
				Time: nowISO(), Client: "<unauthenticated>", Outcome: OutcomeDenied,
				Error: "bad or missing bearer token from " + r.RemoteAddr,
			})
			w.Header().Set("WWW-Authenticate", `Bearer realm="openwrt-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getServer(r *http.Request) *mcp.Server {
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	client, ok := s.tokens.Resolve(raw)
	if !ok {
		return nil // unreachable: authenticate() already rejected it
	}
	return s.serverFor(client)
}

// isLoopbackOrigin reports whether an Origin header names a loopback host. It parses the value
// as a URL rather than trimming it by hand: "http://localhost:80@evil.example" has the host
// evil.example, and a string trim reads it as localhost.
func isLoopbackOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" {
		return false
	}
	// An Origin is scheme://host[:port] and nothing more.
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	return strings.EqualFold(h, "localhost") || net.ParseIP(h).IsLoopback()
}

// ---------------------------------------------------------------- unix socket (stdio bridge)
//
// `openwrt-mcp stdio --client NAME` is what an SSH forced command runs: the MCP client's
// stdin/stdout travel over the SSH session, and the bridge pipes them into this socket. The
// daemon, not the bridge, runs the tools, so a pending rollback outlives the session that
// armed it.
//
// Identity here is asserted, not proven: the first line names the client. That is sound only
// because the socket is reachable by root alone (mode 0600 inside a 0700 directory), and root
// can already edit the policy file directly -- so the assertion grants root nothing it lacks.
// The name is bound to an SSH key by the forced command in authorized_keys, which is the real
// authentication.

type bridgeHello struct {
	Client  string `json:"client"`
	Origin  string `json:"origin,omitempty"`
	Command string `json:"command,omitempty"` // SSH_ORIGINAL_COMMAND, raw; the daemon parses it (entry.go)
	Peer    string `json:"peer,omitempty"`    // the client's address from SSH_CLIENT; the daemon keeps it only if it is an address
}

var reClientName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (s *Server) listenSocket(sock string) (net.Listener, error) {
	dir := path.Dir(sock)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(sock) // stale socket from a previous run
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Server) serveSocket(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("openwrt-mcp: socket accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.handleBridge(conn)
	}
}

func (s *Server) handleBridge(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 64<<10)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return
	}
	var hello bridgeHello
	if json.Unmarshal(line, &hello) != nil || !reClientName.MatchString(hello.Client) {
		fmt.Fprintln(conn, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"openwrt-mcp: bad bridge handshake"}}`)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	ent, err := parseEntry(hello.Command)
	if err != nil {
		s.audit.Record(AuditEvent{Time: nowISO(), Client: hello.Client, Tool: "session", Outcome: OutcomeDenied,
			Summary: "session refused, command " + strconv.Quote(hello.Command), Error: err.Error()})
		msg, _ := json.Marshal("openwrt-mcp: " + err.Error())
		fmt.Fprintf(conn, `{"jsonrpc":"2.0","error":{"code":-32600,"message":%s}}`+"\n", msg)
		return
	}
	profile := sessionProfile{Toolsets: ent.Toolsets, ReadOnly: ent.ReadOnly, Peer: parsePeer(hello.Peer)}
	opened := stdioOpened + orDefault(hello.Origin, "local socket")
	if ent.Mode == entryCall {
		opened = "call via " + orDefault(hello.Origin, "local socket")
	}
	if note := profile.String(); note != "" {
		opened += " [" + note + "]"
	}
	s.audit.Record(AuditEvent{Time: nowISO(), Client: hello.Client, Tool: "session", Outcome: OutcomeOK, Summary: opened})
	if ent.Mode == entryCall {
		s.handleCall(conn, br, hello.Client, ent, profile)
		return
	}

	start := time.Now()
	ss, err := s.serverFor(hello.Client).Connect(withProfile(context.Background(), profile),
		&mcp.IOTransport{Reader: readCloser{br, conn}, Writer: conn}, nil)
	if err != nil {
		log.Printf("openwrt-mcp: bridge session for %s: %v", hello.Client, err)
		return
	}
	werr := ss.Wait()
	took := time.Since(start)
	s.audit.Record(AuditEvent{Time: nowISO(), Client: hello.Client, Tool: "session", Outcome: OutcomeOK,
		Summary: sessionClosedSummary(took, werr), Duration: took.Milliseconds()})
}

type readCloser struct {
	io.Reader
	io.Closer
}

// ---------------------------------------------------------------- serve

func (s *Server) Serve() error {
	cfg := s.cfg()
	// Refuse to bind anything but loopback. This is a deliberate hard stop rather than a
	// default: reaching the router is SSH's job, and a mis-edited config must not silently
	// expose a root-equivalent RPC surface to the LAN.
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("bad listen address %q: %w", cfg.Listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; openwrt-mcp refuses to bind a routable address (reach it with: ssh -L %s:%s root@router)", cfg.Listen, cfg.Listen, cfg.Listen)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.Socket != "" {
		sl, err := s.listenSocket(cfg.Socket)
		if err != nil {
			return fmt.Errorf("socket %s: %w", cfg.Socket, err)
		}
		go s.serveSocket(sl)
	}
	// The old daemon could not write anything as it died, so `status` reads a restart off this line.
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<daemon>", Tool: "daemon", Outcome: OutcomeOK, Summary: "daemon started " + version})
	log.Printf("openwrt-mcp %s listening on %s and %s (%d policies, %d paired clients)",
		version, cfg.Listen, orDefault(cfg.Socket, "(no socket)"), len(cfg.Policies), len(s.tokens.Clients()))
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.Serve(ln)
}

// runBridge is the `stdio` subcommand: connect to the daemon's socket, announce the client,
// then copy bytes both ways until either side closes.
func runBridge(sock, client string) error {
	if !reClientName.MatchString(client) {
		return fmt.Errorf("bad client name %q", client)
	}
	cmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	if len(cmd) > entryMaxLen {
		return fmt.Errorf("SSH command too long (%d bytes, limit %d)", len(cmd), entryMaxLen)
	}
	conn, err := dialDaemon(sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	origin, peer := "stdio", ""
	if c := os.Getenv("SSH_CLIENT"); c != "" {
		peer = strings.Fields(c)[0]
		origin = "ssh from " + peer
	}
	hello, _ := json.Marshal(bridgeHello{Client: client, Origin: origin, Command: cmd, Peer: peer})
	if _, err := conn.Write(append(hello, '\n')); err != nil {
		return err
	}
	e, perr := parseEntry(cmd)
	switch {
	case perr == nil && e.Mode == entryCall:
		return readCallReply(conn, sock)
	case perr != nil && contains(strings.Fields(cmd), "call"):
		// A call the grammar refused: the person at the shell gets the reason as text, not the
		// JSON-RPC line an MCP client would be sent.
		return readCallRefusal(conn, sock)
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		close(done)
	}()
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		close(stdinDone)
	}()
	select {
	case <-stdinDone:
	case <-done:
		// The daemon went away (a restart, a crash). Exit now rather than on the client's next
		// request: the stdin reader is left blocked, and the process exit ends it.
		return fmt.Errorf("daemon closed the connection on %s", sock)
	}
	// stdin closed: the client has gone. Half-close so the daemon sees EOF and ends the
	// session, then wait for anything it still had to say.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}
