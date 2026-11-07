package main

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func listenOffServer(t *testing.T, listen, extra string) (*Server, string) {
	t.Helper()
	sock := shortSocketPath(t)
	// Serve has no shutdown, so the daemon may still write here when the test ends: not a t.TempDir.
	dir, err := os.MkdirTemp("", "listenoff")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "config")
	body := "config server\n\toption listen '" + listen + "'\n\toption socket '" + sock + "'\n\toption audit '" + filepath.Join(dir, "a.jsonl") + "'\n" + extra
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfgPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, sock
}

// option listen ” turns the HTTP listener off (ROADMAP 10.4): the daemon runs on the socket alone,
// status and doctor see it there, and an MCP session works over the socket.
func TestDaemonRunsOnTheSocketAloneWhenHTTPIsOff(t *testing.T) {
	s, sock := listenOffServer(t, "", "")
	if got := s.cfg().Listen; got != "" {
		t.Fatalf("Listen = %q, want empty", got)
	}
	if daemonUp(s.cfg()) {
		t.Fatal("daemonUp before the daemon started")
	}
	go func() { _ = s.Serve() }()
	for i := 0; i < 100 && !daemonUp(s.cfg()); i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if !daemonUp(s.cfg()) {
		t.Fatal("daemonUp is false with the daemon serving its socket")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for _, l := range []string{
		`{"client":"t","origin":"test"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
	} {
		if _, err := conn.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, `"serverInfo"`) {
		t.Errorf("initialize over the socket: %q, %v", line, err)
	}
}

func TestDaemonRefusesToStartWithNothingToListenOn(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgPath, []byte("config server\n\toption listen ''\n\toption socket ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfgPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(); err == nil || !strings.Contains(err.Error(), "no way to be reached") {
		t.Errorf("Serve with HTTP and the socket both off: %v", err)
	}
}
