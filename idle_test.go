package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func idleServer(t *testing.T) (*Server, *Config, time.Time) {
	t.Helper()
	dir, err := os.MkdirTemp("", "idle")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfgPath := filepath.Join(dir, "config")
	body := "config server\n\toption listen ''\n\toption socket '" + shortSocketPath(t) + "'\n\toption audit '" + filepath.Join(dir, "a.jsonl") + "'\n\toption idle_exit '5'\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfgPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.idle.touch(now.Add(-10 * time.Minute))
	return s, s.cfg(), now
}

// Each condition that keeps the daemon up must do so alone (ROADMAP 10.5); a mutation that drops one
// from keepAliveReason turns one of these rows red.
func TestEachKeepAliveConditionAloneKeepsTheDaemonUp(t *testing.T) {
	s, cfg, now := idleServer(t)
	if r := s.keepAliveReason(cfg, now); r != "" {
		t.Fatalf("an idle daemon with nothing open must be allowed to stop, got %q", r)
	}
	cases := []struct {
		name string
		set  func(*Server, *Config)
	}{
		{"idle_exit off", func(_ *Server, c *Config) { c.IdleExitMin = 0 }},
		{"HTTP listener on", func(_ *Server, c *Config) { c.Listen = "127.0.0.1:8730" }},
		{"open session", func(s *Server, _ *Config) { s.idle.sessions.Add(1) }},
		{"armed rollback", func(s *Server, _ *Config) { s.pending["tok"] = &pendingApply{Token: "tok"} }},
		{"waiting request", func(s *Server, _ *Config) {
			s.requests.Open(now, time.Minute, "c", "uci_apply", "network.lan", nil)
		}},
		{"used a moment ago", func(s *Server, _ *Config) { s.idle.touch(now.Add(-time.Minute)) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, cfg, now := idleServer(t)
			cc := *cfg
			c.set(s, &cc)
			if s.keepAliveReason(&cc, now) == "" {
				t.Errorf("%s did not keep the daemon up", c.name)
			}
		})
	}
}

func TestIdleLoopStopsAnIdleDaemonOnce(t *testing.T) {
	s, _, _ := idleServer(t)
	stopped := make(chan struct{}, 2)
	old := stopDaemon
	stopDaemon = func() error { stopped <- struct{}{}; return nil }
	defer func() { stopDaemon = old }()
	done := make(chan struct{})
	go func() { s.idleLoop(10 * time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idleLoop never stopped an idle daemon")
	}
	if len(stopped) != 1 {
		t.Errorf("stop called %d times, want 1", len(stopped))
	}
}

func TestEnsureDaemonStartsOnlyWhenTheSocketIsDeadAndIdleExitIsOn(t *testing.T) {
	var started int
	old := startDaemon
	startDaemon = func() { started++ }
	defer func() { startDaemon = old }()
	sock := shortSocketPath(t)
	if err := os.MkdirAll(filepath.Dir(sock), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Socket: sock, IdleExitMin: 5}
	ensureDaemon(cfg)
	if started != 1 {
		t.Errorf("dead socket: started %d, want 1", started)
	}
	ensureDaemon(&Config{Socket: sock})
	if started != 1 {
		t.Error("started the daemon with idle_exit off")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	defer ln.Close()
	ensureDaemon(cfg)
	if started != 1 {
		t.Error("started the daemon although the socket answers")
	}
}

func TestIdleExitOption(t *testing.T) {
	for v, want := range map[string]int{"": 0, "5": 5, "0": 0, "-1": 0, "abc": 0, "99999": maxIdleExitMin} {
		p := filepath.Join(t.TempDir(), "c")
		body := "config server\n\toption socket ''\n"
		if v != "" {
			body += "\toption idle_exit '" + v + "'\n"
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if err != nil {
			t.Fatal(err)
		}
		if c.IdleExitMin != want {
			t.Errorf("idle_exit %q gave %d, want %d", v, c.IdleExitMin, want)
		}
	}
}
