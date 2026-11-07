package main

import (
	"log"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

// On-demand daemon (ROADMAP 10.5). With `option idle_exit '<minutes>'` above 0 the daemon stops
// itself through procd once nothing needs it, and a bridge or `call` that finds no socket starts it
// again. 0, the default, keeps it resident.

const (
	maxIdleExitMin = 1440
	initScriptPath = "/etc/init.d/openwrt-mcp"
)

// idleState is what the keep-alive check reads. Sessions and the last activity are updated by the
// socket handler; the rest is asked of the stores when the check runs.
type idleState struct {
	sessions   atomic.Int32
	lastActive atomic.Int64 // unix nanoseconds
}

func (i *idleState) touch(now time.Time) { i.lastActive.Store(now.UnixNano()) }

// keepAliveReason says why the daemon must stay up, or "" when it may stop.
func (s *Server) keepAliveReason(cfg *Config, now time.Time) string {
	switch {
	case cfg.IdleExitMin <= 0:
		return "idle_exit is off"
	case cfg.Listen != "":
		return "the HTTP listener is on (set option listen '' to allow idle exit)"
	case s.idle.sessions.Load() > 0:
		return "a session is open"
	}
	s.mu.RLock()
	armed := len(s.pending)
	s.mu.RUnlock()
	if armed > 0 {
		return "an apply is armed for rollback"
	}
	for _, r := range s.requests.List(now) {
		if r.State == reqOpen {
			return "a request is waiting for the operator"
		}
	}
	if idle := now.Sub(time.Unix(0, s.idle.lastActive.Load())); idle < time.Duration(cfg.IdleExitMin)*time.Minute {
		return "used less than idle_exit ago"
	}
	return ""
}

// stopDaemon asks procd to stop the service, which ends this process. A variable so a test need
// not stop anything.
var stopDaemon = func() error {
	if _, err := os.Stat(initScriptPath); err != nil {
		return err
	}
	return exec.Command(initScriptPath, "stop").Start()
}

// idleLoop checks the keep-alive conditions about once a minute (or four times per idle period when
// that is shorter, as in tests) and stops the daemon when none holds.
func (s *Server) idleLoop(every time.Duration) {
	for {
		time.Sleep(every)
		cfg := s.cfg()
		if s.keepAliveReason(cfg, time.Now()) != "" {
			continue
		}
		s.audit.Record(AuditEvent{Time: nowISO(), Client: "<daemon>", Tool: "daemon", Outcome: OutcomeOK,
			Summary: "daemon stopping, idle for " + (time.Duration(cfg.IdleExitMin) * time.Minute).String() + "; the next bridge starts it"})
		if err := stopDaemon(); err != nil {
			log.Printf("openwrt-mcp: idle exit: %v", err)
			continue
		}
		return
	}
}

// ensureDaemon starts the daemon through procd when the socket does not answer and idle exit is
// on; the bridge's own dial retry then waits for it.
func ensureDaemon(cfg *Config) {
	if cfg.IdleExitMin <= 0 || cfg.Socket == "" {
		return
	}
	if c, err := net.DialTimeout("unix", cfg.Socket, time.Second); err == nil {
		c.Close()
		return
	}
	startDaemon()
}

// startDaemon is a variable so a test need not start anything.
var startDaemon = func() { _ = exec.Command(initScriptPath, "start").Run() }
