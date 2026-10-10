package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Session lifecycle: how the bridge waits for a daemon that is not up yet, and how the daemon
// records the end of a session so `openwrt-mcp status` can say why one dropped.

// defaultDialRetryFor is how long the bridge waits for the daemon's socket. SSH answers before
// the daemon is listening after a reboot or an upgrade restart; a client that reconnects in that
// window should get a session, not a failure. It stays well under the 30 s most MCP clients
// allow a server to start, and `connect doctor` (doctorTimeout) must outlast it plus SSH's own
// connect timeout, or a stopped daemon would be reported as a vague timeout.
const defaultDialRetryFor = 10 * time.Second

// Variables so tests need not wait.
var (
	dialRetryFor   = defaultDialRetryFor
	dialRetryEvery = 250 * time.Millisecond
)

// daemonStartingLine ends the output of a bridge that gave up waiting (ROADMAP 5.6). codeLine's
// own advice for TIMEOUT, to narrow the request, does not fit a daemon that is not up yet.
const daemonStartingLine = "[code: TIMEOUT; next: the daemon may still be starting after a reboot or an upgrade; wait a few seconds and retry]"

// dialDaemon connects to the daemon's socket, retrying every error until dialRetryFor has passed.
// Not classifying the error is deliberate: a missing socket file and a stale one that refuses
// are both "not up yet", and the OS reports them differently.
func dialDaemon(sock string) (net.Conn, error) {
	deadline := time.Now().Add(dialRetryFor)
	for {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return conn, nil
		}
		if !time.Now().Before(deadline) {
			return nil, withCode(codeTimeout, fmt.Errorf("daemon not reachable on %s after waiting %s (is it running? /etc/init.d/openwrt-mcp start): %w",
				sock, dialRetryFor, err))
		}
		time.Sleep(dialRetryEvery)
	}
}

// The audit summaries of a stdio session's two ends. lastDisconnect reads them back, so both
// sides use these.
const (
	stdioOpened = "stdio session opened via "
	stdioClosed = "stdio session closed after "
)

// sessionClosedSummary is the audit summary for a session that ended after d. err is what
// Wait returned: nil or EOF is the client going away, anything else is the link failing.
func sessionClosedSummary(d time.Duration, err error) string {
	reason := "client closed the connection"
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		reason = "connection error: " + err.Error()
	}
	return stdioClosed + d.Round(time.Second).String() + ": " + reason
}

type disconnectRow struct {
	Time   string `json:"time"`
	Client string `json:"client"`
	Reason string `json:"reason"`
}

const restartReason = "the daemon restarted (router reboot, upgrade or crash)"

// lastDisconnect finds the most recent end of a stdio session in the audit log. A session the
// daemon saw close says why; one that was still open when the daemon started again was cut by
// that restart (nothing could be written as the old daemon died, so it is read off the log). The
// log is scanned once, with a count of open sessions per client; a close whose open was rotated
// away does not take the count below zero.
func lastDisconnect(path string) *disconnectRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	open := map[string]int{}
	var last *disconnectRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		var e AuditEvent
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		switch {
		case e.Tool == "daemon":
			var cut []string
			for c, n := range open {
				if n > 0 {
					cut = append(cut, c)
				}
			}
			if len(cut) > 0 {
				sort.Strings(cut)
				last = &disconnectRow{Time: e.Time, Client: strings.Join(cut, ", "), Reason: restartReason}
			}
			open = map[string]int{}
		case e.Tool == "session" && strings.HasPrefix(e.Summary, stdioOpened):
			open[e.Client]++
		case e.Tool == "session" && strings.HasPrefix(e.Summary, stdioClosed):
			if open[e.Client] > 0 {
				open[e.Client]--
			}
			_, reason, _ := strings.Cut(e.Summary, ": ")
			last = &disconnectRow{Time: e.Time, Client: e.Client, Reason: reason}
		}
	}
	return last
}
