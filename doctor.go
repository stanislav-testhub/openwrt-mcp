package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// `openwrt-mcp connect doctor` starts the same ssh command a client would and talks MCP over it.
// One connection tells a lot, so the steps below are the order a fault shows up in, and a later
// step passing proves the earlier ones. Each failure says what to do about it.

var doctorSteps = []string{
	"ssh reachable", "host key", "key accepted", "forced command", "daemon socket", "initialize", "tools/list",
}

const (
	stepReach = iota
	stepHostKey
	stepKey
	stepForced
	stepDaemon
	stepInit
	stepTools
)

// doctorTimeout bounds the whole check; a variable so a test need not wait for it.
var doctorTimeout = 25 * time.Second

type doctorFault struct {
	step   int
	detail string
	fix    string
}

// lockedBuffer collects ssh's stderr while the transport is still using the process.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// firstNonEmptyLine is the first non-empty line of s, for a one-line detail.
func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// lineWith returns the first line of s that contains any of the words.
func lineWith(s string, words ...string) string {
	for _, l := range strings.Split(s, "\n") {
		for _, w := range words {
			if strings.Contains(l, w) {
				return strings.TrimSpace(l)
			}
		}
	}
	return ""
}

func anyOf(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// classify turns what ssh and the bridge printed, and whether nothing answered in time, into the
// step that failed. The words are what OpenSSH and our bridge print, on Linux, macOS and Windows.
func classify(stderr string, timedOut bool, p connectParams) doctorFault {
	hostPort := p.Host + ":" + strconv.Itoa(p.Port)
	switch {
	case anyOf(stderr, "Could not resolve hostname"):
		return doctorFault{stepReach, lineWith(stderr, "Could not resolve hostname"),
			"check the spelling of --host, or use the router's address; `ping " + p.Host + "` should answer"}
	case anyOf(stderr, "Connection refused"):
		return doctorFault{stepReach, lineWith(stderr, "Connection refused"),
			"nothing listens on port " + strconv.Itoa(p.Port) + ": is dropbear running on the router, and is --port the SSH port?"}
	case anyOf(stderr, "Connection timed out", "Operation timed out", "No route to host", "Network is unreachable"):
		return doctorFault{stepReach, lineWith(stderr, "timed out", "No route", "unreachable"),
			"the router did not answer at " + hostPort + ": check the address, that this PC is on its network (or its VPN), and any firewall between"}
	case anyOf(stderr, "kex_exchange_identification", "Connection closed by", "Connection reset"):
		return doctorFault{stepReach, lineWith(stderr, "kex_exchange_identification", "Connection closed", "Connection reset"),
			"the router closed the connection during the handshake. Too many recent failed logins from this address can do that; wait a minute and retry"}
	case anyOf(stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED"):
		return doctorFault{stepHostKey, "the router's host key is not the one this PC remembers",
			"expected after a reflash or a reset; otherwise someone may be in the middle. If you trust it: ssh-keygen -R " +
				quoteArg("linux", "["+p.Host+"]:"+strconv.Itoa(p.Port)) + ", then connect once by hand to accept the new key"}
	case anyOf(stderr, "Host key verification failed", "host key is known"):
		return doctorFault{stepHostKey, "this PC has not seen the router's host key, and a client cannot ask",
			"connect once by hand and accept it after checking the fingerprint: ssh -p " + strconv.Itoa(p.Port) + " root@" + p.Host}
	case anyOf(stderr, "UNPROTECTED PRIVATE KEY", "are too open", "bad permissions"):
		return doctorFault{stepKey, lineWith(stderr, "are too open", "bad permissions", "UNPROTECTED"),
			"ssh refuses a private key other users can read: chmod 600 " + p.Key + " (on Windows, remove other users from the file's permissions)"}
	case anyOf(stderr, "not accessible", "No such file", "invalid format", "Load key"):
		return doctorFault{stepKey, lineWith(stderr, "not accessible", "No such file", "invalid format", "Load key"),
			"ssh cannot use " + p.Key + ": check --key, or make the key with `openwrt-mcp connect`"}
	case anyOf(stderr, "Permission denied"):
		return doctorFault{stepKey, lineWith(stderr, "Permission denied"),
			"the router did not accept " + p.Key + ": run the authorize-key line from `openwrt-mcp connect` on the router, and check --key and --user"}
	case anyOf(stderr, "stdio bridge is disabled"):
		return doctorFault{stepDaemon, lineWith(stderr, "stdio bridge is disabled"),
			"the router has `option socket ''`: remove it from /etc/config/openwrt-mcp (the default is /var/run/openwrt-mcp/mcp.sock), then /etc/init.d/openwrt-mcp restart"}
	case anyOf(stderr, "daemon not reachable", "daemon closed the connection"):
		return doctorFault{stepDaemon, lineWith(stderr, "daemon not reachable", "daemon closed"),
			"the daemon is not running: on the router /etc/init.d/openwrt-mcp start, and `logread -e openwrt-mcp` says why it stopped"}
	}
	detail := "the key logged in, but nothing answered as an MCP server"
	if l := firstNonEmptyLine(stderr); l != "" {
		detail += " (" + l + ")"
	} else if timedOut {
		detail += " within " + doctorTimeout.String()
	}
	return doctorFault{stepForced, detail,
		"the key is probably authorized without its forced command, so a shell ran instead: remove its line from " +
			"/etc/dropbear/authorized_keys on the router and run `openwrt-mcp authorize-key " + p.Name + " '<public key>'` again"}
}

// runDoctor prints one line per step and returns an error if one failed. Steps after the failing
// one are not run: they would only repeat it.
func runDoctor(ctx context.Context, w io.Writer, p connectParams) error {
	if err := p.validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, doctorTimeout)
	defer cancel()

	argv := append(append([]string(nil), sshCommand...), append([]string{"-o", "ConnectTimeout=10"}, p.sshArgs()...)...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	errBuf := &lockedBuffer{}
	cmd.Stderr = errBuf

	client := mcp.NewClient(&mcp.Implementation{Name: "openwrt-mcp-doctor", Version: version}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: time.Second}, nil)
	if err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait() // lets the stderr copy finish
		}
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		var notFound *exec.Error
		if errors.As(err, &notFound) {
			fmt.Fprintf(w, "[FAIL] %-15s %v\n       fix: install OpenSSH (Windows: Settings > Optional features; macOS and Linux have it)\n", doctorSteps[stepReach], err)
			return errors.New("doctor: ssh not found")
		}
		return report(w, p, classify(errBuf.String(), timedOut, p), "")
	}
	defer cs.Close()

	info := "openwrt-mcp"
	if ir := cs.InitializeResult(); ir != nil && ir.ServerInfo != nil {
		info = ir.ServerInfo.Name + " " + ir.ServerInfo.Version
	}
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		return report(w, p, doctorFault{stepTools, err.Error(),
			"the server answered initialize but not tools/list: check `openwrt-mcp version` on the router and /etc/init.d/openwrt-mcp restart"}, info)
	}
	if len(res.Tools) == 0 {
		return report(w, p, doctorFault{stepTools, "the server lists no tools",
			"this is not openwrt-mcp, or it is a broken build: openwrt-mcp version on the router"}, info)
	}
	for i := 0; i < stepTools; i++ {
		fmt.Fprintf(w, "[ ok ] %-15s %s\n", doctorSteps[i], passedDetail(i, p, info))
	}
	fmt.Fprintf(w, "[ ok ] %-15s %d tools\n", doctorSteps[stepTools], len(res.Tools))
	return nil
}

// passedDetail is what a step that passed has to say for itself.
func passedDetail(step int, p connectParams, info string) string {
	switch step {
	case stepReach:
		return p.Host + ":" + strconv.Itoa(p.Port)
	case stepKey:
		return p.Key
	case stepInit:
		return info
	}
	return ""
}

// report prints the steps that passed before the fault, the fault with its fix, and the rest as
// skipped, then returns an error naming the step.
func report(w io.Writer, p connectParams, f doctorFault, info string) error {
	for i, name := range doctorSteps {
		switch {
		case i < f.step:
			fmt.Fprintf(w, "[ ok ] %-15s %s\n", name, passedDetail(i, p, info))
		case i == f.step:
			fmt.Fprintf(w, "[FAIL] %-15s %s\n       fix: %s\n", name, f.detail, f.fix)
		default:
			fmt.Fprintf(w, "[skip] %-15s\n", name)
		}
	}
	return fmt.Errorf("doctor: %s failed", doctorSteps[f.step])
}
