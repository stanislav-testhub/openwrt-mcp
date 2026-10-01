package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeRouter stands in for the router's binaries. Commands are matched by the longest
// registered prefix of their space-joined argv; anything unregistered fails the way a
// missing binary would, so a tool that runs something unexpected shows up as an error.
type fakeRouter struct {
	mu       sync.Mutex
	calls    []string
	argvs    [][]string // the same commands with their argument boundaries intact
	stdins   []string
	handlers map[string]func(argv []string, stdin string) (string, error)
}

func newFakeRouter(t *testing.T) *fakeRouter {
	t.Helper()
	f := &fakeRouter{handlers: map[string]func([]string, string) (string, error){}}
	old := cmdRunner
	cmdRunner = f.run
	t.Cleanup(func() { cmdRunner = old })
	return f
}

// withFixtureRoot points file access at a temp tree and returns its root.
func withFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	oldRoot, oldConf := sysRoot, uciConfDir
	sysRoot = root
	uciConfDir = filepath.Join(root, "etc", "config")
	if err := os.MkdirAll(uciConfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sysRoot, uciConfDir = oldRoot, oldConf })
	return root
}

func writeFixture(t *testing.T, root, p, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeRouter) on(prefix, out string) {
	f.onFn(prefix, func([]string, string) (string, error) { return out, nil })
}

func (f *fakeRouter) fail(prefix, out string) {
	f.onFn(prefix, func([]string, string) (string, error) { return out, errors.New("exit status 1") })
}

func (f *fakeRouter) onFn(prefix string, fn func(argv []string, stdin string) (string, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[prefix] = fn
}

func (f *fakeRouter) run(_ context.Context, stdin *string, argv []string) (string, string, error) {
	line := strings.Join(argv, " ")
	in := ""
	if stdin != nil {
		in = *stdin
	}
	f.mu.Lock()
	f.calls = append(f.calls, line)
	f.argvs = append(f.argvs, append([]string(nil), argv...))
	f.stdins = append(f.stdins, in)
	var best string
	var fn func([]string, string) (string, error)
	for p, h := range f.handlers {
		if (line == p || strings.HasPrefix(line, p+" ")) && len(p) >= len(best) {
			best, fn = p, h
		}
	}
	f.mu.Unlock()
	if fn == nil {
		return "", "fake: not found: " + line, errors.New("exit status 127")
	}
	out, err := fn(argv, in)
	if err != nil {
		return "", out, err
	}
	return out, "", nil
}

func (f *fakeRouter) ran(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == prefix || strings.HasPrefix(c, prefix+" ") {
			return true
		}
	}
	return false
}

// argvList returns every command's argv, so a test can tell "a b" (one argument) from "a", "b".
func (f *fakeRouter) argvList() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.argvs...)
}

func (f *fakeRouter) allCalls() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

// testServer builds a Server on temp config/state paths with the given policy config.
func testServer(t *testing.T, policies string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "openwrt-mcp")
	if err := os.WriteFile(cfg, []byte("config server\n\toption socket ''\n\toption audit '"+
		filepath.ToSlash(filepath.Join(dir, "audit.jsonl"))+"'\n"+policies), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(cfg, filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
