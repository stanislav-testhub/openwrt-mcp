package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// Footprint budgets (ROADMAP 10.1). Raising one needs a reason in the commit that raises it.
//
// maxStrippedMipsleBytes: stripped, trimpath, GOOS=linux GOARCH=mipsle GOMIPS=softfloat, the build a
// 128 MB / 16 MB-flash router gets. Measured 12 976 319 bytes after Milestone 9 (1.5.0 was 11.9 MB).
// maxStartupHeapBytes: heap bytes allocated by our own package init, from GODEBUG=inittrace=1. Measured
// 2 557 528 bytes: mostly package-level regexps that the bridge never uses. Milestone 10.2 moves them
// behind sync.OnceValue and lowers this to 100 000.
const (
	maxStrippedMipsleBytes = 13_300_000
	maxStartupHeapBytes    = 2_800_000
)

func buildTo(t *testing.T, out string, env []string, flags ...string) {
	t.Helper()
	args := append([]string{"build", "-trimpath"}, flags...)
	cmd := exec.Command("go", append(args, "-o", out, ".")...)
	cmd.Env = append(os.Environ(), env...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
}

func TestFootprintBinarySize(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-build takes a while")
	}
	out := filepath.Join(t.TempDir(), "openwrt-mcp-mipsle")
	buildTo(t, out, []string{"GOOS=linux", "GOARCH=mipsle", "GOMIPS=softfloat", "CGO_ENABLED=0"}, "-ldflags=-s -w")
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("stripped mipsle-softfloat binary: %d bytes (budget %d)", fi.Size(), maxStrippedMipsleBytes)
	if fi.Size() > maxStrippedMipsleBytes {
		t.Errorf("binary is %d bytes, budget %d: raise it only with a reason in the commit", fi.Size(), maxStrippedMipsleBytes)
	}
}

var initMain = regexp.MustCompile(`(?m)^init main @\S+ ms, \S+ ms clock, (\d+) bytes`)

func TestFootprintStartupHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	out := filepath.Join(t.TempDir(), "openwrt-mcp")
	buildTo(t, out, nil)
	cmd := exec.Command(out, "version")
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1")
	b, _ := cmd.CombinedOutput()
	m := initMain.FindSubmatch(b)
	if m == nil {
		t.Fatalf("no 'init main' line in inittrace output:\n%s", b)
	}
	n, _ := strconv.Atoi(string(m[1]))
	t.Logf("our package init allocates %d bytes (budget %d)", n, maxStartupHeapBytes)
	if n > maxStartupHeapBytes {
		t.Errorf("start-up allocates %d bytes, budget %d: new package-level work belongs behind sync.OnceValue", n, maxStartupHeapBytes)
	}
}

func TestSelfMemoryLine(t *testing.T) {
	if _, err := os.Stat("/proc/self/status"); err != nil {
		t.Skip("no /proc")
	}
	if !regexp.MustCompile(`^openwrt-mcp memory \d+\.\d MiB resident, \d+\.\d MiB peak$`).MatchString(selfMemoryLine()) {
		t.Errorf("unexpected line %q", selfMemoryLine())
	}
}
