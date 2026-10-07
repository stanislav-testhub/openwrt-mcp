package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// ROADMAP 3.2 "Done when": doctor names the failing step for each fault injected in a test: wrong
// key, missing forced command, daemon stopped, socket disabled. The faults are what OpenSSH and
// our bridge print (see TestHelperFakeTool); the healthy case runs the real MCP server.

func doctorRun(t *testing.T, scenario string) (string, error) {
	t.Helper()
	fakeTool(t, scenario)
	old := doctorTimeout
	doctorTimeout = 4 * time.Second
	t.Cleanup(func() { doctorTimeout = old })
	p := testParams()
	p.Key = "/home/u/.ssh/openwrt_mcp"
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, p)
	return out.String(), err
}

func TestDoctorOnAHealthyRouterPassesEveryStep(t *testing.T) {
	out, err := doctorRun(t, "ssh:ok")
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	for _, step := range doctorSteps {
		if !strings.Contains(out, "[ ok ] "+step) {
			t.Errorf("step %q did not pass:\n%s", step, out)
		}
	}
	if strings.Contains(out, "FAIL") || strings.Contains(out, "skip") {
		t.Errorf("a healthy router shows a failure or a skipped step:\n%s", out)
	}
	if !strings.Contains(out, "openwrt-mcp 9.9.9") || !strings.Contains(out, "1 tools") {
		t.Errorf("doctor should say what answered and how many tools it listed:\n%s", out)
	}
}

func TestDoctorNamesTheFailingStepAndHowToFixIt(t *testing.T) {
	for _, tc := range []struct {
		scenario, step, fixHas string
	}{
		{"ssh:resolve", "ssh reachable", "ping"},
		{"ssh:refused", "ssh reachable", "--port"},
		{"ssh:timeout", "ssh reachable", "192.0.2.1:22"},
		{"ssh:hostkey-unknown", "host key", "connect once by hand"},
		{"ssh:hostkey-changed", "host key", "ssh-keygen -R"},
		{"ssh:denied", "key accepted", "authorize-key"},
		{"ssh:key-too-open", "key accepted", "chmod 600"},
		{"ssh:no-key-file", "key accepted", "--key"},
		{"ssh:shell", "forced command", "authorize-key claude-code"},
		{"ssh:banner", "forced command", "forced command"},
		{"ssh:silent", "forced command", "forced command"},
		{"ssh:daemon-down", "daemon socket", "/etc/init.d/openwrt-mcp start"},
		{"ssh:bridge-disabled", "daemon socket", "option socket ''"},
		{"ssh:empty", "tools/list", "openwrt-mcp"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			out, err := doctorRun(t, tc.scenario)
			if err == nil || !strings.Contains(err.Error(), tc.step) {
				t.Fatalf("error %v, want one naming %q\n%s", err, tc.step, out)
			}
			if strings.Count(out, "[FAIL]") != 1 || !strings.Contains(out, "[FAIL] "+tc.step) {
				t.Errorf("exactly the %q step should fail:\n%s", tc.step, out)
			}
			if !strings.Contains(out, "fix:") || !strings.Contains(out, tc.fixHas) {
				t.Errorf("no fix mentioning %q:\n%s", tc.fixHas, out)
			}
			// Steps before the failure passed, steps after it were not run.
			idx := 0
			for i, s := range doctorSteps {
				if s == tc.step {
					idx = i
				}
			}
			for i, s := range doctorSteps {
				want := "[ ok ] " + s
				if i == idx {
					continue
				}
				if i > idx {
					want = "[skip] " + s
				}
				if !strings.Contains(out, want) {
					t.Errorf("step %q should read %q:\n%s", s, want, out)
				}
			}
		})
	}
}

func TestDoctorSaysWhenOpenSSHIsMissing(t *testing.T) {
	old := sshCommand
	sshCommand = []string{"definitely-not-an-ssh-binary"}
	t.Cleanup(func() { sshCommand = old })
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, testParams())
	if err == nil || !strings.Contains(out.String(), "install OpenSSH") {
		t.Errorf("missing ssh: %v\n%s", err, out.String())
	}
}

func TestDoctorRefusesBadParametersBeforeStartingAnything(t *testing.T) {
	fakeTool(t, "ssh:ok")
	p := testParams()
	p.Host = "-oProxyCommand=calc"
	var out bytes.Buffer
	if err := runDoctor(context.Background(), &out, p); err == nil || out.Len() != 0 {
		t.Errorf("a host that is an ssh option: %v %q", err, out.String())
	}
}

// classify is the one place that reads ssh's wording; a table over the real strings keeps it honest
// on the other two OSes, whose wording differs from Linux's.
func TestClassifyReadsTheWordingOfOpenSSHOnEveryOS(t *testing.T) {
	p := testParams()
	for _, tc := range []struct {
		stderr string
		step   int
	}{
		{"ssh: Could not resolve hostname r: nodename nor servname provided, or not known", stepReach}, // macOS
		{"ssh: Could not resolve hostname r: No such host is known.", stepReach},                       // Windows
		{"ssh: connect to host 192.0.2.1 port 22: Operation timed out", stepReach},                     // macOS
		{"ssh: connect to host 192.0.2.1 port 22: No route to host", stepReach},                        //
		{"ssh: connect to host 192.0.2.1 port 22: Network is unreachable", stepReach},                  //
		{"kex_exchange_identification: Connection closed by remote host", stepReach},                   // anti-scan limit
		{"Connection reset by 192.0.2.1 port 22", stepReach},                                           //
		{"Host key verification failed.", stepHostKey},                                                 //
		{"root@192.0.2.1: Permission denied (publickey).", stepKey},                                    //
		{"Load key \"C:\\\\k\": invalid format\nroot@h: Permission denied (publickey).", stepKey},      //
		{"openwrt-mcp: daemon closed the connection on /var/run/openwrt-mcp/mcp.sock", stepDaemon},     //
		{"", stepForced},                   // nothing at all
		{"Welcome to OpenWrt", stepForced}, //
	} {
		if got := classify(tc.stderr, false, p); got.step != tc.step {
			t.Errorf("%q -> step %q, want %q", tc.stderr, doctorSteps[got.step], doctorSteps[tc.step])
		}
	}
}
