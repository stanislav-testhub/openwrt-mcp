package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScrubRewritesAddressesMACsHostsAndSecrets(t *testing.T) {
	in := "wan 203.0.113.9 gw 10.20.30.1 lan 192.168.1.1 lo 127.0.0.1 mask 255.255.255.0\n" +
		"peer 84.12.7.5:51820 again 84.12.7.5 router7.home.arpa ROUTER7\n" +
		"mac AA:BB:CC:DD:EE:01 and aa:bb:cc:dd:ee:01 and aa:bb:cc:dd:ee:02\n" +
		"v6 2a02:1234:5678::1 and fe80::1ff:fe23:4567:890a and ::1\n" +
		"key 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG='\n" +
		"adblock.global.password='hunter2'\nAuthorization: Bearer abc123def\n" +
		"nets 10.0.0.0/8 stay\n"
	got := newScrubber([]string{"router7"}).scrubCapture(in)
	for _, bad := range []string{"10.20.30.1", "84.12.7.5", "aa:bb:cc", "AA:BB", "2a02", "fe80", "AbCdEf", "hunter2", "abc123def", "router7", "ROUTER7"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived:\n%s", bad, got)
		}
	}
	for _, keep := range []string{"203.0.113.9", "192.168.1.1", "127.0.0.1", "255.255.255.0", "::1", "host-1.home.arpa", "10.0.0.0/8"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was rewritten:\n%s", keep, got)
		}
	}
	// The same input scrubs to the same stand-in, and two inputs to two.
	if strings.Count(got, "198.51.100.2") != 2 || !strings.Contains(got, "02:00:00:00:00:01 and 02:00:00:00:00:01 and 02:00:00:00:00:02") {
		t.Errorf("stand-ins are not stable:\n%s", got)
	}
	if p := fixtureProblems(got); len(p) != 0 {
		t.Errorf("scrubbed text still has problems: %v", p)
	}
	if again := newScrubber([]string{"router7"}).scrubCapture(got); again != got {
		t.Errorf("scrubbing twice changes the text:\n%s\n---\n%s", got, again)
	}
}

func TestFixtureProblemsCatchWhatAScrubberMustRemove(t *testing.T) {
	for _, bad := range []string{"gw 10.0.0.1", "lan 172.16.4.2 x", "mac aa:bb:cc:dd:ee:ff", "k AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG=", "token=abcdef"} {
		if len(fixtureProblems(bad)) == 0 {
			t.Errorf("%q passed the hygiene check", bad)
		}
	}
	for _, ok := range []string{"gw 192.168.1.1", "wan 198.51.100.7", "mac 02:00:00:00:00:01", "token=<secret>", "ver 1.2.3.4"} {
		if p := fixtureProblems(ok); len(p) != 0 {
			t.Errorf("%q flagged: %v", ok, p)
		}
	}
}

// Every checked-in fixture is clean. Synthetic fixtures use the lab subnet or documentation
// ranges by construction; a real capture that skipped the scrubber fails here.
func TestCheckedInFixturesHoldNoRealAddressesOrSecrets(t *testing.T) {
	n := 0
	err := filepath.Walk("testdata", func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 4<<20 {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		for _, prob := range fixtureProblems(string(b)) {
			t.Errorf("%s: %s", p, prob)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("no fixtures walked")
	}
}

// A capture manifest can only name commands that read: the oracle of the contract test, or a
// `cat` of one file under /etc, /tmp or /var/run.
func TestCaptureManifestsAreReadOnly(t *testing.T) {
	files, _ := filepath.Glob("testdata/capture/*.cmds")
	if len(files) == 0 {
		t.Fatal("no capture manifests")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			a := strings.Fields(line)
			if a[0] == "cat" {
				ok := len(a) == 2 && !strings.Contains(a[1], "..")
				ok = ok && (strings.HasPrefix(a[1], "/etc/") || strings.HasPrefix(a[1], "/tmp/") || strings.HasPrefix(a[1], "/var/run/"))
				if !ok {
					t.Errorf("%s: %q reads more than one file under /etc, /tmp or /var/run", f, line)
				}
				continue
			}
			if !readOnlyCommand(a) {
				t.Errorf("%s: %q is not a read-only command", f, line)
			}
		}
	}
}
