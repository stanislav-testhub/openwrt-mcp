package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestSemverLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"1.7.0", "v1.7.1", true},
		{"v1.7.0", "1.7.0", false},
		{"1.9.0", "1.10.0", true}, // numeric, not lexical
		{"2.0.0", "1.99.99", false},
		{"1.7.0", "garbage", false},
		{"garbage", "1.7.0", false},
		{"1.7.0-rc1", "1.7.1", true},
	}
	for _, c := range cases {
		if got := semverLess(c.a, c.b); got != c.less {
			t.Errorf("semverLess(%q, %q) = %v, want %v", c.a, c.b, got, c.less)
		}
	}
}

// checkAgainst runs `version --check` with wget answering as GitHub would: body, and exit status 8 (uclient-fetch's
// "server issued an error response") when the status is not 200.
func checkAgainst(t *testing.T, status int, body string) (string, int) {
	t.Helper()
	f := newFakeRouter(t)
	f.handlers["wget"] = func(argv []string, _ string) (string, error) {
		if status != 200 {
			return "", fmt.Errorf("exit status 8: HTTP error %d", status)
		}
		return body, nil
	}
	var out bytes.Buffer
	code := versionMain([]string{"--check", "--url", "https://api.example.test/latest"}, &out)
	if argv := f.argvList(); len(argv) == 1 {
		w := strings.Join(argv[0], " ")
		if !strings.HasPrefix(w, "wget -q") || !strings.Contains(w, "-O - https://api.example.test/latest") {
			t.Errorf("wget called as %q", w)
		}
	} else {
		t.Errorf("wget ran %d times", len(argv))
	}
	return out.String(), code
}

func TestVersionCheck(t *testing.T) {
	out, code := checkAgainst(t, 200, `{"tag_name":"v99.0.0"}`)
	if code != 0 || !strings.Contains(out, "newer release: v99.0.0 ") {
		t.Errorf("newer release not reported: code %d, %q", code, out)
	}
	out, code = checkAgainst(t, 200, `{"tag_name":"v`+version+`"}`)
	if code != 0 || !strings.Contains(out, "up to date") {
		t.Errorf("same release not reported as current: code %d, %q", code, out)
	}
	out, code = checkAgainst(t, 200, `{"tag_name":"v0.0.1"}`)
	if code != 0 || strings.Contains(out, "upgrade:") {
		t.Errorf("an older latest release must not offer an upgrade: %q", out)
	}
	for name, body := range map[string]string{
		"prerelease": `{"tag_name":"v99.0.0","prerelease":true}`,
		"draft":      `{"tag_name":"v99.0.0","draft":true}`,
		"bad tag":    `{"tag_name":"nightly"}`,
		"not json":   `<html>`,
	} {
		if out, code := checkAgainst(t, 200, body); code != 1 || strings.Contains(out, "upgrade:") {
			t.Errorf("%s: want exit 1 and no upgrade offer, got %d %q", name, code, out)
		}
	}
	if out, code := checkAgainst(t, 403, `{"message":"rate limit"}`); code != 1 || !strings.Contains(out, "403") {
		t.Errorf("an HTTP error must exit 1 and say why: %d %q", code, out)
	}
}

func TestVersionWithoutCheckMakesNoRequest(t *testing.T) {
	f := newFakeRouter(t)
	var out bytes.Buffer
	if code := versionMain(nil, &out); code != 0 || out.String() != "openwrt-mcp "+version+"\n" {
		t.Errorf("plain version must print only the version: %d %q", code, out.String())
	}
	if n := len(f.argvList()); n != 0 {
		t.Errorf("plain version ran %d commands", n)
	}
}

func TestVersionCheckRefusesAURLThatIsNotHTTP(t *testing.T) {
	f := newFakeRouter(t)
	var out bytes.Buffer
	for _, u := range []string{"-O/etc/passwd", "file:///etc/shadow", "ftp://x"} {
		if code := versionMain([]string{"--check", "--url", u}, &out); code != 1 {
			t.Errorf("%q: exit %d", u, code)
		}
	}
	if n := len(f.argvList()); n != 0 {
		t.Errorf("a bad URL reached wget (%d runs)", n)
	}
}
