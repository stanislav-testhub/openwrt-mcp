package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// `openwrt-mcp version --check` (ROADMAP, Later: update check). It asks GitHub for the latest release once, when the
// operator runs it. The daemon never calls out on its own: a root daemon on a router does not phone home.
//
// It fetches with wget (uclient-fetch on OpenWrt, with ca-bundle, as install-router.sh does) and not with net/http's
// client: the client's transport, HTTP/2 and gzip add about 450 KB to the mipsle binary (measured), and a 16 MB flash
// pays for that on every router for a command run once in a while.
const releasesAPI = "https://api.github.com/repos/stanislav-testhub/openwrt-mcp/releases/latest"

// parseSemver reads "v1.2.3" or "1.2.3" (a "-rc1" style suffix is ignored for ordering) into three numbers.
func parseSemver(s string) ([3]int, bool) {
	var out [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// semverLess reports whether a is an older release than b. A version that does not parse is never older.
func semverLess(a, b string) bool {
	x, ok1 := parseSemver(a)
	y, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}

// latestRelease returns the tag of the newest non-draft, non-prerelease release the API names.
func latestRelease(ctx context.Context, url string) (string, error) {
	if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
		return "", fmt.Errorf("%q is not an http(s) URL", url) // also keeps it from being read as an option
	}
	out, err := run(ctx, 20*time.Second, "wget", "-q", "-T", "15", "-O", "-", url)
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return "", errors.New("wget is not installed")
		}
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	var rel struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(io.LimitReader(strings.NewReader(out), 1<<20)).Decode(&rel); err != nil {
		return "", fmt.Errorf("reading the release: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return "", errors.New("the latest release is a draft or a prerelease")
	}
	if _, ok := parseSemver(rel.Tag); !ok {
		return "", fmt.Errorf("release tag %q is not a version", rel.Tag)
	}
	return rel.Tag, nil
}

// versionMain runs `version [--check]`. It returns the process exit code: 0 when the check ran (up to date or not),
// 1 when it could not ask.
func versionMain(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	check := fs.Bool("check", false, "ask GitHub whether a newer release exists")
	url := fs.String("url", releasesAPI, "release API to ask (a mirror, or a test server)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(out, "usage: openwrt-mcp version [--check]\n")
		return 2
	}
	fmt.Fprintf(out, "openwrt-mcp %s\n", version)
	if !*check {
		return 0
	}
	tag, err := latestRelease(context.Background(), *url)
	if err != nil {
		fmt.Fprintf(out, "could not check for a newer release: %v\n", err)
		return 1
	}
	if semverLess(version, tag) {
		fmt.Fprintf(out, "newer release: %s (you run %s)\nupgrade: ./install.sh upgrade (from a checkout), or run the release's install-router.sh on the router\n", tag, version)
	} else {
		fmt.Fprintf(out, "up to date (latest release %s)\n", tag)
	}
	return 0
}
