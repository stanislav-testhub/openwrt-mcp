//go:build capture

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// `openwrt-mcp scrub [-hosts a,b] < capture > scrubbed`: built only with -tags capture, so the
// router's binary does not carry it. `make capture` pipes every captured output through it.
func init() {
	extraCommands["scrub"] = func(args []string) int {
		fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
		hosts := fs.String("hosts", "", "comma-separated host names to replace")
		if err := fs.Parse(args); err != nil {
			return 2
		}
		in, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		out := newScrubber(strings.Split(*hosts, ",")).scrubCapture(string(in))
		fmt.Print(out)
		if p := fixtureProblems(out); len(p) > 0 {
			fmt.Fprintln(os.Stderr, "scrub: still present:", strings.Join(p, "; "))
			return 1
		}
		return 0
	}
}
