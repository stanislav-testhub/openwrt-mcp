package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Pre-reload validation (ROADMAP 2.1). A checker asks a service's own tool whether it accepts
// the staged configuration. Measured on the router: `fw4 check` sees changes staged in uci, but
// it exits 0 even for an invalid value and only prints "[!]" lines for what it would ignore, so
// the verdict comes from those lines. dnsmasq has nothing equivalent: `dnsmasq --test` reads a
// file the init script generates at service start, from the committed config. Configs without
// a checker are reported as not checked rather than passed.
//
// A checker is run before staging (the baseline) and after (the candidate). Only problems that
// are new block an apply, so a config that was already broken can still be fixed.
var checkers = map[string]func(ctx context.Context) []string{
	"firewall": fw4Problems,
}

func fw4Problems(ctx context.Context) []string {
	out, err := run(ctx, defaultCmdTimeout, "fw4", "check")
	var warn, rest []string
	for _, l := range strings.Split(out, "\n") {
		switch l = strings.TrimSpace(l); {
		case strings.HasPrefix(l, "[!]"):
			warn = append(warn, l)
		case l != "":
			rest = append(rest, l)
		}
	}
	if err != nil {
		warn = append(warn, "fw4 check failed: "+err.Error())
		warn = append(warn, rest[:min(len(rest), 5)]...)
	}
	return warn
}

// checkAll runs the checker of every named config that has one. A config with a checker has a
// key in the result, even when it reported nothing.
func checkAll(ctx context.Context, names []string) map[string][]string {
	out := map[string][]string{}
	for _, c := range names {
		if chk := checkers[c]; chk != nil {
			out[c] = chk(ctx)
		}
	}
	return out
}

// Section indexes shift when an earlier section goes, so "@rule[3]" and "@rule[2]" are the same
// warning. Counting, not set membership, still notices a second copy of one.
var reSectionIndex = regexp.MustCompile(`@([A-Za-z0-9_-]+)\[-?[0-9]+\]`)

func newProblems(base, cand []string) []string {
	seen := map[string]int{}
	for _, p := range base {
		seen[reSectionIndex.ReplaceAllString(p, "@$1[]")]++
	}
	var fresh []string
	for _, p := range cand {
		k := reSectionIndex.ReplaceAllString(p, "@$1[]")
		if seen[k] > 0 {
			seen[k]--
			continue
		}
		fresh = append(fresh, p)
	}
	return fresh
}

// validationReport renders the comparison. fresh is empty when nothing new was found; otherwise
// it is the problem text a refusal quotes.
func validationReport(names []string, base, cand map[string][]string) (report, fresh string) {
	var lines, unchecked []string
	var nb strings.Builder
	for _, c := range names {
		got, ok := cand[c]
		if !ok {
			unchecked = append(unchecked, c)
			continue
		}
		nw := newProblems(base[c], got)
		if len(nw) == 0 {
			l := "  " + c + ": OK"
			if len(got) > 0 {
				l += fmt.Sprintf(" (%d existing warning(s) unchanged)", len(got))
			}
			lines = append(lines, l)
			continue
		}
		lines = append(lines, fmt.Sprintf("  %s: %d NEW problem(s):", c, len(nw)))
		fmt.Fprintf(&nb, "%s: %d NEW problem(s):\n", c, len(nw))
		for _, p := range nw {
			lines = append(lines, "      "+p)
			nb.WriteString("    " + p + "\n")
		}
	}
	if len(unchecked) > 0 {
		lines = append(lines, "  not checked (no pre-reload checker exists): "+strings.Join(unchecked, ", "))
	}
	return "validation (each service's own checker, run on the staged config before any reload):\n" +
		strings.Join(lines, "\n"), strings.TrimRight(nb.String(), "\n")
}
