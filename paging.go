package main

import "fmt"

// The truncation contract (ROADMAP 4.7): whenever a result is cut, its last line says so in one
// shape, "[truncated: <what>; <how to get the rest>]", so a client can find it without parsing
// prose and a cut result never reads as complete. A tool that can page names the offset to ask
// for next. The text inside the brackets has no ']' in it.
func truncNotice(what, next string) string {
	return "[truncated: " + what + "; " + next + "]"
}

// Lines per page for the tools that page. A page is a bound on tokens, not on what exists: the
// total stays in the result and the rest is one call away.
const (
	pkgPageLines   = 200
	clientPageRows = 100
)

// pageLines returns lines[offset:offset+limit] and the notice that goes after it. The notice is
// empty when nothing is left, and says so plainly when offset is past the end.
func pageLines(lines []string, offset, limit int, unit string) ([]string, string) {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(lines) {
		if offset == 0 {
			return nil, ""
		}
		return nil, fmt.Sprintf("(nothing at offset %d; %d %s in total)", offset, len(lines), unit)
	}
	end := offset + limit
	if end >= len(lines) {
		return lines[offset:], ""
	}
	return lines[offset:end], truncNotice(fmt.Sprintf("%d more %s omitted", len(lines)-end, unit),
		fmt.Sprintf("call again with offset=%d", end))
}
