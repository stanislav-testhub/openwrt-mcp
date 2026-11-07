package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// request_access asks for several permissions in one go. A refused call opens a request and holds
// the call until the owner answers, and a client that runs its calls one after another then shows
// the owner one card at a time, each needing its own tap. This tool opens every request first, at
// once and without waiting, so LuCI shows them together under one "Allow all N" row; the real calls
// then find their requests already answered (or reuse the same request: it is keyed by client, tool
// and scope). It grants nothing and is not a way around the limits on open requests: each one goes
// through RequestStore.Open like a refused call would.

const maxAccessWants = 8

// accessScope is what a scope looks like: the characters real scopes use, nothing a card could be
// made to render as markup or a line break.
var accessScope = regexp.MustCompile(`^[A-Za-z0-9_.*@\[\]:/ -]{1,300}$`)

type requestAccessIn struct {
	Wants []string `json:"wants" jsonschema:"1 to 8 coming calls, each 'tool scope scope', e.g. 'uci_apply wireless.radio1.channel'"`
}

// parseWant splits "tool scope scope" into the tool and its scopes.
func parseWant(w string) (string, []string) {
	f := strings.Fields(w)
	if len(f) == 0 {
		return "", nil
	}
	return f[0], f[1:]
}

func (in requestAccessIn) validate() error {
	if n := len(in.Wants); n < 1 || n > maxAccessWants {
		return invalid("wants needs 1 to %d entries, got %d", maxAccessWants, n)
	}
	for _, w := range in.Wants {
		tool, scopes := parseWant(w)
		if !slices.Contains(allToolNames, tool) || ungatedTools[tool] {
			return invalid("%q is not a tool that needs a grant", tool)
		}
		if len(scopes) > 0 && !accessScope.MatchString(strings.Join(scopes, " ")) {
			return invalid("scope in %q has characters a scope never has", w)
		}
	}
	return nil
}

func (s *Server) requestAccess(client string, in requestAccessIn, now time.Time) (string, string, error) {
	cfg := s.cfg()
	var lines []string
	opened := 0
	for _, w := range in.Wants {
		tool, scopes := parseWant(w)
		label := tool + " " + orStar(strings.Join(scopes, " "))
		p, _, missing := cfg.authorise(client, tool, scopes, now)
		switch {
		case p != nil:
			lines = append(lines, label+": already allowed")
		case missing == "":
			lines = append(lines, label+": not a missing grant (a rate limit); nothing to ask for")
		default:
			req, ok := s.requests.Open(now, cfg.RequestTTL, client, tool, missing, nil)
			if !ok {
				lines = append(lines, label+": not opened, too many requests are waiting; ask the operator to answer them first")
				continue
			}
			opened++
			lines = append(lines, fmt.Sprintf("%s: request %s", label, req.ID))
		}
	}
	head := fmt.Sprintf("%d of %d requests are waiting.", opened, len(in.Wants))
	if opened > 0 {
		head += " Tell the operator to open LuCI → Services → MCP Server and answer them together (Allow all); then make the calls."
	}
	return head + "\n" + strings.Join(lines, "\n"), fmt.Sprintf("%d requested", opened), nil
}
