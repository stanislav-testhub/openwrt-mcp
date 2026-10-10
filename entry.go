package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// What a client types after the host name in `ssh host ...` reaches the bridge as
// SSH_ORIGINAL_COMMAND, because the key's forced command is fixed. It is the one input of the
// bridge that the client, not the operator, controls, so the grammar is an allow-list that can
// only narrow a session or ask for one tool call. It never names a client, a path or a shell:
//
//	entry   = { option } [ "call" ( "--list" | tool [ json | "--help" ] ) ]
//	option  = "--read-only" | "--toolset" list | "--toolset=" list
//	list    = name { "," name }          names: toolsetNames, each at most once
//	tool    = [a-z][a-z0-9_]{0,39}       whether such a tool exists is the server's question
//	json    = a JSON object, the rest of the string verbatim
//
// Tokens are separated by blanks or tabs; there is no quoting and nothing is ever handed to a
// shell. Options may not repeat. Errors are fixed texts and never quote the input.

const entryMaxLen = 16 << 10

// toolsetNames are the toolsets a client may select, in canonical order.
var toolsetNames = []string{"diag", "config", "pkg", "wg"}

type entryMode string

const (
	entryStdio entryMode = "stdio" // an MCP session over the connection
	entryCall  entryMode = "call"  // one tool call, then the connection ends
)

type entry struct {
	Mode     entryMode
	Toolsets []string // canonical order; nil means every toolset
	ReadOnly bool
	Tool     string // entryCall: the tool to run, or to describe when Help is set
	Args     string // entryCall: a JSON object, "{}" when none was given; empty with List or Help
	List     bool   // entryCall: print the session's catalogue, one line per tool
	Help     bool   // entryCall: print Tool's description and argument schema
}

var (
	errEntryTooLong = errors.New("command too long")
	errEntryChar    = errors.New("unexpected character in command")
	errEntryOption  = errors.New("unknown option (allowed: --read-only, --toolset NAME[,NAME], call TOOL [JSON])")
	errEntryRepeat  = errors.New("option given twice")
	errEntryToolset = errors.New("bad toolset (allowed: diag, config, pkg, wg, each once)")
	errEntryTool    = errors.New("bad tool name after call")
	errEntryJSON    = errors.New("call arguments must be one JSON object")
	errEntryForm    = errors.New("call takes TOOL [JSON], TOOL --help or --list")

	reEntryHeadToken = regexp.MustCompile(`^[A-Za-z0-9_=,-]+$`)
	reEntryTool      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
)

func parseEntry(cmd string) (entry, error) {
	if len(cmd) > entryMaxLen {
		return entry{}, errEntryTooLong
	}
	rest := strings.Trim(cmd, " \t\r\n")
	e := entry{Mode: entryStdio}
	for rest != "" {
		tok, after := nextEntryToken(rest)
		if !reEntryHeadToken.MatchString(tok) {
			return entry{}, errEntryChar
		}
		switch {
		case tok == "--read-only":
			if e.ReadOnly {
				return entry{}, errEntryRepeat
			}
			e.ReadOnly = true
			rest = after
		case tok == "--toolset" || strings.HasPrefix(tok, "--toolset="):
			if e.Toolsets != nil {
				return entry{}, errEntryRepeat
			}
			list, next := strings.TrimPrefix(tok, "--toolset="), after
			if tok == "--toolset" {
				list, next = nextEntryToken(after)
			}
			sets, err := parseToolsets(list)
			if err != nil {
				return entry{}, err
			}
			e.Toolsets, rest = sets, next
		case tok == "call":
			e.Mode = entryCall
			name, args := nextEntryToken(after)
			if name == "--list" {
				if args != "" {
					return entry{}, errEntryForm
				}
				e.List = true
				return e, nil
			}
			if !reEntryTool.MatchString(name) {
				return entry{}, errEntryTool
			}
			if args == "--help" {
				e.Tool, e.Help = name, true
				return e, nil
			}
			if args == "" {
				args = "{}"
			}
			if args[0] != '{' || !utf8.ValidString(args) || !json.Valid([]byte(args)) {
				return entry{}, errEntryJSON
			}
			e.Tool, e.Args = name, args
			return e, nil
		default:
			return entry{}, errEntryOption
		}
	}
	return e, nil
}

// nextEntryToken returns the first blank-separated token of s and what follows it with the
// separators stripped. A newline is not a separator: it ends up in a token and is refused there.
func nextEntryToken(s string) (tok, rest string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i:], " \t")
}

// parseToolsets checks a comma list against toolsetNames and returns it in canonical order.
func parseToolsets(list string) ([]string, error) {
	want := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		known := false
		for _, k := range toolsetNames {
			known = known || k == n
		}
		if !known || want[n] {
			return nil, errEntryToolset
		}
		want[n] = true
	}
	var out []string
	for _, k := range toolsetNames {
		if want[k] {
			out = append(out, k)
		}
	}
	return out, nil
}
