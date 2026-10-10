package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// `ssh router call TOOL '{...}'` runs one tool and prints its text. It is a transport, not a
// second way in: the daemon makes the call through an in-memory MCP client against the same
// per-client server an MCP session would use, with the session profile on the context, so the
// policy check, the audit record, the redaction and the rollback arming are the tool handler's own.
// Nothing here can reach uci, exec or the filesystem except through a registered tool.

// callReply is the single line the daemon answers a call with. A failed call (a denial, a bad
// argument, a tool error) has Error set; the bridge prints it to stderr and exits 1.
type callReply struct {
	Text  string `json:"text"`
	Error bool   `json:"error,omitempty"`
}

// errCallFailed makes the stdio subcommand exit 1 without a log prefix: the reason is already
// on stderr.
var errCallFailed = errors.New("call failed")

// handleCall answers one call on conn. The caller sends nothing after its hello, so a read that
// returns means the connection is gone (ssh dropped, the agent gave up): the call is cancelled
// then, which kills the tool's child process.
func (s *Server) handleCall(conn net.Conn, br *bufio.Reader, client string, ent entry, profile sessionProfile) {
	ctx, cancel := context.WithCancel(withProfile(context.Background(), profile))
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, br)
		cancel()
	}()
	text, failed := s.runCall(ctx, client, ent)
	line, _ := json.Marshal(callReply{Text: text, Error: failed})
	_, _ = conn.Write(append(line, '\n'))
}

func (s *Server) runCall(ctx context.Context, client string, ent entry) (text string, failed bool) {
	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.serverFor(client).Connect(ctx, st, nil)
	if err != nil {
		return err.Error(), true
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "openwrt-mcp-call", Version: version}, nil).Connect(ctx, ct, nil)
	if err != nil {
		return err.Error(), true
	}
	defer cs.Close()

	if ent.List || ent.Help {
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			return err.Error(), true
		}
		if ent.List {
			return describeCatalogue(res.Tools), false
		}
		for _, tl := range res.Tools {
			if tl.Name == ent.Tool {
				return describeTool(tl), false
			}
		}
		return fmt.Sprintf("no tool %q in this session (see: call --list)", ent.Tool), true
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: ent.Tool, Arguments: json.RawMessage(ent.Args)})
	if err != nil {
		return err.Error(), true
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String(), res.IsError
}

// describeCatalogue is `call --list`: one line per tool the session has, name then title.
func describeCatalogue(tools []*mcp.Tool) string {
	sorted := append([]*mcp.Tool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var b strings.Builder
	for _, tl := range sorted {
		fmt.Fprintf(&b, "%-20s %s\n", tl.Name, tl.Title)
	}
	return b.String()
}

// describeTool is `call TOOL --help`: what the tool does and the JSON schema of its arguments,
// which a CLI user fetches only for the tools it is about to use.
func describeTool(tl *mcp.Tool) string {
	schema, _ := json.Marshal(tl.InputSchema)
	return fmt.Sprintf("%s - %s\n\n%s\n\narguments, one JSON object: %s\n", tl.Name, tl.Title, tl.Description, schema)
}

// readCallRefusal prints the reason the daemon gave for a command it refused, as the JSON-RPC
// error it sends to any refused session, and ends the way a failed call does.
func readCallRefusal(conn net.Conn, sock string) error {
	var r struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(conn).Decode(&r); err != nil || r.Error.Message == "" {
		return fmt.Errorf("daemon closed the connection on %s before answering", sock)
	}
	fmt.Fprintln(os.Stderr, r.Error.Message)
	return errCallFailed
}

// readCallReply is the bridge's half: wait for the one reply line and print it.
func readCallReply(conn net.Conn, sock string) error {
	var r callReply
	if err := json.NewDecoder(conn).Decode(&r); err != nil {
		return fmt.Errorf("daemon closed the connection on %s before answering: %w", sock, err)
	}
	text := strings.TrimRight(r.Text, "\n")
	if r.Error {
		fmt.Fprintln(os.Stderr, text)
		return errCallFailed
	}
	fmt.Fprintln(os.Stdout, text)
	return nil
}
