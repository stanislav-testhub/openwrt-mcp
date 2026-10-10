package main

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The 1.5 session profile (toolsets, --read-only, the peer address) rides on the context
// handed to Server.Connect, and one receiving middleware enforces it, so the server stays
// shared per client. These tests pin the SDK behaviour that design relies on: a bump of
// go-sdk that stops carrying Connect's context into handlers, or stops letting middleware
// rewrite tools/list, must fail here rather than silently widen a read-only session.

type sessionProbeKey struct{}

type probeArgs struct{}

func probeServer(tools ...string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "probe", Version: "0"}, nil)
	for _, n := range tools {
		mcp.AddTool(srv, &mcp.Tool{Name: n}, func(ctx context.Context, _ *mcp.CallToolRequest, _ probeArgs) (*mcp.CallToolResult, any, error) {
			v, _ := ctx.Value(sessionProbeKey{}).(string)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: v}}}, nil, nil
		})
	}
	return srv
}

// probeSession connects one client to srv, with the session value on the server-side context.
func probeSession(t *testing.T, srv *mcp.Server, value string) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(context.WithValue(context.Background(), sessionProbeKey{}, value), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func probeCall(t *testing.T, cs *mcp.ClientSession, tool string) (string, error) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool})
	if err != nil {
		return "", err
	}
	return res.Content[0].(*mcp.TextContent).Text, nil
}

func TestConnectContextReachesHandlerPerSession(t *testing.T) {
	srv := probeServer("alpha")
	a, b := probeSession(t, srv, "profile-A"), probeSession(t, srv, "profile-B")
	// Interleaved on purpose: sessions of one shared server must not see each other's value.
	for _, c := range []struct {
		cs   *mcp.ClientSession
		want string
	}{{a, "profile-A"}, {b, "profile-B"}, {a, "profile-A"}} {
		if got, err := probeCall(t, c.cs, "alpha"); err != nil || got != c.want {
			t.Fatalf("handler saw %q (err %v), want %q", got, err, c.want)
		}
	}
}

func TestMiddlewareFiltersListAndRefusesCallPerSession(t *testing.T) {
	srv := probeServer("alpha", "beta")
	srv.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			allowed, _ := ctx.Value(sessionProbeKey{}).(string) // the one tool this session may use
			switch method {
			case "tools/call":
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); !ok || p.Name != allowed {
					return nil, fmt.Errorf("tool not in this session's profile")
				}
			case "tools/list":
				res, err := next(ctx, method, req)
				if lr, ok := res.(*mcp.ListToolsResult); ok && err == nil {
					lr.Tools = slices.DeleteFunc(lr.Tools, func(tl *mcp.Tool) bool { return tl.Name != allowed })
				}
				return res, err
			}
			return next(ctx, method, req)
		}
	})
	for _, allowed := range []string{"alpha", "beta"} {
		other := map[string]string{"alpha": "beta", "beta": "alpha"}[allowed]
		cs := probeSession(t, srv, allowed)
		lt, err := cs.ListTools(context.Background(), nil)
		if err != nil || len(lt.Tools) != 1 || lt.Tools[0].Name != allowed {
			t.Fatalf("session %s lists %v (err %v), want only itself", allowed, lt, err)
		}
		if _, err := probeCall(t, cs, allowed); err != nil {
			t.Fatalf("allowed tool %s refused: %v", allowed, err)
		}
		if _, err := probeCall(t, cs, other); err == nil {
			t.Fatalf("session %s was allowed to call %s", allowed, other)
		}
	}
}
