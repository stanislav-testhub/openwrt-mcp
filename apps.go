package main

import (
	"context"
	_ "embed"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Interactive views (ROADMAP 6.6), the MCP Apps extension. A tool can point at a `ui://` page that
// a host which supports the extension draws beside the text. Three views, all read-only:
//
//	clients    network_clients  a sortable, filterable table of the structured rows
//	audit      system_status    the findings of mode=doctor or audit, worst first (the plain text otherwise)
//	approvals  request_access   the requests it opened and where to answer them
//
// Text stays the default and nothing opens by itself, on two counts. The owner must switch the
// feature on (`option apps '1'` in config server, off by default, read on every call so a config
// edit applies at once); with it off tools/list is unchanged and the resource list is empty. And a client must ask: only one whose initialize
// declares the io.modelcontextprotocol/ui extension with the text/html;profile=mcp-app type sees
// the `_meta.ui` link, the resource list or the page. A view draws the result the host hands it
// (the same text or structured rows the model got, so masking and sanitising already happened),
// uses text nodes only, has a default-deny CSP, and never calls a tool, so it cannot approve or
// change anything.

const (
	appsExt  = "io.modelcontextprotocol/ui"
	appsMIME = "text/html;profile=mcp-app"
)

//go:embed apps/view.html
var appsPage string

type appView struct{ name, tool, title string }

var appViews = []appView{
	{"clients", "network_clients", "Clients"},
	{"audit", "system_status", "Findings"},
	{"approvals", "request_access", "Requests"},
}

func (v appView) uri() string { return "ui://openwrt-mcp/" + v.name }

func (v appView) html() string { return strings.Replace(appsPage, "{{VIEW}}", v.name, 1) }

// negotiatesApps reports whether the session's client declared the extension and the page type.
func negotiatesApps(sess mcp.Session) bool {
	ss, ok := sess.(*mcp.ServerSession)
	if !ok || ss.InitializeParams() == nil || ss.InitializeParams().Capabilities == nil {
		return false
	}
	ext, ok := ss.InitializeParams().Capabilities.Extensions[appsExt].(map[string]any)
	if !ok {
		return false
	}
	types, _ := ext["mimeTypes"].([]any)
	return slices.ContainsFunc(types, func(t any) bool { return t == appsMIME })
}

// addApps registers the pages. They are always registered and always gated by appsGate.
func addApps(srv *mcp.Server) {
	for _, v := range appViews {
		srv.AddResource(&mcp.Resource{URI: v.uri(), Name: "view-" + v.name, Title: v.title + " view", MIMEType: appsMIME,
			Description: "Read-only page for MCP Apps hosts"},
			func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				for _, w := range appViews {
					if w.uri() == req.Params.URI {
						return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: w.uri(), MIMEType: appsMIME, Text: w.html()}}}, nil
					}
				}
				return nil, mcp.ResourceNotFoundError(req.Params.URI)
			})
	}
}

// appsGate shows the links, the resource list and the pages to the clients that asked for them,
// when the owner allows it, and to nobody else. Like profileCatalogue it only changes what a
// client is shown.
func (s *Server) appsGate(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case "tools/list", "resources/list", "resources/read":
		default:
			return next(ctx, method, req) // no other method concerns the views, and the rest are none of its business
		}
		c := s.cfg()
		asked := c != nil && c.Apps && negotiatesApps(req.GetSession())
		if method == "resources/read" && !asked {
			if rr, ok := req.(*mcp.ReadResourceRequest); ok && strings.HasPrefix(rr.Params.URI, "ui://openwrt-mcp/") {
				return nil, mcp.ResourceNotFoundError(rr.Params.URI)
			}
		}
		res, err := next(ctx, method, req)
		if err != nil {
			return res, err
		}
		switch r := res.(type) {
		case *mcp.ListToolsResult:
			if !asked {
				return res, nil
			}
			for _, tl := range r.Tools {
				for _, v := range appViews {
					if tl.Name == v.tool {
						tl.Meta = mcp.Meta{"ui": map[string]any{"resourceUri": v.uri()}}
					}
				}
			}
		case *mcp.ListResourcesResult:
			if !asked {
				r.Resources = nil
			}
		}
		return res, err
	}
}
