package main

import (
	"slices"

	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"strings"
	"sync"
)

// Structured output (ROADMAP 5.5). A tool that can say what it found as data does it twice: the
// text table stays in `content`, which is what most clients forward to the model, and the same
// rows go in `structuredContent` under the tool's outputSchema. A tool hands its data over with
// setStructured; addTool attaches it to a successful result only, so an error carries none.
// Text a third party chose (host names, SSIDs) goes through sanitizeText on the way in.

type structuredSink struct {
	mu sync.Mutex
	v  any
}

type sinkKey struct{}

func withSink(ctx context.Context) (context.Context, *structuredSink) {
	s := &structuredSink{}
	return context.WithValue(ctx, sinkKey{}, s), s
}

func setStructured(ctx context.Context, v any) {
	if s, ok := ctx.Value(sinkKey{}).(*structuredSink); ok {
		s.mu.Lock()
		s.v = v
		s.mu.Unlock()
	}
}

func (s *structuredSink) value() any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

var (
	strT  = map[string]any{"type": "string"}
	intT  = map[string]any{"type": "integer"}
	boolT = map[string]any{"type": "boolean"}
	objL  = map[string]any{"type": "object"}
	strsT = map[string]any{"type": "array", "items": strT}
)

// objT: required names are kept to the keys a consumer cannot do without; every other key is optional.
func objT(required []string, props map[string]any) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func arrT(item any) map[string]any { return map[string]any{"type": "array", "items": item} }

// outputSchemas: the tools that return structured content. Every tool not listed here returns text only.
var outputSchemas = map[string]any{
	"network_clients": objT([]string{"clients"}, map[string]any{
		"total": intT,
		"clients": arrT(objT([]string{"mac"}, map[string]any{
			"mac": strT, "ips": strsT, "host": strT, "device": strT, "wireless": boolT, "ssid": strT,
			"signal_dbm": intT, "connected_s": intT, "rx_kbit": intT, "tx_kbit": intT, "lease": strT,
		})),
	}),
	"wg_list_clients": objT([]string{"peers"}, map[string]any{
		"interface": strT, "port": strT, "public_key": strT, "addresses": strsT,
		"peers": arrT(objT([]string{"public_key"}, map[string]any{
			"name": strT, "public_key": strT, "allowed_ips": strsT, "endpoint": strT, "handshake_unix": intT,
			"rx_bytes": intT, "tx_bytes": intT, "in_uci": boolT, "in_kernel": boolT, "psk": boolT, "section": strT,
		})),
	}),
	// Nested objects are left loose to keep the catalogue inside its byte budget (TestCatalogueStaysWithinBudget).
	"system_status": objT([]string{"outstanding"}, map[string]any{
		"board": objL, "uptime_s": intT, "load": arrT(map[string]any{"type": "number"}), "memory_mib": objL, "conntrack": objL,
		"temperatures": arrT(objL), "interfaces": arrT(objL), "radios": arrT(objL), "outstanding": strsT,
	}),
	"uci_get": objT([]string{"entries"}, map[string]any{
		"entries": arrT(objL), "notes": strsT,
	}),
	"logread": objT([]string{"lines"}, map[string]any{
		"lines": arrT(objL),
	}),
	"exec": objT([]string{"lines"}, map[string]any{"lines": strsT}),
	"pkg_query": objT([]string{"packages"}, map[string]any{
		"total": intT, "packages": arrT(objT([]string{"name"}, map[string]any{"name": strT, "version": strT, "upgradable_from": strT})),
	}),
	"service_list": objT([]string{"services"}, map[string]any{
		"services": arrT(objT([]string{"name"}, map[string]any{"name": strT, "enabled": boolT, "running": boolT})), "add_ons": strsT,
	}),
}

// derivedStructured: tools whose text can carry secrets. Their data is parsed from the text
// AFTER sanitising, masking and bounding (presentBody), never from the raw output, so
// structuredContent shows exactly what the text shows and the masker stays the only place a
// secret is decided. A tool in this map does not call setStructured.
var derivedStructured = map[string]func(body string) any{
	"uci_get": deriveUCI,
	"logread": deriveLog,
	"exec":    deriveLines,
}

var reUCIEntry = lazyRegexp(`^([A-Za-z0-9_.@\[\]-]+)=(.*)$`)

// deriveUCI splits `config.section.option='value'` lines into key and value (quotes removed from
// a single value; a list keeps its quotes). Anything else, such as the revision line, goes to notes.
func deriveUCI(body string) any {
	entries, notes := []map[string]any{}, []string{}
	for _, l := range splitLines(body) {
		if m := reUCIEntry.FindStringSubmatch(l); m != nil {
			v := m[2]
			if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' && !strings.Contains(v[1:len(v)-1], "' '") {
				v = v[1 : len(v)-1]
			}
			entries = append(entries, map[string]any{"key": m[1], "value": v})
		} else {
			notes = append(notes, l)
		}
	}
	return map[string]any{"entries": entries, "notes": notes}
}

var reLogLine = lazyRegexp(`^([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}) (\S+\.\S+) (.*)$`)

// deriveLog: one object per log line, with the time and level when the line has the syslog shape.
func deriveLog(body string) any {
	lines := []map[string]any{}
	for _, l := range splitLines(body) {
		if m := reLogLine.FindStringSubmatch(l); m != nil {
			lines = append(lines, map[string]any{"time": m[1], "level": m[2], "text": m[3]})
		} else {
			lines = append(lines, map[string]any{"text": l})
		}
	}
	return map[string]any{"lines": lines}
}

func deriveLines(body string) any {
	return map[string]any{"lines": splitLines(body)}
}

func splitLines(s string) []string {
	out := []string{}
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// structuredSince is the first MCP protocol version with outputSchema and structuredContent. A
// client that negotiated an older one gets the text alone, so structured output costs it nothing
// (ROADMAP 10.9): no schema in tools/list and no duplicate of the data in the result.
const structuredSince = "2025-06-18"

// negotiatesStructured reports whether the session's protocol version has structured output.
// Versions are dates, so they compare as strings. A version the SDK does not know is negotiated
// up to the latest, which has it; a session that has not initialised keeps it too.
func negotiatesStructured(sess mcp.Session) bool {
	ss, ok := sess.(*mcp.ServerSession)
	if !ok || ss.InitializeParams() == nil {
		return true
	}
	v := ss.InitializeParams().ProtocolVersion
	return v >= structuredSince || !slices.Contains(mcp.SupportedProtocolVersions(), v)
}

// structuredGate removes outputSchema and structuredContent from what a client that does not
// negotiate them would receive. It is presentation only, like profileCatalogue.
func structuredGate(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || negotiatesStructured(req.GetSession()) {
			return res, err
		}
		switch r := res.(type) {
		case *mcp.ListToolsResult:
			for _, tl := range r.Tools {
				tl.OutputSchema = nil
			}
		case *mcp.CallToolResult:
			r.StructuredContent = nil
		}
		return res, err
	}
}
