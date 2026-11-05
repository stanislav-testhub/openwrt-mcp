package main

import (
	"context"
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
	"service_list": objT([]string{"services"}, map[string]any{
		"services": arrT(objT([]string{"name"}, map[string]any{"name": strT, "enabled": boolT, "running": boolT})), "add_ons": strsT,
	}),
}
