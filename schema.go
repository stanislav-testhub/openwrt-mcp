package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// inputSchema is the schema the SDK would infer for In, with one plain string type per
// property. The inferer marks every slice nullable (`"type": ["null","array"]`), and type
// arrays break Gemini's OpenAPI subset and older VS Code (ROADMAP 3.3). Passing the result as
// Tool.InputSchema makes the SDK validate against it instead of inferring its own.
func inputSchema[In any]() *jsonschema.Schema {
	s, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Errorf("input schema for %T: %w", *new(In), err))
	}
	dropNullType(s)
	return s
}

// dropNullType rewrites ["null", X] to X throughout the parts of a schema For emits.
func dropNullType(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if len(s.Types) > 0 {
		if rest := slices.DeleteFunc(slices.Clone(s.Types), func(t string) bool { return t == "null" }); len(rest) == 1 {
			s.Type, s.Types = rest[0], nil
		}
	}
	for _, p := range s.Properties {
		dropNullType(p)
	}
	dropNullType(s.Items)
	dropNullType(s.AdditionalProperties)
}

// omitNulls keeps a call that was valid before the schema lost its null alternative valid:
// models that fill every optional parameter (OpenAI's strict mode makes them) send
// `"probe": null` for "not set". The SDK would now reject that with a type error; this drops
// such members before it validates, so the call behaves as if the field were omitted.
// Only members the schema declares are dropped, so free-form objects (ubus_call.args) keep
// their nulls.
func omitNulls(tool string, schema *jsonschema.Schema) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p.Name == tool {
					p.Arguments = stripNulls(p.Arguments, schema)
				}
			}
			return next(ctx, method, req)
		}
	}
}

// stripNulls returns raw without the null members schema declares, or raw itself, byte for
// byte, when there is nothing to drop or raw is not a JSON document.
func stripNulls(raw json.RawMessage, schema *jsonschema.Schema) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // do not round large integers through float64
	var doc any
	if dec.Decode(&doc) != nil {
		return raw
	}
	if !dropDeclaredNulls(doc, schema) {
		return raw
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// dropDeclaredNulls deletes null members that schema declares and reports whether it did.
func dropDeclaredNulls(v any, s *jsonschema.Schema) bool {
	if s == nil {
		return false
	}
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			prop, declared := s.Properties[k]
			switch {
			case !declared:
			case val == nil:
				delete(x, k)
				changed = true
			default:
				changed = dropDeclaredNulls(val, prop) || changed
			}
		}
	case []any:
		for _, e := range x {
			changed = dropDeclaredNulls(e, s.Items) || changed
		}
	}
	return changed
}
