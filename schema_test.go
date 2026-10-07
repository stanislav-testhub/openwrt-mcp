package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The schemas lost their null alternative (ROADMAP 3.3), so a client that sends
// `"probe": null` for "not set" must still be understood. The literals below are the wire
// shapes OpenAI-style clients produce, not whatever stripNulls happens to output.

func TestStripNulls(t *testing.T) {
	uci, ubus := inputSchema[uciApplyIn](), inputSchema[ubusCallIn]()
	for _, tc := range []struct {
		name string
		in   string
		sch  string // "uci" or "ubus"
		want string // "" = unchanged, byte for byte
	}{
		{"top-level optional array", `{"dry_run":true,"changes":null,"probe":null}`, "uci", `{"dry_run":true}`},
		{"nested member of an array item", `{"changes":[{"config":"dhcp","section":"x","values":null}]}`, "uci",
			`{"changes":[{"config":"dhcp","section":"x"}]}`},
		{"null inside free-form ubus args is data", `{"object":"o","method":"m","args":{"a":null}}`, "ubus", ""},
		{"null for a free-form ubus args member is dropped, as for any optional", `{"object":"o","method":"m","args":null}`, "ubus",
			`{"object":"o","method":"m"}`},
		{"nothing to drop keeps the bytes", "{\"dry_run\" :true,\n \"timeout\":  5}", "uci", ""},
		{"undeclared member is left for the schema to reject", `{"nonsense":null}`, "uci", ""},
		{"large integer survives", `{"timeout":12345678901234567890,"probe":null}`, "uci", `{"timeout":12345678901234567890}`},
		{"not JSON", `{"probe":`, "uci", ""},
		{"JSON null as a whole", `null`, "uci", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sch := uci
			if tc.sch == "ubus" {
				sch = ubus
			}
			got := string(stripNulls(json.RawMessage(tc.in), sch))
			if tc.want == "" {
				if got != tc.in {
					t.Fatalf("stripNulls(%s) changed an input with nothing to drop: %s", tc.in, got)
				}
				return
			}
			if !sameJSON(t, got, tc.want) { // a rewritten document may reorder keys
				t.Fatalf("stripNulls(%s)\n got %s\nwant %s", tc.in, got, tc.want)
			}
		})
	}
	if got := stripNulls(nil, uci); got != nil {
		t.Fatalf("empty arguments must stay empty, got %q", got)
	}
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	for _, p := range []struct {
		s string
		v *any
	}{{a, &x}, {b, &y}} {
		d := json.NewDecoder(strings.NewReader(p.s))
		d.UseNumber()
		if err := d.Decode(p.v); err != nil {
			t.Fatalf("not JSON: %q: %v", p.s, err)
		}
	}
	return reflect.DeepEqual(x, y)
}

// End to end: a null optional array is answered exactly as if the field were omitted, which
// is what the nullable schema allowed before. Through the real client, SDK validation included.
func TestNullOptionalArraysBehaveLikeOmittedOnes(t *testing.T) {
	cs := connectClient(t, testServer(t, ""), "c")
	for _, tc := range []struct {
		tool        string
		omitted, nl map[string]any
		required    bool // the field is required, so both calls fail the same way, in validation
	}{
		{"uci_apply", map[string]any{"dry_run": true}, map[string]any{"dry_run": true, "changes": nil, "probe": nil}, false},
		{"pkg_change", map[string]any{"action": "install"}, map[string]any{"action": "install", "packages": nil}, false},
		{"exec", map[string]any{}, map[string]any{"argv": nil}, true},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			want, wantErr := callTextAllowingProtocolError(t, cs, tc.tool, tc.omitted)
			got, gotErr := callTextAllowingProtocolError(t, cs, tc.tool, tc.nl)
			if got != want || gotErr != wantErr {
				t.Fatalf("null differs from omitted:\n null: %q (error %v)\n omit: %q (error %v)", got, gotErr, want, wantErr)
			}
			if !tc.required && strings.Contains(got, "validating") {
				t.Fatalf("null was rejected by schema validation: %q", got)
			}
		})
	}
}

// callTextAllowingProtocolError is callText for calls whose arguments may be refused by the
// SDK before the tool runs: that refusal comes back as a Go error, which callText treats as fatal.
func callTextAllowingProtocolError(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
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
