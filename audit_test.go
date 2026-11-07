package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRedaction(t *testing.T) {
	in := map[string]any{
		"password":  "hunter2",
		"wifi_psk":  "correct-horse",
		"wgkey":     "abc123",
		"api_key":   "sk-secret",
		"keyId":     "id-42",       // must survive: it is an identifier, not a secret
		"publicKey": "ssh-ed25519", // must survive
		"ipaddr":    "192.168.1.1",
		"nested":    map[string]any{"secret": "shh", "name": "lan"},
		"list":      []any{map[string]any{"passphrase": "open sesame"}},
	}
	out, _ := json.Marshal(redact(in))
	s := string(out)

	for _, leaked := range []string{"hunter2", "correct-horse", "abc123", "sk-secret", "shh", "open sesame"} {
		if strings.Contains(s, leaked) {
			t.Errorf("secret %q leaked into the audit record: %s", leaked, s)
		}
	}
	for _, kept := range []string{"id-42", "ssh-ed25519", "192.168.1.1", "lan"} {
		if !strings.Contains(s, kept) {
			t.Errorf("non-secret %q was redacted, making the log useless: %s", kept, s)
		}
	}
}

func TestAuditWritesJSONLAndRedacts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	a := NewAuditor(p, 16)
	a.Record(AuditEvent{
		Time: nowISO(), Client: "claude-code", Tool: "ubus_call", Scope: "network.status",
		Args: map[string]any{"password": "hunter2", "object": "network"}, Outcome: OutcomeDenied,
		Error: "denied: no policy grants ubus_call",
	})

	raw := readFile(t, p)
	if strings.Contains(raw, "hunter2") {
		t.Fatal("recorder failed to redact before writing")
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &ev); err != nil {
		t.Fatalf("audit line is not valid JSON: %v\n%s", err, raw)
	}
	// DENIED must be distinguishable from ERROR: "we said no" is not "it broke".
	if ev.Outcome != OutcomeDenied {
		t.Errorf("outcome = %q, want DENIED", ev.Outcome)
	}
	if ev.Client != "claude-code" || ev.Tool != "ubus_call" {
		t.Errorf("attribution lost: %+v", ev)
	}
}

func TestAuditNeverPanicsOnBadPath(t *testing.T) {
	// Auditing must not be able to break the request path it is auditing.
	a := NewAuditor("/proc/nonexistent/cannot/write/audit.jsonl", 16)
	a.Record(AuditEvent{Time: nowISO(), Client: "x", Outcome: OutcomeOK})
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("ab", 5); got != "ab" {
		t.Errorf("truncate should leave short strings alone, got %q", got)
	}
}

// A cut inside a multi-byte character must back up to its start, not leave invalid UTF-8 in the
// audit log (and in the push hook and the request record, which truncate the same way).
func TestTruncateKeepsUTF8Valid(t *testing.T) {
	for n := 0; n <= 9; n++ {
		got := truncate("яблоко€語", n)
		if !utf8.ValidString(got) {
			t.Errorf("truncate(.., %d) = %q is not valid UTF-8", n, got)
		}
		if len(strings.TrimSuffix(got, "…")) > n {
			t.Errorf("truncate(.., %d) kept %d bytes", n, len(strings.TrimSuffix(got, "…")))
		}
	}
}
