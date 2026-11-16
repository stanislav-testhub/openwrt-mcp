package main

import (
	"encoding/json"
	"os"
	"testing"
)

// OWM_CATALOGUE_OUT=file go test -run TestDumpCatalogue . writes the tools/list array a client receives, for
// bench/select_eval.py and bench/claude_cost.py (ROADMAP 3.11). It writes nothing unless the variable is set.
func TestDumpCatalogue(t *testing.T) {
	out := os.Getenv("OWM_CATALOGUE_OUT")
	if out == "" {
		t.Skip("OWM_CATALOGUE_OUT not set")
	}
	cs := connectClient(t, testServer(t, ""), "c")
	b, err := json.MarshalIndent(listedTools(t, cs), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
