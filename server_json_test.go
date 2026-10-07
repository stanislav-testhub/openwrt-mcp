package main

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// server.json is the entry for the official MCP Registry (ROADMAP 3.10). The registry's rules
// are in its schema (checked 2026-10-07): name `io.github.<user>/<repo>` for GitHub login, a
// description of at most 100 characters, a semantic version, and `packages` or `remotes` only
// when there is something to install from npm, PyPI, NuGet, OCI, Cargo or MCPB. This server is
// installed on a router, so the entry carries the repository and nothing else. The test keeps it
// from drifting from the code.
func TestServerJSONMatchesTheRegistrySchemaAndTheRelease(t *testing.T) {
	b, err := os.ReadFile("server.json")
	if err != nil {
		t.Skipf("server.json not readable from the test directory: %v", err)
	}
	var s struct {
		Schema      string `json:"$schema"`
		Name        string `json:"name"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
		Repository  struct {
			URL    string `json:"url"`
			Source string `json:"source"`
		} `json:"repository"`
		WebsiteURL string            `json:"websiteUrl"`
		Packages   []json.RawMessage `json:"packages"`
		Remotes    []json.RawMessage `json:"remotes"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("server.json is not JSON: %v", err)
	}
	if !regexp.MustCompile(`^https://static\.modelcontextprotocol\.io/schemas/[0-9-]+/server\.schema\.json$`).MatchString(s.Schema) {
		t.Errorf("$schema %q", s.Schema)
	}
	if s.Name != "io.github.stanislav-testhub/openwrt-mcp" {
		t.Errorf("name %q: GitHub login only publishes names under io.github.<user>/", s.Name)
	}
	if n := len([]rune(s.Description)); n < 1 || n > 100 {
		t.Errorf("description is %d characters; the registry allows 1 to 100", n)
	}
	if n := len([]rune(s.Title)); n < 1 || n > 100 {
		t.Errorf("title is %d characters", n)
	}
	if s.Version != version {
		t.Errorf("server.json says version %q, the binary says %q: bump both together", s.Version, version)
	}
	if s.Repository.URL != "https://github.com/stanislav-testhub/openwrt-mcp" || s.Repository.Source != "github" {
		t.Errorf("repository %+v", s.Repository)
	}
	if len(s.Packages) != 0 || len(s.Remotes) != 0 {
		t.Error("packages or remotes would claim an install path (npm, PyPI, ...) that this server does not have")
	}
}
