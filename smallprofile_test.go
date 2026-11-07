package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func loadServerOptions(t *testing.T, opts string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg")
	if err := os.WriteFile(p, []byte("config server\n"+opts), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withOverlay(t *testing.T, mib int) {
	t.Helper()
	old := overlayMiB
	overlayMiB = func(string) int { return mib }
	t.Cleanup(func() { overlayMiB = old })
}

// The values are the ones ROADMAP 10.6 names.
func TestSmallProfileSetsItsDefaults(t *testing.T) {
	withOverlay(t, 100000)
	c := loadServerOptions(t, "\toption profile 'small'\n")
	if c.Profile != "small" || c.IdleExitMin != 5 || c.Listen != "" || c.MemoryLimitMiB != 16 ||
		c.AuditMaxMB != 1 || c.HistoryKeep != 3 || !slices.Equal(c.Toolsets, []string{"diag", "config"}) {
		t.Fatalf("small profile = %+v", c)
	}
}

func TestExplicitOptionsBeatTheProfile(t *testing.T) {
	withOverlay(t, 100000)
	c := loadServerOptions(t, "\toption profile 'small'\n\toption idle_exit '9'\n\toption listen '127.0.0.1:9999'\n"+
		"\toption memory_limit '32'\n\toption audit_max_mb '4'\n\toption history_keep '0'\n\toption toolsets 'pkg'\n")
	if c.IdleExitMin != 9 || c.Listen != "127.0.0.1:9999" || c.MemoryLimitMiB != 32 || c.AuditMaxMB != 4 ||
		c.HistoryKeep != 0 || !slices.Equal(c.Toolsets, []string{"pkg"}) {
		t.Fatalf("explicit options lost to the profile: %+v", c)
	}
}

func TestNoProfileKeepsTheOldDefaults(t *testing.T) {
	withOverlay(t, 100000)
	c := loadServerOptions(t, "")
	if c.Profile != "" || c.IdleExitMin != 0 || c.Listen != defaultListen || c.AuditMaxMB != defaultAuditMaxMB || c.Toolsets != nil {
		t.Fatalf("default config changed: %+v", c)
	}
	if c := loadServerOptions(t, "\toption profile 'tiny'\n"); c.Profile != "" || c.Listen != defaultListen {
		t.Fatalf("an unknown profile must be ignored: %+v", c)
	}
}

func TestAuditDefaultIsAThirtySecondOfTheOverlay(t *testing.T) {
	for _, c := range []struct{ overlayMiB, want int }{
		{4, 1}, {16, 1}, {64, 2}, {256, 8}, {512, 16}, {32768, 16}, {0, 16},
	} {
		withOverlay(t, c.overlayMiB)
		if got := loadServerOptions(t, "").AuditMaxMB; got != c.want {
			t.Errorf("overlay %d MiB: audit_max_mb = %d, want %d", c.overlayMiB, got, c.want)
		}
	}
	withOverlay(t, 16)
	if got := loadServerOptions(t, "\toption audit_max_mb '12'\n").AuditMaxMB; got != 12 {
		t.Errorf("an explicit audit_max_mb must not be clamped: %d", got)
	}
}

func TestToolsetCap(t *testing.T) {
	for _, c := range []struct{ session, cap, want []string }{
		{nil, nil, nil},
		{[]string{"pkg"}, nil, []string{"pkg"}},
		{nil, []string{"diag", "config"}, []string{"diag", "config"}},
		{[]string{"config", "pkg"}, []string{"diag", "config"}, []string{"config"}},
		{[]string{"wg"}, []string{"diag"}, []string{}},
	} {
		got := capToolsets(c.session, c.cap)
		if !slices.Equal(got, c.want) || (got == nil) != (c.want == nil) {
			t.Errorf("capToolsets(%v, %v) = %#v, want %#v", c.session, c.cap, got, c.want)
		}
	}
	if _, err := parseToolsetCap("diag nonsense"); err == nil {
		t.Error("an unknown toolset in the cap was accepted")
	}
	if c := loadServerOptions(t, "\toption toolsets 'diag nonsense'\n"); c.Toolsets != nil {
		t.Errorf("a bad cap must leave no cap, got %v", c.Toolsets)
	}
}

// The cap holds on every transport and is not widened by what a client asks for or is granted.
func TestOperatorCapTrimsTheCatalogueOnHTTP(t *testing.T) {
	s := testServer(t, "\toption toolsets 'diag'\n"+policyFor("alice", []string{"*"}, "*"))
	tok, _ := s.tokens.Mint("alice")
	ts := startHTTP(t, s)
	tr := &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: headerRT{map[string]string{"Authorization": "Bearer " + tok}}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "alice", Version: "0"}, nil).Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	for _, want := range append(slices.Clone(toolsetTools["diag"]), coreTools...) {
		if !slices.Contains(names, want) {
			t.Errorf("%s missing under the cap: %v", want, names)
		}
	}
	for _, banned := range []string{"exec", "uci_apply", "pkg_change", "wg_new_client"} {
		if slices.Contains(names, banned) {
			t.Errorf("%s listed despite the cap", banned)
		}
	}
	if out, isErr := callText(t, cs, "exec", map[string]any{"argv": []string{"ls"}}); !isErr || !strings.Contains(out, "not available") {
		t.Errorf("a call outside the cap was not refused: err=%v %s", isErr, out)
	}
}

// The same cap on the bridge: a call outside it is refused, a client's own --toolset cannot widen it.
func TestOperatorCapAppliesOnTheBridge(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call system board", boardJSON)
	s := testServer(t, "\toption toolsets 'diag'\n"+policyFor("c", []string{"ubus_call", "pkg_query"}, "*"))
	for _, cmd := range []string{`call pkg_query {"action":"installed"}`, `--toolset diag,pkg call pkg_query {"action":"installed"}`} {
		_, stderr, err := runCallCLI(t, s, "c", cmd)
		if err == nil || !strings.Contains(stderr, "not available") {
			t.Errorf("%q: want a refusal outside the cap, got err=%v stderr=%q", cmd, err, stderr)
		}
	}
	if _, stderr, err := runCallCLI(t, s, "c", "call ubus_call "+boardArgs); err != nil {
		t.Errorf("a diag tool under the cap failed: %v %s", err, stderr)
	}
}

func TestFitLine(t *testing.T) {
	oldMem, oldOv := memTotalMiB, overlayMiB
	t.Cleanup(func() { memTotalMiB, overlayMiB = oldMem, oldOv })
	overlayMiB = func(string) int { return 10 }
	cases := []struct {
		ram  int
		cfg  Config
		want []string
	}{
		{128, Config{}, []string{"128 MiB RAM", "10 MiB", "profile=small"}},
		{512, Config{}, []string{"512 MiB RAM"}},
		{128, Config{Profile: "small", Toolsets: []string{"diag"}}, []string{"profile small", "capped to diag"}},
	}
	for _, c := range cases {
		memTotalMiB = func() int { return c.ram }
		got := fitLine(&c.cfg)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("ram %d: %q lacks %q", c.ram, got, w)
			}
		}
		if c.ram >= smallRAMMiB && strings.Contains(got, "consider") {
			t.Errorf("ram %d: suggested the small profile: %q", c.ram, got)
		}
	}
	if got := parseMemTotalMiB("MemTotal:  126976 kB\nMemFree: 1 kB\n"); got != 124 {
		t.Errorf("parseMemTotalMiB = %d, want 124", got)
	}
}
