package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The command line is where the operator grants and revokes access, so it is tested as a
// process: the test binary re-executes itself as `openwrt-mcp`, runs the real main(), and the
// test reads its exit status, stdout and stderr.
//
// Only the subcommands that work on a workstation are driven; authorize-key writes the
// router's /etc/dropbear/authorized_keys and is covered at the function level.

func TestHelperMain(t *testing.T) {
	raw := os.Getenv("OPENWRT_MCP_CLI")
	if raw == "" {
		return
	}
	os.Args = append([]string{"openwrt-mcp"}, strings.Split(raw, "\x1f")...)
	main()
	os.Exit(0)
}

type cliEnv struct {
	t      *testing.T
	config string
	state  string
}

func newCLI(t *testing.T) *cliEnv {
	t.Helper()
	dir := t.TempDir()
	return &cliEnv{t: t, config: filepath.Join(dir, "openwrt-mcp"), state: filepath.Join(dir, "state")}
}

// run executes one command and returns its output and exit code.
func (c *cliEnv) run(args ...string) (stdout, stderr string, code int) {
	c.t.Helper()
	full := append([]string{"-config", c.config, "-state", c.state}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperMain$")
	// The unit separator, not NUL: an environment variable cannot carry NUL.
	cmd.Env = append(os.Environ(), "OPENWRT_MCP_CLI="+strings.Join(full, "\x1f"))
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code = 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			c.t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		c.t.Fatalf("openwrt-mcp %v did not finish", args)
	}
	return out.String(), errb.String(), code
}

func (c *cliEnv) ok(args ...string) string {
	c.t.Helper()
	out, errs, code := c.run(args...)
	if code != 0 {
		c.t.Fatalf("openwrt-mcp %v exited %d\nstdout: %s\nstderr: %s", args, code, out, errs)
	}
	return out
}

func (c *cliEnv) fails(want string, args ...string) {
	c.t.Helper()
	out, errs, code := c.run(args...)
	if code == 0 {
		c.t.Errorf("openwrt-mcp %v succeeded; want a failure mentioning %q\n%s", args, want, out)
		return
	}
	if !strings.Contains(errs, want) {
		c.t.Errorf("openwrt-mcp %v: stderr lacks %q:\n%s", args, want, errs)
	}
}

func TestCLIVersionUsageAndUnknownCommand(t *testing.T) {
	c := newCLI(t)
	if out := c.ok("version"); strings.TrimSpace(out) != "openwrt-mcp "+version {
		t.Errorf("version output %q", out)
	}
	if _, errs, code := c.run(); code != 2 || !strings.Contains(errs, "authorize-key") {
		t.Errorf("no arguments: exit %d, usage on stderr: %v", code, strings.Contains(errs, "authorize-key"))
	}
	c.fails(`unknown command "frobnicate"`, "frobnicate")
}

func TestCLIAllowPresetThenPoliciesThenRevoke(t *testing.T) {
	c := newCLI(t)
	if out := c.ok("policies"); !strings.Contains(out, "none") {
		t.Errorf("an empty policy file should say every gated tool is denied: %q", out)
	}

	out := c.ok("allow", "claude-code", "@readonly", "never")
	if !strings.Contains(out, "granted claude-code preset @readonly") {
		t.Errorf("allow: %q", out)
	}
	cfg, err := LoadConfig(c.config)
	if err != nil {
		t.Fatalf("the file `allow` wrote does not parse: %v", err)
	}
	if ok, _ := cfg.Authorise("claude-code", "system_status", nil, time.Now()); !ok {
		t.Error("@readonly does not allow system_status")
	}
	if ok, _ := cfg.Authorise("claude-code", "uci_apply", []string{"dhcp.x"}, time.Now()); ok {
		t.Error("@readonly allowed uci_apply")
	}
	if pol := c.ok("policies"); !strings.Contains(pol, "claude-code") || !strings.Contains(pol, "expires:never") {
		t.Errorf("policies listing: %s", pol)
	}

	if out := c.ok("revoke", "claude-code"); !strings.Contains(out, "removed 4 policy block(s)") {
		t.Errorf("revoke: %q", out)
	}
	cfg, _ = LoadConfig(c.config)
	if len(cfg.Policies) != 0 {
		t.Errorf("%d policies survived the revoke", len(cfg.Policies))
	}
	if out := c.ok("revoke", "nobody"); !strings.Contains(out, "removed 0") {
		t.Errorf("revoking an unknown client: %q", out)
	}
}

func TestCLIAllowACustomGrantWithAnExpiry(t *testing.T) {
	c := newCLI(t)
	before := time.Now()
	c.ok("allow", "bot", "net_diag,logread", "ping.* route", "2h")
	cfg, err := LoadConfig(c.config)
	if err != nil || len(cfg.Policies) != 1 {
		t.Fatalf("%v %+v", err, cfg)
	}
	p := cfg.Policies[0]
	if d := p.Expires.Sub(before); d < 2*time.Hour-time.Minute || d > 2*time.Hour+time.Minute {
		t.Errorf("expires in %s, want about 2h", d)
	}
	if ok, _ := cfg.Authorise("bot", "net_diag", []string{"ping.1.1.1.1"}, time.Now()); !ok {
		t.Error("granted scope refused")
	}
	if ok, _ := cfg.Authorise("bot", "net_diag", []string{"traceroute.1.1.1.1"}, time.Now()); ok {
		t.Error("scope outside the grant allowed")
	}
}

func TestCLIAllowRefusesBadGrantsAndWritesNothing(t *testing.T) {
	c := newCLI(t)
	for _, tc := range []struct {
		want string
		args []string
	}{
		{"unknown tool", []string{"allow", "c", "not_a_tool", "*", "1h"}},
		{"unknown tool", []string{"allow", "c", "logread,exec_all", "*", "1h"}},
		{"unknown preset", []string{"allow", "c", "@root", "1h"}},
		{"usage", []string{"allow", "c", "logread"}},
		{"invalid duration", []string{"allow", "c", "logread", "*", "soon"}},
		{"bad client name", []string{"allow", "a'b", "logread", "*", "1h"}},
		{"bad client name", []string{"allow", "a b", "logread", "*", "1h"}},
		{"bad client name", []string{"allow", "x\ny", "logread", "*", "1h"}},
		{"bad scope", []string{"allow", "c", "logread", "a'b", "1h"}},
		{"bad scope", []string{"allow", "c", "logread", `a"b`, "1h"}},
	} {
		c.fails(tc.want, tc.args...)
	}
	if b, err := os.ReadFile(c.config); err == nil && strings.TrimSpace(string(b)) != "" {
		t.Errorf("refused grants still wrote to the policy file:\n%s", b)
	}
}

func TestCLIPairNeverStoresTheTokenOnlyItsDigest(t *testing.T) {
	c := newCLI(t)
	tok := strings.TrimSpace(c.ok("pair", "laptop"))
	if len(tok) < 40 {
		t.Fatalf("token %q is too short to be a 256-bit secret", tok)
	}
	b, err := os.ReadFile(filepath.Join(c.state, "tokens"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(tok))
	if strings.Contains(string(b), tok) {
		t.Error("the raw bearer token is on disk: anyone who can read the file can impersonate the client")
	}
	if !strings.Contains(string(b), hex.EncodeToString(sum[:])+" laptop") {
		t.Errorf("tokens file does not hold the digest and client name:\n%s", b)
	}
	if st, _ := os.Stat(filepath.Join(c.state, "tokens")); st.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("tokens file mode %o", st.Mode().Perm())
	}

	// Two pairings give two different secrets.
	if again := strings.TrimSpace(c.ok("pair", "laptop")); again == tok {
		t.Error("pairing twice minted the same token")
	}
	if out := c.ok("clients"); strings.Count(out, "laptop") != 1 {
		t.Errorf("clients should list each client once:\n%s", out)
	}
	if out := c.ok("unpair", "laptop"); !strings.Contains(out, "revoked 2 token(s)") {
		t.Errorf("unpair: %q", out)
	}
	if out := strings.TrimSpace(c.ok("clients")); out != "" {
		t.Errorf("clients after unpair: %q", out)
	}
	c.fails("usage", "pair")
	c.fails("usage", "unpair")
}

func TestCLIStatusJSONIsValidAndCarriesNoSecrets(t *testing.T) {
	c := newCLI(t)
	tok := strings.TrimSpace(c.ok("pair", "laptop"))
	c.ok("allow", "claude-code", "@readonly", "never")
	out := c.ok("status", "--json", "--audit", "0")
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("status --json is not JSON: %v\n%s", err, out)
	}
	if strings.Contains(out, tok) {
		t.Error("status leaks a bearer token")
	}
	if text := c.ok("status"); !strings.Contains(text, "claude-code") {
		t.Errorf("text status does not show the grant:\n%s", text)
	}
}

func TestCLIMFAEnrolAndStatus(t *testing.T) {
	c := newCLI(t)
	if out := c.ok("mfa", "status"); !strings.Contains(out, "no clients enrolled") {
		t.Errorf("%q", out)
	}
	out := c.ok("mfa", "enrol", "claude-code", "my-router")
	if !strings.Contains(out, "otpauth://totp/") || !strings.Contains(out, "secret:") {
		t.Errorf("enrol output lacks the provisioning URI or secret:\n%s", out)
	}
	if st := c.ok("mfa", "status"); !strings.Contains(st, "claude-code: enrolled") {
		t.Errorf("%q", st)
	}
	// A policy that demands a code from a client with no secret is called out.
	if err := os.WriteFile(c.config, []byte("config policy\n\toption client 'ghost'\n\tlist tools 'exec'\n\tlist mfa_tools 'exec'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := c.ok("mfa", "status"); !strings.Contains(st, `WARNING: "ghost" has no enrolled secret`) {
		t.Errorf("a client that can never unlock is not flagged:\n%s", st)
	}
	c.fails("usage", "mfa", "enrol")
	c.fails("usage", "mfa", "wat")
}

func TestCLIStdioRefusesWhenTheBridgeIsSwitchedOff(t *testing.T) {
	c := newCLI(t)
	if err := os.WriteFile(c.config, []byte("config server\n\toption socket ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.fails("stdio bridge is disabled", "stdio", "--client", "claude-code")
}

// ---------------------------------------------------------------- expired grants

// grantBlock is one policy block as `allow` writes it; expires "" means never.
func grantBlock(client, tool, scope, expires string) string {
	b := "\nconfig policy\n\toption client\t'" + client + "'\n\tlist tools\t'" + tool + "'\n\tlist scopes\t'" + scope + "'\n"
	if expires != "" {
		b += "\toption expires\t'" + expires + "'\n"
	}
	return b + "\toption enabled\t'1'\n"
}

// cliHeader keeps the audit log in the test's directory: the default is /etc/openwrt-mcp.
func (c *cliEnv) header() string {
	return "config server\n\toption audit\t'" + filepath.ToSlash(filepath.Join(filepath.Dir(c.config), "audit.jsonl")) + "'\n# keep me\n"
}

func ago(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

func TestCLIStatusFoldsExpiredGrantsIntoOneLine(t *testing.T) {
	c := newCLI(t)
	cfg := c.header() +
		grantBlock("claude-code", "logread", "*", "2020-01-01T00:00:00Z") +
		grantBlock("claude-code", "uci_get", "*", "2021-01-01T00:00:00Z") +
		grantBlock("claude-code", "system_status", "*", "")
	if err := os.WriteFile(c.config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	const fold = "  2 expired grant(s) not shown: `openwrt-mcp status --all` lists them, `openwrt-mcp prune` deletes them\n"

	out := c.ok("status", "--audit", "0")
	if !strings.Contains(out, "  claude-code: system_status on *, 60/min, expires never\n") {
		t.Errorf("the live grant is missing:\n%s", out)
	}
	if strings.Contains(out, "EXPIRED") || !strings.Contains(out, fold) {
		t.Errorf("expired grants are not folded into one line:\n%s", out)
	}

	all := c.ok("status", "--all", "--audit", "0")
	for _, want := range []string{
		"  claude-code: logread on *, 60/min, expires 2020-01-01T00:00:00Z (EXPIRED)\n",
		"  claude-code: uci_get on *, 60/min, expires 2021-01-01T00:00:00Z (EXPIRED)\n",
		"  claude-code: system_status on *, 60/min, expires never\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("status --all lacks %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "not shown") {
		t.Errorf("status --all still folds:\n%s", all)
	}

	// JSON backs the LuCI page, which marks expired rows itself: it keeps every grant.
	var rep statusReport
	if err := json.Unmarshal([]byte(c.ok("status", "--json", "--audit", "0")), &rep); err != nil || len(rep.Policies) != 3 {
		t.Errorf("status --json: %d policies, %v; want all 3", len(rep.Policies), err)
	}

	c2 := newCLI(t)
	c2.ok("allow", "claude-code", "@readonly", "never")
	if out := c2.ok("status", "--audit", "0"); strings.Contains(out, "expired") {
		t.Errorf("a fold line with nothing expired:\n%s", out)
	}
}

func TestCLIPruneDeletesOnlyExpiredGrantsAndIsAudited(t *testing.T) {
	c := newCLI(t)
	old := grantBlock("claude-code", "logread", "*", ago(10*24*time.Hour))
	oldOther := grantBlock("laptop", "uci_get", "*", ago(8*24*time.Hour))
	recent := grantBlock("claude-code", "uci_get", "*", ago(time.Hour))
	live := grantBlock("claude-code", "exec", "*", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	never := grantBlock("laptop", "system_status", "*", "")
	if err := os.WriteFile(c.config, []byte(c.header()+old+recent+oldOther+live+never), 0o600); err != nil {
		t.Fatal(err)
	}
	file := func() string {
		b, err := os.ReadFile(c.config)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if out := c.ok("prune", "--older-than", "7d"); !strings.Contains(out, "removed 2 expired grant(s)") {
		t.Errorf("prune --older-than 7d: %q", out)
	}
	if got, want := file(), c.header()+recent+live+never; got != want {
		t.Errorf("after prune --older-than 7d:\n%s\nwant:\n%s", got, want)
	}
	if out := c.ok("prune"); !strings.Contains(out, "removed 1 expired grant(s)") {
		t.Errorf("prune: %q", out)
	}
	if got, want := file(), c.header()+live+never; got != want {
		t.Errorf("after prune:\n%s\nwant:\n%s", got, want)
	}
	if out := c.ok("prune"); !strings.Contains(out, "removed 0 expired grant(s)") {
		t.Errorf("prune with nothing expired: %q", out)
	}

	// One audit line per prune that removed something; a no-op leaves none.
	b, err := os.ReadFile(filepath.Join(filepath.Dir(c.config), "audit.jsonl"))
	if err != nil {
		t.Fatalf("prune was not audited: %v", err)
	}
	var sums []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		if ev.Client != "<cli>" || ev.Tool != "prune" || ev.Outcome != OutcomeOK {
			t.Errorf("audit event %+v", ev)
		}
		sums = append(sums, ev.Summary)
	}
	if len(sums) != 2 || !strings.Contains(sums[0], "removed 2 expired grant(s)") || !strings.Contains(sums[1], "removed 1 expired grant(s)") {
		t.Errorf("audit summaries %q", sums)
	}

	c.fails("bad duration", "prune", "--older-than", "soon")
	// A negative age would reach into the future and delete live grants.
	c.fails("must not be negative", "prune", "--older-than", "-1h")
	c.fails("usage", "prune", "extra")
	if got, want := file(), c.header()+live+never; got != want {
		t.Errorf("a refused prune changed the file:\n%s", got)
	}
}

func TestCLIAllowReplacesAnExpiredGrantWithTheSameToolsAndScopes(t *testing.T) {
	c := newCLI(t)
	cfg := c.header() +
		grantBlock("claude-code", "logread", "*", "2020-01-01T00:00:00Z") +
		grantBlock("claude-code", "logread", "x.*", "2020-01-01T00:00:00Z") + // other scopes: kept
		grantBlock("laptop", "logread", "*", "2020-01-01T00:00:00Z") + // other client: kept
		grantBlock("claude-code", "uci_get", "*", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)) // live: kept, even when granted again
	if err := os.WriteFile(c.config, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	type row struct {
		client, tools, scopes string
		expired               bool
	}
	rows := func() []row {
		t.Helper()
		cfg, err := LoadConfig(c.config)
		if err != nil {
			t.Fatal(err)
		}
		var out []row
		for _, p := range cfg.Policies {
			out = append(out, row{p.Client, strings.Join(p.Tools, ","), strings.Join(p.Scopes, " "), time.Now().After(p.Expires) && !p.Expires.IsZero()})
		}
		return out
	}

	if out := c.ok("allow", "claude-code", "logread", "*", "1d"); !strings.Contains(out, "replaced 1 expired grant(s)") {
		t.Errorf("allow: %q", out)
	}
	if out := c.ok("allow", "claude-code", "uci_get", "*", "1d"); strings.Contains(out, "replaced") {
		t.Errorf("allow replaced a live grant: %q", out)
	}
	want := []row{
		{"claude-code", "logread", "x.*", true},
		{"laptop", "logread", "*", true},
		{"claude-code", "uci_get", "*", false},
		{"claude-code", "logread", "*", false},
		{"claude-code", "uci_get", "*", false},
	}
	if got := rows(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("policies after allow:\n got %v\nwant %v", got, want)
	}

	// A preset: each of its blocks replaces its own expired twin, so re-granting does not pile up.
	p := newCLI(t)
	if err := os.WriteFile(p.config, []byte(p.header()), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, b := range presets["operator"] {
		if err := appendPolicy(p.config, "claude-code", strings.Join(b.tools, ","), strings.Join(b.scopes, " "), "-1h"); err != nil {
			t.Fatal(err)
		}
	}
	n := len(presets["operator"])
	if out := p.ok("allow", "claude-code", "@operator", "2h"); !strings.Contains(out, fmt.Sprintf("replaced %d expired grant(s)", n)) {
		t.Errorf("allow @operator: %q", out)
	}
	got, err := LoadConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Policies) != n {
		t.Errorf("%d policies after re-granting @operator, want %d", len(got.Policies), n)
	}
	for _, pol := range got.Policies {
		if time.Now().After(pol.Expires) {
			t.Errorf("an expired grant survived: %+v", pol)
		}
	}
}
