package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The state directory holds bearer-token digests, TOTP secrets, rollback snapshots of the whole
// UCI tree and the audit log. uhttpd serves /www and runs anything under a cgi-bin directory, so
// a state path that resolves there would publish that material to the LAN. These tests pin the
// guard that prevents it, and the layout it guards. Expected values are written out here, not
// derived from the code under test.

func TestStatePathLayoutIsPinned(t *testing.T) {
	cfg := &Config{AuditPath: "/a/audit.jsonl", Socket: "/run/x/mcp.sock"}
	got := statePaths("/var/lib/x", cfg)
	want := []string{
		"/a/audit.jsonl", "/a/audit.jsonl.1", "/run/x/mcp.sock", "/run/x/wg",
		"/var/lib/x/history", "/var/lib/x/mfa", "/var/lib/x/mfa.new", "/var/lib/x/pending.json",
		"/var/lib/x/rollback", "/var/lib/x/tokens", "/var/lib/x/tokens.tmp",
	}
	g := make([]string, len(got))
	for i, p := range got {
		g[i] = filepath.ToSlash(p)
	}
	sort.Strings(g)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("state paths:\n got  %q\n want %q", g, want)
	}
	// A disabled socket is not a path.
	for _, p := range statePaths("/var/lib/x", &Config{AuditPath: "/a/audit.jsonl"}) {
		if p == "" || strings.HasSuffix(filepath.ToSlash(p), "mcp.sock") {
			t.Errorf("empty or socket path listed with the socket disabled: %q", p)
		}
	}
}

func TestNoStatePathCanBeWebServed(t *testing.T) {
	withFixtureRoot(t) // no /etc/config/uhttpd: only the built-in rules apply

	t.Run("default layout is fine", func(t *testing.T) {
		cfg := &Config{AuditPath: defaultAuditPath, Socket: defaultSocket}
		if err := checkStatePaths(defaultStatePath, cfg); err != nil {
			t.Fatalf("default layout refused: %v", err)
		}
	})

	hostile := []string{
		"/www", "/www/x", "/www/openwrt-mcp", "/www/../www/x", "/etc/../www/state", "/www/./x", "//www/x",
		"/www/cgi-bin/state", "/tmp/cgi-bin", "/tmp/cgi-bin/state", "/srv/cgi-bin/a/b", "/etc/openwrt-mcp/../../www/s",
	}
	cfg := &Config{AuditPath: defaultAuditPath, Socket: defaultSocket}
	for _, state := range hostile {
		if err := checkNotWebServed(state); err == nil {
			t.Errorf("checkNotWebServed(%q) accepted a web-served path", state)
		}
		if err := checkStatePaths(state, cfg); err == nil {
			t.Errorf("checkStatePaths(%q) accepted a web-served state dir", state)
		}
		// The audit log and the socket are independent paths: each one alone is enough.
		if err := checkStatePaths(defaultStatePath, &Config{AuditPath: state + "/audit.jsonl", Socket: defaultSocket}); err == nil {
			t.Errorf("audit path under %q accepted", state)
		}
		if err := checkStatePaths(defaultStatePath, &Config{AuditPath: defaultAuditPath, Socket: state + "/mcp.sock"}); err == nil {
			t.Errorf("socket path under %q accepted", state)
		}
	}

	for _, ok := range []string{
		"/etc/openwrt-mcp", "/var/run/openwrt-mcp/mcp.sock", "/wwwroot/x", "/www2/x", "/tmp/www/x",
		"/mnt/usb/openwrt-mcp", "/etc/cgi-bin-notes/x",
	} {
		if err := checkNotWebServed(ok); err != nil {
			t.Errorf("checkNotWebServed(%q) refused a safe path: %v", ok, err)
		}
	}
}

func TestStatePathGuardFollowsUhttpdAndSymlinks(t *testing.T) {
	root := withFixtureRoot(t)
	web := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "/etc/config/uhttpd",
		"config uhttpd 'main'\n\toption home '"+filepath.ToSlash(web)+"'\n\toption cgi_prefix '/bin-cgi'\n")

	if err := checkNotWebServed(filepath.Join(web, "state")); err == nil {
		t.Error("a directory under the configured uhttpd home was accepted")
	}
	if err := checkNotWebServed(filepath.Join(filepath.Dir(web), "elsewhere")); err != nil {
		t.Errorf("a sibling of the web root was refused: %v", err)
	}
	if err := checkNotWebServed(filepath.Join(filepath.Dir(web), "x", "bin-cgi", "s")); err == nil {
		t.Error("a directory named after the configured cgi_prefix was accepted")
	}

}

// makeDirLink points link at the directory target. Windows grants symlinks only to privileged
// users and Go no longer resolves junctions, so there these tests skip and CI on Linux runs them.
func makeDirLink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
}

// The shape of /etc/config/uhttpd as OpenWrt ships it: the web server section with its `home`, a
// `list` of listen addresses and Lua prefixes, and a second section of another type (`cert`) that
// has nothing to do with web roots. Moving `home` does not make /www safe, so both are refused.
func TestStateGuardReadsTheUhttpdConfigAsShipped(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "/etc/config/uhttpd", `config uhttpd 'main'
	list listen_http '0.0.0.0:80'
	list listen_http '[::]:80'
	option redirect_https '1'
	option home '/srv/web'
	option rfc1918_filter '1'
	option max_requests '3'
	option cert '/etc/uhttpd.crt'
	option key '/etc/uhttpd.key'
	option cgi_prefix '/cgi-bin'
	list lua_prefix '/cgi-bin/luci=/usr/lib/lua/luci/sgi/uhttpd.lua'
	option script_timeout '60'
	option network_timeout '30'
	option tcp_keepalive '1'

config cert 'defaults'
	option days '730'
	option key_type 'ec'
	option bits '2048'
	option ec_curve 'P-256'
	option country 'ZZ'
	option commonname 'OpenWrt'
`)
	roots, cgi := webServed()
	if strings.Join(roots, " ") != "/www /srv/web" {
		t.Errorf("web roots = %q, want the built-in /www and the configured /srv/web", roots)
	}
	if strings.Join(cgi, " ") != "cgi-bin cgi-bin" {
		t.Errorf("cgi directory names = %q", cgi)
	}
	for _, p := range []string{"/srv/web/mcp", "/srv/web", "/www/mcp", "/srv/web/cgi-bin/x"} {
		if err := checkNotWebServed(p); err == nil {
			t.Errorf("%s is web-served and was accepted", p)
		}
	}
	for _, p := range []string{"/srv/webdata/mcp", "/srv/other", "/etc/uhttpd.key", "/etc/openwrt-mcp"} {
		if err := checkNotWebServed(p); err != nil {
			t.Errorf("%s is not web-served and was refused: %v", p, err)
		}
	}
}

// A relative path means the daemon's working directory, so that is what is checked.
func TestRelativeStatePathsAreCheckedAgainstTheWorkingDirectory(t *testing.T) {
	root := withFixtureRoot(t)
	web := t.TempDir()
	writeFixture(t, root, "/etc/config/uhttpd", "config uhttpd 'main'\n\toption home '"+filepath.ToSlash(web)+"'\n")

	t.Chdir(web)
	for _, p := range []string{"state", "./state/tokens", "a/../state"} {
		if err := checkNotWebServed(p); err == nil {
			t.Errorf("relative path %q inside the web root was accepted", p)
		}
	}
	t.Chdir(t.TempDir())
	if err := checkNotWebServed("state"); err != nil {
		t.Errorf("a relative path outside the web root was refused: %v", err)
	}
}

// vfs is a virtual file tree with symlinks, standing in for the three calls the resolver makes.
// Keys are slash-separated and carry the volume name on Windows, as the resolver's own paths do,
// so the same test runs on both: real symlinks need a privilege on Windows and CI is not the only
// place the resolver should be exercised.
type vfs struct {
	dirs  map[string]bool
	links map[string]string
}

type vinfo struct{ mode fs.FileMode }

func (v vinfo) Name() string       { return "" }
func (v vinfo) Size() int64        { return 0 }
func (v vinfo) Mode() fs.FileMode  { return v.mode }
func (v vinfo) ModTime() time.Time { return time.Time{} }
func (v vinfo) IsDir() bool        { return v.mode.IsDir() }
func (v vinfo) Sys() any           { return nil }

// vp turns a unix-style path into one that is absolute on this OS.
func vp(p string) string { return filepath.VolumeName(os.TempDir()) + p }

func vclean(p string) string { return filepath.ToSlash(filepath.Clean(p)) }

// eval resolves every symlink in p, like filepath.EvalSymlinks, and fails if anything is missing.
func (v *vfs) eval(p string, depth int) (string, error) {
	if depth > 40 {
		return "", errors.New("too many links")
	}
	parts := strings.Split(vclean(p), "/")
	cur := parts[0] // "" on unix, "C:" on Windows
	for _, c := range parts[1:] {
		if c == "" {
			continue
		}
		next := cur + "/" + c
		if tgt, ok := v.links[next]; ok {
			if !filepath.IsAbs(filepath.FromSlash(tgt)) {
				tgt = path.Join(path.Dir(next), tgt)
			}
			r, err := v.eval(tgt, depth+1)
			if err != nil {
				return "", err
			}
			cur = r
			continue
		}
		if !v.dirs[next] {
			return "", fs.ErrNotExist
		}
		cur = next
	}
	if cur == "" {
		cur = "/"
	}
	return cur, nil
}

// entry resolves the directory part of p, as the OS does for lstat and readlink, and returns the
// full key of the entry itself.
func (v *vfs) entry(p string) (string, error) {
	p = vclean(p)
	i := strings.LastIndex(p, "/")
	dir, base := p[:i], p[i+1:]
	parent := dir
	if dir != "" && dir != vp("") {
		r, err := v.eval(dir, 0)
		if err != nil {
			return "", err
		}
		parent = r
	}
	return parent + "/" + base, nil
}

func (v *vfs) lstat(p string) (fs.FileInfo, error) {
	if c := vclean(p); c == "/" || c == vp("") || c == vp("/") {
		return vinfo{fs.ModeDir}, nil
	}
	full, err := v.entry(p)
	if err != nil {
		return nil, err
	}
	if _, ok := v.links[full]; ok {
		return vinfo{fs.ModeSymlink}, nil
	}
	if v.dirs[full] {
		return vinfo{fs.ModeDir}, nil
	}
	return nil, fs.ErrNotExist
}

func (v *vfs) readlink(p string) (string, error) {
	full, err := v.entry(p)
	if err != nil {
		return "", err
	}
	if tgt, ok := v.links[full]; ok {
		return tgt, nil
	}
	return "", fs.ErrInvalid
}

func installVFS(t *testing.T, v *vfs) {
	t.Helper()
	oldL, oldR, oldE := fsLstat, fsReadlink, fsEvalSymlinks
	fsLstat, fsReadlink = v.lstat, v.readlink
	fsEvalSymlinks = func(p string) (string, error) { return v.eval(p, 0) }
	t.Cleanup(func() { fsLstat, fsReadlink, fsEvalSymlinks = oldL, oldR, oldE })
}

// Every way a symlink can lead into the web root, on a virtual tree, so it runs on every OS.
func TestSymlinkResolutionOnAVirtualTree(t *testing.T) {
	root := withFixtureRoot(t)
	web := vp("/v/web")
	writeFixture(t, root, "/etc/config/uhttpd", "config uhttpd 'main'\n\toption home '"+web+"'\n")
	installVFS(t, &vfs{
		dirs: map[string]bool{vp("/v"): true, web: true, vp("/v/safe"): true, vp("/v/other"): true},
		links: map[string]string{
			vp("/v/state"):    web,                // absolute link to the web root
			vp("/v/rel"):      "web",              // relative link
			vp("/v/up"):       "../v/web",         // relative link through ..
			vp("/v/chain1"):   vp("/v/chain2"),    // a chain of links
			vp("/v/chain2"):   web,                //
			vp("/v/dangling"): vp("/v/web/later"), // creating a file through it creates the target
			vp("/v/good"):     vp("/v/safe"),      // a link somewhere harmless
			vp("/v/loopA"):    vp("/v/loopB"),     // a loop
			vp("/v/loopB"):    vp("/v/loopA"),
		},
	})

	for _, p := range []string{
		"/v/state", "/v/state/audit.jsonl", "/v/state/a/b/c", "/v/rel", "/v/rel/x", "/v/up/x",
		"/v/chain1", "/v/chain1/x", "/v/dangling", "/v/web", "/v/web/x",
	} {
		if err := checkNotWebServed(vp(p)); err == nil {
			t.Errorf("%s leads into the web root and was accepted", p)
		}
	}
	for _, p := range []string{"/v/good", "/v/good/audit.jsonl", "/v/safe/x", "/v/other/x", "/v/webby/x", "/v"} {
		if err := checkNotWebServed(vp(p)); err != nil {
			t.Errorf("%s is harmless and was refused: %v", p, err)
		}
	}

	// A loop of links cannot be followed to an end: the resolver must stop, not spin.
	done := make(chan struct{})
	go func() {
		_ = checkNotWebServed(vp("/v/loopA/x"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a symlink loop made the resolver run forever")
	}
}

func TestStatePathGuardFollowsSymlinks(t *testing.T) {
	root := withFixtureRoot(t)
	web := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "/etc/config/uhttpd", "config uhttpd 'main'\n\toption home '"+filepath.ToSlash(web)+"'\n")

	// A link out of a harmless-looking directory into the web root, with a file that does not
	// exist yet: the OS creates it inside the web root.
	link := filepath.Join(t.TempDir(), "state")
	makeDirLink(t, web, link)
	if err := checkNotWebServed(filepath.Join(link, "audit.jsonl")); err == nil {
		t.Error("a path reached through a link into the web root was accepted")
	}
	if err := checkNotWebServed(link); err == nil {
		t.Error("a link to the web root was accepted")
	}
	if err := checkNotWebServed(filepath.Join(link, "a", "b", "c")); err == nil {
		t.Error("a deep path through a link into the web root was accepted")
	}
	// Control: a link to somewhere harmless stays allowed.
	safe := filepath.Join(t.TempDir(), "safe")
	if err := os.MkdirAll(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	okLink := filepath.Join(t.TempDir(), "ok")
	makeDirLink(t, safe, okLink)
	if err := checkNotWebServed(filepath.Join(okLink, "audit.jsonl")); err != nil {
		t.Errorf("a link to a harmless directory was refused: %v", err)
	}
}

func TestStatePathGuardFollowsADanglingSymlink(t *testing.T) {
	root := withFixtureRoot(t)
	web := filepath.Join(t.TempDir(), "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "/etc/config/uhttpd", "config uhttpd 'main'\n\toption home '"+filepath.ToSlash(web)+"'\n")
	// Creating a file through a dangling symlink creates its target, here inside the web root.
	link := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Symlink(filepath.Join(web, "later.jsonl"), link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	if err := checkNotWebServed(link); err == nil {
		t.Error("a dangling symlink into the web root was accepted")
	}
}

func TestLoadConfigIgnoresWebServedAuditAndSocket(t *testing.T) {
	withFixtureRoot(t)
	dir := t.TempDir()
	cases := []struct{ name, body string }{
		{"audit in /www", "config server\n\toption audit '/www/audit.jsonl'\n"},
		{"audit via dotdot", "config server\n\toption audit '/etc/../www/a.jsonl'\n"},
		{"audit in cgi-bin", "config server\n\toption audit '/srv/cgi-bin/a.jsonl'\n"},
		{"socket in /www", "config server\n\toption socket '/www/mcp.sock'\n"},
		{"socket in cgi-bin", "config server\n\toption socket '/tmp/cgi-bin/mcp.sock'\n"},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "cfg"+strconv.Itoa(i))
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("%s: a bad path must keep the default, not fail the load: %v", c.name, err)
		}
		if strings.HasPrefix(c.name, "audit") && cfg.AuditPath != defaultAuditPath {
			t.Errorf("%s: AuditPath = %q, want the default %q", c.name, cfg.AuditPath, defaultAuditPath)
		}
		if strings.HasPrefix(c.name, "socket") && cfg.Socket != defaultSocket {
			t.Errorf("%s: Socket = %q, want the default %q", c.name, cfg.Socket, defaultSocket)
		}
	}

	// Still allowed: a sane override, and an empty socket (bridge off).
	p := filepath.Join(dir, "ok")
	if err := os.WriteFile(p, []byte("config server\n\toption audit '/mnt/usb/audit.jsonl'\n\toption socket ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil || cfg.AuditPath != "/mnt/usb/audit.jsonl" || cfg.Socket != "" {
		t.Errorf("sane overrides lost: %+v, %v", cfg, err)
	}
}

func TestNewServerRefusesAWebServedStateDir(t *testing.T) {
	root := withFixtureRoot(t)
	web := filepath.Join(t.TempDir(), "web")
	writeFixture(t, root, "/etc/config/uhttpd", "config uhttpd 'main'\n\toption home '"+filepath.ToSlash(web)+"'\n")
	cfgPath := filepath.Join(t.TempDir(), "openwrt-mcp")
	if err := os.WriteFile(cfgPath, []byte("config server\n\toption socket ''\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(web, "state")
	if _, err := NewServer(cfgPath, state); err == nil {
		t.Fatal("NewServer started with its state directory inside the web root")
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("the refused state directory was created anyway")
	}
}

// Tripwires over the source. A guard on the accessors is worthless if a new file is written by a
// path built somewhere else, so the layout may be spelled out in exactly one place.

func nonTestSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil || len(matches) == 0 {
		t.Fatalf("no sources found: %v", err)
	}
	out := map[string]*ast.File{}
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, m, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out[m] = f
	}
	return out
}

func stringLiterals(f *ast.File) []string {
	var lits []string
	ast.Inspect(f, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				lits = append(lits, s)
			}
		}
		return true
	})
	return lits
}

func TestNoSourceFileNamesAWebRoot(t *testing.T) {
	for name, f := range nonTestSources(t) {
		if name == "statepaths.go" {
			continue
		}
		for _, s := range stringLiterals(f) {
			if s == "/www" || strings.HasPrefix(s, "/www/") || strings.Contains(s, "cgi-bin") {
				t.Errorf("%s has a literal %q: web-served locations belong in statepaths.go only", name, s)
			}
		}
	}
}

// pathBuildingLiterals returns the string literals that are joined or concatenated into a path:
// arguments of path.Join / filepath.Join and operands of "+". A command name in a switch
// (case "mfa":) is not one.
func pathBuildingLiterals(f *ast.File) []string {
	var lits []string
	add := func(e ast.Expr) {
		if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				lits = append(lits, s)
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Join" {
				for _, a := range x.Args {
					add(a)
				}
			}
		case *ast.BinaryExpr:
			if x.Op == token.ADD {
				add(x.X)
				add(x.Y)
			}
		}
		return true
	})
	return lits
}

func TestStateFileNamesLiveOnlyInStatepaths(t *testing.T) {
	forbidden := map[string]bool{"tokens": true, "mfa": true, "pending.json": true, "rollback": true, "history": true,
		"/tokens": true, "/mfa": true, "/pending.json": true, "/rollback": true, "/history": true}
	for name, f := range nonTestSources(t) {
		if name == "statepaths.go" {
			continue
		}
		for _, s := range pathBuildingLiterals(f) {
			if forbidden[s] {
				t.Errorf("%s builds a state path from the literal %q: use the accessor in statepaths.go", name, s)
			}
		}
	}
}

// Every CLI command that touches state refuses a web-served directory, not only `serve`: `pair`
// would otherwise write token digests there. The directory is under a temp dir, so a regression
// writes inside it and nowhere else.
func TestCLIRefusesAWebServedStateDir(t *testing.T) {
	c := newCLI(t)
	c.state = filepath.Join(filepath.Dir(c.state), "cgi-bin", "state")
	for _, args := range [][]string{{"pair", "laptop"}, {"clients"}, {"mfa", "list"}} {
		_, stderr, code := c.run(args...)
		if code == 0 {
			t.Errorf("openwrt-mcp %v succeeded with -state in a cgi-bin directory", args)
		}
		if !strings.Contains(stderr, "cgi-bin") {
			t.Errorf("openwrt-mcp %v: refusal does not say why: %q", args, stderr)
		}
	}
	if _, err := os.Stat(c.state); err == nil {
		t.Error("the refused state directory was created anyway")
	}
}
