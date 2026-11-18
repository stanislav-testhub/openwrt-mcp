package main

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func mfRoot(t *testing.T) string {
	t.Helper()
	root := withFixtureRoot(t)
	for _, d := range []string{"etc/crontabs", "etc/dnsmasq.d"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// no reload against a real init script
	cmdRunner = func(_ context.Context, _ *string, argv []string) (string, string, error) { return "", "", nil }
	t.Cleanup(func() { cmdRunner = execRunner })
	return root
}

func mfCall(t *testing.T, s *Server, in managedFileIn) (string, error) {
	t.Helper()
	out, _, err := s.managedFile(context.Background(), "c", in)
	return out, err
}

func TestManagedFileWritesKeepModeAndHistory(t *testing.T) {
	root := mfRoot(t)
	p := filepath.Join(root, "etc/crontabs/root")
	if err := os.WriteFile(p, []byte("0 3 * * * /sbin/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, "")
	out, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "crontab", Content: "0 3 * * * /sbin/x\n*/5 * * * * /bin/y"})
	if err != nil || !strings.Contains(out, "wrote /etc/crontabs/root") || !strings.Contains(out, "+*/5 * * * * /bin/y") {
		t.Fatalf("write: %q / %v", out, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "0 3 * * * /sbin/x\n*/5 * * * * /bin/y\n" {
		t.Errorf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if m, _ := filepath.Glob(filepath.Join(root, "etc/crontabs/.mcp-*")); len(m) != 0 {
		t.Errorf("temp file left: %v", m)
	}
	h, _ := mfCall(t, s, managedFileIn{Action: "history", Kind: "crontab"})
	id := strings.Fields(strings.SplitN(h, "\n  ", 2)[1])[0]
	if d, err := mfCall(t, s, managedFileIn{Action: "diff", Kind: "crontab", ID: id}); err != nil || !strings.Contains(d, "*/5") {
		t.Errorf("diff: %q / %v", d, err)
	}
	if _, err := mfCall(t, s, managedFileIn{Action: "restore", Kind: "crontab", ID: id}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "0 3 * * * /sbin/x\n" {
		t.Errorf("restore gave %q", b)
	}
}

func TestManagedFileDnsmasqSaysWhenTheDirectoryIsNotRead(t *testing.T) {
	mfRoot(t)
	s := testServer(t, "")
	out, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "dnsmasq", Name: "a.conf", Content: "address=/x/0.0.0.0"})
	if err != nil || !strings.Contains(out, "does not read /etc/dnsmasq.d until") {
		t.Fatalf("%q / %v", out, err)
	}
	cmdRunner = func(_ context.Context, _ *string, argv []string) (string, string, error) {
		return "/etc/dnsmasq.d\n", "", nil
	}
	out, _ = mfCall(t, s, managedFileIn{Action: "write", Kind: "dnsmasq", Name: "b.conf", Content: "address=/y/0.0.0.0"})
	if strings.Contains(out, "Note:") {
		t.Errorf("confdir is set, yet: %q", out)
	}
}

func TestManagedFileDryRunAndNoChange(t *testing.T) {
	root := mfRoot(t)
	p := filepath.Join(root, "etc/hosts")
	os.WriteFile(p, []byte("127.0.0.1 localhost\n"), 0o644)
	s := testServer(t, "")
	out, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "hosts", Content: "127.0.0.1 localhost\n10.0.0.2 nas", DryRun: true})
	if err != nil || !strings.Contains(out, "not written") || !strings.Contains(out, "+10.0.0.2 nas") {
		t.Fatalf("dry run: %q / %v", out, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "127.0.0.1 localhost\n" {
		t.Errorf("dry run wrote %q", b)
	}
	out, _ = mfCall(t, s, managedFileIn{Action: "write", Kind: "hosts", Content: "127.0.0.1 localhost"})
	if !strings.Contains(out, "nothing written") {
		t.Errorf("same content: %q", out)
	}
}

func TestManagedFileValidators(t *testing.T) {
	mfRoot(t)
	s := testServer(t, "")
	for _, c := range []struct {
		in   managedFileIn
		want string
	}{
		{managedFileIn{Action: "write", Kind: "crontab", Content: "0 3 * *  /x"}, "5 time fields"},
		{managedFileIn{Action: "write", Kind: "crontab", Content: "0 3 * * $(x) /x"}, "bad time field"},
		{managedFileIn{Action: "write", Kind: "hosts", Content: "nas 10.0.0.2"}, "not an IP"},
		{managedFileIn{Action: "write", Kind: "hosts", Content: "10.0.0.2"}, "no host name"},
		{managedFileIn{Action: "write", Kind: "sysupgrade_conf", Content: "etc/x"}, "absolute path"},
		{managedFileIn{Action: "write", Kind: "sysupgrade_conf", Content: "/etc/../shadow"}, "no .."},
		{managedFileIn{Action: "write", Kind: "dnsmasq", Name: "a.conf", Content: "dhcp-script=/tmp/x"}, "not allowed"},
		{managedFileIn{Action: "write", Kind: "dnsmasq", Name: "a.conf", Content: "conf-file=/etc/shadow"}, "not allowed"},
	} {
		if _, err := mfCall(t, s, c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: want %q, got %v", c.in, c.want, err)
		}
	}
}

func TestManagedFileNamesAndKindsCannotEscape(t *testing.T) {
	mfRoot(t)
	s := testServer(t, "")
	for _, name := range []string{"../shadow", "../../etc/shadow.conf", "a/b.conf", ".hidden.conf", "x", "x.conf/..", "a b.conf", "", "x.conf\n"} {
		if _, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "dnsmasq", Name: name, Content: "x=1"}); err == nil {
			t.Errorf("name %q was accepted", name)
		}
	}
	if _, err := mfCall(t, s, managedFileIn{Action: "read", Kind: "crontab", Name: "x"}); err == nil {
		t.Error("a fixed-file kind took a name")
	}
	if _, err := mfCall(t, s, managedFileIn{Action: "read", Kind: "shadow"}); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestManagedFileRefusesASymlinkTarget(t *testing.T) {
	root := mfRoot(t)
	secret := filepath.Join(root, "secret")
	os.WriteFile(secret, []byte("keep\n"), 0o600)
	if err := os.Symlink(secret, filepath.Join(root, "etc/dnsmasq.d/x.conf")); err != nil {
		t.Skip("no symlinks here")
	}
	s := testServer(t, "")
	for _, a := range []managedFileIn{{Action: "read", Kind: "dnsmasq", Name: "x.conf"}, {Action: "write", Kind: "dnsmasq", Name: "x.conf", Content: "a=1"}} {
		if _, err := mfCall(t, s, a); err == nil || !strings.Contains(err.Error(), "not a plain file") {
			t.Errorf("%s through a symlink: %v", a.Action, err)
		}
	}
	if b, _ := os.ReadFile(secret); string(b) != "keep\n" {
		t.Errorf("the link target changed: %q", b)
	}
}

func TestManagedFileMasksSecretsInReadsAndDiffs(t *testing.T) {
	root := mfRoot(t)
	os.WriteFile(filepath.Join(root, "etc/crontabs/root"), []byte("API_TOKEN=abc123\n0 * * * * curl --password hunter2 x\n"), 0o600)
	s := testServer(t, "")
	out, err := mfCall(t, s, managedFileIn{Action: "read", Kind: "crontab"})
	if err != nil || strings.Contains(out, "abc123") || strings.Contains(out, "hunter2") || !strings.Contains(out, "API_TOKEN="+redacted) {
		t.Errorf("read: %q / %v", out, err)
	}
	out, _ = mfCall(t, s, managedFileIn{Action: "write", Kind: "crontab", Content: "API_TOKEN=new999\n", DryRun: true})
	if strings.Contains(out, "abc123") || strings.Contains(out, "new999") {
		t.Errorf("dry run leaks: %q", out)
	}
}

func TestManagedFileListNamesDnsmasqFiles(t *testing.T) {
	root := mfRoot(t)
	os.WriteFile(filepath.Join(root, "etc/dnsmasq.d/ads.conf"), []byte("address=/x/0.0.0.0\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/dnsmasq.d/README"), []byte("x"), 0o644)
	out, _ := mfCall(t, testServer(t, ""), managedFileIn{Action: "list"})
	if !strings.Contains(out, "ads.conf") || strings.Contains(out, "README") || !strings.Contains(out, "/etc/crontabs/root (missing)") {
		t.Errorf("list: %q", out)
	}
}

func TestManagedFileScope(t *testing.T) {
	if got := managedFileScope(managedFileIn{Action: "write", Kind: "crontab"}); got[0] != "crontab.write" {
		t.Errorf("%v", got)
	}
}

func FuzzManagedFileNameGrammar(f *testing.F) {
	for _, s := range []string{"a.conf", "../x.conf", "a\x00.conf"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if reDnsmasqFile.MatchString(name) {
			p := fileKinds["dnsmasq"].target(name)
			if filepath.Dir(p) != "/etc/dnsmasq.d" || strings.Contains(name, "/") || strings.HasPrefix(name, ".") {
				t.Fatalf("name %q gives %q", name, p)
			}
		}
	})
}

// ---------------------------------------------------------------- kind path

const pathConf = "config server\n\tlist managed_path '/etc/blocklists/*'\n\tlist managed_path '/srv/app/*.conf'\n"

func pathRoot(t *testing.T) string {
	root := mfRoot(t)
	for _, d := range []string{"etc/blocklists", "srv/app", "etc/other"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestManagedPathIsOffUntilTheOwnerListsAGlob(t *testing.T) {
	root := pathRoot(t)
	s := testServer(t, "")
	_, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "path", Path: "/etc/blocklists/a", Content: "x\n"})
	if err == nil || errCode(err) != codePolicyDenied || !strings.Contains(err.Error(), "managed_path") {
		t.Fatalf("%v", err)
	}
	if _, serr := os.Stat(filepath.Join(root, "etc/blocklists/a")); serr == nil {
		t.Error("a refused write created the file")
	}
	if out, _ := mfCall(t, s, managedFileIn{Action: "list"}); !strings.Contains(out, "off: the owner has listed no managed_path") {
		t.Errorf("list: %s", out)
	}
}

func TestManagedPathWritesWithinAGlobAndKeepsHistory(t *testing.T) {
	root := pathRoot(t)
	s := testServer(t, pathConf)
	p := filepath.Join(root, "etc/blocklists/ads")
	if err := os.WriteFile(p, []byte("a.example\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	in := managedFileIn{Action: "write", Kind: "path", Path: "/etc/blocklists/ads", Content: "a.example\nb.example"}
	if out, err := mfCall(t, s, in); err != nil || !strings.Contains(out, "+b.example") {
		t.Fatalf("%q / %v", out, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "a.example\nb.example\n" {
		t.Errorf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	h, err := mfCall(t, s, managedFileIn{Action: "history", Kind: "path", Path: "/etc/blocklists/ads"})
	if err != nil || !strings.Contains(h, "file_path_") {
		t.Fatalf("history: %q / %v", h, err)
	}
	// Another path has its own history: the id of this one is refused for it.
	id := strings.Fields(strings.SplitN(h, "\n  ", 2)[1])[0]
	if _, err := mfCall(t, s, managedFileIn{Action: "diff", Kind: "path", Path: "/srv/app/x.conf", ID: id}); err == nil {
		t.Error("a version of one path was accepted for another")
	}
	if _, err := mfCall(t, s, managedFileIn{Action: "restore", Kind: "path", Path: "/etc/blocklists/ads", ID: id}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "a.example\n" {
		t.Errorf("restore: %q", b)
	}
	if out, _ := mfCall(t, s, managedFileIn{Action: "read", Kind: "path", Path: "/etc/blocklists/ads"}); out != "a.example\n" {
		t.Errorf("read: %q", out)
	}
}

func TestManagedPathRefusesEverythingOutsideTheGlobsAndTheFloor(t *testing.T) {
	root := pathRoot(t)
	s := testServer(t, pathConf+"\tlist managed_path '/etc/*'\n")
	for _, bad := range []string{
		"/etc/shadow", "/etc/passwd", "/etc/config/openwrt-mcp", "/etc/openwrt-mcp/audit.jsonl", "/etc/config/rpcd",
		"/etc/dropbear/authorized_keys", "/etc/x.key", "/etc/ssl.PEM", "/etc/Shadow-", "/etc/shadow.bak",
		"/etc/blocklists/../shadow", "/etc/blocklists/./a", "/etc//blocklists/a", "/etc/blocklists/a/", "etc/blocklists/a",
		"relative", "/", "", "/etc/blocklists/a\nb", "/etc/blocklists/a\x00", `/etc/blocklists\a`, "/usr/bin/openwrt-mcp",
		"/srv/app/x.conf/y", "/home/u/.ssh/config",
	} {
		_, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "path", Path: bad, Content: "x\n"})
		if err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	// A glob does not cross a slash: /srv/app/*.conf is not /srv/app/sub/x.conf.
	s2 := testServer(t, pathConf)
	if _, err := mfCall(t, s2, managedFileIn{Action: "write", Kind: "path", Path: "/srv/app/sub/x.conf", Content: "x\n"}); err == nil {
		t.Error("glob crossed a slash")
	}
	if _, err := mfCall(t, s2, managedFileIn{Action: "write", Kind: "path", Path: "/etc/other/x", Content: "x\n"}); err == nil {
		t.Error("a path outside every glob was written")
	}
	filepath.WalkDir(root, func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			t.Errorf("a refused write left a file: %s", p)
		}
		return nil
	})
	// Kinds do not take the other's arguments.
	if _, err := mfCall(t, s2, managedFileIn{Action: "read", Kind: "hosts", Path: "/etc/hosts"}); err == nil {
		t.Error("path accepted for a typed kind")
	}
	if _, err := mfCall(t, s2, managedFileIn{Action: "read", Kind: "path", Name: "a", Path: "/etc/blocklists/a"}); err == nil {
		t.Error("name accepted for kind path")
	}
}

func TestManagedPathRefusesSymlinksOnTheWayAndAtTheTarget(t *testing.T) {
	root := pathRoot(t)
	s := testServer(t, pathConf)
	if err := os.WriteFile(filepath.Join(root, "etc/other/secret"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink as the file, and a symlink as a directory on the path.
	if err := os.Symlink(filepath.Join(root, "etc/other/secret"), filepath.Join(root, "etc/blocklists/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "etc/other"), filepath.Join(root, "srv/app/dir")); err != nil {
		t.Fatal(err)
	}
	for _, in := range []managedFileIn{
		{Action: "write", Kind: "path", Path: "/etc/blocklists/link", Content: "pwned\n"},
		{Action: "read", Kind: "path", Path: "/etc/blocklists/link"},
	} {
		if _, err := mfCall(t, s, in); err == nil || !strings.Contains(err.Error(), "refusing to follow") {
			t.Errorf("%+v: %v", in, err)
		}
	}
	s3 := testServer(t, "config server\n\tlist managed_path '/srv/app/dir/*'\n")
	if _, err := mfCall(t, s3, managedFileIn{Action: "write", Kind: "path", Path: "/srv/app/dir/secret", Content: "pwned\n"}); err == nil || !strings.Contains(err.Error(), "refusing to follow") {
		t.Errorf("symlinked directory: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/other/secret")); string(b) != "keep\n" {
		t.Errorf("the link target was written: %q", b)
	}
	// The directory must exist: kind path never creates one.
	s4 := testServer(t, "config server\n\tlist managed_path '/nope/*'\n")
	if _, err := mfCall(t, s4, managedFileIn{Action: "write", Kind: "path", Path: "/nope/a", Content: "x\n"}); errCode(err) != codeNotFound {
		t.Errorf("missing directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "nope")); err == nil {
		t.Error("a directory was created")
	}
}

func TestManagedPathRefusesBinaryAndHugeContent(t *testing.T) {
	pathRoot(t)
	s := testServer(t, pathConf)
	for _, c := range []string{"a\x00b\n", "\xff\xfe\n"} {
		if _, err := mfCall(t, s, managedFileIn{Action: "write", Kind: "path", Path: "/etc/blocklists/a", Content: c}); err == nil {
			t.Errorf("accepted %q", c)
		}
	}
}

func TestManagedPathBadConfigGlobsAreIgnored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "openwrt-mcp")
	if err := os.WriteFile(p, []byte("config server\n\tlist managed_path 'etc/rel/*'\n\tlist managed_path '/etc/shadow'\n\tlist managed_path '/etc/../x/*'\n\tlist managed_path '/ok/*'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.ManagedPaths) != 1 || cfg.ManagedPaths[0] != "/ok/*" {
		t.Errorf("ManagedPaths = %v", cfg.ManagedPaths)
	}
}

func FuzzCanonManagedPath(f *testing.F) {
	for _, s := range []string{"/etc/a", "/etc/../shadow", "//etc/a", "/a/./b", "/a/b/", "/etc/shadow", "/a\x00", "/a/..", "/../a", "/etc/passwd", "/a%2e%2e/b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, err := canonManagedPath(p)
		if err != nil {
			return
		}
		// What is accepted is its own canonical form, absolute, free of .. and of the floor.
		if got != p || path.Clean(p) != p || !strings.HasPrefix(p, "/") || p == "/" {
			t.Fatalf("accepted a non-canonical path %q", p)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				t.Fatalf("accepted %q", p)
			}
		}
		if managedPathFloor(p) != "" || strings.ContainsAny(p, "\x00\\\n") {
			t.Fatalf("accepted a floor path %q", p)
		}
		if path.Base(strings.ToLower(p)) == "shadow" || path.Base(strings.ToLower(p)) == "passwd" {
			t.Fatalf("accepted %q", p)
		}
	})
}
