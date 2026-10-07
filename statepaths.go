package main

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Where the daemon keeps what must never be public: token digests, TOTP secrets, rollback
// snapshots and history of the whole UCI tree (Wi-Fi keys and WireGuard private keys included)
// and the audit log. uhttpd serves /www and executes anything under a cgi-bin directory, so a state
// path that resolves there would hand that material to the LAN. A published advisory in a
// comparable tool was exactly this: backups written into a web-served directory.
//
// Every path the daemon creates is built here and nowhere else (a test enforces it), and every
// one is checked against the web roots before the daemon starts or accepts a config value.

func tokensPath(state string) string       { return path.Join(state, "tokens") }
func mfaPath(state string) string          { return path.Join(state, "mfa") }
func pendingPath(state string) string      { return path.Join(state, "pending.json") }
func rollbackDir(state string) string      { return path.Join(state, "rollback") }
func historyDir(state string) string       { return path.Join(state, "history") }
func tokensTmpPath(tokens string) string   { return tokens + ".tmp" }
func mfaTmpPath(mfa string) string         { return mfa + ".new" }
func auditRotatedPath(audit string) string { return audit + ".1" }

// wgClientDir holds the client configs wg_new_client writes for the operator to collect. It sits
// beside the socket, in RAM and root-only, because the files carry a private key that the router
// itself never keeps: a reboot must take them away. It is not a path under the state directory
// on purpose (that is flash).
func wgClientDir(cfg *Config) string {
	sock := defaultSocket
	if cfg != nil && cfg.Socket != "" {
		sock = cfg.Socket
	}
	return path.Join(path.Dir(sock), "wg")
}

// statePaths lists every file or directory the daemon creates, writes or listens on. The
// rollback and history directories stand for everything beneath them. A disabled socket is not a path.
func statePaths(state string, cfg *Config) []string {
	tokens, mfa := tokensPath(state), mfaPath(state)
	out := []string{
		tokens, tokensTmpPath(tokens),
		mfa, mfaTmpPath(mfa),
		pendingPath(state), rollbackDir(state), historyDir(state), wgClientDir(cfg),
	}
	if cfg != nil {
		if cfg.AuditPath != "" {
			out = append(out, cfg.AuditPath, auditRotatedPath(cfg.AuditPath))
		}
		if cfg.Socket != "" {
			out = append(out, cfg.Socket)
		}
	}
	return out
}

// checkStatePaths refuses a layout in which any state path is web-served.
func checkStatePaths(state string, cfg *Config) error {
	for _, p := range statePaths(state, cfg) {
		if err := checkNotWebServed(p); err != nil {
			return err
		}
	}
	return nil
}

// builtinWebRoot is uhttpd's default document root. It is refused even when /etc/config/uhttpd
// says otherwise: moving the root does not make the old one safe to keep secrets in.
const builtinWebRoot = "/www"

// cgiDirName is the directory name uhttpd's default configuration executes scripts from.
const cgiDirName = "cgi-bin"

// webServed reads uhttpd's document roots and CGI prefixes through the sysRoot seam, so a test
// can supply its own /etc/config/uhttpd.
func webServed() (roots, cgiSegments []string) {
	roots = []string{builtinWebRoot}
	cgiSegments = []string{cgiDirName}
	body, err := readSys("/etc/config/uhttpd")
	if err != nil {
		return
	}
	for _, s := range parseUCI(bufio.NewScanner(strings.NewReader(body))) {
		if s.Type != "uhttpd" {
			continue
		}
		if h := s.Options["home"]; h != "" {
			roots = append(roots, h)
		}
		if c := strings.Trim(s.Options["cgi_prefix"], "/"); c != "" {
			cgiSegments = append(cgiSegments, path.Base(c))
		}
	}
	return
}

// checkNotWebServed returns an error when p lies inside a web root or beneath a CGI directory,
// either as written or after following symlinks. p need not exist yet: the longest existing
// ancestor is resolved and the missing tail is appended, which is what the OS will do when the
// daemon creates the file.
func checkNotWebServed(p string) error {
	if strings.TrimSpace(p) == "" {
		return nil
	}
	forms, err := pathForms(p)
	if err != nil {
		return fmt.Errorf("cannot check %q: %w", p, err)
	}
	roots, cgi := webServed()
	for _, root := range roots {
		rootForms, err := pathForms(root)
		if err != nil {
			continue
		}
		for _, r := range rootForms {
			for _, f := range forms {
				if f == r || strings.HasPrefix(f, strings.TrimSuffix(r, "/")+"/") {
					return fmt.Errorf("%s is inside the web root %s: refusing to keep state there", p, root)
				}
			}
		}
	}
	for _, f := range forms {
		for _, seg := range strings.Split(f, "/") {
			for _, c := range cgi {
				if seg == c {
					return fmt.Errorf("%s is inside a %s directory: refusing to keep state where uhttpd executes files", p, c)
				}
			}
		}
	}
	return nil
}

// pathForms returns p as written (cleaned) and p with symlinks resolved, both slash-separated,
// absolute and without a volume name. Both are checked: "/etc/../www" is caught by the first,
// a symlink into /www by the second.
func pathForms(p string) ([]string, error) {
	lex := path.Clean(filepath.ToSlash(p))
	if !strings.HasPrefix(lex, "/") && filepath.VolumeName(p) == "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		lex = path.Clean(filepath.ToSlash(abs))
	}
	resolved := resolveExisting(filepath.FromSlash(lex), 0)
	return []string{stripVolume(lex), stripVolume(resolved)}, nil
}

func stripVolume(p string) string {
	p = strings.TrimPrefix(p, filepath.VolumeName(p))
	return path.Clean("/" + strings.TrimPrefix(filepath.ToSlash(p), "/"))
}

// The file-system calls the resolver makes. Variables so that a test can stand in a virtual
// tree: creating a real symlink needs a privilege on Windows, and the resolver is too important
// to be exercised only where CI happens to run.
var (
	fsLstat        = os.Lstat
	fsReadlink     = os.Readlink
	fsEvalSymlinks = filepath.EvalSymlinks
)

// resolveExisting follows symlinks along the existing part of p. A dangling symlink is followed
// too: creating a file through one creates its target.
func resolveExisting(p string, depth int) string {
	if depth > 32 {
		return p
	}
	q, rest := p, ""
	for {
		if fi, err := fsLstat(q); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				if tgt, err := fsReadlink(q); err == nil {
					if !filepath.IsAbs(tgt) {
						tgt = filepath.Join(filepath.Dir(q), tgt)
					}
					return resolveExisting(filepath.Join(tgt, rest), depth+1)
				}
			}
			if r, err := fsEvalSymlinks(q); err == nil {
				return filepath.Join(r, rest)
			}
			return filepath.Join(q, rest)
		}
		parent := filepath.Dir(q)
		if parent == q {
			return filepath.Join(q, rest)
		}
		rest = filepath.Join(filepath.Base(q), rest)
		q = parent
	}
}
