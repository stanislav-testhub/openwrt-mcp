package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

// managed_file (ROADMAP 6.5): the files outside UCI that operators otherwise reach through exec,
// which is a root shell. Typed kinds only; there is no generic path argument at all, so there is
// nothing to traverse. Each kind names its one file (dnsmasq: one name inside one directory), a
// validator that runs before anything is written, and the service to reload afterwards.
//
//	crontab         /etc/crontabs/root      cron format, then cron restarts
//	dnsmasq         /etc/dnsmasq.d/<name>   dnsmasq --test, no script hooks, then dnsmasq restarts
//	hosts           /etc/hosts              "ip name [alias...]", then dnsmasq reloads
//	sysupgrade_conf /etc/sysupgrade.conf    one absolute path per line
//
// A write replaces the file atomically (temp file in the same directory, fsync, rename) with the
// old mode and owner, and keeps the version it replaced as history (the newest history_keep, as
// for UCI configs), so action=restore can put one back. The deny floor is structural: no kind
// maps to /etc/shadow, a key, or the policy, and a symlink at the target is refused rather than
// followed.
//
// The generic kind `path` is the exception that needs more care, and is off until the owner lists
// globs (`list managed_path '/etc/foo/*'` in config server). A path must be absolute and already
// clean (no `..`, no `//`, no trailing slash), match one glob (`*` never crosses a `/`), avoid the
// deny floor (the policy, rpcd, the SSH keys, shadow and passwd, private keys), have no symlink
// among its directories, and be a plain file or not exist yet in a directory that does. It has no
// validator beyond "UTF-8 text, no NUL" and no reload; use a typed kind when there is one.

type managedFileIn struct {
	Action  string `json:"action" jsonschema:"list | read | write | history | diff | restore"`
	Kind    string `json:"kind,omitempty" jsonschema:"crontab | dnsmasq | hosts | sysupgrade_conf | path"`
	Name    string `json:"name,omitempty" jsonschema:"dnsmasq: x.conf"`
	Path    string `json:"path,omitempty" jsonschema:"kind path: absolute file, owner-listed"`
	Content string `json:"content,omitempty" jsonschema:"whole new file"`
	ID      string `json:"id,omitempty" jsonschema:"version from history"`
	DryRun  bool   `json:"dry_run,omitempty" jsonschema:"validate, show diff only"`
}

type fileKind struct {
	name     string
	dir      string // directory of the file
	file     string // fixed file name; empty when the caller names it
	mode     os.FileMode
	validate func(ctx context.Context, name, content string) error
	reload   []string // argv run after a write; empty for none
	hist     string   // history key when the file name is not enough (kind path)
}

const maxManagedBytes = 256 << 10

var reDnsmasqFile = lazyRegexp(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,60}\.conf$`)

var fileKinds = map[string]*fileKind{
	"crontab": {name: "crontab", dir: "/etc/crontabs", file: "root", mode: 0o600,
		validate: validateCrontab, reload: []string{"/etc/init.d/cron", "restart"}},
	"dnsmasq": {name: "dnsmasq", dir: "/etc/dnsmasq.d", mode: 0o644,
		validate: validateDnsmasq, reload: []string{"/etc/init.d/dnsmasq", "restart"}},
	"hosts": {name: "hosts", dir: "/etc", file: "hosts", mode: 0o644,
		validate: validateHosts, reload: []string{"/etc/init.d/dnsmasq", "reload"}},
	"sysupgrade_conf": {name: "sysupgrade_conf", dir: "/etc", file: "sysupgrade.conf", mode: 0o644,
		validate: validateSysupgradeConf},
}

var fileKindNames = []string{"crontab", "dnsmasq", "hosts", "sysupgrade_conf"}

func (in managedFileIn) kind() (*fileKind, error) {
	if in.Kind == "path" {
		if in.Name != "" {
			return nil, invalid("kind path takes path, not name")
		}
		p, err := canonManagedPath(in.Path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(p))
		return &fileKind{name: "path", dir: path.Dir(p), file: path.Base(p), mode: 0o644, validate: validateText,
			hist: "file_path_" + hex.EncodeToString(sum[:4])}, nil
	}
	if in.Path != "" {
		return nil, invalid("path belongs to kind path")
	}
	k := fileKinds[in.Kind]
	if k == nil {
		return nil, invalid("kind must be one of %s or path", strings.Join(fileKindNames, ", "))
	}
	switch {
	case k.file != "" && in.Name != "":
		return nil, invalid("%s is one fixed file: leave name out", k.name)
	case k.file == "" && !reDnsmasqFile.MatchString(in.Name):
		return nil, invalid("dnsmasq needs name like blocklist.conf (letters, digits, _ - . and the .conf ending)")
	}
	return k, nil
}

// target is the file's absolute path. The name grammar has no separator and no leading dot, so
// the result is always directly inside k.dir.
func (k *fileKind) target(name string) string {
	if k.file != "" {
		return path.Join(k.dir, k.file)
	}
	return path.Join(k.dir, name)
}

// historyKey names the file's history. It fits the history id grammar (config:stamp).
func (k *fileKind) historyKey(name string) string {
	if k.hist != "" {
		return k.hist
	}
	if k.file != "" {
		return "file_" + k.name
	}
	return "file_" + k.name + "_" + strings.ReplaceAll(name, ".", "_")
}

func (in managedFileIn) validate() error {
	switch in.Action {
	case "list":
		if in.Kind != "" || in.Name != "" || in.Path != "" || in.Content != "" || in.ID != "" {
			return invalid("list takes no other argument")
		}
		return nil
	case "read", "history":
		if in.Content != "" || in.ID != "" || in.DryRun {
			return invalid("%s takes kind (and name for dnsmasq) only", in.Action)
		}
	case "write":
		if in.ID != "" {
			return invalid("id belongs to diff and restore")
		}
		if in.Content == "" {
			return invalid("write needs content (the whole new file)")
		}
		if len(in.Content) > maxManagedBytes {
			return invalid("content is %d bytes; the limit is %d", len(in.Content), maxManagedBytes)
		}
	case "diff", "restore":
		if in.Content != "" {
			return invalid("content belongs to write")
		}
		if in.ID == "" {
			return invalid("%s needs id, from action=history", in.Action)
		}
	default:
		return invalid("action must be list, read, write, history, diff or restore")
	}
	_, err := in.kind()
	return err
}

// managedFileScope is "<kind>.<action>", so a grant can say crontab.read or dnsmasq.* and keep
// write apart from read.
func managedFileScope(in managedFileIn) []string {
	kind := in.Kind
	if kind == "" {
		kind = "*"
	}
	return []string{kind + "." + in.Action}
}

// ---------------------------------------------------------------- reading the live file

// liveFile returns the current content and mode. A missing file is empty content with the
// kind's default mode; anything that is not a plain file (a symlink, a directory) is refused.
func (k *fileKind) liveFile(name string) (body string, mode os.FileMode, exists bool, err error) {
	if k.name == "path" {
		if err := noSymlinkDirs(k.dir); err != nil {
			return "", 0, false, err
		}
	}
	p := sysPath(k.target(name))
	fi, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return "", k.mode, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, false, invalid("%s is not a plain file (a symlink or directory): refusing to follow it", k.target(name))
	}
	if k.name == "path" && fi.Size() > maxManagedBytes {
		return "", 0, false, invalid("%s is %d bytes; managed_file handles files up to %d", k.target(name), fi.Size(), maxManagedBytes)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", 0, false, err
	}
	return string(b), fi.Mode().Perm(), true, nil
}

// ---------------------------------------------------------------- kind path

// canonManagedPath accepts only a path that is already in its one canonical form, so what is
// matched against the owner's globs is exactly what is opened. It does not look at the disk.
func canonManagedPath(p string) (string, error) {
	switch {
	case p == "":
		return "", invalid("kind path needs path")
	case !strings.HasPrefix(p, "/") || len(p) > 255 || p == "/":
		return "", invalid("path must be absolute, at most 255 bytes, and name a file")
	case strings.ContainsAny(p, "\x00\\") || strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		return "", invalid("path has a control character or a backslash")
	case path.Clean(p) != p:
		return "", invalid("path must be clean: no .., //, ./ or trailing slash")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", invalid("path must not contain ..")
		}
	}
	if why := managedPathFloor(p); why != "" {
		return "", withCode(codePolicyDenied, fmt.Errorf("denied by the deny floor: %s. No grant or managed_path glob lifts this.", why))
	}
	return p, nil
}

// managedFloorNames are file names managed_file never touches under any glob, on top of the
// directories in floorPaths.
var managedFloorNames = []string{"shadow", "passwd", "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "id_dropbear", "dropbear_rsa_host_key", "dropbear_ed25519_host_key"}

// managedFloorSuffixes mark private keys and certificates' keys by extension.
var managedFloorSuffixes = []string{".key", ".pem", ".p12", ".pfx"}

func managedPathFloor(p string) string {
	lower := strings.ToLower(p)
	clean := strings.TrimPrefix(lower, "/")
	for _, f := range floorPaths {
		if clean == f || strings.HasPrefix(clean, f+"/") || strings.HasPrefix(clean, f+".") || strings.Contains(clean, "/"+f) {
			return fmt.Sprintf("%s is part of the policy, the approval path or the daemon", p)
		}
	}
	base := path.Base(lower)
	for _, n := range managedFloorNames {
		if base == n || strings.HasPrefix(base, n+"-") || strings.HasPrefix(base, n+".") {
			return fmt.Sprintf("%s holds credentials", p)
		}
	}
	for _, sfx := range managedFloorSuffixes {
		if strings.HasSuffix(base, sfx) {
			return fmt.Sprintf("%s looks like a private key", p)
		}
	}
	if strings.Contains(lower, "/.ssh/") {
		return fmt.Sprintf("%s is under an .ssh directory", p)
	}
	return ""
}

// noSymlinkDirs walks the directory path component by component and refuses a symlink or a
// non-directory anywhere on it. The directory must already exist: kind path never creates one.
func noSymlinkDirs(dir string) error {
	cur := "/"
	for _, seg := range strings.Split(strings.TrimPrefix(dir, "/"), "/") {
		if seg == "" {
			continue
		}
		cur = path.Join(cur, seg)
		fi, err := os.Lstat(sysPath(cur))
		if os.IsNotExist(err) {
			return notFound("directory %s does not exist: kind path never creates one", cur)
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return invalid("%s is a symlink or not a directory: refusing to follow it", cur)
		}
	}
	return nil
}

// managedPathAllowed is the owner's list: a path is in only when it matches one glob.
func managedPathAllowed(globs []string, p string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, p); err == nil && ok {
			return true
		}
	}
	return false
}

func validateText(_ context.Context, _, content string) error {
	if !utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return invalid("content must be UTF-8 text without NUL bytes")
	}
	return nil
}

// ---------------------------------------------------------------- validators

var (
	reCronField = lazyRegexp(`^[A-Za-z0-9*/,-]+$`)
	reCronEnv   = lazyRegexp(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

func validateCrontab(_ context.Context, _, content string) error {
	for i, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || reCronEnv.MatchString(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 6 {
			return invalid("crontab line %d: want 5 time fields and a command, got %q", i+1, l)
		}
		for _, t := range f[:5] {
			if !reCronField.MatchString(t) {
				return invalid("crontab line %d: bad time field %q", i+1, t)
			}
		}
	}
	return nil
}

// Directives that run a program or pull in more configuration than the file shows.
var dnsmasqForbidden = map[string]bool{
	"dhcp-script": true, "dhcp-luascript": true, "conf-script": true,
	"conf-file": true, "conf-dir": true, "servers-file": true,
}

func validateDnsmasq(ctx context.Context, _, content string) error {
	for i, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		key, _, _ := strings.Cut(l, "=")
		if dnsmasqForbidden[strings.TrimSpace(key)] {
			return invalid("dnsmasq line %d: %s is not allowed here (it runs a program or includes other files)", i+1, strings.TrimSpace(key))
		}
	}
	if _, err := os.Stat(sysPath("/usr/sbin/dnsmasq")); err != nil && sysRoot == "/" {
		return nil // no binary to ask (a build without dnsmasq): the checks above are all there is
	}
	tmp, err := os.CreateTemp("", "mcp-dnsmasq-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	out, err := run(ctx, defaultCmdTimeout, "dnsmasq", "--test", "--conf-file="+tmp.Name())
	if err != nil {
		return invalid("dnsmasq --test: %s", strings.TrimSpace(strings.ReplaceAll(out, tmp.Name(), "<file>")))
	}
	return nil
}

func validateHosts(_ context.Context, _, content string) error {
	for i, l := range strings.Split(content, "\n") {
		if h, _, ok := strings.Cut(l, "#"); ok {
			l = h
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if _, err := netip.ParseAddr(f[0]); err != nil {
			return invalid("hosts line %d: %q is not an IP address", i+1, f[0])
		}
		if len(f) < 2 {
			return invalid("hosts line %d: no host name after the address", i+1)
		}
	}
	return nil
}

func validateSysupgradeConf(_ context.Context, _, content string) error {
	for i, l := range strings.Split(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !strings.HasPrefix(l, "/") {
			return invalid("sysupgrade.conf line %d: %q is not an absolute path", i+1, l)
		}
		if strings.Contains(l, "..") {
			return invalid("sysupgrade.conf line %d: no .. in a path", i+1)
		}
	}
	return nil
}

// ---------------------------------------------------------------- redaction

// A cron command or hosts comment can carry a token. Mask the value of anything named like a
// secret, in `name=value` and `--name value` shapes, the way the UCI masker does for options.
var reFileSecret = lazyRegexp(`(?i)([A-Za-z0-9_.-]*(?:pass|secret|token|psk|key)[A-Za-z0-9_.-]*)(=|\s+)([^\s'"]+|'[^']*'|"[^"]*")`)

func maskFileText(s string) string {
	return reFileSecret.ReplaceAllStringFunc(s, func(m string) string {
		sub := reFileSecret.FindStringSubmatch(m)
		if sub[3] == "" || sub[2] != "=" && !strings.HasPrefix(sub[1], "-") {
			return m
		}
		return sub[1] + sub[2] + redacted
	})
}

// ---------------------------------------------------------------- the tool

func (s *Server) managedFile(ctx context.Context, client string, in managedFileIn) (string, string, error) {
	if err := in.validate(); err != nil {
		return "", "", err
	}
	if in.Action == "list" {
		return s.managedFileList(), "listed managed files", nil
	}
	k, _ := in.kind()
	if in.Kind == "path" && !managedPathAllowed(s.cfg().ManagedPaths, k.target("")) {
		return "", "", withCode(codePolicyDenied, fmt.Errorf("%s is not in the owner's managed_path list (%s). The owner adds a glob with `list managed_path` in config server; the tool cannot.",
			k.target(""), orNone(s.cfg().ManagedPaths)))
	}
	switch in.Action {
	case "read":
		body, _, exists, err := k.liveFile(in.Name)
		if err != nil {
			return "", "", err
		}
		if !exists {
			return "", "", notFound("%s does not exist yet", k.target(in.Name))
		}
		return maskFileText(body), "read " + k.target(in.Name), nil
	case "history":
		return s.managedHistory(k, in.Name), "history of " + k.target(in.Name), nil
	case "diff":
		return s.managedDiff(k, in)
	case "write":
		return s.managedWrite(ctx, client, k, in, in.Content, "write")
	default: // restore
		key := k.historyKey(in.Name)
		cfg, _, err := parseHistoryID(in.ID)
		if err != nil {
			return "", "", err
		}
		if cfg != key {
			return "", "", invalid("%s is a version of %s, not of %s", in.ID, cfg, key)
		}
		_, body, err := s.loadHistory(in.ID)
		if err != nil {
			return "", "", err
		}
		return s.managedWrite(ctx, client, k, in, string(body), "restore "+in.ID)
	}
}

func (s *Server) managedFileList() string {
	var b strings.Builder
	b.WriteString("managed files (read, write, history, diff, restore by kind):\n")
	for _, n := range fileKindNames {
		k := fileKinds[n]
		switch {
		case k.file != "":
			state := "missing"
			if _, _, ok, err := k.liveFile(""); err != nil {
				state = "unreadable"
			} else if ok {
				state = "present"
			}
			fmt.Fprintf(&b, "  %-16s %s (%s)\n", k.name, k.target(""), state)
		default:
			var names []string
			if es, err := os.ReadDir(sysPath(k.dir)); err == nil {
				for _, e := range es {
					if reDnsmasqFile.MatchString(e.Name()) {
						names = append(names, e.Name())
					}
				}
			}
			fmt.Fprintf(&b, "  %-16s %s/<name>.conf  files: %s\n", k.name, k.dir, orNone(names))
		}
	}
	if g := s.cfg().ManagedPaths; len(g) == 0 {
		b.WriteString("  path             off: the owner has listed no managed_path glob\n")
	} else {
		fmt.Fprintf(&b, "  path             any file matching %s\n", strings.Join(g, " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, " ")
}

func (s *Server) managedHistory(k *fileKind, name string) string {
	key := k.historyKey(name)
	keep := s.cfg().HistoryKeep
	if keep <= 0 {
		return "history is off (history_keep is 0)."
	}
	es := s.historyEntries(key)
	if len(es) == 0 {
		return fmt.Sprintf("no earlier version of %s is recorded yet (the newest %d are kept).", k.target(name), keep)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "versions of %s from before each write, newest first (the newest %d are kept).\n"+
		"Compare one with action=diff id=<id>; put one back with action=restore id=<id>.\n", k.target(name), keep)
	for _, e := range es {
		fmt.Fprintf(&b, "  %s  %s  %s  %s\n", e.id(), e.Time, e.Client, e.What)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (s *Server) managedDiff(k *fileKind, in managedFileIn) (string, string, error) {
	cfg, _, err := parseHistoryID(in.ID)
	if err != nil {
		return "", "", err
	}
	if cfg != k.historyKey(in.Name) {
		return "", "", invalid("%s is a version of %s, not of %s", in.ID, cfg, k.historyKey(in.Name))
	}
	_, old, err := s.loadHistory(in.ID)
	if err != nil {
		return "", "", err
	}
	cur, _, _, err := k.liveFile(in.Name)
	if err != nil {
		return "", "", err
	}
	d := unifiedDiff(strings.Split(string(old), "\n"), strings.Split(cur, "\n"), 2)
	if d == "" {
		d = "(no difference)"
	}
	return fmt.Sprintf("--- %s (before that write)  +++ current\n%s", in.ID, maskFileText(d)), "diff of " + in.ID, nil
}

func (s *Server) managedWrite(ctx context.Context, client string, k *fileKind, in managedFileIn, content, what string) (string, string, error) {
	if len(content) > maxManagedBytes {
		return "", "", invalid("content is %d bytes; the limit is %d", len(content), maxManagedBytes)
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := k.validate(ctx, in.Name, content); err != nil {
		return "", "", err
	}
	old, mode, exists, err := k.liveFile(in.Name)
	if err != nil {
		return "", "", err
	}
	diff := unifiedDiff(strings.Split(old, "\n"), strings.Split(content, "\n"), 2)
	if diff == "" {
		return k.target(in.Name) + ": already has this content, nothing written.", "no change", nil
	}
	diff = maskFileText(diff)
	if in.DryRun {
		return fmt.Sprintf("dry run, %s validated and not written:\n%s", k.target(in.Name), diff), "managed_file dry run", nil
	}
	if exists {
		s.saveHistory(k.historyKey(in.Name), []byte(old), uint32(mode), client, what, fmt.Sprintf("%s%d", k.target(in.Name), time.Now().UnixNano()))
	}
	if err := writeManaged(sysPath(k.target(in.Name)), []byte(content), mode); err != nil {
		return "", "", fmt.Errorf("writing %s: %w", k.target(in.Name), err)
	}
	if got, _, _, err := k.liveFile(in.Name); err != nil || got != content {
		return "", "", notApplied("%s was written but a re-read does not show the new content; the earlier version is in history (action=history)", k.target(in.Name))
	}
	msg := fmt.Sprintf("wrote %s (%d bytes, mode %04o).\n%s", k.target(in.Name), len(content), mode, diff)
	if len(k.reload) > 0 {
		out, err := run(ctx, 30*time.Second, k.reload...)
		if err != nil {
			msg += fmt.Sprintf("\n\n%s failed: %v %s\nThe file is written; the earlier version is in history (action=history).",
				strings.Join(k.reload, " "), err, strings.TrimSpace(out))
		} else {
			msg += "\n\nran " + strings.Join(k.reload, " ") + "."
		}
	}
	if k.name == "dnsmasq" {
		if got, _ := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "dhcp.@dnsmasq[0].confdir"); strings.TrimSpace(got) != k.dir {
			msg += "\n\nNote: dnsmasq does not read " + k.dir + " until dhcp.@dnsmasq[0].confdir is " + k.dir + " (set it with uci_apply)."
		}
	}
	return msg, "managed_file " + what, nil
}

// writeManaged is replaceFile; tests swap in a backend that accepts a write and drops it.
var writeManaged = replaceFile

// replaceFile writes body next to path and renames it into place, so a reader sees the old
// file or the new one and never a half-written one. Mode and owner of the old file carry over.
func replaceFile(p string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".mcp-"+filepath.Base(p)+".tmp")
	if err := writeSynced(tmp, body, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	copyOwner(p, tmp)
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
