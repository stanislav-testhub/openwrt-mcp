package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// OpenWrt 25.12 manages packages with apk-tools 3; 24.10 and older with opkg (pkgmanager.go
// picks the one on the router). What changed for an agent with apk:
//   - `apk list --installed|--upgradable`, `apk info -L`, `apk info --who-owns`, `apk policy`
//   - a modified config file is never overwritten on upgrade: the new default lands beside it
//     as <file>.apk-new (opkg: <file>-opkg) and waits for someone to merge it -- pkg_config_diff / _resolve.
//   - `apk audit` reports files changed since installation.

var (
	rePkgName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	rePkgPattern = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9._+*-]{0,127}$`)
)

// ---------------------------------------------------------------- pkg_query

type pkgQueryIn struct {
	Action  string `json:"action" jsonschema:"installed | upgradable | search | info | files | owner | policy | audit | world"`
	Package string `json:"package,omitempty" jsonschema:"package name (info/files/policy), search term (search), or glob (installed, e.g. 'luci-app-*')"`
	Path    string `json:"path,omitempty" jsonschema:"for owner: absolute file path, e.g. /usr/sbin/nft"`
	Refresh bool   `json:"refresh,omitempty" jsonschema:"update the package lists first so upgradable/search/policy see current repository indexes"`
	Offset  int    `json:"offset,omitempty" jsonschema:"first line to return (200 per page); a cut result names the next offset"`
}

func pkgQuery(ctx context.Context, in pkgQueryIn) (string, string, error) {
	needPkg := func(re *regexp.Regexp) error {
		if !re.MatchString(in.Package) {
			return fmt.Errorf("%s needs a valid package name", in.Action)
		}
		return nil
	}
	m := currentPkgManager()
	pre := ""
	if in.Refresh {
		out, err := run(ctx, 2*time.Minute, m.updateArgv()...)
		if err != nil {
			return out, "", fmt.Errorf("%s update: %w", m.name(), err)
		}
		pre = lastLine(out) + "\n\n"
	}
	arg := ""
	compact := false
	switch in.Action {
	case "installed":
		if in.Package != "" {
			if err := needPkg(rePkgPattern); err != nil {
				return "", "", err
			}
			arg = in.Package
		}
		compact = true
	case "upgradable":
		compact = true
	case "search":
		if err := needPkg(rePkgPattern); err != nil {
			return "", "", err
		}
		arg = in.Package
	case "info", "files", "policy":
		if err := needPkg(rePkgName); err != nil {
			return "", "", err
		}
		arg = in.Package
	case "owner":
		p := path.Clean(in.Path)
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "/-") {
			return "", "", fmt.Errorf("owner needs an absolute path")
		}
		arg = p
	case "audit":
	case "world":
		w, err := m.world()
		return pre + w, "read world", err
	default:
		return "", "", invalid("unknown action %q", in.Action)
	}
	argv, err := m.queryArgv(in.Action, arg)
	if err != nil {
		return "", "", err
	}
	out, err := run(ctx, time.Minute, argv...)
	if compact {
		out = m.compactList(out)
	}
	if strings.TrimSpace(out) == "" && err == nil {
		out = "(nothing)"
	}
	return pre + pagePkgOutput(out, compact, in.Offset), strings.Join(argv, " "), err
}

// pagePkgOutput returns one page of a long result. A compacted list ends with its "(N packages)"
// total, which is kept on every page, so the size of the whole is never hidden by the cut.
func pagePkgOutput(out string, compact bool, offset int) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	trailer := ""
	if compact && len(lines) > 0 {
		trailer, lines = lines[len(lines)-1], lines[:len(lines)-1]
	}
	page, notice := pageLines(lines, offset, pkgPageLines, "lines")
	res := strings.Join(page, "\n")
	for _, extra := range []string{trailer, notice} {
		if extra == "" {
			continue
		}
		if res != "" {
			res += "\n"
		}
		res += extra
	}
	return res
}

// compactApkList trims `apk list` lines to what an agent needs -- name-version and state --
// dropping the arch, origin and licence that make 400 installed packages cost 50 KB.
//
//	luci-26.270.72870~a24d1f2 noarch {feeds/luci/...} (Apache-2.0) [upgradable from: luci-26.268...]
//	-> luci-26.270.72870~a24d1f2 [upgradable from: luci-26.268...]
func compactApkList(out string) string {
	var b strings.Builder
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		state := ""
		if i := strings.LastIndex(line, "["); i >= 0 && strings.HasSuffix(line, "]") {
			state = " " + line[i:]
			if state == " [installed]" {
				state = ""
			}
		}
		b.WriteString(f[0] + state + "\n")
		n++
	}
	return fmt.Sprintf("%s(%d packages)", b.String(), n)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// ---------------------------------------------------------------- pkg_change

type pkgChangeIn struct {
	Action   string   `json:"action" jsonschema:"add | del | upgrade"`
	Packages []string `json:"packages,omitempty" jsonschema:"package names. For upgrade, omit to upgrade everything (discouraged on OpenWrt)."`
	Commit   bool     `json:"commit,omitempty" jsonschema:"false (default): simulate and show the plan, change nothing. true: actually do it."`
}

// pkgChangeScope: one scope per package ("add.tcpdump"), or the bare "upgrade" for a full
// upgrade -- deliberately not "upgrade.*", which a policy granting individual upgrades by
// glob would otherwise match.
func pkgChangeScope(in pkgChangeIn) []string {
	if len(in.Packages) == 0 {
		return []string{in.Action}
	}
	out := make([]string, len(in.Packages))
	for i, p := range in.Packages {
		out[i] = in.Action + "." + p
	}
	return out
}

func pkgChange(ctx context.Context, in pkgChangeIn) (string, string, error) {
	switch in.Action {
	case "add", "del":
		if len(in.Packages) == 0 {
			return "", "", fmt.Errorf("%s needs at least one package", in.Action)
		}
	case "upgrade":
	default:
		return "", "", invalid("action must be add, del or upgrade")
	}
	for _, p := range in.Packages {
		if !rePkgName.MatchString(p) {
			return "", "", invalid("bad package name %q", p)
		}
	}
	m := currentPkgManager()
	var pre strings.Builder
	if in.Action != "del" {
		if out, err := run(ctx, 2*time.Minute, m.updateArgv()...); err != nil {
			return out, "", fmt.Errorf("%s update: %w", m.name(), err)
		}
	}
	targets := in.Packages
	if in.Action == "upgrade" && len(targets) == 0 && m.name() == "opkg" {
		// opkg upgrade takes package names and has no upgrade-everything form.
		out, err := run(ctx, defaultCmdTimeout, "opkg", "list-upgradable")
		if err != nil {
			return out, "", fmt.Errorf("opkg list-upgradable: %w", err)
		}
		for _, line := range strings.Split(out, "\n") {
			if f := strings.Fields(line); len(f) > 0 {
				targets = append(targets, f[0])
			}
		}
		if len(targets) == 0 {
			if !in.Commit {
				return "SIMULATION -- nothing changed. opkg would:\nupgrade nothing: no package has a newer version.", "opkg list-upgradable", nil
			}
			return "Nothing to upgrade.", "opkg list-upgradable", nil
		}
	}
	argv := m.changeArgv(in.Action, in.Commit, targets)
	summary := strings.Join(argv, " ")

	if !in.Commit {
		out, err := run(ctx, 2*time.Minute, argv...)
		if err != nil {
			return out, summary, fmt.Errorf("simulation failed: %w", err)
		}
		note := ""
		if in.Action == "upgrade" && len(in.Packages) == 0 {
			note = "\nNote: upgrading everything in place is discouraged on OpenWrt (kernel modules and " +
				"base-files can end up out of step with the kernel); a sysupgrade/owut image is the supported path."
		}
		return fmt.Sprintf("SIMULATION -- nothing changed. %s would:\n%s%s\n\nCall again with commit=true to do it.",
			m.name(), strings.TrimSpace(out), note), summary, nil
	}

	before := findNewConfigs()
	out, err := run(ctx, 5*time.Minute, argv...)
	pre.WriteString(strings.TrimSpace(out))
	if err != nil {
		return pre.String(), summary, fmt.Errorf("%s %s failed: %w", m.name(), in.Action, err)
	}
	var fresh []string
	for _, f := range findNewConfigs() {
		if !contains(before, f) {
			fresh = append(fresh, f)
		}
	}
	if len(fresh) > 0 {
		fmt.Fprintf(&pre, "\n\nNew config defaults were NOT applied because you have local changes; "+
			"review with pkg_config_diff:\n  %s", strings.Join(fresh, "\n  "))
	}
	// An upgrade changes versions, not what the operator asked to have installed, so only add
	// and del have a record to read back.
	verified, err := m.verify(ctx, in.Action, in.Packages)
	if err != nil {
		return pre.String(), summary, err
	}
	if verified != "" {
		pre.WriteString("\n\n" + verified)
	}
	return pre.String(), summary, nil
}

// ---------------------------------------------------------------- new package defaults (.apk-new, -opkg)

func findNewConfigs() []string {
	var out []string
	root := sysPath("/etc")
	suffix := currentPkgManager().newConfigSuffix()
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			rel, _ := filepath.Rel(root, p)
			out = append(out, "/etc/"+filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(out)
	return out
}

type pkgConfigDiffIn struct {
	Path    string `json:"path,omitempty" jsonschema:"one file to show in full, e.g. /etc/config/dhcp (the .apk-new / -opkg suffix is optional). Omit for all."`
	Context int    `json:"context,omitempty" jsonschema:"lines of context around each change (default 2)"`
}

func pkgConfigDiff(ctx context.Context, in pkgConfigDiffIn) (string, string, error) {
	suffix := currentPkgManager().newConfigSuffix()
	files := findNewConfigs()
	if in.Path != "" {
		want := strings.TrimSuffix(path.Clean(in.Path), suffix) + suffix
		if !contains(files, want) {
			return "", "", fmt.Errorf("no %s", want)
		}
		files = []string{want}
	}
	if len(files) == 0 {
		return "No " + suffix + " files: every package config is as installed or already merged.", "none", nil
	}
	ctxLines := clampInt(in.Context, 2, 0, 10)
	perFile := 120
	if in.Path != "" {
		perFile = 2000
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d %s file(s). Each is a package's NEW default that was not applied because the live file differs.\n", len(files), suffix)
	for _, f := range files {
		live := strings.TrimSuffix(f, suffix)
		newB, _ := readSys(f)
		liveB, err := readSys(live)
		b.WriteString("\n=== " + live + "\n")
		if err != nil {
			b.WriteString("live file is missing; the " + suffix + " would be installed as-is\n")
			continue
		}
		if liveB == newB {
			b.WriteString("identical -- the " + suffix + " can simply be removed (keep_current)\n")
			continue
		}
		a, bb, how := strings.Split(liveB, "\n"), strings.Split(newB, "\n"), "line diff"
		// A UCI file the router has rewritten (quotes, tabs) differs line by line from the
		// package's hand-written default even when every setting agrees. Compare what uci
		// reads instead, so the diff shows settings, not formatting.
		if dir, name := path.Split(live); dir == "/etc/config/" {
			la, errA := uciNormalised(ctx, name, liveB)
			lb, errB := uciNormalised(ctx, name, newB)
			if errA == nil && errB == nil {
				a, bb, how = la, lb, "settings diff via uci show, formatting ignored"
			}
		}
		d := unifiedDiff(a, bb, ctxLines)
		if d == "" {
			b.WriteString("same settings, only formatting differs -- keep_current is safe\n")
			continue
		}
		lines := strings.Split(d, "\n")
		if len(lines) > perFile {
			d = strings.Join(lines[:perFile], "\n") + fmt.Sprintf("\n... %d more diff lines (ask for this path alone)", len(lines)-perFile)
		}
		fmt.Fprintf(&b, "--- live  +++ package default  (%s)\n%s\n", how, d)
	}
	b.WriteString("\nResolve with pkg_config_resolve: keep_current drops the new default; use_new replaces " +
		"the live file (for /etc/config/* with a rollback timer, like uci_apply).")
	return b.String(), fmt.Sprintf("%d file(s)", len(files)), nil
}

// uciNormalised renders config text through `uci show` from a private copy: its own config
// dir (-c) and its own empty delta dir (-t), so neither the live file nor anybody's staged
// changes in /tmp/.uci leak into the result.
func uciNormalised(ctx context.Context, name, body string) ([]string, error) {
	dir, err := os.MkdirTemp("", "openwrt-mcp-diff-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	conf, save := filepath.Join(dir, "conf"), filepath.Join(dir, "save")
	if err := os.MkdirAll(conf, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(save, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(conf, name), []byte(body), 0o600); err != nil {
		return nil, err
	}
	out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "-c", filepath.ToSlash(conf), "-t", filepath.ToSlash(save), "show", name)
	if err != nil {
		return nil, fmt.Errorf("uci cannot parse it: %w", err)
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

type pkgConfigResolveIn struct {
	Path    string `json:"path" jsonschema:"the live file, e.g. /etc/config/dhcp (or its .apk-new / -opkg name)"`
	Action  string `json:"action" jsonschema:"keep_current: delete the new default | use_new: replace the live file with it (the old one is kept as <file>.pre-apk-new, opkg: .pre-opkg-new)"`
	Timeout int    `json:"timeout,omitempty" jsonschema:"use_new on /etc/config/*: seconds before automatic rollback (default 90, max 600)"`
}

func pkgResolveScope(in pkgConfigResolveIn) []string {
	return []string{strings.TrimSuffix(path.Clean(in.Path), currentPkgManager().newConfigSuffix())}
}

func (s *Server) pkgConfigResolve(ctx context.Context, client string, in pkgConfigResolveIn) (string, string, error) {
	m := currentPkgManager()
	live := strings.TrimSuffix(path.Clean(in.Path), m.newConfigSuffix())
	newF := live + m.newConfigSuffix()
	oldF := live + m.oldConfigSuffix()
	if !strings.HasPrefix(live, "/etc/") || !contains(findNewConfigs(), newF) {
		return "", "", fmt.Errorf("no %s", newF)
	}
	if in.Action == "use_new" && s.isPolicyFile(live) {
		return "", "", errPolicyFile
	}
	switch in.Action {
	case "keep_current":
		if err := os.Remove(sysPath(newF)); err != nil {
			return "", "", err
		}
		return fmt.Sprintf("Kept %s; removed %s.", live, newF), "kept " + live, nil
	case "use_new":
	default:
		return "", "", invalid("action must be keep_current or use_new")
	}

	newB, err := os.ReadFile(sysPath(newF))
	if err != nil {
		return "", "", err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(sysPath(live)); err == nil {
		mode = st.Mode().Perm()
		old, _ := os.ReadFile(sysPath(live))
		if err := writeSynced(sysPath(oldF), old, mode); err != nil {
			return "", "", fmt.Errorf("backing up %s: %w", live, err)
		}
	}

	// A UCI config goes through the same snapshot/rollback path as uci_apply: the new default
	// may well drop an interface or a firewall zone the router depends on.
	if dir, name := path.Split(live); dir == "/etc/config/" {
		s.applyMu.Lock()
		defer s.applyMu.Unlock()
		if p := s.pendingSummary(); p != "" {
			return "", "", pending("an apply is already pending confirmation: %s", p)
		}
		timeout := clampSec(in.Timeout, 90, 600)
		p, err := s.snapshot([]string{name}, client, "replacing "+live+" with the package default", timeout)
		if err != nil {
			return "", "", err
		}
		s.arm(p, timeout)
		if err := writeSynced(sysPath(newF)+".tmp", newB, mode); err == nil {
			err = os.Rename(sysPath(newF)+".tmp", sysPath(live))
			if err == nil {
				_ = os.Remove(sysPath(newF))
			}
		}
		if err != nil {
			if s.take(p.Token) != nil {
				_ = s.restore(ctx, p, false)
				s.savePending()
			}
			return "", "", err
		}
		out := reloadConfigs(ctx, []string{name}, false)
		return fmt.Sprintf("Replaced %s with the package default (old copy: %s) and reloaded.\n\n"+
			"ROLLBACK ARMED: reverts at %s unless you call uci_confirm {\"token\": %q}.%s",
			live, oldF, p.Deadline.Format(time.RFC3339), p.Token, indentOut(out)), "use_new " + live, nil
	}

	if err := writeSynced(sysPath(live), newB, mode); err != nil {
		return "", "", err
	}
	_ = os.Remove(sysPath(newF))
	return fmt.Sprintf("Replaced %s with the package default (old copy: %s). "+
		"Restart the owning service for it to take effect.", live, oldF), "use_new " + live, nil
}

// ---------------------------------------------------------------- unified diff

// unifiedDiff renders a line diff with n lines of context. Config files are small, so a
// plain LCS table is fine; a pathological pair is reported rather than computed.
func unifiedDiff(a, b []string, n int) string {
	if len(a)*len(b) > 4_000_000 {
		return fmt.Sprintf("(files too large to diff here: %d and %d lines)", len(a), len(b))
	}
	// lcs[i][j] = LCS length of a[i:], b[j:]
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		text string
		ai   int
	}
	var ops []op
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i})
			i++
			j++
		// Deletions before insertions, as a unified diff reads.
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', a[i], i})
			i++
		default:
			ops = append(ops, op{'+', b[j], i})
			j++
		}
	}
	show := make([]bool, len(ops))
	for k, o := range ops {
		if o.kind == ' ' {
			continue
		}
		for x := k - n; x <= k+n; x++ {
			if x >= 0 && x < len(ops) {
				show[x] = true
			}
		}
	}
	var out strings.Builder
	for k := range ops {
		if !show[k] {
			continue
		}
		if k == 0 || !show[k-1] {
			fmt.Fprintf(&out, "@@ line %d @@\n", ops[k].ai+1)
		}
		fmt.Fprintf(&out, "%c%s\n", ops[k].kind, ops[k].text)
	}
	return strings.TrimRight(out.String(), "\n")
}
