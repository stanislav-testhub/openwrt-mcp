package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// OpenWrt 25.12 manages packages with apk, 24.10 and older with opkg. Everything the package
// tools say or run goes through the manager found on the router, so a tool never names a binary.
// What opkg cannot answer (policy, audit) is refused with a message that says so; it is never
// guessed at.
type pkgManager interface {
	name() string
	updateArgv() []string
	// queryArgv is the command for one pkg_query action. arg is the package, glob or path the
	// action needs; the caller has already checked it.
	queryArgv(action, arg string) ([]string, error)
	// compactList trims the output of the installed and upgradable lists.
	compactList(out string) string
	// world is what the operator asked to have installed.
	world() (string, error)
	// changeArgv is the command for add, del or upgrade; without commit it only simulates.
	changeArgv(action string, commit bool, pkgs []string) []string
	// verify reads back what an add or a del should have left behind.
	verify(ctx context.Context, action string, pkgs []string) (string, error)
	// newConfigSuffix marks the package's new default beside a config file the operator changed;
	// oldConfigSuffix is where use_new keeps the file it replaced.
	newConfigSuffix() string
	oldConfigSuffix() string
	// installedKernel is the version of the kernel package, to compare with the running one.
	installedKernel(ctx context.Context) (string, error)
	// audit lists files that differ from their package, as `apk audit` prints them.
	audit(ctx context.Context) (string, error)
}

// currentPkgManager is chosen from the binaries on the router. A router with neither (a test
// tree, or a build with no package manager) is treated as the current release.
func currentPkgManager() pkgManager {
	if anyExists("/usr/bin/apk", "/sbin/apk", "/bin/apk") {
		return apkManager{}
	}
	if anyExists("/bin/opkg", "/usr/bin/opkg") {
		return opkgManager{}
	}
	return apkManager{}
}

func anyExists(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(sysPath(p)); err == nil {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- apk (25.12)

type apkManager struct{}

func (apkManager) name() string         { return "apk" }
func (apkManager) updateArgv() []string { return []string{"apk", "update"} }

func (apkManager) queryArgv(action, arg string) ([]string, error) {
	switch action {
	case "installed":
		argv := []string{"apk", "list", "--installed"}
		if arg != "" {
			argv = append(argv, arg)
		}
		return argv, nil
	case "upgradable":
		return []string{"apk", "list", "--upgradable"}, nil
	case "search":
		return []string{"apk", "search", arg}, nil
	case "info":
		return []string{"apk", "info", "-a", arg}, nil
	case "files":
		return []string{"apk", "info", "-L", arg}, nil
	case "owner":
		return []string{"apk", "info", "--who-owns", arg}, nil
	case "policy":
		return []string{"apk", "policy", arg}, nil
	case "audit":
		// A: added, U: updated (differs from the package), X: missing. Config drift and
		// hand-patched binaries both show up here.
		return []string{"apk", "audit"}, nil
	}
	return nil, invalid("unknown action %q", action)
}

func (apkManager) compactList(out string) string { return compactApkList(out) }
func (apkManager) world() (string, error)        { return readSys(apkWorld) }

func (apkManager) changeArgv(action string, commit bool, pkgs []string) []string {
	argv := []string{"apk"}
	if !commit {
		argv = append(argv, "--simulate")
	}
	argv = append(argv, action)
	return append(argv, pkgs...)
}

func (apkManager) verify(_ context.Context, action string, pkgs []string) (string, error) {
	return verifyWorld(action, pkgs)
}

func (apkManager) newConfigSuffix() string { return ".apk-new" }
func (apkManager) oldConfigSuffix() string { return ".pre-apk-new" }

func (apkManager) installedKernel(ctx context.Context) (string, error) {
	out, err := run(ctx, defaultCmdTimeout, "apk", "list", "--installed", "kernel")
	if err != nil {
		return "", fmt.Errorf("apk list: %w", err)
	}
	m := reKernelPkg.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no installed kernel package found")
	}
	return m[1], nil
}

func (apkManager) audit(ctx context.Context) (string, error) {
	out, err := run(ctx, 2*time.Minute, "apk", "audit")
	if err != nil {
		return "", fmt.Errorf("apk audit: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------- opkg (24.10 and older)

type opkgManager struct{}

func (opkgManager) name() string         { return "opkg" }
func (opkgManager) updateArgv() []string { return []string{"opkg", "update"} }

func (opkgManager) queryArgv(action, arg string) ([]string, error) {
	switch action {
	case "installed":
		argv := []string{"opkg", "list-installed"}
		if arg != "" {
			argv = append(argv, arg)
		}
		return argv, nil
	case "upgradable":
		return []string{"opkg", "list-upgradable"}, nil
	case "search":
		// find matches a glob against the whole name or description, so a bare word finds only
		// the package of exactly that name. apk search takes a word anywhere in the name.
		if !strings.Contains(arg, "*") {
			arg = "*" + arg + "*"
		}
		return []string{"opkg", "find", arg}, nil
	case "info":
		return []string{"opkg", "info", arg}, nil
	case "files":
		return []string{"opkg", "files", arg}, nil
	case "owner":
		return []string{"opkg", "search", arg}, nil
	case "policy":
		return nil, invalid("policy needs apk; with opkg, search and info show the version the repositories offer")
	case "audit":
		return nil, invalid("audit needs apk; opkg cannot compare installed files with their packages")
	}
	return nil, invalid("unknown action %q", action)
}

// compactOpkgList turns opkg's "name - version" and "name - old - new" lines into the form
// compactApkList gives: name-version, and the version it would upgrade from.
func (opkgManager) compactList(out string) string {
	var b strings.Builder
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), " - ")
		if len(f) < 2 {
			continue
		}
		switch {
		case len(f) >= 3:
			b.WriteString(f[0] + "-" + f[2] + " [upgradable from: " + f[0] + "-" + f[1] + "]\n")
		default:
			b.WriteString(f[0] + "-" + f[1] + "\n")
		}
		n++
	}
	return fmt.Sprintf("%s(%d packages)", b.String(), n)
}

const opkgStatus = "/usr/lib/opkg/status"

// world lists the packages the operator installed. opkg flags the package of an explicit
// `opkg install` as "user" in its status file ("Status: install user installed"; several flags
// are joined with commas); the packages it pulls in as dependencies are "install ok installed".
func (opkgManager) world() (string, error) {
	body, err := readSys(opkgStatus)
	if err != nil {
		return "", err
	}
	names := userInstalled(body)
	if len(names) == 0 {
		return "(nothing)", nil
	}
	return strings.Join(names, "\n") + "\n", nil
}

// userInstalled picks the names of the user-flagged, installed packages out of a status file.
func userInstalled(body string) []string {
	var names []string
	for _, stanza := range strings.Split(body, "\n\n") {
		var pkg string
		user := false
		for _, l := range strings.Split(stanza, "\n") {
			if strings.HasPrefix(l, "Package: ") {
				pkg = strings.TrimSpace(strings.TrimPrefix(l, "Package: "))
			} else if st := strings.Fields(strings.TrimPrefix(l, "Status:")); strings.HasPrefix(l, "Status:") && len(st) == 3 {
				user = st[0] == "install" && st[2] == "installed" && contains(strings.Split(st[1], ","), "user")
			}
		}
		if user && pkg != "" {
			names = append(names, pkg)
		}
	}
	return names
}

var opkgVerbs = map[string]string{"add": "install", "del": "remove", "upgrade": "upgrade"}

// changeArgv simulates with --noaction: opkg still resolves dependencies and downloads the
// packages, but skips the maintainer scripts and leaves the files and the package database alone.
func (opkgManager) changeArgv(action string, commit bool, pkgs []string) []string {
	argv := []string{"opkg"}
	if !commit {
		argv = append(argv, "--noaction")
	}
	argv = append(argv, opkgVerbs[action])
	return append(argv, pkgs...)
}

// verify asks opkg what is installed. opkg keeps no list of what was asked for beyond a flag in
// its status file, so the installed list is the record to read back.
func (opkgManager) verify(ctx context.Context, action string, pkgs []string) (string, error) {
	if action != "add" && action != "del" {
		return "", nil
	}
	out, err := run(ctx, defaultCmdTimeout, "opkg", "list-installed")
	if err != nil {
		return fmt.Sprintf("Not verified: could not run opkg list-installed (%v).", err), nil
	}
	have := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			have[f[0]] = true
		}
	}
	var wrong []string
	for _, p := range pkgs {
		if have[p] != (action == "add") {
			wrong = append(wrong, p)
		}
	}
	if len(wrong) > 0 {
		if action == "add" {
			return "", notApplied("opkg install exited 0, but opkg list-installed does not list %s", strings.Join(wrong, ", "))
		}
		return "", notApplied("opkg remove exited 0, but opkg list-installed still lists %s", strings.Join(wrong, ", "))
	}
	if action == "add" {
		return fmt.Sprintf("Verified: opkg list-installed lists %s.", strings.Join(pkgs, ", ")), nil
	}
	return fmt.Sprintf("Verified: opkg list-installed no longer lists %s.", strings.Join(pkgs, ", ")), nil
}

func (opkgManager) newConfigSuffix() string { return "-opkg" }
func (opkgManager) oldConfigSuffix() string { return ".pre-opkg-new" }

var reKernelOpkg = regexp.MustCompile(`(?m)^kernel - ([0-9]+(?:\.[0-9]+)+)`)

func (opkgManager) installedKernel(ctx context.Context) (string, error) {
	out, err := run(ctx, defaultCmdTimeout, "opkg", "list-installed", "kernel")
	if err != nil {
		return "", fmt.Errorf("opkg list-installed: %w", err)
	}
	m := reKernelOpkg.FindStringSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("no installed kernel package found")
	}
	return m[1], nil
}

func (opkgManager) audit(context.Context) (string, error) {
	return "", errors.New("opkg has no audit command, so installed files are not compared with their packages")
}

// ---------------------------------------------------------------- firewall

// firewallBackend is "fw4" (nftables, 22.03 and later), "fw3" (iptables, 21.02 and older and
// firmware built on it) or "" when neither is installed.
func firewallBackend() string {
	switch {
	case anyExists("/sbin/fw4", "/usr/sbin/fw4"):
		return "fw4"
	case anyExists("/sbin/fw3", "/usr/sbin/fw3"):
		return "fw3"
	}
	return ""
}

// capabilityLine is what system_status says about the software the tools depend on.
func capabilityLine() string {
	fw := "none found"
	switch firewallBackend() {
	case "fw4":
		fw = "fw4 (nftables)"
	case "fw3":
		fw = "fw3 (iptables)"
	}
	return "packages: " + currentPkgManager().name() + "; firewall: " + fw
}
