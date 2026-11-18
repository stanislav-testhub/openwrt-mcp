package main

import (
	"context"
	"fmt"
	"strings"
)

// upgradePlan turns the output of a simulated upgrade into what an operator wants to know before
// committing (ROADMAP 6.4, within a release): which versions move, whether a reboot is needed,
// which init scripts the packages ship, which /etc files a package owns, and which of its files
// were changed or replaced locally. It only reads: package file lists and `apk audit`.

type pkgUpgrade struct{ name, from, to string }

var (
	// apk: "(3/12) Upgrading busybox (1.37.0-r1 -> 1.37.0-r2)"
	reApkUpgrade = lazyRegexp(`(?m)Upgrading (\S+) \(([^ )]+) -> ([^ )]+)\)`)
	// opkg: "Upgrading busybox from 1.36.1-r1 to 1.37.0-r1 on root."
	reOpkgUpgrade = lazyRegexp(`(?m)Upgrading (\S+) from (\S+) to (\S+?)(?: on \S+)?\.?$`)
)

func parseUpgrades(out string) []pkgUpgrade {
	var ups []pkgUpgrade
	for _, re := range []*lazyRE{reApkUpgrade, reOpkgUpgrade} {
		for _, m := range re.FindAllStringSubmatch(out, -1) {
			ups = append(ups, pkgUpgrade{m[1], m[2], m[3]})
		}
	}
	return ups
}

// needsReboot: the kernel and its modules only change what runs after a restart.
func needsReboot(name string) bool {
	return name == "kernel" || strings.HasPrefix(name, "kmod-")
}

// planFiles pulls the file paths out of `apk info -L` / `opkg files` output, each as an absolute path.
func planFiles(out string) []string {
	var files []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasSuffix(l, ":") || strings.Contains(l, " contains") || strings.HasPrefix(l, "Package ") {
			continue
		}
		files = append(files, "/"+strings.TrimPrefix(l, "/"))
	}
	return files
}

const upgradePlanMaxPkgs = 25

func upgradePlan(ctx context.Context, m pkgManager, simOut string) string {
	ups := parseUpgrades(simOut)
	if len(ups) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Upgrade plan: %d package(s) change version.\n", len(ups))
	var reboot, scripts, conf, local []string

	drift := map[string]string{} // absolute path -> apk audit flag
	driftKnown := false
	if out, err := m.audit(ctx); err == nil {
		driftKnown = true
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Fields(l); len(f) == 2 {
				drift["/"+strings.TrimPrefix(f[1], "/")] = f[0]
			}
		}
	}
	for i, u := range ups {
		fmt.Fprintf(&b, "  %s: %s -> %s\n", u.name, u.from, u.to)
		if needsReboot(u.name) {
			reboot = append(reboot, u.name)
		}
		if i >= upgradePlanMaxPkgs {
			continue
		}
		argv, err := m.queryArgv("files", u.name)
		if err != nil {
			continue
		}
		out, err := run(ctx, defaultCmdTimeout, argv...)
		if err != nil {
			continue
		}
		for _, f := range planFiles(out) {
			switch {
			case strings.HasPrefix(f, "/etc/init.d/"):
				scripts = append(scripts, strings.TrimPrefix(f, "/etc/init.d/")+" ("+u.name+")")
			case strings.HasPrefix(f, "/etc/"):
				conf = append(conf, f)
				if _, ok := drift[f]; ok {
					local = append(local, f+" (kept: the new default lands beside it)")
				}
			default:
				if flag, ok := drift[f]; ok && flag != "A" {
					local = append(local, f+" (changed or replaced locally; the upgrade will overwrite it)")
				}
			}
		}
	}
	if len(ups) > upgradePlanMaxPkgs {
		fmt.Fprintf(&b, "File checks cover the first %d packages only.\n", upgradePlanMaxPkgs)
	}
	if len(reboot) > 0 {
		fmt.Fprintf(&b, "Reboot needed: the kernel or kernel modules change (%s). Mixing a new module with the running kernel is the usual way an in-place upgrade breaks a router.\n", strings.Join(reboot, ", "))
	} else {
		b.WriteString("No kernel or kernel module changes: no reboot needed.\n")
	}
	if len(scripts) > 0 {
		fmt.Fprintf(&b, "Init scripts shipped (a package's post-upgrade step may restart a running service): %s\n", strings.Join(scripts, ", "))
	}
	if len(conf) > 0 {
		fmt.Fprintf(&b, "Files under /etc owned by these packages: %d. Ones you changed are kept; check pkg_config_diff after.\n", len(conf))
	}
	if len(local) > 0 {
		b.WriteString("Locally changed files:\n  " + strings.Join(local, "\n  ") + "\n")
	} else if driftKnown {
		b.WriteString("No locally changed file belongs to these packages.\n")
	} else {
		b.WriteString("Local changes were not checked: this package manager cannot compare installed files with their packages.\n")
	}
	return b.String()
}
