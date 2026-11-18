package main

import (
	"context"
	"sort"
	"strings"
	"time"
)

// sysupgradePlan is what an operator wants before a release upgrade (ROADMAP 6.4, across
// releases). It reads only: the packages the operator added on top of the firmware image, what
// owut says about the target release, and the changed /etc files a sysupgrade would not keep.
// Flashing stays manual.

// romWorld is the package selection of the firmware image itself: what a fresh flash already has.
func romWorld(m pkgManager) map[string]bool {
	set := map[string]bool{}
	switch m.name() {
	case "apk":
		if body, err := readSys("/rom" + apkWorld); err == nil {
			for _, p := range strings.Fields(body) {
				set[apkWorldName(p)] = true
			}
		}
	case "opkg":
		if body, err := readSys("/rom" + opkgStatus); err == nil {
			for _, p := range userInstalled(body) {
				set[p] = true
			}
		}
	}
	return set
}

// apkWorldName strips a version constraint ("pkg>=1.2", "pkg=1.2", "pkg~1.2") from a world entry.
func apkWorldName(e string) string {
	if i := strings.IndexAny(e, "<>=~"); i > 0 {
		return e[:i]
	}
	return e
}

// userPackages is the world minus the image's own selection. known is false when the image's
// selection could not be read, and then every world entry counts.
func userPackages(m pkgManager) (pkgs []string, known bool) {
	body, err := m.world()
	if err != nil {
		return nil, false
	}
	rom := romWorld(m)
	for _, p := range strings.Fields(body) {
		if p == "(nothing)" {
			continue
		}
		if n := apkWorldName(p); !rom[n] {
			pkgs = append(pkgs, n)
		}
	}
	sort.Strings(pkgs)
	return pkgs, len(rom) > 0
}

// atRisk are the changed or added files under /etc that the sysupgrade file list does not carry.
func atRisk(auditOut, keptList string) []string {
	kept := map[string]bool{}
	for _, l := range strings.Split(keptList, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			kept["/"+strings.TrimPrefix(l, "/")] = true
		}
	}
	var risk []string
	for _, l := range strings.Split(auditOut, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		p := "/" + strings.TrimPrefix(f[1], "/")
		if strings.HasPrefix(p, "/etc/") && !kept[p] {
			risk = append(risk, p)
		}
	}
	sort.Strings(risk)
	return risk
}

func sysupgradePlan(ctx context.Context) (string, error) {
	m := currentPkgManager()
	var b strings.Builder
	if rel, err := readSys("/etc/openwrt_release"); err == nil {
		for _, l := range strings.Split(rel, "\n") {
			if strings.HasPrefix(l, "DISTRIB_DESCRIPTION=") {
				b.WriteString("Running: " + strings.Trim(strings.TrimPrefix(l, "DISTRIB_DESCRIPTION="), "'\"") + "\n")
			}
		}
	}

	pkgs, known := userPackages(m)
	if known {
		b.WriteString("Packages you added on top of the image: ")
	} else {
		b.WriteString("Packages selected on this router (the image's own selection could not be read, so base packages are included): ")
	}
	if len(pkgs) == 0 {
		b.WriteString("none.\n")
	} else {
		b.WriteString(strings.Join(pkgs, " ") + "\n")
		b.WriteString("An Attended Sysupgrade request for the new release carries exactly this list. A package missing from the target is dropped from the image, and the service it ran stops working after the flash.\n")
	}

	if anyExists("/usr/bin/owut") {
		if out, err := run(ctx, 2*time.Minute, "owut", "check"); err == nil {
			b.WriteString("Target release (owut check):\n" + strings.TrimRight(out, "\n") + "\n")
		} else {
			b.WriteString("owut check failed: " + err.Error() + "\n")
		}
	} else {
		b.WriteString("owut is not installed, so the target release and package availability were not checked: pkg_change add owut.\n")
	}

	kept, kerr := run(ctx, defaultCmdTimeout, "sysupgrade", "-l")
	audit, aerr := m.audit(ctx)
	switch {
	case kerr != nil:
		b.WriteString("Files at risk were not checked: sysupgrade -l failed.\n")
	case aerr != nil:
		b.WriteString("Files at risk were not checked: this package manager cannot compare installed files with their packages.\n")
	default:
		if risk := atRisk(audit, kept); len(risk) > 0 {
			b.WriteString("Changed files under /etc that a sysupgrade does not keep (add them to /etc/sysupgrade.conf or copy them off):\n  " +
				strings.Join(risk, "\n  ") + "\n")
		} else {
			b.WriteString("Every changed file under /etc is on the sysupgrade keep list.\n")
		}
	}
	b.WriteString("Run sysupgrade action=backup first. Flashing stays manual: nothing was changed.\n")
	return b.String(), nil
}
