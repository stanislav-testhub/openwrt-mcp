package main

import (
	"context"
	"fmt"
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

// planNoise are changed /etc files that every flash regenerates or that no operator keeps.
var planNoise = []string{"/etc/apk/", "/etc/board.json", "/etc/urandom.seed", "/etc/passwd-", "/etc/shadow-"}

// atRisk are the changed or added files under /etc that the sysupgrade file list does not carry.
// A directory in the audit counts as kept when any kept file lies under it. Service enable links
// under /etc/rc.d are returned as a count: packages recreate them, a hand-made change is lost.
func atRisk(auditOut, keptList string) (files []string, links int) {
	var kept []string
	for _, l := range strings.Split(keptList, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			kept = append(kept, "/"+strings.TrimPrefix(l, "/"))
		}
	}
	isKept := func(p string) bool {
		for _, k := range kept {
			if k == p || strings.HasSuffix(p, "/") && strings.HasPrefix(k, p) {
				return true
			}
		}
		return false
	}
next:
	for _, l := range strings.Split(auditOut, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		p := "/" + strings.TrimPrefix(f[1], "/")
		if !strings.HasPrefix(p, "/etc/") || isKept(p) {
			continue
		}
		for _, n := range planNoise {
			if p == n || strings.HasSuffix(n, "/") && strings.HasPrefix(p, n) {
				continue next
			}
		}
		if strings.HasPrefix(p, "/etc/rc.d/") {
			links++
			continue
		}
		files = append(files, p)
	}
	sort.Strings(files)
	return files, links
}

// wrapWords joins words into lines of at most width bytes: tool output cuts a line at 1 KiB.
func wrapWords(words []string, indent string, width int) string {
	var b strings.Builder
	line := indent
	for _, w := range words {
		if len(line)+len(w)+1 > width && line != indent {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = indent
		}
		line += w + " "
	}
	return b.String() + strings.TrimRight(line, " ") + "\n"
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
		var shown []string
		mods := 0
		for _, p := range pkgs {
			if p == "kernel" || strings.HasPrefix(p, "kmod-") {
				mods++
			} else {
				shown = append(shown, p)
			}
		}
		b.WriteString("\n" + wrapWords(shown, "  ", 100))
		if mods > 0 {
			fmt.Fprintf(&b, "  (+ the kernel and %d kernel modules, which the target image brings itself)\n", mods)
		}
		b.WriteString("An Attended Sysupgrade request for the new release carries exactly this list. A package missing from the target is dropped from the image, and the service it ran stops working after the flash.\n")
	}

	if anyExists("/usr/bin/owut") {
		out, err := run(ctx, 2*time.Minute, "owut", "check")
		if err == nil {
			b.WriteString("Target release (owut check):\n" + strings.TrimRight(out, "\n") + "\n")
		} else {
			b.WriteString("owut check failed (no route to the upgrade server?): " + strings.TrimSpace(out+" "+err.Error()) + "\n")
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
		risk, links := atRisk(audit, kept)
		if len(risk) > 0 {
			b.WriteString("Changed files under /etc that a sysupgrade does not keep (add them to /etc/sysupgrade.conf or copy them off):\n" +
				"  " + strings.Join(risk, "\n  ") + "\n")
		} else {
			b.WriteString("Every changed file under /etc is on the sysupgrade keep list.\n")
		}
		if links > 0 {
			fmt.Fprintf(&b, "Service enable links under /etc/rc.d: %d. Packages recreate them; a service you enabled or disabled by hand needs doing again.\n", links)
		}
	}
	b.WriteString("Run sysupgrade action=backup first. Flashing stays manual: nothing was changed.\n")
	return b.String(), nil
}
