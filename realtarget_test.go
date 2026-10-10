//go:build realtarget

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These tests run the tools against a real OpenWrt userland instead of the fakes, to catch what a
// fake cannot: a command line the package manager rejects, or output of a different shape. CI
// runs them inside the openwrt/rootfs container of each supported release (.github/workflows/
// ci.yml, job real-target); nothing here needs a router, a ubus daemon or netifd, so the
// network, wireless and firewall paths stay untested on the real thing (fw4 needs ubus).
//
//	go test -c -tags realtarget -o realtarget.test .
//	docker run --rm -v "$PWD:/w" -e REALTARGET_PKG=opkg openwrt/rootfs:x86-64-24.10.8 /w/realtarget.test -test.v
//
// REALTARGET_PKG is the package manager the image should have ("apk" or "opkg").

func needTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not in this userland", name)
	}
}

// updated refreshes the package lists once; without a network the tests that need them skip.
func updated(t *testing.T) pkgManager {
	t.Helper()
	m := currentPkgManager()
	if out, err := run(context.Background(), 0, m.updateArgv()...); err != nil {
		t.Skipf("%s update failed (no network?): %v\n%s", m.name(), err, out)
	}
	return m
}

func TestRealThePackageManagerIsTheOneTheImageHas(t *testing.T) {
	want := os.Getenv("REALTARGET_PKG")
	if want == "" {
		t.Skip("REALTARGET_PKG is not set")
	}
	if got := currentPkgManager().name(); got != want {
		t.Errorf("detected %s, the image has %s", got, want)
	}
	if got := capabilityLine(); !strings.HasPrefix(got, "packages: "+want+";") {
		t.Errorf("capability line = %q", got)
	}
}

func TestRealPkgQueryReadsTheInstalledSet(t *testing.T) {
	m := currentPkgManager()
	needTool(t, m.name())
	ctx := context.Background()

	out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "installed"})
	if err != nil || !strings.Contains(out, "busybox") || !strings.Contains(out, " packages)") {
		t.Fatalf("installed: %v\n%s", err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "installed", Package: "busybox"}); err != nil || !strings.Contains(out, "(1 packages)") {
		t.Errorf("installed busybox: %v\n%s", err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "info", Package: "busybox"}); err != nil || !strings.Contains(out, "busybox") {
		t.Errorf("info: %v\n%s", err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "files", Package: "busybox"}); err != nil || !strings.Contains(out, "bin/busybox") {
		t.Errorf("files: %v\n%s", err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "owner", Path: "/bin/busybox"}); err != nil || !strings.Contains(out, "busybox") {
		t.Errorf("owner: %v\n%s", err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "world"}); err != nil {
		t.Errorf("world: %v\n%s", err, out)
	} else {
		t.Logf("world: %.200s", out)
	}
	if m.name() == "apk" {
		if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "audit"}); err != nil {
			t.Errorf("audit: %v\n%s", err, out)
		}
	} else if _, _, err := pkgQuery(ctx, pkgQueryIn{Action: "audit"}); errCode(err) != codeValidation {
		t.Errorf("audit on opkg: %v", err)
	}
}

func TestRealSearchAndUpgradableNeedTheLists(t *testing.T) {
	m := updated(t)
	ctx := context.Background()
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "search", Package: "tcpdump"}); err != nil || !strings.Contains(out, "tcpdump") {
		t.Errorf("search on %s: %v\n%s", m.name(), err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "upgradable"}); err != nil {
		t.Errorf("upgradable on %s: %v\n%s", m.name(), err, out)
	}
}

// A simulation must leave the package database exactly as it was. For opkg that is --noaction,
// which was read in libopkg, not yet observed: this is where it is.
func TestRealSimulationChangesNothing(t *testing.T) {
	m := updated(t)
	ctx := context.Background()
	record := "/etc/apk/world"
	if m.name() == "opkg" {
		record = opkgStatus
	}
	before, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("reading %s: %v", record, err)
	}
	listed, _, _ := pkgQuery(ctx, pkgQueryIn{Action: "installed"})
	files := findNewConfigs()

	for _, in := range []pkgChangeIn{
		{Action: "add", Packages: []string{"tcpdump"}},
		{Action: "del", Packages: []string{"busybox"}},
		{Action: "upgrade"},
	} {
		out, _, err := pkgChange(ctx, in)
		if in.Action == "del" && err != nil {
			t.Logf("del busybox: refused by the package manager, which is a fine answer: %v", err)
		} else if err != nil || !strings.Contains(out, "SIMULATION -- nothing changed. "+m.name()+" would:") {
			t.Errorf("%+v: %v\n%s", in, err, out)
		}
		after, _ := os.ReadFile(record)
		if string(after) != string(before) {
			t.Fatalf("%+v changed %s", in, record)
		}
		if now, _, _ := pkgQuery(ctx, pkgQueryIn{Action: "installed"}); now != listed {
			t.Fatalf("%+v changed what is installed", in)
		}
	}
	if got := findNewConfigs(); strings.Join(got, " ") != strings.Join(files, " ") {
		t.Errorf("a simulation left new config files: %v", got)
	}
}

func TestRealAddThenRemoveIsVerified(t *testing.T) {
	m := updated(t)
	ctx := context.Background()
	out, _, err := pkgChange(ctx, pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || !strings.Contains(out, "Verified:") {
		t.Fatalf("add on %s: %v\n%s", m.name(), err, out)
	}
	if out, _, err := pkgQuery(ctx, pkgQueryIn{Action: "installed", Package: "tcpdump"}); err != nil || !strings.Contains(out, "(1 packages)") {
		t.Errorf("tcpdump not listed after add: %v\n%s", err, out)
	}
	out, _, err = pkgChange(ctx, pkgChangeIn{Action: "del", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || !strings.Contains(out, "Verified:") {
		t.Fatalf("del on %s: %v\n%s", m.name(), err, out)
	}
	if out, _, _ := pkgQuery(ctx, pkgQueryIn{Action: "installed", Package: "tcpdump"}); !strings.Contains(out, "(0 packages)") {
		t.Errorf("tcpdump still listed after del:\n%s", out)
	}
}

func TestRealKernelPackageIsFoundOrSaidToBeMissing(t *testing.T) {
	m := currentPkgManager()
	needTool(t, m.name())
	// A container has no kernel package of its own, so either answer is fine; what must not
	// happen is an error that is not one of the two the doctor knows how to report.
	v, err := m.installedKernel(context.Background())
	if err != nil && !strings.Contains(err.Error(), "no installed kernel package found") {
		t.Errorf("installedKernel: %v", err)
	}
	t.Logf("kernel package: %q, %v", v, err)
}

func TestRealUciReadsAConfigTheImageShips(t *testing.T) {
	needTool(t, "uci")
	ctx := context.Background()
	out, _, err := uciGet(ctx, uciGetIn{Config: "firewall"})
	if err != nil || !strings.Contains(out, "=defaults") {
		t.Fatalf("uci_get firewall: %v\n%s", err, out)
	}
	tree, err := uciShow(ctx, "firewall", false)
	if err != nil || len(tree.sectionsOfType("defaults")) == 0 {
		t.Errorf("uciShow firewall: %v", err)
	}
}

// The dry-run warnings compare a reading of the live config with a reading of the staged one. That
// works only if `uci show` prints staged edits and `-X` names an unnamed section by its id, which
// the fakes assume and a real uci has to confirm.
func TestRealTheWarningsSeeAStagedEditToTheShippedFirewall(t *testing.T) {
	needTool(t, "uci")
	ctx := context.Background()
	tree, err := uciShow(ctx, "firewall", true)
	if err != nil {
		t.Fatal(err)
	}
	zone := ""
	for _, sec := range tree.sectionsOfType("zone") {
		if tree.get(sec, "name") == "wan" {
			zone = sec
		}
	}
	if zone == "" || !strings.HasPrefix(zone, "cfg") {
		t.Fatalf("the shipped wan zone should be an unnamed section with an id, got %q", zone)
	}
	live := takeAdvice(ctx)
	if out, err := run(ctx, 0, "uci", "set", "firewall."+zone+".input=ACCEPT"); err != nil {
		t.Fatalf("uci set: %v\n%s", err, out)
	}
	defer func() { _, _ = run(ctx, 0, "uci", "revert", "firewall") }()
	got := live.report(ctx)
	if !strings.Contains(got, "[high] wan-zone-input-accept") {
		t.Errorf("a staged input=ACCEPT on the wan zone raised no warning:\n%s", got)
	}
}

// The reference table was written from the documentation; the firewall config an image ships
// (zone lan, zone wan, a lan to wan forwarding) is the real thing it has to read.
func TestRealRefsReadTheShippedFirewall(t *testing.T) {
	needTool(t, "uci")
	for _, name := range []string{"lan", "wan"} {
		tree, err := uciShow(context.Background(), "firewall", false)
		if err != nil {
			t.Fatal(err)
		}
		defs, uses := refStrings(findRefs(map[string]*uciTree{"firewall": tree}, name))
		hasUse := func(target string) bool {
			for _, u := range uses {
				if strings.HasSuffix(u, " "+target) {
					return true
				}
			}
			return false
		}
		if len(defs) != 1 || !strings.HasSuffix(defs[0], " zone") || !hasUse("interface") || !hasUse("zone") {
			t.Errorf("%s: defs %q, uses %q (want one zone, a zone.network use and a forwarding or rule use)", name, defs, uses)
		}
	}
}
