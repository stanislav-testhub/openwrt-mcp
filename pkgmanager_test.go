package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenWrt 25.12 has apk; 24.10 and older have opkg. Everything the tools say about packages goes
// through one pkgManager chosen from the binaries on the router. The expected commands below are
// opkg's own: list-installed, list-upgradable, find, info, files, search, install/remove/upgrade
// and --noaction (libopkg: opkg_cmd.c, opkg_install.c).

func opkgRouter(t *testing.T) (*fakeRouter, string) {
	t.Helper()
	root := withFixtureRoot(t)
	writeFixture(t, root, "bin/opkg", "")
	return newFakeRouter(t), root
}

func TestPkgManagerIsChosenFromTheBinariesOnTheRouter(t *testing.T) {
	for _, c := range []struct {
		name  string
		files []string
		want  string
	}{
		{"nothing found: the current release", nil, "apk"},
		{"apk-tools 3", []string{"usr/bin/apk"}, "apk"},
		{"opkg", []string{"bin/opkg"}, "opkg"},
		{"opkg in /usr/bin", []string{"usr/bin/opkg"}, "opkg"},
		{"both: apk wins", []string{"usr/bin/apk", "bin/opkg"}, "apk"},
	} {
		root := withFixtureRoot(t)
		for _, f := range c.files {
			writeFixture(t, root, f, "")
		}
		if got := currentPkgManager().name(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestOpkgQueryRunsTheOpkgCommandForEachAction(t *testing.T) {
	for _, c := range []struct {
		in   pkgQueryIn
		want string
	}{
		{pkgQueryIn{Action: "installed"}, "opkg list-installed"},
		{pkgQueryIn{Action: "installed", Package: "luci-app-*"}, "opkg list-installed luci-app-*"},
		{pkgQueryIn{Action: "upgradable"}, "opkg list-upgradable"},
		{pkgQueryIn{Action: "search", Package: "tcpdump"}, "opkg find *tcpdump*"},
		{pkgQueryIn{Action: "search", Package: "tcp*"}, "opkg find tcp*"},
		{pkgQueryIn{Action: "info", Package: "dnsmasq-full"}, "opkg info dnsmasq-full"},
		{pkgQueryIn{Action: "files", Package: "dnsmasq-full"}, "opkg files dnsmasq-full"},
		{pkgQueryIn{Action: "owner", Path: "/usr/sbin/nft"}, "opkg search /usr/sbin/nft"},
	} {
		f, _ := opkgRouter(t)
		f.on(c.want, "pkg-a - 1.0")
		out, summary, err := pkgQuery(context.Background(), c.in)
		if err != nil || !strings.Contains(out, "pkg-a") || summary != c.want {
			t.Errorf("%s: %q / %q / %v", c.want, out, summary, err)
		}
		if f.ran("apk") {
			t.Errorf("%s: apk was run on an opkg router", c.want)
		}
	}
}

func TestOpkgRouterSaysWhatItCannotAnswer(t *testing.T) {
	for _, action := range []string{"policy", "audit"} {
		f, _ := opkgRouter(t)
		_, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: action, Package: "dnsmasq"})
		if err == nil || !strings.Contains(err.Error(), "opkg") || errCode(err) != codeValidation {
			t.Errorf("%s on opkg: %v (code %s), want a VALIDATION error naming opkg", action, err, errCode(err))
		}
		if len(f.argvList()) != 0 {
			t.Errorf("%s ran a command: %v", action, f.argvList())
		}
	}
}

func TestOpkgQueryKeepsTheInputChecks(t *testing.T) {
	f, _ := opkgRouter(t)
	for _, in := range []pkgQueryIn{
		{Action: "info", Package: "--help"},
		{Action: "files", Package: "-x"},
		{Action: "search", Package: "a b"},
		{Action: "installed", Package: "-f"},
		{Action: "owner", Path: "relative"},
		{Action: "owner", Path: "/-x"},
	} {
		if _, _, err := pkgQuery(context.Background(), in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	if len(f.argvList()) != 0 {
		t.Errorf("a refused query ran %v", f.argvList())
	}
}

func TestOpkgListsAreCompactedLikeApkLists(t *testing.T) {
	f, _ := opkgRouter(t)
	f.on("opkg list-installed", "base-files - 1556-r27996\ndnsmasq-full - 2.90-r3\n")
	out, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "installed"})
	if err != nil || out != "base-files-1556-r27996\ndnsmasq-full-2.90-r3\n(2 packages)" {
		t.Errorf("installed: %v\n%q", err, out)
	}
	f.on("opkg list-upgradable", "curl - 8.9.1-r1 - 8.10.1-r1\nlibcurl4 - 8.9.1-r1 - 8.10.1-r1\n")
	out, _, err = pkgQuery(context.Background(), pkgQueryIn{Action: "upgradable"})
	want := "curl-8.10.1-r1 [upgradable from: curl-8.9.1-r1]\nlibcurl4-8.10.1-r1 [upgradable from: libcurl4-8.9.1-r1]\n(2 packages)"
	if err != nil || out != want {
		t.Errorf("upgradable: %v\n got %q\nwant %q", err, out, want)
	}
	f.on("opkg list-installed", "")
	if out, _, _ := pkgQuery(context.Background(), pkgQueryIn{Action: "installed"}); !strings.Contains(out, "(0 packages)") {
		t.Errorf("empty list: %q", out)
	}
}

func TestOpkgRefreshRunsOpkgUpdate(t *testing.T) {
	f, _ := opkgRouter(t)
	f.on("opkg update", "Downloaded.\nUpdated list of available packages in /var/opkg-lists/base\n")
	f.on("opkg list-upgradable", "")
	out, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "upgradable", Refresh: true})
	if err != nil || !strings.HasPrefix(out, "Updated list of available packages in /var/opkg-lists/base\n\n") {
		t.Errorf("%v\n%q", err, out)
	}
	f.fail("opkg update", "Failed to download")
	if _, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "upgradable", Refresh: true}); err == nil || !strings.Contains(err.Error(), "opkg update") {
		t.Errorf("a failed update: %v", err)
	}
}

// The status file marks what the operator asked for ("user installed"); packages pulled in as
// dependencies are "install ok installed".
const opkgStatusFixture = `Package: base-files
Version: 1556-r27996
Depends: libc, netifd
Status: install user installed
Architecture: x86_64

Package: libc
Version: 1.2.5-r4
Status: install ok installed
Architecture: x86_64

Package: tcpdump
Version: 4.99.4-r1
Status: install user installed
Architecture: x86_64

Package: held
Version: 2
Status: install user,hold installed
Auto-Installed: yes

Package: unpacked
Version: 3
Status: install user unpacked

Package: leaving
Version: 4
Status: deinstall user installed

Package: odd
Version: 1
Status: deinstall user not-installed
`

func TestOpkgWorldListsWhatTheOperatorInstalled(t *testing.T) {
	f, root := opkgRouter(t)
	writeFixture(t, root, "usr/lib/opkg/status", opkgStatusFixture)
	out, summary, err := pkgQuery(context.Background(), pkgQueryIn{Action: "world"})
	if err != nil || out != "base-files\ntcpdump\nheld\n" || summary != "read world" {
		t.Errorf("world: %v / %q / %q", err, out, summary)
	}
	if len(f.argvList()) != 0 {
		t.Errorf("world ran a command: %v", f.argvList())
	}
	if err := os.Remove(filepath.Join(root, "usr/lib/opkg/status")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "world"}); err == nil {
		t.Error("a missing status file was not reported")
	}
}

func TestOpkgChangeSimulatesWithNoactionAndInstallsForReal(t *testing.T) {
	f, _ := opkgRouter(t)
	f.on("opkg update", "Updated list of available packages")
	f.on("opkg --noaction install tcpdump", "Installing tcpdump (4.99.4-r1) to root...")
	out, summary, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}})
	if err != nil || !strings.Contains(out, "SIMULATION -- nothing changed. opkg would:\nInstalling tcpdump") ||
		summary != "opkg --noaction install tcpdump" {
		t.Fatalf("%v / %q\n%s", err, summary, out)
	}
	if f.ran("opkg install") || f.ran("apk") {
		t.Errorf("a simulation went further:\n%s", f.allCalls())
	}

	f.on("opkg install tcpdump", "Installing tcpdump (4.99.4-r1) to root...")
	f.on("opkg list-installed", "base-files - 1556-r27996\ntcpdump - 4.99.4-r1\n")
	out, summary, err = pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"tcpdump"}, Commit: true})
	if err != nil || summary != "opkg install tcpdump" || !strings.Contains(out, "Verified: opkg list-installed lists tcpdump.") {
		t.Errorf("commit: %v / %q\n%s", err, summary, out)
	}
}

func TestOpkgChangeMapsEveryActionToItsOpkgCommand(t *testing.T) {
	for _, c := range []struct {
		in   pkgChangeIn
		want string
	}{
		{pkgChangeIn{Action: "add", Packages: []string{"a", "b"}}, "opkg --noaction install a b"},
		{pkgChangeIn{Action: "del", Packages: []string{"a"}}, "opkg --noaction remove a"},
		{pkgChangeIn{Action: "upgrade", Packages: []string{"a"}}, "opkg --noaction upgrade a"},
		{pkgChangeIn{Action: "del", Packages: []string{"a"}, Commit: true}, "opkg remove a"},
		{pkgChangeIn{Action: "upgrade", Packages: []string{"a"}, Commit: true}, "opkg upgrade a"},
	} {
		f, _ := opkgRouter(t)
		f.on("opkg update", "ok")
		f.on("opkg", "done")
		f.on("opkg list-installed", "")
		_, summary, _ := pkgChange(context.Background(), c.in)
		if summary != c.want {
			t.Errorf("%+v: %q, want %q", c.in, summary, c.want)
		}
	}
}

// opkg upgrade has no upgrade-everything form: it needs the names, so a bare upgrade takes
// them from list-upgradable (seen on a 24.10.8 rootfs, where a bare "opkg upgrade" prints usage).
func TestOpkgUpgradeWithNoPackagesNamesWhatIsUpgradable(t *testing.T) {
	f, _ := opkgRouter(t)
	f.on("opkg update", "ok")
	f.on("opkg list-upgradable", "base-files - 1556-r27996 - 1557-r27997\nbusybox - 1.36.1-r1 - 1.36.1-r2\n")
	f.on("opkg", "done")
	_, summary, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade"})
	if err != nil || summary != "opkg --noaction upgrade base-files busybox" {
		t.Errorf("%v / %q", err, summary)
	}
}

func TestOpkgUpgradeWithNothingUpgradableRunsNoUpgrade(t *testing.T) {
	for _, commit := range []bool{false, true} {
		f, _ := opkgRouter(t)
		f.on("opkg update", "ok")
		f.on("opkg list-upgradable", "")
		out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade", Commit: commit})
		if err != nil || !strings.Contains(out, "upgrade nothing") && !strings.Contains(out, "Nothing to upgrade") {
			t.Errorf("commit=%v: %v\n%s", commit, err, out)
		}
		if f.ran("opkg --noaction") || f.ran("opkg upgrade") {
			t.Errorf("commit=%v ran an upgrade:\n%s", commit, f.allCalls())
		}
	}
}

func TestOpkgChangeUpdatesFirstExceptForARemoval(t *testing.T) {
	for action, wantUpdate := range map[string]bool{"add": true, "upgrade": true, "del": false} {
		f, _ := opkgRouter(t)
		f.on("opkg", "ok")
		pkgChange(context.Background(), pkgChangeIn{Action: action, Packages: []string{"a"}})
		if f.ran("opkg update") != wantUpdate {
			t.Errorf("%s: opkg update ran = %v, want %v", action, f.ran("opkg update"), wantUpdate)
		}
	}
}

func TestOpkgChangeKeepsTheInputChecks(t *testing.T) {
	f, _ := opkgRouter(t)
	for _, in := range []pkgChangeIn{
		{Action: "add", Packages: []string{"--force-depends"}},
		{Action: "add", Packages: []string{"x;reboot"}},
		{Action: "add"},
		{Action: "purge", Packages: []string{"a"}},
	} {
		if _, _, err := pkgChange(context.Background(), in); err == nil {
			t.Errorf("%+v accepted", in)
		}
	}
	if len(f.argvList()) != 0 {
		t.Errorf("a refused change ran %v", f.argvList())
	}
}

func TestOpkgChangeChecksWhatIsInstalledAfterwards(t *testing.T) {
	for _, c := range []struct {
		name, action, installed, wantErr, wantOK string
	}{
		{"added and listed", "add", "a - 1\nb - 2\n", "", "Verified: opkg list-installed lists a, b."},
		{"added, one missing", "add", "a - 1\n", "opkg install exited 0, but opkg list-installed does not list b", ""},
		{"removed and gone", "del", "c - 3\n", "", "Verified: opkg list-installed no longer lists a, b."},
		{"removed, one remains", "del", "b - 2\n", "opkg remove exited 0, but opkg list-installed still lists b", ""},
		{"a prefix is not the package", "add", "ab - 1\nb - 2\n", "opkg install exited 0, but opkg list-installed does not list a", ""},
	} {
		f, _ := opkgRouter(t)
		f.on("opkg", "done")
		f.on("opkg list-installed", c.installed)
		out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: c.action, Packages: []string{"a", "b"}, Commit: true})
		switch {
		case c.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || errCode(err) != codeNotApplied {
				t.Errorf("%s: %v (code %s), want NOT_APPLIED %q", c.name, err, errCode(err), c.wantErr)
			}
		case err != nil || !strings.Contains(out, c.wantOK):
			t.Errorf("%s: %v\n%s", c.name, err, out)
		}
	}
	// An upgrade changes versions, not what is installed: nothing to read back.
	f, _ := opkgRouter(t)
	f.on("opkg", "done")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade", Packages: []string{"a"}, Commit: true})
	if err != nil || strings.Contains(out, "Verified") || f.ran("opkg list-installed") {
		t.Errorf("upgrade: %v\n%s", err, out)
	}
	// When opkg cannot be asked, the change still happened: say it was not verified.
	f, _ = opkgRouter(t)
	f.on("opkg update", "ok")
	f.on("opkg install", "done")
	f.fail("opkg list-installed", "Collected errors")
	out, _, err = pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"a"}, Commit: true})
	if err != nil || !strings.Contains(out, "Not verified: could not run opkg list-installed") {
		t.Errorf("unreadable list: %v\n%s", err, out)
	}
}

// opkg keeps the local file and puts the package's new default beside it as <file>-opkg.
func TestOpkgLeavesNewDefaultsAsDashOpkgFiles(t *testing.T) {
	f, root := opkgRouter(t)
	writeFixture(t, root, "etc/config/dhcp", "config dnsmasq\n\toption domain 'lan'\n")
	writeFixture(t, root, "etc/config/dhcp-opkg", "config dnsmasq\n\toption domain 'new'\n")
	writeFixture(t, root, "etc/other.apk-new", "an apk leftover is not opkg's\n")
	if got := findNewConfigs(); strings.Join(got, " ") != "/etc/config/dhcp-opkg" {
		t.Errorf("new configs = %v", got)
	}

	f.on("opkg update", "ok")
	f.onFn("opkg install dnsmasq-full", func([]string, string) (string, error) {
		writeFixture(t, root, "etc/config/firewall-opkg", "x")
		return "done", nil
	})
	f.on("opkg list-installed", "dnsmasq-full - 1\n")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "add", Packages: []string{"dnsmasq-full"}, Commit: true})
	if err != nil || !strings.Contains(out, "/etc/config/firewall-opkg") || strings.Contains(out, "/etc/config/dhcp-opkg") {
		t.Errorf("only the new -opkg file should be reported: %v\n%s", err, out)
	}
}

func TestOpkgConfigDiffShowsTheDashOpkgFiles(t *testing.T) {
	_, root := opkgRouter(t)
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf", "a\nb\n")
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf-opkg", "a\nc\n")
	for _, p := range []string{"/etc/avahi/avahi-daemon.conf", "/etc/avahi/avahi-daemon.conf-opkg"} {
		out, _, err := pkgConfigDiff(context.Background(), pkgConfigDiffIn{Path: p})
		if err != nil || !strings.Contains(out, "-b") || !strings.Contains(out, "+c") || !strings.Contains(out, "1 -opkg file(s)") {
			t.Errorf("diff of %s: %v\n%s", p, err, out)
		}
	}
	if err := os.Remove(filepath.Join(root, "etc/avahi/avahi-daemon.conf-opkg")); err != nil {
		t.Fatal(err)
	}
	if out, _, err := pkgConfigDiff(context.Background(), pkgConfigDiffIn{}); err != nil || !strings.HasPrefix(out, "No -opkg files") {
		t.Errorf("nothing waiting: %v / %q", err, out)
	}
}

func TestOpkgResolveUseNewKeepsTheOldCopyAsPreOpkgNew(t *testing.T) {
	s := testServer(t, "")
	_, root := opkgRouter(t)
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf", "a\nb\n")
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf-opkg", "a\nc\n")
	if got := pkgResolveScope(pkgConfigResolveIn{Path: "/etc/avahi/avahi-daemon.conf-opkg"}); strings.Join(got, " ") != "/etc/avahi/avahi-daemon.conf" {
		t.Errorf("scope = %v", got)
	}
	out, _, err := s.pkgConfigResolve(context.Background(), "c", pkgConfigResolveIn{Path: "/etc/avahi/avahi-daemon.conf-opkg", Action: "use_new"})
	if err != nil || !strings.Contains(out, "avahi-daemon.conf.pre-opkg-new") {
		t.Fatalf("use_new: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/avahi/avahi-daemon.conf")); string(b) != "a\nc\n" {
		t.Errorf("live file = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/avahi/avahi-daemon.conf.pre-opkg-new")); string(b) != "a\nb\n" {
		t.Errorf("old copy = %q", b)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/avahi/avahi-daemon.conf-opkg")); err == nil {
		t.Error("the -opkg file was left behind")
	}
}

func TestOpkgResolveKeepCurrentDeletesTheDashOpkgFile(t *testing.T) {
	s := testServer(t, "")
	_, root := opkgRouter(t)
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf", "a\nb\n")
	writeFixture(t, root, "etc/avahi/avahi-daemon.conf-opkg", "a\nc\n")
	out, _, err := s.pkgConfigResolve(context.Background(), "c", pkgConfigResolveIn{Path: "/etc/avahi/avahi-daemon.conf", Action: "keep_current"})
	if err != nil || !strings.Contains(out, "removed /etc/avahi/avahi-daemon.conf-opkg") {
		t.Fatalf("keep_current: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/avahi/avahi-daemon.conf")); string(b) != "a\nb\n" {
		t.Errorf("live file = %q", b)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/avahi/avahi-daemon.conf-opkg")); err == nil {
		t.Error("the -opkg file was left behind")
	}
}

func TestApkRoutersKeepTheirOwnSuffixes(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "usr/bin/apk", "")
	writeFixture(t, root, "etc/config/dhcp.apk-new", "x")
	writeFixture(t, root, "etc/config/dhcp-opkg", "an opkg leftover is not apk's")
	if got := findNewConfigs(); strings.Join(got, " ") != "/etc/config/dhcp.apk-new" {
		t.Errorf("new configs = %v", got)
	}
}

func TestSystemStatusSaysWhichPackageManagerAndFirewall(t *testing.T) {
	for _, c := range []struct {
		files []string
		want  string
	}{
		{[]string{"usr/bin/apk", "sbin/fw4"}, "packages: apk; firewall: fw4 (nftables)"},
		{[]string{"bin/opkg", "sbin/fw4"}, "packages: opkg; firewall: fw4 (nftables)"},
		{[]string{"bin/opkg", "sbin/fw3"}, "packages: opkg; firewall: fw3 (iptables)"},
		{[]string{"bin/opkg"}, "packages: opkg; firewall: none found"},
		{[]string{"usr/bin/apk", "sbin/fw3", "sbin/fw4"}, "packages: apk; firewall: fw4 (nftables)"},
	} {
		root := withFixtureRoot(t)
		for _, f := range c.files {
			writeFixture(t, root, f, "")
		}
		if got := capabilityLine(); got != c.want {
			t.Errorf("%v: %q, want %q", c.files, got, c.want)
		}
	}
}

func TestFirewallShowOnAnIptablesRouter(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "sbin/fw3", "")
	f := newFakeRouter(t)
	f.on("iptables-save", "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
	f.on("fw3 -q print", "iptables -t filter -A INPUT -j ACCEPT\n")

	out, summary, err := firewallShow(context.Background(), firewallShowIn{})
	if err != nil || !strings.Contains(out, ":INPUT ACCEPT") || summary != "iptables-save" {
		t.Errorf("ruleset: %v / %q\n%s", err, summary, out)
	}
	out, summary, err = firewallShow(context.Background(), firewallShowIn{View: "rendered"})
	if err != nil || !strings.Contains(out, "-A INPUT") || summary != "fw3 -q print" {
		t.Errorf("rendered: %v / %q\n%s", err, summary, out)
	}
	for _, view := range []string{"check", "chain", "table"} {
		_, _, err := firewallShow(context.Background(), firewallShowIn{View: view, Chain: "input"})
		if err == nil || !strings.Contains(err.Error(), "fw3") || errCode(err) != codeValidation {
			t.Errorf("view %s on fw3: %v (code %s), want a VALIDATION error naming fw3", view, err, errCode(err))
		}
	}
	if f.ran("nft") || f.ran("fw4") {
		t.Errorf("nft or fw4 was run on an fw3 router:\n%s", f.allCalls())
	}
}

func TestFirewallShowOnFw4StaysAsItWas(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "sbin/fw4", "")
	f := newFakeRouter(t)
	f.on("nft list ruleset", "table inet fw4 {}")
	if out, _, err := firewallShow(context.Background(), firewallShowIn{}); err != nil || out != "table inet fw4 {}" {
		t.Errorf("%v / %q", err, out)
	}
	if f.ran("iptables-save") {
		t.Error("iptables on an fw4 router")
	}
}

// fw4 check is how a firewall apply is validated. fw3 has no such command, so the config is
// reported as not checked rather than failing every time.
func TestFirewallApplyIsNotCheckedWhereThereIsNoFw4(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "sbin/fw3", "")
	f := newFakeRouter(t)
	got := checkAll(context.Background(), []string{"firewall", "dhcp"})
	if _, ok := got["firewall"]; ok || f.ran("fw4") {
		t.Errorf("firewall was checked on fw3: %v\n%s", got, f.allCalls())
	}
	root = withFixtureRoot(t)
	writeFixture(t, root, "sbin/fw4", "")
	f = newFakeRouter(t)
	f.on("fw4 check", "")
	if _, ok := checkAll(context.Background(), []string{"firewall"})["firewall"]; !ok {
		t.Error("firewall was not checked on fw4")
	}
}

// The doctor and the audit read the package manager too: new config defaults, the installed
// kernel, and (apk only) the files changed since install.

func opkgDoctorRouter(t *testing.T) (*fakeRouter, string) {
	t.Helper()
	d := newDocFixture()
	d.kernelPkg = ""
	f := d.install(t)
	writeFixture(t, sysRoot, "bin/opkg", "")
	f.on("opkg list-installed kernel", "kernel - 6.12.94-1-5a6c1f71be683ae9980b15d3ce73e24d\n")
	return f, sysRoot
}

func TestDoctorOnAnOpkgRouterFindsNothingWhenHealthy(t *testing.T) {
	f, _ := opkgDoctorRouter(t)
	r := healthFindings(context.Background())
	if len(r.findings) != 0 || len(r.skipped) != 0 {
		t.Fatalf("findings %q, skipped %v", findingIDs(r), r.skipped)
	}
	out := r.render()
	if !strings.Contains(out, "opkg-new") || strings.Contains(out, "apk-new") {
		t.Errorf("the list of what was checked should name opkg-new, not apk-new:\n%s", out)
	}
	if f.ran("apk") {
		t.Errorf("apk was run on an opkg router:\n%s", f.allCalls())
	}
}

func TestDoctorOnAnOpkgRouterReportsNewDefaultsAndANewKernel(t *testing.T) {
	f, root := opkgDoctorRouter(t)
	writeFixture(t, root, "etc/config/dhcp-opkg", "x\n")
	writeFixture(t, root, "etc/other.apk-new", "an apk leftover\n")
	f.on("opkg list-installed kernel", "kernel - 6.12.95-1-0123456789abcdef0123456789abcdef\n")
	r := healthFindings(context.Background())
	nf := r.byID("opkg-new-pending")
	if nf == nil || nf.sev != sevLow || !strings.Contains(nf.evidence, "/etc/config/dhcp-opkg") || strings.Contains(nf.evidence, "other.apk-new") {
		t.Errorf("opkg-new-pending: %+v (all: %q)", nf, findingIDs(r))
	}
	if r.byID("apk-new-pending") != nil {
		t.Error("an apk finding on an opkg router")
	}
	kf := r.byID("reboot-needed")
	if kf == nil || kf.sev != sevMedium || !strings.Contains(kf.evidence, "running 6.12.94, installed 6.12.95") {
		t.Errorf("reboot-needed: %+v (all: %q)", kf, findingIDs(r))
	}
}

func TestDoctorOnAnOpkgRouterSkipsAKernelCheckItCannotMake(t *testing.T) {
	f, _ := opkgDoctorRouter(t)
	f.on("opkg list-installed kernel", "base-files - 1\n")
	r := healthFindings(context.Background())
	if len(r.skipped) != 1 || !strings.Contains(r.skipped[0], "kernel (no installed kernel package found)") {
		t.Errorf("skipped = %v", r.skipped)
	}
}

func TestAuditOnAnOpkgRouterSaysItCannotCompareFilesWithPackages(t *testing.T) {
	a := newAuditFixture()
	a.install(t)
	writeFixture(t, sysRoot, "bin/opkg", "")
	r := auditFindings(context.Background())
	joined := strings.Join(r.skipped, "\n")
	if !strings.Contains(joined, "packages (opkg has no audit command") {
		t.Errorf("skipped = %v", r.skipped)
	}
	if r.byID("apk-audit-modified") != nil {
		t.Error("an apk audit finding on an opkg router")
	}
}

func FuzzOpkgParsers(f *testing.F) {
	f.Add("Package: a\nStatus: install user installed\n\nPackage: b\n", "a - 1\nb - 1 - 2\n")
	f.Add("Status:\nStatus: x y\nPackage: \n\n\n", " - \n - - - -\n")
	f.Fuzz(func(t *testing.T, status, list string) {
		_ = userInstalled(status)
		if out := (opkgManager{}).compactList(list); !strings.HasSuffix(out, " packages)") {
			t.Errorf("compactList lost its total: %q", out)
		}
	})
}

func TestSystemStatusShowsTheCapabilitiesAndTheRightKindOfNewDefault(t *testing.T) {
	for _, c := range []struct {
		files   []string
		want    string
		pending string
	}{
		{[]string{"bin/opkg", "sbin/fw4", "etc/config/dhcp-opkg"}, "packages: opkg; firewall: fw4 (nftables)\n", "  1 -opkg config file(s) awaiting review (pkg_config_diff)\n"},
		{[]string{"usr/bin/apk", "sbin/fw4", "etc/config/dhcp.apk-new"}, "packages: apk; firewall: fw4 (nftables)\n", "  1 .apk-new config file(s) awaiting review (pkg_config_diff)\n"},
	} {
		root := withFixtureRoot(t)
		for _, f := range c.files {
			writeFixture(t, root, f, "x")
		}
		f := newFakeRouter(t)
		f.on("ubus call system board", `{"model":"M","board_name":"b","kernel":"6.6.1","hostname":"h","release":{"description":"OpenWrt"}}`)
		f.on("uci changes", "")
		out, _, err := testServer(t, "").systemStatus(context.Background(), systemStatusIn{})
		if err != nil || !strings.Contains(out, c.want) || !strings.Contains(out, c.pending) {
			t.Errorf("%v\nwant %q and %q in:\n%s", err, c.want, c.pending, out)
		}
	}
}

func TestOpkgKernelVersionComesFromTheKernelPackageLine(t *testing.T) {
	f, _ := opkgRouter(t)
	f.on("opkg list-installed kernel", "libfoo-kernel - 9.9\nkernel - 6.12.94-1-5a6c1f71be683ae9980b15d3ce73e24d\n")
	if v, err := (opkgManager{}).installedKernel(context.Background()); err != nil || v != "6.12.94" {
		t.Errorf("kernel = %q, %v", v, err)
	}
	f.on("opkg list-installed kernel", "libfoo-kernel - 9.9\n")
	if _, err := (opkgManager{}).installedKernel(context.Background()); err == nil || !strings.Contains(err.Error(), "no installed kernel package found") {
		t.Errorf("a package that only ends in -kernel was taken for the kernel: %v", err)
	}
	f.fail("opkg list-installed kernel", "Collected errors")
	if _, err := (opkgManager{}).installedKernel(context.Background()); err == nil || !strings.Contains(err.Error(), "opkg list-installed") {
		t.Errorf("a failing opkg: %v", err)
	}
}

func TestOpkgWorldSaysWhenNothingWasInstalledByHand(t *testing.T) {
	_, root := opkgRouter(t)
	writeFixture(t, root, "usr/lib/opkg/status", "Package: libc\nStatus: install ok installed\n")
	out, _, err := pkgQuery(context.Background(), pkgQueryIn{Action: "world"})
	if err != nil || out != "(nothing)" {
		t.Errorf("%v / %q", err, out)
	}
}

func TestAnAuditOnOpkgIsAnErrorNotAnEmptyReport(t *testing.T) {
	opkgRouter(t)
	out, err := (opkgManager{}).audit(context.Background())
	if err == nil || out != "" {
		t.Errorf("audit = %q, %v", out, err)
	}
}
