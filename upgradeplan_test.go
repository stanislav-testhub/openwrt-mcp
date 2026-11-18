package main

import (
	"context"
	"strings"
	"testing"
)

func TestParseUpgradesReadsBothManagers(t *testing.T) {
	apk := "(1/3) Upgrading busybox (1.37.0-r1 -> 1.37.0-r2)\n(2/3) Installing foo (1-r1)\n(3/3) Upgrading kmod-nft-core (6.12.1-r1 -> 6.12.2-r1)\n"
	got := parseUpgrades(apk)
	if len(got) != 2 || got[0] != (pkgUpgrade{"busybox", "1.37.0-r1", "1.37.0-r2"}) || got[1].name != "kmod-nft-core" {
		t.Errorf("apk: %+v", got)
	}
	got = parseUpgrades("Upgrading dnsmasq from 2.90-r1 to 2.91-r1 on root.\nInstalling x (1) to root...\n")
	if len(got) != 1 || got[0] != (pkgUpgrade{"dnsmasq", "2.90-r1", "2.91-r1"}) {
		t.Errorf("opkg: %+v", got)
	}
}

func TestUpgradeSimulationCarriesThePlan(t *testing.T) {
	f := newFakeRouter(t)
	f.on("apk update", "ok")
	f.on("apk --simulate upgrade", "(1/2) Upgrading dnsmasq (2.90-r1 -> 2.91-r1)\n(2/2) Upgrading kmod-nft-core (1-r1 -> 2-r1)\n")
	f.on("apk info -L dnsmasq", "dnsmasq-2.91-r1 contains:\netc/init.d/dnsmasq\netc/config/dhcp\nusr/sbin/dnsmasq\n")
	f.on("apk info -L kmod-nft-core", "kmod-nft-core-2-r1 contains:\nlib/modules/6.12/nf_tables.ko\n")
	f.on("apk audit", "U etc/config/dhcp\nU usr/sbin/dnsmasq\nA etc/config/mine\n")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Upgrade plan: 2 package(s)", "dnsmasq: 2.90-r1 -> 2.91-r1",
		"Reboot needed: the kernel or kernel modules change (kmod-nft-core)",
		"dnsmasq (dnsmasq)", "/etc/config/dhcp (kept",
		"/usr/sbin/dnsmasq (changed or replaced locally; the upgrade will overwrite it)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "mine") {
		t.Error("an added file that belongs to no package was listed")
	}
}

func TestUpgradePlanSaysWhenNothingNeedsAReboot(t *testing.T) {
	f := newFakeRouter(t)
	f.on("apk update", "ok")
	f.on("apk --simulate upgrade", "(1/1) Upgrading curl (8-r1 -> 8-r2)\n")
	f.on("apk info -L curl", "curl-8-r2 contains:\nusr/bin/curl\n")
	f.on("apk audit", "")
	out, _, err := pkgChange(context.Background(), pkgChangeIn{Action: "upgrade"})
	if err != nil || !strings.Contains(out, "no reboot needed") || !strings.Contains(out, "No locally changed file") {
		t.Errorf("%v\n%s", err, out)
	}
}
