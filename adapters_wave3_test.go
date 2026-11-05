package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Wave 3 first batch (ROADMAP 9.5): synthetic fixtures from the add-ons' UCI schemas and
// config formats, fixture-tested only.

func TestSambaSharesAndKsmbdShowGuestAndWritable(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "samba4", "ksmbd")
	f.on("pidof smbd", "5\n")
	f.on("uci -q show samba4", "samba4.@samba[0]=samba\nsamba4.@samba[0].interface='lan'\nsamba4.@samba[0].password='canary-pw'\nsamba4.@sambashare[0]=sambashare\nsamba4.@sambashare[0].name='media'\nsamba4.@sambashare[0].path='/mnt/media'\nsamba4.@sambashare[0].guest_ok='yes'\nsamba4.@sambashare[0].read_only='no'\n")
	f.on("pidof ksmbd.mountd", "")
	f.on("uci -q show ksmbd", "ksmbd.@share[0]=share\nksmbd.@share[0].name='docs'\nksmbd.@share[0].path='/mnt/docs'\nksmbd.@share[0].read_only='yes'\n")
	s := body(t, "samba4")
	mustNotContain(t, s, "canary-pw")
	wantAll(t, s, "bound to: lan", "media (/mnt/media): guest access, writable")
	wantAll(t, body(t, "ksmbd"), "docs (/mnt/docs): login required, read-only")
}

func TestTransmissionAria2AndMiniDLNA(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "transmission", "aria2", "minidlna")
	f.on("pidof transmission-daemon", "1\n")
	f.on("uci -q show transmission", "transmission.transmission=transmission\ntransmission.transmission.rpc_bind_address='127.0.0.1'\ntransmission.transmission.rpc_username='bob'\ntransmission.transmission.rpc_password='canary-rpc'\n")
	f.on("pidof aria2c", "2\n")
	f.on("uci -q show aria2", "aria2.main=aria2\naria2.main.rpc_listen_all='1'\naria2.main.rpc_secret='canary-secret'\n")
	f.on("pidof minidlnad", "3\n")
	f.on("uci -q show minidlna", "minidlna.config=minidlna\nminidlna.config.media_dir='/mnt/a' '/mnt/b'\n")
	all := body(t, "transmission") + body(t, "aria2") + body(t, "minidlna")
	mustNotContain(t, all, "canary", "bob")
	wantAll(t, all, "RPC: 127.0.0.1:9091", "RPC authentication: not required", "RPC listens on: all addresses", "RPC secret: set (not shown)", "media directories: 2")
}

func TestMosquittoAndTorReadOnlyKnownDirectives(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "mosquitto", "tor")
	writeFixture(t, root, "etc/mosquitto/mosquitto.conf", "listener 1883 0.0.0.0\nallow_anonymous true\npassword_file /etc/mosquitto/canary-passwd\nconnection bridge1\nremote_password canary-bridge\n")
	writeFixture(t, root, "etc/tor/torrc", "SocksPort 0.0.0.0:9050\nTransPort 9040\nUseBridges 1\nBridge obfs4 canary-bridge-line\n")
	f.on("pidof mosquitto", "1\n")
	f.on("pidof tor", "2\n")
	all := body(t, "mosquitto") + body(t, "tor")
	mustNotContain(t, all, "canary")
	wantAll(t, all, "1883 0.0.0.0", "anonymous clients: allowed", "password file: set", "SocksPort: 0.0.0.0:9050", "bridges: in use")
}

func TestACMEShowsDaysLeftWithoutUsingTheConfigAsAPath(t *testing.T) {
	withFixtureRoot(t)
	acmeNow = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { acmeNow = time.Now })
	f := newFakeRouter(t)
	addRC(f, "acme")
	f.on("uci -q show acme", "acme.a=cert\nacme.a.domains='router.example.com'\nacme.a.validation_method='dns'\nacme.b=cert\nacme.b.domains='../../etc/shadow'\n")
	f.on("openssl x509 -noout -enddate -in /etc/ssl/acme/router.example.com.crt", "notAfter=Nov 11 12:00:00 2026 GMT\n")
	got := body(t, "acme")
	wantAll(t, got, "router.example.com: enabled, dns, 10 days left", "expiry unknown")
	for _, a := range f.argvList() {
		if strings.Contains(strings.Join(a, " "), "shadow") {
			t.Errorf("a config value reached argv: %v", a)
		}
	}
}

func TestNUTReadsFixedFieldsOnly(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "nut-monitor")
	f.on("pidof upsmon", "1\n")
	f.on("uci -q show nut_monitor", "nut_monitor.@master[0]=master\nnut_monitor.@master[0].upsname='myups'\nnut_monitor.@master[0].password='canary-nut'\n")
	f.on("upsc myups@localhost", "ups.status: OB DISCHRG\nbattery.charge: 80\nbattery.runtime: 900\nups.serial: canary-serial\n")
	got := body(t, "nut-monitor")
	mustNotContain(t, got, "canary")
	wantAll(t, got, "status: OB DISCHRG", "battery charge %: 80", "runtime (s): 900")
}

func TestWave3Findings(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "samba4")
	installAddonConfig(t, root, "transmission")
	f.on("uci -q show samba4", "samba4.@sambashare[0]=sambashare\nsamba4.@sambashare[0].name='media'\nsamba4.@sambashare[0].guest_ok='yes'\nsamba4.@sambashare[0].read_only='no'\n")
	f.on("uci -q show transmission", "transmission.transmission=transmission\ntransmission.transmission.enabled='1'\n")
	writeFixture(t, root, "etc/mosquitto/mosquitto.conf", "listener 1883\nallow_anonymous true\n")
	r := auditFindings(context.Background())
	for _, id := range []string{"smb-guest-writable", "rpc-open", "mosquitto-anonymous"} {
		if r.byID(id) == nil {
			t.Errorf("%s not flagged", id)
		}
	}
	writeFixture(t, root, "etc/mosquitto/mosquitto.conf", "listener 1883 127.0.0.1\nallow_anonymous true\n")
	f.on("uci -q show samba4", "samba4.@sambashare[0]=sambashare\nsamba4.@sambashare[0].guest_ok='yes'\nsamba4.@sambashare[0].read_only='yes'\n")
	f.on("uci -q show transmission", "transmission.transmission=transmission\ntransmission.transmission.enabled='1'\ntransmission.transmission.rpc_bind_address='127.0.0.1'\n")
	r = auditFindings(context.Background())
	for _, id := range []string{"smb-guest-writable", "rpc-open", "mosquitto-anonymous"} {
		if r.byID(id) != nil {
			t.Errorf("%s flagged on a safe config", id)
		}
	}
}

func TestDoctorFlagsAnExpiringCertificate(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "acme")
	acmeNow = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { acmeNow = time.Now })
	f.on("uci -q show acme", "acme.a=cert\nacme.a.domains='r.example.com'\n")
	f.on("openssl x509", "notAfter=Nov  5 12:00:00 2026 GMT\n")
	if healthFindings(context.Background()).byID("acme-expiring") == nil {
		t.Error("a certificate expiring in 4 days is not flagged")
	}
}
