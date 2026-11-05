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

func TestWave3SecondBatch(t *testing.T) {
	root := withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "wifischedule", "vnstat", "hd-idle", "keepalived", "lldpd", "nlbwmon")
	writeFixture(t, root, "dev/sda", "")
	f.on("uci -q show wifi_schedule", "wifi_schedule.global=global\nwifi_schedule.global.enabled='1'\nwifi_schedule.e1=entry\nwifi_schedule.e1.enabled='1'\nwifi_schedule.e1.daysofweek='Monday' 'Tuesday'\nwifi_schedule.e1.starttime='07:00'\nwifi_schedule.e1.stoptime='23:00'\n")
	f.on("pidof vnstatd", "1\n")
	f.on("uci -q show vnstat", "vnstat.@vnstat[0]=vnstat\nvnstat.@vnstat[0].interface='br-lan' 'wan'\n")
	f.on("pidof hd-idle", "2\n")
	f.on("uci -q show hd-idle", "hd-idle.@hd-idle[0]=hd-idle\nhd-idle.@hd-idle[0].disk='sda'\nhd-idle.@hd-idle[0].enabled='1'\nhd-idle.@hd-idle[0].idle_time_interval='600'\nhd-idle.@hd-idle[1]=hd-idle\nhd-idle.@hd-idle[1].disk='sdb'\n")
	f.on("pidof keepalived", "3\n")
	f.on("uci -q show keepalived", "keepalived.vi=vrrp_instance\nkeepalived.vi.name='VI_1'\nkeepalived.vi.state='MASTER'\nkeepalived.vi.priority='100'\nkeepalived.vi.interface='br-lan'\nkeepalived.vi.auth_pass='canary-vrrp'\n")
	f.on("pidof lldpd", "4\n")
	f.on("lldpcli -f json show neighbors", `{"lldp":{"interface":{"lan1":{"chassis":{"canary-switch":{}}},"lan3":{}}}}`)
	f.on("pidof nlbwmon", "5\n")
	f.on("uci -q show nlbwmon", "nlbwmon.@nlbwmon[0]=nlbwmon\n")
	all := ""
	for _, s := range []string{"wifischedule", "vnstat", "hd-idle", "keepalived", "lldpd", "nlbwmon"} {
		all += body(t, s) + "\n"
	}
	mustNotContain(t, all, "canary")
	wantAll(t, all, "e1: enabled, days Monday Tuesday, on 07:00, off 23:00", "tracked interfaces: br-lan, wan", "sda: enabled, idle after 600s, present", "sdb: disabled, idle after ?s, not present",
		"VI_1: configured state MASTER, priority 100, interface br-lan, auth set", "local ports with a neighbour (2): lan1, lan3", "/var/lib/nlbwmon, in RAM, lost on reboot")
}

func TestDoctorFlagsTheTrafficDatabaseInRAM(t *testing.T) {
	f, root := wave1Router(t)
	installAddonConfig(t, root, "nlbwmon")
	f.on("ubus call rc list", `{"nlbwmon":{"enabled":true,"running":true,"start":50,"stop":4}}`)
	f.on("uci -q show nlbwmon", "nlbwmon.@nlbwmon[0]=nlbwmon\n")
	if healthFindings(context.Background()).byID("stats-db-in-ram") == nil {
		t.Error("RAM database not flagged")
	}
	f.on("uci -q show nlbwmon", "nlbwmon.@nlbwmon[0]=nlbwmon\nnlbwmon.@nlbwmon[0].database_directory='/mnt/usb/nlbwmon'\n")
	if healthFindings(context.Background()).byID("stats-db-in-ram") != nil {
		t.Error("a database on a disk is flagged")
	}
}

// Wave 4 (best effort): status only, no names, links or secrets.
func TestWave4StacksReportStatusAndNeverNodesOrSecrets(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall", "openclash", "zapret", "homeproxy")
	f.on("pidof xray", "10\n")
	f.on("pidof sing-box", "")
	f.on("nft list table inet passwall", "table inet passwall {}\n")
	f.on("uci -q show passwall", "passwall.@global[0]=global\npasswall.@global[0].enabled='1'\npasswall.@global[0].dns_mode='tcp'\npasswall.n1=nodes\npasswall.n1.remarks='canary-node-name'\npasswall.n1.address='canary.example'\npasswall.s1=shunt_rules\n")
	f.on("pidof clash", "11\n")
	f.on("uci -q show openclash", "openclash.config=openclash\nopenclash.config.enable='1'\nopenclash.config.en_mode='fake-ip'\nopenclash.config.dashboard_password='canary-dash'\nopenclash.@config_subscribe[0]=config_subscribe\nopenclash.@config_subscribe[0].address='https://canary.example/sub?token=x'\n")
	f.on("pidof nfqws", "")
	f.on("pidof tpws", "")
	f.on("nft list table inet zapret", "")
	f.fail("nft list table inet zapret", "no such table")
	f.on("uci -q show homeproxy", "homeproxy.config=homeproxy\nhomeproxy.config.routing_mode='bypass_mainland_china'\nhomeproxy.n1=node\nhomeproxy.n1.label='canary-label'\n")
	all := ""
	for _, s := range []string{"passwall", "openclash", "zapret", "homeproxy"} {
		all += body(t, s) + "\n"
	}
	mustNotContain(t, all, "canary", "token=")
	wantAll(t, all, "xray: running, pid 10", "nft table passwall: loaded", "DNS mode: tcp", "nodes: 1", "shunt rules: 1", "mode: fake-ip", "dashboard secret: set (not shown)",
		"subscriptions: 1", "nft table zapret: not loaded", "routing mode: bypass_mainland_china")
}

// Option and table names taken from the upstream default configs and init scripts (passwall2
// 26.11.3, nikki 1.26.2), which differ from passwall: passwall2 has no dns_mode, nikki loads inet nikki.
func TestWave4Passwall2AndNikkiUseUpstreamNames(t *testing.T) {
	withFixtureRoot(t)
	f := newFakeRouter(t)
	addRC(f, "passwall2", "nikki")
	f.on("pidof xray", "")
	f.on("pidof sing-box", "")
	f.on("nft list table inet passwall2", "table inet passwall2 {}\n")
	f.on("uci -q show passwall2", "passwall2.@global[0]=global\npasswall2.@global[0].enabled='1'\npasswall2.@global[0].remote_dns_protocol='tcp'\n")
	f.on("pidof mihomo", "12\n")
	f.on("nft list table inet nikki", "table inet nikki {}\n")
	f.on("uci -q show nikki", "nikki.config=config\nnikki.config.enabled='1'\nnikki.proxy=proxy\nnikki.proxy.tcp_mode='redirect'\n")
	all := body(t, "passwall2") + "\n" + body(t, "nikki")
	wantAll(t, all, "remote DNS protocol: tcp", "nft table passwall2: loaded", "nft table nikki: loaded", "TCP mode: redirect")
}
