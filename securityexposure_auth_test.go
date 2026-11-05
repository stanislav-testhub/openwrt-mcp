package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// holdSocket makes /proc/<pid>/{comm,fd/3} for a process that owns the socket inode.
func holdSocket(t *testing.T, pid, comm, inode string) {
	t.Helper()
	dir := filepath.Join(sysRoot, "proc", pid)
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, sysRoot, "proc/"+pid+"/comm", comm+"\n")
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, "fd", "3")); err != nil {
		t.Fatal(err)
	}
}

// The exposure view names the process behind each reachable port and whether it asks for a login,
// and lists UPnP mappings next to the firewall forwards.
func TestAuditExposureViewNamesTheOwnerAndItsLoginAndListsUPnPMappings(t *testing.T) {
	a := newAuditFixture()
	a.upnpd = "upnpd.config=upnpd\nupnpd.config.enabled='1'\nupnpd.config.secure_mode='1'\n"
	a.firewall += `firewall.@rule[3]=rule
firewall.@rule[3].name='Allow-Mgmt'
firewall.@rule[3].src='wan'
firewall.@rule[3].proto='tcp udp'
firewall.@rule[3].dest_port='22 80 5000 1900'
firewall.@rule[3].target='ACCEPT'
`
	f := a.install(t)
	writeFixture(t, sysRoot, "proc/net/tcp", "  sl  local_address rem_address   st tx rx tr retr uid timeout inode\n"+
		"   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1001\n"+
		"   1: 00000000:0050 00000000:0000 0A 0:0 0:0 0 0 0 1002\n"+
		"   2: 00000000:1388 00000000:0000 0A 0:0 0:0 0 0 0 1003\n")
	writeFixture(t, sysRoot, "proc/net/udp", "  sl  local_address rem_address   st tx rx tr retr uid timeout inode\n"+
		"   0: 00000000:076C 00000000:0000 07 0:0 0:0 0 0 0 1004\n")
	holdSocket(t, "100", "dropbear", "1001")
	holdSocket(t, "101", "uhttpd", "1002")
	holdSocket(t, "102", "transmission-daemon", "1003")
	holdSocket(t, "103", "miniupnpd", "1004")
	writeFixture(t, sysRoot, "etc/config/transmission", "x")
	f.on("uci -q show transmission", "transmission.transmission=transmission\ntransmission.transmission.enabled='1'\n")
	writeFixture(t, sysRoot, "var/run/miniupnpd.leases", "TCP:8080:192.0.2.50:80:0:web\x1b[31m cam\nUDP:9000:192.0.2.51:9000:0:\n")
	out := auditFindings(context.Background()).render()
	wantAll(t, out, "wan-exposure", "tcp/22 (rule \"Allow-Mgmt\"; dropbear: key login only)", "uhttpd: LuCI login",
		"transmission", "UPnP tcp 8080 -> 192.0.2.50:80", "UPnP udp 9000 -> 192.0.2.51:9000", "answers with no login")
	mustNotContain(t, out, "\x1b")
}
