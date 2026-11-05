package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Who answers on an exposed port and whether it asks for a login (ROADMAP 9.3, exposure view).
// The owner comes from /proc: the inode in /proc/net/tcp or udp, matched to the socket link in
// /proc/<pid>/fd, then the process name from /proc/<pid>/comm. When /proc cannot be read, or the
// process is not one this file knows, the entry carries no note rather than a guess.

const maxProcScan = 600

// socketOwners maps a socket inode to the name of the process that holds it.
func socketOwners() map[string]string {
	out := map[string]string{}
	procs, err := filepath.Glob(sysPath("/proc/[0-9]*"))
	if err != nil {
		return out
	}
	if len(procs) > maxProcScan {
		procs = procs[:maxProcScan]
	}
	for _, p := range procs {
		fds, err := os.ReadDir(filepath.Join(p, "fd"))
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(p, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if name == "" {
				b, err := os.ReadFile(filepath.Join(p, "comm"))
				if err != nil {
					break
				}
				name = strings.TrimSpace(string(b))
			}
			out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = name
		}
	}
	return out
}

// listenerAuth says what the process behind a port asks for. login is false only when the service
// accepts a client with no credential at all; DNS and UPnP are open by design and say so.
func listenerAuth(sn *snapshot, comm string, port int) (note string, login bool) {
	switch comm {
	case "dropbear":
		db, err := sn.getUCI("dropbear")
		if err != nil {
			return "", true
		}
		for _, s := range db.sectionsOfType("dropbear") {
			if p, _ := strconv.Atoi(orDefault(db.get(s, "Port"), "22")); p == port {
				return "dropbear: " + pick(uciOff(db.get(s, "PasswordAuth")), "key login only", "password login allowed"), true
			}
		}
		return "dropbear: key or password login", true
	case "uhttpd":
		return "uhttpd: LuCI login (static files need none)", true
	case "miniupnpd":
		return "miniupnpd: no login, any host may ask for a mapping", false
	case "dnsmasq":
		return "dnsmasq: no login (DNS)", true // answering DNS is its job; other checks look at who may ask
	case "ttyd":
		if !addonInstalled("ttyd") {
			return "", true
		}
		t, err := sn.getUCI("ttyd")
		if err != nil {
			return "", true
		}
		for _, s := range t.sectionsOfType("ttyd") {
			if p, _ := strconv.Atoi(orDefault(t.get(s, "port"), "7681")); p != port {
				continue
			}
			if t.get(s, "credential") != "" || ttydRunsLogin(t.get(s, "command")) {
				return "ttyd: login", true
			}
			return "ttyd: shell with no login", false
		}
	case "smbd", "ksmbd.mountd":
		for _, c := range []struct{ cfg, typ string }{{"samba4", "sambashare"}, {"ksmbd", "share"}} {
			if !addonInstalled(c.cfg) {
				continue
			}
			t, err := sn.getUCI(c.cfg)
			if err != nil {
				continue
			}
			for _, s := range t.sectionsOfType(c.typ) {
				if smbGuest(t, s) {
					return comm + ": guest shares need no login", false
				}
			}
		}
		return comm + ": login", true
	case "transmission-daemon":
		if addonInstalled("transmission") {
			if t, err := sn.getUCI("transmission"); err == nil {
				if uciFlag(t.get("transmission", "rpc_authentication_required"), false) {
					return "transmission: RPC login", true
				}
				return "transmission: RPC with no login", false
			}
		}
	case "aria2c":
		if addonInstalled("aria2") {
			if t, err := sn.getUCI("aria2"); err == nil {
				if t.get("main", "rpc_secret") != "" {
					return "aria2: RPC secret set", true
				}
				return "aria2: RPC with no secret", false
			}
		}
	case "mosquitto":
		if d := confDirectives(mosquittoConf, "allow_anonymous"); d != nil {
			if v := d["allow_anonymous"]; len(v) > 0 && strings.EqualFold(v[len(v)-1], "true") {
				return "mosquitto: anonymous clients accepted", false
			}
		}
		return "mosquitto: login", true
	}
	return "", true
}
