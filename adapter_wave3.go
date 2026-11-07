package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Wave 3 (ROADMAP 9.5), first batch: file shares, download and media daemons, MQTT, Tor, ACME
// and NUT. Passwords, RPC secrets, certificates' private keys and user lists are never read or
// printed; the adapters say whether a secret is set and what the service is reachable from.

// ---------------------------------------------------------------- samba4 / ksmbd

func readShares(ctx context.Context, config, shareType, daemon string) string {
	lines := []string{running(ctx, daemon)}
	tree, err := uciShow(ctx, config, false)
	if err != nil {
		return strings.Join(append(lines, config+" config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	if ifs := tree.get(sambaMain(tree), "interface"); ifs != "" {
		lines = append(lines, "bound to: "+clip(ifs, 60))
	}
	shares := tree.sectionsOfType(shareType)
	lines = append(lines, fmt.Sprintf("shares (%d):", len(shares)))
	for i, s := range shares {
		if i == maxShown {
			lines = append(lines, fmt.Sprintf("  ... %d more", len(shares)-maxShown))
			break
		}
		lines = append(lines, fmt.Sprintf("  %s (%s): %s, %s", clip(tree.get(s, "name"), 40), clip(tree.get(s, "path"), 60),
			pick(smbGuest(tree, s), "guest access", "login required"), pick(smbReadOnly(tree, s), "read-only", "writable")))
	}
	return strings.Join(lines, "\n")
}

func sambaMain(t *uciTree) string {
	for _, typ := range []string{"samba", "globals"} {
		if s := t.sectionsOfType(typ); len(s) > 0 {
			return s[0]
		}
	}
	return ""
}

func smbGuest(t *uciTree, s string) bool {
	return uciFlag(t.get(s, "guest_ok"), false) || strings.EqualFold(t.get(s, "guest_ok"), "yes")
}

func smbReadOnly(t *uciTree, s string) bool { return uciFlag(t.get(s, "read_only"), false) }

func readSamba4(ctx context.Context) string { return readShares(ctx, "samba4", "sambashare", "smbd") }
func readKsmbd(ctx context.Context) string  { return readShares(ctx, "ksmbd", "share", "ksmbd.mountd") }

// ---------------------------------------------------------------- transmission, aria2, minidlna

func readTransmission(ctx context.Context) string {
	lines := []string{running(ctx, "transmission-daemon")}
	tree, err := uciShow(ctx, "transmission", false)
	if err != nil {
		return strings.Join(append(lines, "transmission config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	s := "transmission"
	bind := tree.get(s, "rpc_bind_address")
	lines = append(lines,
		"RPC: "+pick(bind != "", clip(bind, 40), "0.0.0.0")+":"+pick(tree.get(s, "rpc_port") != "", clip(tree.get(s, "rpc_port"), 6), "9091"),
		"RPC authentication: "+pick(uciFlag(tree.get(s, "rpc_authentication_required"), false), "required", "not required"),
		"RPC whitelist: "+pick(uciFlag(tree.get(s, "rpc_whitelist_enabled"), false), "on", "off"))
	return strings.Join(lines, "\n")
}

func readAria2(ctx context.Context) string {
	lines := []string{running(ctx, "aria2c")}
	tree, err := uciShow(ctx, "aria2", false)
	if err != nil {
		return strings.Join(append(lines, "aria2 config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	lines = append(lines,
		"RPC listens on: "+pick(uciFlag(tree.get("main", "rpc_listen_all"), false), "all addresses", "loopback"),
		"RPC port: "+pick(tree.get("main", "rpc_listen_port") != "", clip(tree.get("main", "rpc_listen_port"), 6), "6800"),
		"RPC secret: "+pick(tree.get("main", "rpc_secret") != "", "set (not shown)", "not set"))
	return strings.Join(lines, "\n")
}

func readMiniDLNA(ctx context.Context) string {
	lines := []string{running(ctx, "minidlnad")}
	tree, err := uciShow(ctx, "minidlna", false)
	if err != nil {
		return strings.Join(append(lines, "minidlna config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	dirs := tree.list("config", "media_dir")
	lines = append(lines, "interface: "+pick(tree.get("config", "interface") != "", clip(tree.get("config", "interface"), 20), "all"),
		"port: "+pick(tree.get("config", "port") != "", clip(tree.get("config", "port"), 6), "8200"), fmt.Sprintf("media directories: %d", len(dirs)))
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- mosquitto, tor (text config)

// confDirectives collects, per directive, the values of a plain `key value` config file. Only
// the directives asked for are kept, so no other line (password_file paths, bridge secrets)
// is ever carried further.
func confDirectives(path string, keys ...string) map[string][]string {
	text, err := readSys(path)
	out := map[string][]string{}
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, " ")
		for _, w := range keys {
			if strings.EqualFold(k, w) {
				out[w] = append(out[w], strings.TrimSpace(v))
			}
		}
	}
	return out
}

const mosquittoConf = "/etc/mosquitto/mosquitto.conf"

func readMosquitto(ctx context.Context) string {
	lines := []string{running(ctx, "mosquitto")}
	d := confDirectives(mosquittoConf, "listener", "allow_anonymous", "password_file", "cafile", "certfile")
	if d == nil {
		return strings.Join(append(lines, "main config file not readable; conf.d includes are not followed"), "\n")
	}
	ls := d["listener"]
	if len(ls) == 0 {
		ls = []string{"1883 (default, loopback only)"}
	}
	lines = append(lines, fmt.Sprintf("listeners (%d):", len(ls)))
	for _, l := range ls {
		lines = append(lines, "  "+clip(l, 60))
	}
	anon := "default (denied)"
	if v := d["allow_anonymous"]; len(v) > 0 {
		anon = pick(strings.EqualFold(v[len(v)-1], "true"), "allowed", "denied")
	}
	lines = append(lines, "anonymous clients: "+anon, "password file: "+pick(len(d["password_file"]) > 0, "set", "not set"),
		"TLS: "+pick(len(d["certfile"]) > 0 || len(d["cafile"]) > 0, "configured", "not configured"))
	return strings.Join(lines, "\n")
}

func readTor(ctx context.Context) string {
	lines := []string{running(ctx, "tor")}
	d := confDirectives("/etc/tor/torrc", "SocksPort", "TransPort", "DNSPort", "ControlPort", "UseBridges")
	if d == nil {
		return strings.Join(append(lines, "torrc not readable"), "\n")
	}
	for _, k := range []string{"SocksPort", "TransPort", "DNSPort", "ControlPort"} {
		if v := d[k]; len(v) > 0 {
			lines = append(lines, k+": "+clip(strings.Join(v, ", "), 80))
		}
	}
	lines = append(lines, "bridges: "+pick(len(d["UseBridges"]) > 0 && d["UseBridges"][0] == "1", "in use (lines not shown)", "none"))
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- acme

var reDomain = lazyRegexp(`^[A-Za-z0-9*][A-Za-z0-9.*-]{0,251}$`)

func readACME(ctx context.Context) string {
	lines := []string{"acme: renewals run from cron (acme.sh)"}
	tree, err := uciShow(ctx, "acme", false)
	if err != nil {
		return strings.Join(append(lines, "acme config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	certs := tree.sectionsOfType("cert")
	lines = append(lines, fmt.Sprintf("certificates (%d):", len(certs)))
	for i, s := range certs {
		if i == maxShown {
			break
		}
		dom := tree.list(s, "domains")
		name := "(no domain)"
		if len(dom) > 0 {
			name = clip(dom[0], 60)
		}
		days, ok := certDaysLeft(ctx, dom)
		exp := "expiry unknown"
		if ok {
			exp = fmt.Sprintf("%d days left", days)
			if days < 0 {
				exp = fmt.Sprintf("expired %d days ago", -days)
			}
		}
		lines = append(lines, fmt.Sprintf("  %s: %s, %s, %s", name, pick(uciFlag(tree.get(s, "enabled"), true), "enabled", "disabled"), clip(tree.get(s, "validation_method"), 12), exp))
	}
	return strings.Join(lines, "\n")
}

var acmeNow = time.Now

// certDaysLeft reads the expiry of the certificate acme.sh stores for the first domain. The path
// is built from a validated domain name, never from the config's free text.
func certDaysLeft(ctx context.Context, domains []string) (int, bool) {
	if len(domains) == 0 || !reDomain.MatchString(domains[0]) || strings.Contains(domains[0], "..") {
		return 0, false
	}
	dom := strings.TrimPrefix(domains[0], "*.")
	out, err := run(ctx, defaultCmdTimeout, "openssl", "x509", "-noout", "-enddate", "-in", "/etc/ssl/acme/"+dom+".crt")
	if err != nil {
		return 0, false
	}
	_, v, ok := strings.Cut(strings.TrimSpace(out), "notAfter=")
	if !ok {
		return 0, false
	}
	t, err := time.Parse("Jan _2 15:04:05 2006 MST", strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return int(t.Sub(acmeNow()).Hours() / 24), true
}

// ---------------------------------------------------------------- nut

func readNUT(ctx context.Context) string {
	lines := []string{running(ctx, "upsmon")}
	tree, err := uciShow(ctx, "nut_monitor", false)
	if err != nil {
		return strings.Join(append(lines, "nut_monitor config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	ups := ""
	for _, s := range tree.sectionsOfType("master") {
		ups = tree.get(s, "upsname")
		break
	}
	if !uciName.MatchString(ups) {
		return strings.Join(append(lines, "no UPS monitored (no master section with a usable name)"), "\n")
	}
	out, err := run(ctx, defaultCmdTimeout, "upsc", ups+"@localhost")
	if err != nil {
		return strings.Join(append(lines, "upsc does not answer for "+ups+": "+clip(firstLine(strings.TrimSpace(out+" "+err.Error())), 100)), "\n")
	}
	want := map[string]string{"ups.status": "status", "battery.charge": "battery charge %", "battery.runtime": "runtime (s)", "ups.load": "load %"}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if label, hit := want[k]; ok && hit {
			lines = append(lines, fmt.Sprintf("%s: %s", label, clip(strings.TrimSpace(v), 30)))
		}
	}
	return strings.Join(lines, "\n")
}
