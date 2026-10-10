package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// AdGuard Home: its web API needs the UI login, which this tool must not hold, so the status
// comes from the process table and from the config file. That file also holds the login hash,
// upstream URLs with tokens in them, DNS rewrites, client names and MACs, and the TLS key; the
// summary below picks fixed keys out of it and prints nothing else.

const (
	agDefaultConfig = "/etc/adguardhome/adguardhome.yaml"
	agMaxConfig     = 2 << 20
	agMaxUpstreams  = 8
)

// reAGConfigPath is what the config_file option must look like to be opened: it is
// root-writable configuration, and what it names is read.
var reAGConfigPath = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+\.ya?ml$`)

func readAdGuardHome(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "AdGuardHome"); err == nil && pidText(out) != "" {
		lines = append(lines, "AdGuard Home: running, "+pidText(out))
	} else {
		lines = append(lines, "AdGuard Home: not running")
	}

	path := agDefaultConfig
	if out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "adguardhome.config.config_file"); err == nil {
		if p := strings.TrimSpace(out); p != "" {
			path = p
		}
	}
	port := ""
	switch {
	case !reAGConfigPath.MatchString(path) || strings.Contains(path, ".."):
		lines = append(lines, "config_file option is not an absolute path to a .yaml file; not read")
	default:
		if fi, err := os.Stat(sysPath(path)); err == nil && fi.Size() > agMaxConfig {
			lines = append(lines, "config too large to read (over 2 MiB)")
			break
		}
		text, err := readSys(path)
		if err != nil {
			lines = append(lines, "config unreadable: "+clip(err.Error(), 160))
			break
		}
		var cfg []string
		cfg, port = summariseAdGuardHome(path, text)
		lines = append(lines, cfg...)
	}

	servers := dnsmasqServers(ctx)
	if len(servers) == 0 {
		lines = append(lines, "dnsmasq upstream servers: (none set)")
	} else {
		for i, s := range servers {
			if port != "" && strings.HasSuffix(s, "#"+port) {
				servers[i] = s + " (AdGuard Home)"
			}
		}
		lines = append(lines, "dnsmasq upstream servers: "+strings.Join(servers, ", "))
	}
	return strings.Join(lines, "\n")
}

// summariseAdGuardHome renders the config lines of the status and returns AdGuard Home's DNS
// port for the dnsmasq comparison.
func summariseAdGuardHome(path, text string) (lines []string, port string) {
	y := parseYAML(text)
	cfg := "config: " + clip(path, 120)
	if v := y.val("schema_version"); v != "" {
		cfg += ", schema " + clip(v, 10)
	}
	lines = append(lines, cfg)
	if v := y.val("http.address"); v != "" {
		lines = append(lines, "web UI: "+clip(v, 80))
	}

	port = clip(y.val("dns.port"), 6)
	if hosts := y.list("dns.bind_hosts"); port == "" {
		lines = append(lines, "dns: listen port not found in the config")
	} else if len(hosts) == 0 {
		lines = append(lines, "dns: listens on port "+port)
	} else {
		bound := make([]string, 0, len(hosts))
		for _, h := range hosts {
			h = clip(h, 45)
			if strings.Contains(h, ":") {
				h = "[" + h + "]"
			}
			bound = append(bound, h+":"+port)
		}
		lines = append(lines, "dns: listens on "+strings.Join(bound, ", "))
	}

	if v, ok := y.flag("filtering.protection_enabled"); ok {
		p := "protection: on"
		if !v {
			p = "protection: OFF"
			if until := y.val("filtering.protection_disabled_until"); until != "" && until != "null" && until != "~" {
				p += " until " + clip(until, 40)
			}
		}
		for _, f := range []struct{ key, name string }{
			{"filtering.filtering_enabled", "filtering"},
			{"filtering.safebrowsing_enabled", "safe browsing"},
			{"filtering.parental_enabled", "parental"},
		} {
			if v, ok := y.flag(f.key); ok {
				p += ", " + f.name + " " + onOff(v)
			}
		}
		lines = append(lines, p)
	}

	ups := y.list("dns.upstream_dns")
	head := fmt.Sprintf("upstreams (%d)", len(ups))
	if len(ups) > 0 {
		shown := make([]string, 0, agMaxUpstreams+1)
		for i, u := range ups {
			if i == agMaxUpstreams {
				shown = append(shown, fmt.Sprintf("+%d more", len(ups)-agMaxUpstreams))
				break
			}
			shown = append(shown, upstreamLabel(u))
		}
		head += ": " + strings.Join(shown, ", ")
	}
	lines = append(lines, head)
	if f := y.val("dns.upstream_dns_file"); f != "" {
		lines = append(lines, "upstream file: "+clip(f, 120))
	}
	if boot := y.list("dns.bootstrap_dns"); len(boot) > 0 {
		for i := range boot {
			boot[i] = clip(boot[i], 45)
		}
		lines = append(lines, "bootstrap: "+strings.Join(boot, ", "))
	}

	enabled := 0
	filters := y.items("filters")
	for _, f := range filters {
		if f["enabled"] == "true" {
			enabled++
		}
	}
	rules := y.list("user_rules")
	active := 0
	for _, r := range rules {
		if r != "" && !strings.HasPrefix(r, "#") && !strings.HasPrefix(r, "!") {
			active++
		}
	}
	lines = append(lines, fmt.Sprintf("filter lists: %d of %d enabled; custom rules: %d active of %d", enabled, len(filters), active, len(rules)))

	var feats []string
	for _, f := range []struct{ key, name string }{
		{"querylog.enabled", "query log"}, {"statistics.enabled", "statistics"},
		{"dns.cache_enabled", "cache"}, {"dns.enable_dnssec", "dnssec"},
	} {
		if v, ok := y.flag(f.key); ok {
			feats = append(feats, f.name+": "+onOff(v))
		}
	}
	if len(feats) > 0 {
		lines = append(lines, strings.Join(feats, ", "))
	}
	return lines, port
}

// upstreamLabel keeps what tells upstreams apart (scheme, host, port, and a domain scope in
// front) and drops what is only ever a secret: user info, the path and query of a DoH URL (a
// profile id or token), and the body of a DNS stamp.
func upstreamLabel(u string) string {
	u = strings.TrimSpace(u)
	prefix := ""
	if strings.HasPrefix(u, "[/") {
		if i := strings.Index(u, "]"); i > 0 {
			prefix, u = u[:i+1], u[i+1:]
		}
	}
	switch {
	case strings.HasPrefix(u, "sdns://"):
		u = "sdns://(stamp)"
	default:
		if i := strings.Index(u, "://"); i > 0 {
			scheme, rest := u[:i], u[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j >= 0 {
				rest = rest[:j]
			}
			if at := strings.LastIndex(rest, "@"); at >= 0 {
				rest = rest[at+1:]
			}
			u = scheme + "://" + rest
		}
	}
	return clip(prefix+u, 80)
}
