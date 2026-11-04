package main

import (
	"context"
	"fmt"
	"strings"
)

// ttyd is a web terminal: whoever reaches its port gets a shell as the user it runs as, usually
// root. The status is therefore about exposure: which interface it listens on, whether a
// credential is set (never its value; `credential` is "user:password"), and TLS.

func readTTYD(ctx context.Context) string {
	var lines []string
	if out, err := run(ctx, defaultCmdTimeout, "pidof", "ttyd"); err == nil && pidText(out) != "" {
		lines = append(lines, "ttyd: running, "+pidText(out))
	} else {
		lines = append(lines, "ttyd: not running")
	}
	tree, err := uciShow(ctx, "ttyd", false)
	if err != nil {
		return strings.Join(append(lines, "ttyd config unreadable: "+clip(err.Error(), 160)), "\n")
	}
	secs := tree.sectionsOfType("ttyd")
	if len(secs) == 0 {
		return strings.Join(append(lines, "instances (0)"), "\n")
	}
	lines = append(lines, fmt.Sprintf("instances (%d):", len(secs)))
	for _, s := range secs {
		lines = append(lines, ttydInstance(tree, s))
	}
	return strings.Join(lines, "\n")
}

func ttydInstance(t *uciTree, s string) string {
	port := clip(t.get(s, "port"), 6)
	if port == "" {
		port = "7681"
	}
	iface, open := clip(t.get(s, "interface"), 40), false
	switch {
	case iface == "":
		iface, open = "all interfaces", true
	case strings.HasPrefix(iface, "@"):
		iface = "network " + iface[1:]
	}
	creds := t.get(s, "credential") != ""
	parts := []string{"port " + port, "listens on " + iface, "login: " + pick(creds, "credential set", "none"),
		"tls " + pick(uciFlag(t.get(s, "ssl"), false), "on", "off"), pick(uciFlag(t.get(s, "readonly"), false), "read-only", "read-write")}
	if !uciFlag(t.get(s, "enable"), true) {
		parts = append(parts, "disabled")
	}
	if cmd := strings.Fields(t.get(s, "command")); len(cmd) > 0 {
		parts = append(parts, "runs "+clip(cmd[0], 40))
	}
	line := clip(s, 40) + ": " + strings.Join(parts, ", ")
	switch {
	case open && !creds:
		line += "; WARNING: a shell on every interface with no credential, reachable from WAN unless the firewall blocks port " + port
	case open:
		line += "; listens on every interface: check the firewall does not allow port " + port + " from WAN"
	case !creds:
		line += "; no credential: any host on " + iface + " gets a shell"
	}
	return line
}
