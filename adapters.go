package main

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Add-on adapters: `service_list detail=<service>` returns a defined, read-only status for a
// popular add-on, so a model need not know that tailscale wants `tailscale status --json` or that
// AdGuard Home keeps its settings in a YAML file next to a login hash.
//
// An adapter is a fixed set of reads and a renderer. It applies when the add-on's init script
// exists (the rc listing already enumerates /etc/init.d, so no package manager is involved), and
// the tool list stays flat: there is one tool, and the plain listing names the adapters that
// apply on this router.
//
// Rules every adapter follows:
//   - It runs only read commands, with argv built by the code, never from the caller's input.
//   - It prints fixed fields extracted by name. It never echoes a config file or a command's
//     output, because those hold credentials (login hashes, proxy links, node keys, tokens in
//     upstream URLs) that no masker could be trusted to find in free text.
//   - Text that someone other than the operator chose (a tailnet peer's host name) is clipped,
//     sanitised, and the result is marked untrusted.
//   - It never fails the call: an add-on that does not answer is itself a status.
type adapter struct {
	service   string
	untrusted string // the third-party text the output carries ("" if it is all the operator's own)
	read      func(ctx context.Context) string
}

// adapters is sorted by service name; the listing and the "available here" line follow it.
var adapters = []adapter{
	{"adguardhome", "", readAdGuardHome},
	{"podkop", "", readPodkop},
	{"tailscale", "tailnet host names", readTailscale},
}

func adapterFor(service string) (adapter, bool) {
	for _, a := range adapters {
		if a.service == service {
			return a, true
		}
	}
	return adapter{}, false
}

// adaptersHere are the adapters whose init script is on this router.
func adaptersHere(rc map[string]rcEntry) []string {
	var out []string
	for _, a := range adapters {
		if _, ok := rc[a.service]; ok {
			out = append(out, a.service)
		}
	}
	return out
}

func serviceHeader() string {
	return fmt.Sprintf("%-24s %-9s %-8s %s", "SERVICE", "BOOT", "STATE", "START/STOP")
}

func serviceRow(name string, e rcEntry) string {
	boot, state := "disabled", "stopped"
	if e.Enabled {
		boot = "enabled"
	}
	if e.Running {
		state = "running"
	}
	return fmt.Sprintf("%-24s %-9s %-8s %d/%d", name, boot, state, e.Start, e.Stop)
}

// serviceDetail is the result of service_list detail=name: the service's own row, then what the
// adapter says.
func serviceDetail(ctx context.Context, rc map[string]rcEntry, name string) (string, string, error) {
	e, ok := rc[name]
	if !ok {
		return "", "", fmt.Errorf("no init script %q (see service_list)", name)
	}
	var b strings.Builder
	b.WriteString(serviceHeader() + "\n" + serviceRow(name, e) + "\n\n")
	a, has := adapterFor(name)
	if !has {
		here := strings.Join(adaptersHere(rc), ", ")
		if here == "" {
			here = "none"
		}
		fmt.Fprintf(&b, "no add-on status for %s; available here: %s", name, here)
		return b.String(), "service " + name, nil
	}
	b.WriteString(strings.TrimRight(a.read(ctx), "\n"))
	text := b.String()
	if a.untrusted != "" {
		text = untrustedMarker(a.untrusted) + "\n" + text
	}
	return text, "service detail " + name, nil
}

// ---------------------------------------------------------------- helpers shared by adapters

// clip makes a third-party or config string safe to print: no control or format characters, one
// line, at most n characters.
func clip(s string, n int) string {
	s = strings.Join(strings.Fields(sanitizeText(s)), " ")
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// pidText turns `pidof` output into "pid 8330" or "pids 12 34".
func pidText(out string) string {
	f := strings.Fields(out)
	if len(f) == 0 {
		return ""
	}
	if len(f) > 4 {
		f = f[:4]
	}
	if len(f) == 1 {
		return "pid " + clip(f[0], 10)
	}
	return "pids " + clip(strings.Join(f, " "), 40)
}

// dnsmasqServers reads dnsmasq's upstream servers (dhcp.@dnsmasq[0].server), the first thing to
// check when asking whether an add-on is in the DNS path. Empty when none is set.
func dnsmasqServers(ctx context.Context) []string {
	out, err := run(ctx, defaultCmdTimeout, "uci", "-q", "get", "dhcp.@dnsmasq[0].server")
	if err != nil {
		return nil
	}
	f := strings.Fields(out)
	if len(f) > 8 {
		f = f[:8]
	}
	for i := range f {
		f[i] = clip(f[i], 60)
	}
	return f
}
