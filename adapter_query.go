package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

// Query layer of the adapter contract (ROADMAP 9.1): one bounded lookup per adapter. The value
// arrives validated and lower-cased (cleanQuery), and no query prints a list's contents: it says
// whether the value matched and where, which is what "why is this blocked" needs.

const (
	maxQuerySets = 40
	maxScanBytes = 64 << 20
)

var adblockFastLists = []struct{ file, label string }{
	{"/var/run/adblock-fast/dnsmasq.servers", "dnsmasq.servers"},
	{"/var/run/adblock-fast/dnsmasq.addnhosts", "dnsmasq.addnhosts"},
	{"/var/run/adblock-fast/dnsmasq.conf", "dnsmasq.conf"},
}

// domainChain is the name and each parent that still has a dot: dnsmasq blocks a name's
// subdomains, so ads.example.com is also blocked by an entry for example.com.
func domainChain(d string) []string {
	out := []string{d}
	for {
		i := strings.Index(d, ".")
		if i < 0 {
			return out
		}
		d = d[i+1:]
		if !strings.Contains(d, ".") {
			return out
		}
		out = append(out, d)
	}
}

func queryAdblockFast(ctx context.Context, domain string) string {
	chain := domainChain(domain)
	var lines []string
	if tree, err := uciShow(ctx, "adblock-fast", false); err == nil {
		for _, a := range tree.list("config", "allowed_domain") {
			for _, c := range chain {
				if strings.EqualFold(a, c) {
					lines = append(lines, "allowed: "+c+" is in allowed_domain, so it is not blocked")
				}
			}
		}
	}
	scanned := false
	for _, l := range adblockFastLists {
		hit, ok := scanBlockList(l.file, chain)
		if !ok {
			continue
		}
		scanned = true
		if hit != "" {
			lines = append(lines, fmt.Sprintf("blocked: %s matches an entry for %s in %s", domain, hit, l.label))
		}
	}
	switch {
	case !scanned:
		return "no block list is loaded (adblock-fast has not produced one since boot); status: service_list detail=adblock-fast"
	case len(lines) == 0:
		return "not blocked: " + domain + " is in none of the loaded lists"
	}
	return strings.Join(lines, "\n")
}

// blockedName is the domain a list line blocks: `server=/name/` or `local=/name/` (with no upstream), `address=/name/...` or a hosts
// line `127.0.0.1 name` (`:: name` for IPv6). "" for anything else.
func blockedName(line string) string {
	for _, p := range []string{"server=/", "local=/", "address=/"} {
		if rest, ok := strings.CutPrefix(line, p); ok {
			name, upstream, _ := strings.Cut(rest, "/")
			if p != "address=/" && upstream != "" {
				return "" // `server=/name/#` or `/1.2.3.4` forwards the name: an exception, not a block
			}
			return name
		}
	}
	for _, p := range []string{"127.0.0.1 ", ":: "} {
		if rest, ok := strings.CutPrefix(line, p); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// scanBlockList reads one dnsmasq-format list line by line and reports the first name of chain
// it holds. ok is false when the file does not exist.
func scanBlockList(path string, chain []string) (hit string, ok bool) {
	f, err := os.Open(sysPath(path))
	if err != nil {
		return "", false
	}
	defer f.Close()
	want := map[string]bool{}
	for _, c := range chain {
		want[c] = true
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	read := 0
	for sc.Scan() {
		line := sc.Text()
		if read += len(line) + 1; read > maxScanBytes {
			break
		}
		if name := blockedName(line); want[name] {
			return name, true
		}
	}
	return "", true
}

// adblock (the classic package) merges its feeds into one dnsmasq-format list and keeps the
// operator's exceptions in a plain allowlist file, one domain per line.
const (
	adblockList      = "/tmp/adb_list.overall"
	adblockAllowlist = "/etc/adblock/adblock.allowlist"
)

var adblockDNSDir = lazyRegexp(`dns: (/[^,\s]+)`)

// adblockListPath is where the merged list is. adblock 4.4 writes it into dnsmasq's own conf dir
// (named in the runtime file's run_directories) as `local=/name/` lines; older layouts used /tmp.
func adblockListPath() string {
	if m, err := readRuntime(adblockRuntime()); err == nil {
		if sub := adblockDNSDir.FindStringSubmatch(m.str("run_directories")); sub != nil {
			p := strings.TrimRight(sub[1], "/") + "/adb_list.overall"
			if _, err := os.Stat(sysPath(p)); err == nil {
				return p
			}
		}
	}
	return adblockList
}

func queryAdblock(ctx context.Context, domain string) string {
	chain := domainChain(domain)
	var lines []string
	if b, err := os.ReadFile(sysPath(adblockAllowlist)); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.ToLower(strings.TrimSpace(l))
			for _, c := range chain {
				if l == c {
					lines = append(lines, "allowed: "+c+" is in the adblock allowlist, so it is not blocked")
				}
			}
		}
	}
	list := adblockListPath()
	hit, ok := scanBlockList(list, chain)
	switch {
	case !ok:
		return "no block list is loaded (adblock has not produced " + list + " since boot); status: service_list detail=adblock"
	case hit != "":
		lines = append(lines, fmt.Sprintf("blocked: %s matches an entry for %s in the merged list", domain, hit))
	case len(lines) == 0:
		return "not blocked: " + domain + " is not in the merged list"
	}
	return strings.Join(lines, "\n")
}

func queryBanIP(ctx context.Context, ip string) string {
	m, err := readRuntime(banipRuntime())
	if err != nil {
		return "banIP has not run since boot (no runtime file); status: service_list detail=banip"
	}
	hits, checked, suffix := banipSetsHolding(ctx, m, ip)
	switch {
	case checked == 0:
		return "no active banIP set holds " + strings.TrimPrefix(suffix, ".") + " addresses"
	case len(hits) == 0:
		return fmt.Sprintf("not banned: %s is in none of the %s checked", ip, plural(checked, "set"))
	}
	return fmt.Sprintf("banned: %s is in %s", ip, strings.Join(hits, ", "))
}

// banipSetsHolding lists the active banIP sets of the address's family that hold ip.
func banipSetsHolding(ctx context.Context, m runtimeJSON, ip string) (hits []string, checked int, suffix string) {
	suffix = ".v4"
	if strings.Contains(ip, ":") {
		suffix = ".v6"
	}
	for _, set := range m.list("active_feeds") {
		if !strings.HasSuffix(set, suffix) || !ifaceName.MatchString(set) {
			continue
		}
		if checked == maxQuerySets {
			break
		}
		checked++
		if _, err := run(ctx, defaultCmdTimeout, "nft", "get", "element", "inet", "banIP", set, "{ "+ip+" }"); err == nil {
			hits = append(hits, set)
		}
	}
	return hits, checked, suffix
}
