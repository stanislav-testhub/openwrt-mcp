package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// adblock and banIP both write their last run to a JSON file under /var/run (flat string
// fields and an array of active feed names). The adapters print fixed fields from it; the
// feed names are the operator's selection, the counters the package's own.

type runtimeJSON map[string]json.RawMessage

func readRuntime(p string) (runtimeJSON, error) {
	text, err := readSys(p)
	if err != nil {
		return nil, err
	}
	var m runtimeJSON
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (m runtimeJSON) str(key string) string {
	var s string
	if raw, ok := m[key]; ok && json.Unmarshal(raw, &s) == nil {
		return clip(s, 120)
	}
	return ""
}

func (m runtimeJSON) list(key string) []string {
	var l []string
	if raw, ok := m[key]; ok {
		json.Unmarshal(raw, &l)
	}
	var out []string
	for _, s := range l {
		if s = clip(s, 40); s != "" && s != "-" {
			out = append(out, s)
		}
	}
	return out
}

const (
	adblockRuntime = "/var/run/adblock/adblock.runtime.json"
	maxFeedNames   = 16
)

func readAdblock(ctx context.Context) string {
	return readFilterRuntime(ctx, "adblock", adblockRuntime, "adblock_status", "blocked_domains", "blocked domains", "dns_backend")
}

func feedLine(feeds []string) string {
	if len(feeds) == 0 {
		return "feeds: none active"
	}
	shown := feeds
	more := ""
	if len(shown) > maxFeedNames {
		more = fmt.Sprintf(" (+%d more)", len(shown)-maxFeedNames)
		shown = shown[:maxFeedNames]
	}
	return fmt.Sprintf("feeds (%d): %s%s", len(feeds), strings.Join(shown, ", "), more)
}

func readFilterRuntime(ctx context.Context, name, file, statusKey, countKey, countLabel, extraKey string) string {
	lines := []string{}
	if _, running, _ := procdData(ctx, name); running {
		lines = append(lines, name+": service running")
	} else {
		lines = append(lines, name+": no running procd instance (it may run only at refresh time)")
	}
	m, err := readRuntime(file)
	if err != nil {
		return strings.Join(append(lines, "runtime file not readable: "+name+" has not run since boot, or its output was not recognised"), "\n")
	}
	status := m.str(statusKey)
	if status == "" {
		return strings.Join(append(lines, "output not recognised: no "+statusKey+" in the runtime file ("+name+" "+m.str("frontend_ver")+")"), "\n")
	}
	head := "status: " + status
	if v := m.str("frontend_ver"); v != "" {
		head += ", " + name + " " + v
	}
	lines = append(lines, head)
	if c := m.str(countKey); c != "" {
		lines = append(lines, countLabel+": "+c)
	}
	lines = append(lines, feedLine(m.list("active_feeds")))
	if x := m.str(extraKey); x != "" {
		lines = append(lines, extraKey+": "+x)
	}
	if r := m.str("last_run"); r != "" && r != "-" {
		lines = append(lines, "last run: "+r)
	}
	if status == "error" || status == "paused" || status == "disabled" {
		lines = append(lines, "NOTE: status is "+status+", so nothing is being filtered")
	}
	return strings.Join(lines, "\n")
}
