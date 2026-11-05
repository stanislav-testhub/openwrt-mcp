package main

import (
	"context"
	"fmt"
	"strings"
)

// adblock-fast reports through procd service data (`ubus call service list`): a status code,
// the package's one-line stats, and error and warning codes. Only the codes are printed; the
// info text is a list URL or file name.

var adblockFastStatus = map[string]string{
	"statusSuccess":        "blocking",
	"statusStopped":        "stopped",
	"statusStarting":       "starting",
	"statusRestarting":     "restarting",
	"statusForceReloading": "reloading",
	"statusDownloading":    "downloading lists",
	"statusFail":           "failed",
	"statusPaused":         "paused",
}

func readAdblockFast(ctx context.Context) string {
	found, running, data := procdData(ctx, "adblock-fast")
	var lines []string
	switch {
	case !found:
		lines = append(lines, "adblock-fast: not registered with procd (stopped, or disabled)")
	case running:
		lines = append(lines, "adblock-fast: service running")
	default:
		lines = append(lines, "adblock-fast: registered, no running instance")
	}
	if code := dataString(data, "status"); code != "" {
		text, ok := adblockFastStatus[code]
		if !ok {
			text = clip(code, 40)
		}
		lines = append(lines, "status: "+text)
	} else if found && len(data) == 0 {
		lines = append(lines, "no status yet: adblock-fast has not run since boot (checked on a 24.10 VM, where a never-started service has empty data)")
	} else if found {
		lines = append(lines, "output not recognised: no status in the service data")
	}
	if s := dataString(data, "stats"); s != "" {
		lines = append(lines, "stats: "+clip(s, 160))
	}
	if e := dataCodes(data, "errors"); len(e) > 0 {
		lines = append(lines, "errors: "+strings.Join(e, ", "))
	}
	if w := dataCodes(data, "warnings"); len(w) > 0 {
		lines = append(lines, "warnings: "+strings.Join(w, ", "))
	}
	if tree, err := uciShow(ctx, "adblock-fast", false); err == nil {
		lines = append(lines, adblockFastConfig(tree))
	}
	return strings.Join(lines, "\n")
}

func adblockFastConfig(t *uciTree) string {
	urls := len(t.sectionsOfType("file_url"))
	on := uciFlag(t.get("config", "enabled"), false)
	parts := []string{"config: " + pick(on, "enabled", "disabled"), "dns " + pick(t.get("config", "dns") != "", clip(t.get("config", "dns"), 30), "dnsmasq.servers"),
		fmt.Sprintf("%s configured", plural(urls, "list source"))}
	if uciFlag(t.get("config", "force_dns"), false) {
		parts = append(parts, "force DNS on")
	}
	return strings.Join(parts, ", ")
}
