package main

import (
	"context"
	"strings"
)

const banipRuntime = "/var/run/banIP/banIP.runtime.json"

func readBanIP(ctx context.Context) string {
	out := readFilterRuntime(ctx, "banip", banipRuntime, "status", "element_count", "elements", "")
	if m, err := readRuntime(banipRuntime); err == nil {
		if w := m.list("wan_interfaces"); len(w) > 0 {
			out += "\nwan interfaces: " + strings.Join(w, ", ")
		} else if m.str("status") != "" {
			out += "\nWARNING: no WAN interface detected, so banIP has nothing to protect"
		}
	}
	return out
}
