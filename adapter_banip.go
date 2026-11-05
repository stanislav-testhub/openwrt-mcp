package main

import (
	"context"
	"strings"
)

// banipRuntimeFiles: where banIP writes its status JSON. 1.5.x (OpenWrt 24.10, checked on a 24.10.8 VM) writes
// /var/run/banip_runtime.json; the second path is the one this adapter first assumed, kept for releases
// that may use it.
var banipRuntimeFiles = []string{"/var/run/banip_runtime.json", "/var/run/banIP/banIP.runtime.json"}

func banipRuntime() string {
	for _, f := range banipRuntimeFiles {
		if _, err := readSys(f); err == nil {
			return f
		}
	}
	return banipRuntimeFiles[0]
}

func readBanIP(ctx context.Context) string {
	out := readFilterRuntime(ctx, "banip", banipRuntime(), "status", "element_count", "elements", "")
	if m, err := readRuntime(banipRuntime()); err == nil {
		if w := m.list("wan_interfaces"); len(w) > 0 {
			out += "\nwan interfaces: " + strings.Join(w, ", ")
		} else if m.str("status") == "enabled" {
			out += "\nWARNING: no WAN interface detected, so banIP has nothing to protect"
		}
	}
	return out
}
