package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// The `small` profile is a set of defaults for routers with little RAM or flash (ROADMAP 10.6).
// It only fills options the config leaves unset, so every explicit option wins.
const profileSmall = "small"

var smallDefaults = map[string]string{
	"idle_exit":    "5",
	"listen":       "",
	"memory_limit": "16",
	"audit_max_mb": "1",
	"history_keep": "3",
	"toolsets":     "diag config",
}

// applyProfile fills opts from the named profile. An unknown name is logged and ignored: a typo
// must not stop the daemon from starting.
func applyProfile(opts map[string]string) string {
	name := opts["profile"]
	switch name {
	case "":
		return ""
	case profileSmall:
		for k, v := range smallDefaults {
			if _, set := opts[k]; !set {
				opts[k] = v
			}
		}
		return name
	}
	log.Printf("openwrt-mcp: ignoring option profile %q (known: %s)", name, profileSmall)
	return ""
}

// parseToolsetCap reads option toolsets: a blank- or comma-separated list of toolset names.
// An unknown name is an error for the caller to log; nil means no cap.
func parseToolsetCap(s string) ([]string, error) {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, ",", " ")), ",")
	if s == "" {
		return nil, nil
	}
	return parseToolsets(s)
}

// capToolsets intersects a session's toolsets with the operator's cap. A nil cap changes
// nothing; a nil session list means "every toolset", so the cap itself applies. The result is
// non-nil whenever a cap is set, which also keeps exec (a tool in no toolset) out.
func capToolsets(session, cap []string) []string {
	if cap == nil {
		return session
	}
	if session == nil {
		return cap
	}
	out := []string{}
	for _, n := range toolsetNames {
		if contains(session, n) && contains(cap, n) {
			out = append(out, n)
		}
	}
	return out
}

// overlayMiB is the size of the filesystem holding dir, in MiB; 0 when it cannot be read.
// It shells out to df so the file builds on every platform the client builds for.
var overlayMiB = func(dir string) int {
	out, err := exec.Command("df", "-Pk", dir).Output()
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 2 {
		return 0
	}
	kb, err := strconv.Atoi(f[1])
	if err != nil {
		return 0
	}
	return kb / 1024
}

// defaultAuditMB is the audit log limit when audit_max_mb is unset: the usual default, but at
// most 1/32 of the filesystem it lives on (two copies are kept), and at least 1.
func defaultAuditMB(auditPath string) int {
	mib := overlayMiB(filepath.Dir(auditPath))
	if mib <= 0 {
		return defaultAuditMaxMB
	}
	return min(defaultAuditMaxMB, max(1, mib/32))
}

// smallRAMMiB is the RAM below which the installers and the diagnostic bundle suggest the
// small profile.
const smallRAMMiB = 256

// memTotalMiB reads MemTotal from /proc/meminfo; 0 when it is unavailable.
var memTotalMiB = func() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotalMiB(string(b))
}

func parseMemTotalMiB(meminfo string) int {
	for _, l := range strings.Split(meminfo, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.Atoi(f[1])
			return kb / 1024
		}
	}
	return 0
}

// smallProfileHint is the command that switches the profile on. The stock config sets listen and
// audit_max_mb explicitly and an explicit option beats the profile, so they are removed first;
// without that, profile=small alone leaves HTTP on and idle_exit ignored.
const smallProfileHint = "uci set openwrt-mcp.@server[0].profile=small; uci -q delete openwrt-mcp.@server[0].listen; " +
	"uci -q delete openwrt-mcp.@server[0].audit_max_mb; uci commit openwrt-mcp"

// fitLine is the diagnostic bundle's line about whether the settings suit this router.
func fitLine(cfg *Config) string {
	ram, flash := memTotalMiB(), overlayMiB(filepath.Dir(cfg.AuditPath))
	if ram == 0 && flash == 0 {
		return ""
	}
	s := fmt.Sprintf("%d MiB RAM, %d MiB on the audit log's filesystem", ram, flash)
	if cfg.Profile != "" {
		s += "; profile " + cfg.Profile
	} else if ram > 0 && ram < smallRAMMiB {
		s += "; under " + strconv.Itoa(smallRAMMiB) + " MiB RAM, consider: " + smallProfileHint
	}
	if cfg.Toolsets != nil {
		s += "; toolsets capped to " + strings.Join(cfg.Toolsets, ",")
	}
	return s
}
