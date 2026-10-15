package main

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// The deny floor (ROADMAP 8.1). A grant widens what a client may do; nothing a client can reach
// may widen what a client may do. These calls are refused whatever the grant, `*` on `*` and the
// preset @all included, because each is a way to approve itself: reach the approval objects, edit
// the policy or the rpcd logins that open LuCI, or run the binary that writes grants.
//
// What the floor does not claim: a client with a root shell (exec on sh, or @all) can edit any
// file the floor names. It guarantees that no grant short of a root shell becomes a wider grant.
// The exec checks are therefore best-effort by argument; the ubus and uci checks are exact.
//
// The lists are pinned by TestFloorEntriesArePinned; changing one is a decision that test makes
// you write down. The uci_apply, restore and pkg_config_resolve guard (isPolicyFile) is the same
// floor for the staged-change tools.

// floorUbusObjects are never called through ubus_call: the approval object, LuCI session ids,
// root file access (read, write, exec) and the rpcd system object (password, upgrade).
var floorUbusObjects = []string{"openwrt-mcp", "session", "file", "rpc-sys"}

// floorConfigs are the UCI configs an agent never changes through ubus_call or exec: the policy,
// and rpcd (whose logins decide who may approve in LuCI).
var floorConfigs = []string{"openwrt-mcp", "rpcd"}

// floorUciWriteMethods are the ubus `uci` methods that change a config named in args.config.
var floorUciWriteMethods = []string{"set", "add", "delete", "rename", "order", "commit", "revert"}

// floorPaths are fragments of absolute paths (no leading slash) that exec never touches as an
// argument: the two configs, the state and audit directory with its hooks, the binary, its rpcd
// plugin and the request state in RAM, plus what decides who may approve or runs the daemon: the
// rpcd ACL files, the LuCI scripts the owner clicks, the init script and the SSH authorized keys.
var floorPaths = []string{
	"etc/config/openwrt-mcp", "etc/config/rpcd", "etc/openwrt-mcp",
	"usr/bin/openwrt-mcp", "usr/libexec/rpcd/openwrt-mcp", "var/run/openwrt-mcp",
	"usr/share/rpcd/acl.d", "www/luci-static/resources/view/openwrt-mcp",
	"www/luci-static/resources/view/status/include/15_openwrt-mcp",
	"etc/init.d/openwrt-mcp", "etc/dropbear",
}

// floorProgram is the program name exec never runs, by base name and after symlinks.
const floorProgram = "openwrt-mcp"

func floorRefuse(why string) string {
	return fmt.Sprintf("denied by the deny floor: %s. No grant lifts this, @operator and @all included.", why)
}

func floorHas(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// floorRefusal returns why the floor refuses this call, or "" when it does not apply. in is the
// tool's decoded input; only ubus_call and exec have anything to check.
func floorRefusal(in any) string {
	switch v := in.(type) {
	case ubusCallIn:
		return floorUbus(v)
	case execIn:
		return floorExec(v)
	}
	return ""
}

func floorUbus(in ubusCallIn) string {
	obj := strings.ToLower(strings.TrimSpace(in.Object))
	if floorHas(floorUbusObjects, obj) {
		return floorRefuse(fmt.Sprintf("ubus object %q is never reachable through ubus_call", in.Object))
	}
	if obj == "uci" && floorHas(floorUciWriteMethods, strings.ToLower(strings.TrimSpace(in.Method))) {
		c, present := in.Args["config"]
		if !present {
			return ""
		}
		name, isStr := c.(string)
		if !isStr || floorHas(floorConfigs, strings.TrimSpace(name)) {
			return floorRefuse(fmt.Sprintf("uci %s on the policy or rpcd config is never allowed through ubus_call", in.Method))
		}
	}
	return ""
}

func floorExec(in execIn) string {
	if len(in.Argv) == 0 {
		return ""
	}
	prog := in.Argv[0]
	if path.Base(filepath.ToSlash(prog)) == floorProgram || resolvesToFloorProgram(prog) {
		return floorRefuse("exec never runs the openwrt-mcp binary or its rpcd plugin")
	}
	uci := path.Base(filepath.ToSlash(prog)) == "uci"
	for _, a := range in.Argv {
		clean := strings.TrimPrefix(path.Clean(filepath.ToSlash(a)), "/")
		for _, p := range floorPaths {
			if strings.Contains(clean, p) {
				return floorRefuse("exec never touches the policy, the rpcd config, the openwrt-mcp state or its binary")
			}
		}
		if uci {
			for _, c := range floorConfigs {
				if a == c || strings.HasPrefix(a, c+".") {
					return floorRefuse("exec never runs uci on the policy or rpcd config")
				}
			}
		}
	}
	return ""
}

// resolvesToFloorProgram follows symlinks of an argv[0] that names a path, so a link called
// something else still counts.
func resolvesToFloorProgram(prog string) bool {
	if !strings.Contains(prog, "/") {
		return false
	}
	real, err := filepath.EvalSymlinks(prog)
	return err == nil && path.Base(filepath.ToSlash(real)) == floorProgram
}
