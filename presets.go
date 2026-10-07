package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Presets expand into several policy blocks, because a policy's scope globs apply to every
// tool it grants: ubus_call "*.status" and uci_get "*" must not share a scope list, or the
// first would inherit the second's breadth. Each block below is one scope namespace.

type presetPolicy struct {
	tools  []string
	scopes []string
}

// readonlyUbus lists ubus methods that only read. It is an allow-list of object.method
// pairs, not "*.status"-style globs: a glob like "*.list" would match session.list, which
// returns the LuCI session ids that authenticate a browser.
var readonlyUbus = []string{
	"system.board", "system.info",
	"network.interface.dump", "network.interface.*.status", "network.device.status", "network.wireless.status",
	"iwinfo.devices", "iwinfo.info", "iwinfo.assoclist", "iwinfo.freqlist", "iwinfo.txpowerlist",
	"iwinfo.countrylist", "iwinfo.survey",
	"hostapd.*.get_clients", "hostapd.*.get_status",
	"luci-rpc.getDHCPLeases", "luci-rpc.getHostHints", "luci-rpc.getNetworkDevices",
	"luci-rpc.getWirelessDevices", "luci-rpc.getBoardJSON",
	"service.list", "rc.list", "dnsmasq.metrics", "uci.configs", "uci.changes", "log.read",
}

var presets = map[string][]presetPolicy{
	// Reads everything useful, changes nothing. uci_get '*' includes secrets (Wi-Fi keys), as
	// any config read on OpenWrt does.
	"readonly": {
		{tools: []string{"system_status", "logread", "network_clients", "firewall_show", "service_list",
			"pkg_query", "pkg_config_diff", "wg_list_clients", "uci_get"}, scopes: []string{"*"}},
		{tools: []string{"ubus_call"}, scopes: readonlyUbus},
		{tools: []string{"net_diag"}, scopes: []string{"*"}},
		{tools: []string{"sysupgrade"}, scopes: []string{"list", "test", "check"}},
	},
	// readonly plus every change that is simulated, rollback-armed, or narrowly reversible.
	// Not included: exec, and ubus_call beyond the read list -- both bypass the safety rails.
	"operator": {
		{tools: []string{"system_status", "logread", "network_clients", "firewall_show", "service_list",
			"pkg_query", "pkg_config_diff", "wg_list_clients", "uci_get",
			"uci_apply", "uci_confirm", "uci_rollback", "service_control", "pkg_change",
			"pkg_config_resolve", "wg_new_client", "wg_remove_client"}, scopes: []string{"*"}},
		{tools: []string{"ubus_call"}, scopes: readonlyUbus},
		{tools: []string{"net_diag"}, scopes: []string{"*"}},
		{tools: []string{"sysupgrade"}, scopes: []string{"list", "test", "check", "backup"}},
	},
}

// expandPreset returns the policy blocks for "@name", or nil if tools is not a preset.
func expandPreset(tools string) ([]presetPolicy, error) {
	if !strings.HasPrefix(tools, "@") {
		return nil, nil
	}
	p, ok := presets[strings.TrimPrefix(tools, "@")]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q (have @readonly, @operator)", tools)
	}
	return p, nil
}

func validTool(t string) bool { return contains(allToolNames, t) }

// removePolicies deletes every `config policy` block for client from the UCI file and
// returns how many went. Everything else -- comments, the server section, other clients --
// is copied through byte for byte.
func removePolicies(configPath, client string) (int, error) {
	return removePoliciesWhere(configPath, func(s uciSection) bool { return s.Options["client"] == client })
}

// removeExpired deletes every grant that expired before cutoff and that match accepts. A block
// that does not parse is left alone: LoadConfig reports it, and revoke removes it.
func removeExpired(configPath string, cutoff time.Time, match func(*Policy) bool) (int, error) {
	n, err := removePoliciesWhere(configPath, func(s uciSection) bool {
		p, err := policyFromSection(s)
		return err == nil && !p.Expires.IsZero() && p.Expires.Before(cutoff) && match(p)
	})
	if os.IsNotExist(err) {
		return 0, nil // no config file: nothing was ever granted
	}
	return n, err
}

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// removePoliciesWhere deletes every `config policy` block that drop matches, in the same way.
func removePoliciesWhere(configPath string, drop func(uciSection) bool) (int, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return 0, err
	}
	var blocks [][]string
	var cur []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "config ") && cur != nil {
			blocks = append(blocks, cur)
			cur = nil
		}
		cur = append(cur, line)
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if cur != nil {
		blocks = append(blocks, cur)
	}
	var out []string
	n := 0
	for _, b := range blocks {
		secs := parseUCI(bufio.NewScanner(strings.NewReader(strings.Join(b, "\n"))))
		if len(secs) == 1 && secs[0].Type == "policy" && drop(secs[0]) {
			n++
			continue
		}
		out = append(out, b...)
	}
	if n == 0 {
		return 0, nil
	}
	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, configPath)
}

// ---------------------------------------------------------------- authorize-key

// The comment may hold anything printable: no control character (a bare CR or NUL) can ride
// into a file whose lines other tools split in their own ways.
var reSSHKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]{40,}( [^\x00-\x1f\x7f]*)?$`)

// authorizedKeyLine binds a public key to one MCP client: dropbear runs the stdio bridge for
// that key and nothing else -- no shell, no port forwarding, no pty.
func authorizedKeyLine(client, key string) (string, error) {
	key = strings.TrimSpace(key)
	if !reSSHKey.MatchString(key) {
		return "", fmt.Errorf("not an ssh public key line (want 'ssh-ed25519 AAAA... comment')")
	}
	if !reClientName.MatchString(client) {
		return "", fmt.Errorf("bad client name %q", client)
	}
	return fmt.Sprintf(`command="/usr/bin/openwrt-mcp stdio --client %s",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty %s`,
		client, key), nil
}

func authorizeKey(path, client, key string) (string, error) {
	line, err := authorizedKeyLine(client, key)
	if err != nil {
		return "", err
	}
	blob := strings.Fields(strings.TrimSpace(key))[1]
	existing, _ := os.ReadFile(path)
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.Contains(l, blob) {
			return "", fmt.Errorf("that key is already in %s -- a key can be either a root login or an MCP key, "+
				"not both; generate a dedicated one (ssh-keygen -t ed25519 -f openwrt_mcp)", path)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	prefix := ""
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		prefix = "\n"
	}
	_, err = f.WriteString(prefix + line + "\n")
	return line, err
}
