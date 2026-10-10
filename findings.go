package main

import (
	"fmt"
	"sort"
	"strings"
)

// Findings (ROADMAP 4.2 and 4.3): what system_status mode=doctor and mode=audit return. A finding
// is advice, never an action: it names what was seen, where, and the next read-only call or
// reference that helps. Nothing in a finding changes the router (Principle 3: advisory first).

type severity int

const (
	sevHigh severity = iota
	sevMedium
	sevLow
	sevInfo
)

func (s severity) String() string {
	return [...]string{"high", "medium", "low", "info"}[s]
}

type finding struct {
	sev      severity
	id       string // stable slug, the same on every run
	msg      string
	evidence string
	next     string
	doc      string
}

// findingsRun is one doctor or audit pass: what it found, which checks ran, which could not, and
// where a check can only see part of the picture. "Could not check" is reported, never read as
// "all clear".
type findingsRun struct {
	title    string
	findings []finding
	checked  []string
	skipped  []string
	limits   []string
}

// findingHint is the guidance for one finding id, kept in one table so that a test can hold every
// next step to real tool names and every link to a page that exists.
type findingHint struct{ next, doc string }

const (
	docWifi     = "https://openwrt.org/docs/guide-user/network/wifi/basic"
	docWifiEnc  = "https://openwrt.org/docs/guide-user/network/wifi/encryption"
	docNetwork  = "https://openwrt.org/docs/guide-user/network/network_configuration"
	docServices = "https://openwrt.org/docs/guide-user/base-system/managing_services"
	docExtroot  = "https://openwrt.org/docs/guide-user/additional-software/extroot_configuration"
	docApk      = "https://openwrt.org/docs/guide-user/additional-software/apk"
	docOpkg     = "https://openwrt.org/docs/guide-user/additional-software/opkg"
	docNTP      = "https://openwrt.org/docs/guide-user/advanced/ntp_configuration"
	docFirewall = "https://openwrt.org/docs/guide-user/firewall/firewall_configuration"
	docDropbear = "https://openwrt.org/docs/guide-user/base-system/dropbear"
	docLuciSec  = "https://openwrt.org/docs/guide-user/luci/luci.secure"
	docUPnP     = "https://openwrt.org/docs/guide-user/firewall/upnp/miniupnpd"
	docSecure   = "https://openwrt.org/docs/guide-user/security/secure.access"
	docWG       = "https://openwrt.org/docs/guide-user/services/vpn/wireguard/server"
)

// verifiedDocs are the wiki pages the findings link to. DokuWiki answers 200 for a page that does
// not exist, so each was opened and read for its content on 2026-10-08 (docOpkg on 2026-10-09); a link is added to this
// list only after that.
var verifiedDocs = []string{docWifi, docWifiEnc, docNetwork, docServices, docExtroot, docApk, docOpkg, docNTP,
	docFirewall, docDropbear, docLuciSec, docUPnP, docSecure, docWG}

var findingHints = map[string]findingHint{
	"radio-down":       {"logread with pattern=hostapd or the radio name for the reason; service_control name=network action=restart brings radios back but drops every client", docWifi},
	"iface-no-address": {"logread with the interface name as pattern (DHCP or PPP messages); service_control name=network action=reload retries the link", docNetwork},
	"iface-error":      {"logread with the interface name as pattern; the error code names what the upstream or the link refused", docNetwork},
	"service-crashed":  {"logread with the service name as pattern for why it exited; service_control action=restart once the cause is gone", docServices},
	"conntrack-high":   {"network_clients to find the busiest host: a torrent client or a scan is the usual cause", ""},
	"overlay-full":     {"pkg_query action=installed lists what takes flash; pkg_change action=del removes what you do not use", docExtroot},
	"tmp-full":         {"/tmp is RAM: logs and downloads there vanish on reboot; system_status shows the use", ""},
	"apk-new-pending":  {"pkg_config_diff to read each file, pkg_config_resolve to keep yours or take the new one", docApk},
	"opkg-new-pending": {"pkg_config_diff to read each file, pkg_config_resolve to keep yours or take the new one", docOpkg},
	"ntp-unsynced":     {"logread with pattern=chronyd; net_diag action=nslookup target=pool.ntp.org tests name resolution", docNTP},
	"clock-unset":      {"set up an NTP client (chronyd or sysntpd); logread with pattern=ntp shows whether it ran", docNTP},
	"reboot-needed":    {"reboot when convenient: the new kernel loads only after a restart (no tool here reboots the router)", ""},

	"wan-zone-input-accept":   {"firewall_show view=table shows the zone; set its input back to REJECT with uci_apply (dry_run first)", docFirewall},
	"wan-zone-forward-accept": {"firewall_show view=table shows the zone; set its forward back to REJECT with uci_apply (dry_run first)", docFirewall},
	"wan-port-open":           {"firewall_show shows the live rule; remove or restrict it with uci_apply (dry_run first) if nothing needs it", docFirewall},
	"wan-forward-open":        {"firewall_show shows the live rule; remove or restrict it with uci_apply (dry_run first) if nothing needs it", docFirewall},
	"wan-redirect":            {"firewall_show shows the live redirect; remove it with uci_apply (dry_run first), or reach the device over a VPN instead", docFirewall},
	"ssh-wan":                 {"bind dropbear to the LAN or remove the WAN rule with uci_apply (dry_run first), after a key login works", docDropbear},
	"ssh-password-auth":       {"set PasswordAuth off with uci_apply (dry_run first) once a key login works, in a second session", docDropbear},
	"luci-wan":                {"remove the WAN rule with uci_apply (dry_run first): LuCI belongs on the LAN only", docLuciSec},
	"luci-all-addresses":      {"bind uhttpd to the LAN address with uci_apply (dry_run first): listen_http and listen_https", docLuciSec},
	"upnp-on":                 {"disable upnpd with uci_apply (dry_run first) unless a device needs it", docUPnP},
	"wps-on":                  {"remove wps_pushbutton from the wifi-iface with uci_apply (dry_run first)", docWifi},
	"ssid-open":               {"enable encryption with uci_apply (dry_run first): owe for a guest network, sae-mixed or psk2 otherwise", docWifiEnc},
	"ssid-wep":                {"switch to psk2 or sae with uci_apply (dry_run first)", docWifiEnc},
	"ssid-weak-cipher":        {"use psk2+ccmp or sae with uci_apply (dry_run first)", docWifiEnc},
	"ssid-wpa1":               {"use psk2 or sae with uci_apply (dry_run first) unless an old device needs WPA1", docWifiEnc},
	"root-no-password":        {"set a root password with passwd on the router (no tool here sets it) and prefer SSH keys", docSecure},
	"apk-audit-modified":      {"pkg_query action=owner with the path shows the package; reinstall it with pkg_change if the change is not yours", docApk},
	"wg-stale-peer":           {"wg_list_clients shows every handshake; wg_remove_client removes a peer nobody uses", docWG},

	// dry-run warnings (warnings.go)
	"ref-removed":  {"uci_get refs=NAME lists what defines and uses the name; change or remove every use in the same uci_apply", docNetwork},
	"ref-unknown":  {"check the spelling and case; uci_get refs=NAME shows what the name matches", docNetwork},
	"radio-in-use": {"reach the router another way first (a cable, or the other radio): this session cannot confirm over a radio it switched off, and the rollback restores it", docWifi},
}

func allFindingHints() map[string]findingHint { return findingHints }

// newFinding fills the next step and the link from the hint table.
func newFinding(id string, sev severity, msg, evidence string) finding {
	h := findingHints[id]
	return finding{sev: sev, id: id, msg: msg, evidence: evidence, next: h.next, doc: h.doc}
}

// render prints the findings worst first (then by id, so two runs read alike), then which checks
// ran and which did not.
func (r *findingsRun) render() string {
	fs := append([]finding(nil), r.findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].sev != fs[j].sev {
			return fs[i].sev < fs[j].sev
		}
		if fs[i].id != fs[j].id {
			return fs[i].id < fs[j].id
		}
		return fs[i].evidence < fs[j].evidence
	})
	var b strings.Builder
	if len(fs) == 0 {
		fmt.Fprintf(&b, "%s: no findings; advisory, nothing was changed\n", r.title)
	} else {
		var counts []string
		for s := sevHigh; s <= sevInfo; s++ {
			n := 0
			for _, f := range fs {
				if f.sev == s {
					n++
				}
			}
			if n > 0 {
				counts = append(counts, fmt.Sprintf("%d %s", n, s))
			}
		}
		noun := "findings"
		if len(fs) == 1 {
			noun = "finding"
		}
		fmt.Fprintf(&b, "%s: %d %s (%s); advisory, nothing was changed\n", r.title, len(fs), noun, strings.Join(counts, ", "))
	}
	for _, f := range fs {
		fmt.Fprintf(&b, "[%s] %s: %s\n", f.sev, f.id, f.msg)
		if f.evidence != "" {
			fmt.Fprintf(&b, "  evidence: %s\n", f.evidence)
		}
		if f.next != "" {
			fmt.Fprintf(&b, "  next: %s\n", f.next)
		}
		if f.doc != "" {
			fmt.Fprintf(&b, "  docs: %s\n", f.doc)
		}
	}
	if len(r.checked) > 0 {
		fmt.Fprintf(&b, "checked: %s\n", strings.Join(r.checked, ", "))
	}
	if len(r.skipped) > 0 {
		fmt.Fprintf(&b, "not checked: %s\n", strings.Join(r.skipped, "; "))
	}
	if len(r.limits) > 0 {
		fmt.Fprintf(&b, "limits: %s\n", strings.Join(r.limits, "; "))
	}
	return strings.TrimRight(b.String(), "\n")
}
