package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Tailscale: one read, `tailscale status --json`. The JSON also holds node keys, the endpoints
// peers were reached at, capability lists and, for a node that is logged out, a login link that
// lets whoever opens it add a device. None of that is printed.

type tsNode struct {
	HostName       string
	DNSName        string
	OS             string
	TailscaleIPs   []string
	PrimaryRoutes  []string
	Relay          string
	CurAddr        string
	RxBytes        int64
	TxBytes        int64
	LastSeen       string
	Online         bool
	ExitNode       bool
	ExitNodeOption bool
}

type tsStatus struct {
	Version        string
	BackendState   string
	Health         []string
	CurrentTailnet *struct {
		MagicDNSSuffix  string
		MagicDNSEnabled bool
	}
	Self *tsNode
	Peer map[string]*tsNode
}

const tsMaxPeers = 20

func readTailscale(ctx context.Context) string {
	out, err := run(ctx, 15*time.Second, "tailscale", "status", "--json")
	if err != nil {
		why := strings.TrimSpace(firstLine(strings.TrimSpace(out)))
		if why == "" {
			why = err.Error()
		}
		return "tailscaled is not responding: " + clip(why, 160)
	}
	return renderTailscale(out)
}

func (n *tsNode) name() string {
	if n.HostName != "" {
		return clip(n.HostName, 40)
	}
	if first, _, _ := strings.Cut(strings.TrimSuffix(n.DNSName, "."), "."); first != "" {
		return clip(first, 40)
	}
	return "(unnamed)"
}

func (n *tsNode) firstIP() string {
	if len(n.TailscaleIPs) > 0 {
		return clip(n.TailscaleIPs[0], 45)
	}
	return "-"
}

func renderTailscale(statusJSON string) string {
	var st tsStatus
	if err := json.Unmarshal([]byte(statusJSON), &st); err != nil || st.BackendState == "" {
		return "tailscale status could not be read (not the JSON `tailscale status --json` prints)"
	}
	head := "tailscale"
	if v, _, _ := strings.Cut(st.Version, "-"); v != "" {
		head += " " + clip(v, 24)
	}
	lines := []string{head + ": " + clip(st.BackendState, 40)}

	var health []string
	for _, h := range st.Health {
		if h = clip(h, 160); h != "" {
			health = append(health, "- "+h)
		}
	}
	if len(health) > 5 {
		health = append(health[:5], fmt.Sprintf("- ... %d more", len(health)-5))
	}

	switch st.BackendState {
	case "Running":
		lines = append(lines, tsRunning(&st)...)
		if len(health) == 0 {
			lines = append(lines, "health: ok")
		}
	case "NeedsLogin":
		lines = append(lines, `not logged in: run "tailscale up" on the router to log in (the login link is not shown here)`)
	case "Stopped":
		lines = append(lines, `tailscale is stopped: "tailscale up" brings it back`)
	}
	if len(health) > 0 {
		lines = append(lines, "health:")
		lines = append(lines, health...)
	}
	if st.BackendState == "Running" {
		lines = append(lines, tsPeers(&st)...)
	}
	return strings.Join(lines, "\n")
}

// tsRunning is the part of a running node's status that comes before health and the peers.
func tsRunning(st *tsStatus) []string {
	var lines []string
	// The tailnet is named by its DNS suffix. Its display name is the owner's account (an email
	// address on a personal tailnet) and is not printed.
	if t := st.CurrentTailnet; t != nil && t.MagicDNSSuffix != "" {
		magic := "off"
		if t.MagicDNSEnabled {
			magic = "on"
		}
		lines = append(lines, fmt.Sprintf("tailnet: %s (MagicDNS %s)", clip(t.MagicDNSSuffix, 80), magic))
	}
	self := st.Self
	if self == nil {
		return lines
	}
	state := "offline"
	if self.Online {
		state = "online"
	}
	ips := make([]string, 0, len(self.TailscaleIPs))
	for _, ip := range self.TailscaleIPs {
		ips = append(ips, clip(ip, 45))
	}
	lines = append(lines, strings.TrimSpace(fmt.Sprintf("this node: %s %s %s", self.name(), strings.Join(ips, " "), state)))
	if len(self.PrimaryRoutes) > 0 {
		routes := make([]string, 0, len(self.PrimaryRoutes))
		for _, r := range self.PrimaryRoutes {
			routes = append(routes, clip(r, 45))
		}
		lines = append(lines, "advertised routes: "+strings.Join(routes, ", "))
	}
	var exit []string
	for _, p := range st.Peer {
		if p != nil && p.ExitNode {
			exit = append(exit, p.name())
		}
	}
	sort.Strings(exit)
	var parts []string
	if len(exit) > 0 {
		parts = append(parts, "in use, "+strings.Join(exit, ", "))
	}
	if self.ExitNodeOption {
		parts = append(parts, "offered by this node")
	}
	if len(parts) > 0 {
		lines = append(lines, "exit node: "+strings.Join(parts, "; "))
	}
	return lines
}

func tsPeers(st *tsStatus) []string {
	var peers []*tsNode
	online := 0
	for _, p := range st.Peer {
		if p == nil {
			continue
		}
		peers = append(peers, p)
		if p.Online {
			online++
		}
	}
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online != peers[j].Online {
			return peers[i].Online
		}
		if a, b := strings.ToLower(peers[i].name()), strings.ToLower(peers[j].name()); a != b {
			return a < b
		}
		return peers[i].firstIP() < peers[j].firstIP()
	})
	lines := []string{fmt.Sprintf("peers: %d, %d online", len(peers), online)}
	for i, p := range peers {
		if i == tsMaxPeers {
			lines = append(lines, fmt.Sprintf("... %d more peers not shown", len(peers)-tsMaxPeers))
			break
		}
		os := clip(p.OS, 20)
		if os == "" {
			os = "-"
		}
		l := fmt.Sprintf("%s %s %s", p.name(), p.firstIP(), os)
		switch {
		case p.Online && p.CurAddr != "":
			l += " online direct"
		case p.Online && p.Relay != "":
			l += " online relay " + clip(p.Relay, 20)
		case p.Online:
			l += " online"
		case p.LastSeen == "" || strings.HasPrefix(p.LastSeen, "0001-"):
			l += " offline never seen"
		default:
			l += " offline last seen " + clip(p.LastSeen, 40)
		}
		if p.RxBytes+p.TxBytes > 0 {
			l += fmt.Sprintf(" rx %s tx %s", humanBytes(p.RxBytes), humanBytes(p.TxBytes))
		}
		lines = append(lines, l)
	}
	return lines
}
