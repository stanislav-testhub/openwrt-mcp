package main

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// WireGuard on stock OpenWrt is a netifd interface (`network.<iface>`, proto 'wireguard')
// whose peers are anonymous sections of type `wireguard_<iface>` in the same config -- the
// shape LuCI's WireGuard page and luci-proto-wireguard produce:
//
//	config interface 'wg0'
//		option proto 'wireguard'
//		option private_key '...'
//		option listen_port '51820'
//		list addresses '10.0.0.1/24'
//	config wireguard_wg0
//		option description 'phone'
//		option public_key '...'
//		list allowed_ips '10.0.0.2/32'
//
// Adding a client by hand is: generate a keypair, find a free address, write that section,
// commit, hot-add the peer, then transcribe a config onto a phone. The transcription is what
// actually goes wrong, so wg_new_client returns a scannable QR alongside the text.
//
// Peers are hot-added and removed with `wg set` rather than by restarting the interface: a
// restart drops every established session, which is a poor trade for one client.

type wgServer struct {
	Iface  string
	Port   string
	Addrs  []string // server tunnel addresses, CIDR
	MTU    int
	PubKey string
}

type wgPeer struct {
	Section   string // stable cfgXXXXXX id
	Name      string
	PubKey    string
	Allowed   []string
	HasPSK    bool
	Endpoint  string
	Handshake int64 // unix, 0 = never
	Rx, Tx    int64
	InUCI     bool
	InKernel  bool
}

// wgIfaces returns the wireguard interfaces defined in /etc/config/network, in file order.
func wgIfaces(t *uciTree) []string {
	var out []string
	for _, sec := range t.order {
		if t.typ[sec] == "interface" && t.get(sec, "proto") == "wireguard" {
			out = append(out, sec)
		}
	}
	return out
}

func pickWGIface(t *uciTree, want string) (string, error) {
	ifs := wgIfaces(t)
	if want != "" {
		if !contains(ifs, want) {
			return "", fmt.Errorf("%q is not a wireguard interface (have: %s)", want, strings.Join(ifs, ", "))
		}
		return want, nil
	}
	if len(ifs) != 1 {
		return "", fmt.Errorf("found %d wireguard interfaces %v; pass 'iface' to choose one", len(ifs), ifs)
	}
	return ifs[0], nil
}

func loadWG(ctx context.Context, want string) (*uciTree, *wgServer, []*wgPeer, error) {
	t, err := uciShow(ctx, "network", true)
	if err != nil {
		return nil, nil, nil, err
	}
	iface, err := pickWGIface(t, want)
	if err != nil {
		return nil, nil, nil, err
	}
	srv := &wgServer{Iface: iface, Port: t.get(iface, "listen_port"), Addrs: t.list(iface, "addresses")}
	srv.MTU, _ = strconv.Atoi(t.get(iface, "mtu"))

	peers := map[string]*wgPeer{}
	var order []string
	for _, sec := range t.sectionsOfType("wireguard_" + iface) {
		p := &wgPeer{Section: sec, Name: t.get(sec, "description"), PubKey: t.get(sec, "public_key"),
			Allowed: splitAll(t.list(sec, "allowed_ips")), HasPSK: t.get(sec, "preshared_key") != "", InUCI: true}
		key := p.PubKey
		if key == "" {
			key = "uci:" + sec
		}
		peers[key] = p
		order = append(order, key)
	}

	// `wg show <iface> dump`: first line is the interface (private key, public key, port,
	// fwmark); then one line per peer: pubkey psk endpoint allowed-ips handshake rx tx keepalive.
	// The private key and PSKs are read here and discarded -- never returned or logged.
	if out, err := run(ctx, defaultCmdTimeout, "wg", "show", iface, "dump"); err == nil {
		for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.Split(line, "\t")
			if i == 0 {
				if len(f) >= 3 {
					srv.PubKey = f[1]
					if srv.Port == "" {
						srv.Port = f[2]
					}
				}
				continue
			}
			if len(f) < 8 {
				continue
			}
			p, ok := peers[f[0]]
			if !ok {
				p = &wgPeer{PubKey: f[0]}
				peers[f[0]] = p
				order = append(order, f[0])
			}
			p.InKernel = true
			p.HasPSK = p.HasPSK || f[1] != "(none)"
			if f[2] != "(none)" {
				p.Endpoint = f[2]
			}
			if len(p.Allowed) == 0 && f[3] != "(none)" {
				p.Allowed = strings.Split(f[3], ",")
			}
			p.Handshake, _ = strconv.ParseInt(f[4], 10, 64)
			p.Rx, _ = strconv.ParseInt(f[5], 10, 64)
			p.Tx, _ = strconv.ParseInt(f[6], 10, 64)
		}
	}
	list := make([]*wgPeer, 0, len(order))
	for _, k := range order {
		list = append(list, peers[k])
	}
	return t, srv, list, nil
}

// splitAll flattens list values that were written as one space-separated option.
func splitAll(v []string) []string {
	var out []string
	for _, s := range v {
		out = append(out, strings.Fields(s)...)
	}
	return out
}

// ------------------------------------------------------------------ wg_list_clients

type wgListIn struct {
	Iface string `json:"iface,omitempty" jsonschema:"wireguard interface, e.g. 'wg0'; defaults to the only one"`
}

func wgListClients(ctx context.Context, in wgListIn) (string, string, error) {
	_, srv, peers, err := loadWG(ctx, in.Iface)
	if err != nil {
		return "", "", err
	}
	now := time.Now().Unix()
	var b strings.Builder
	fmt.Fprintf(&b, "%s: port %s, addresses %s, public key %s\n\n", srv.Iface, orDefault(srv.Port, "?"),
		strings.Join(srv.Addrs, " "), orDefault(srv.PubKey, "(interface not running)"))
	fmt.Fprintf(&b, "%-18s %-18s %-14s %-22s %-10s %s\n", "NAME", "ALLOWED IPS", "HANDSHAKE", "ENDPOINT", "RX/TX", "STATE")
	for _, p := range peers {
		hs := "never"
		if p.Handshake > 0 {
			hs = (time.Duration(now-p.Handshake) * time.Second).String() + " ago"
		}
		state := []string{}
		if !p.InUCI {
			state = append(state, "NOT-IN-UCI (lost on restart)")
		}
		if !p.InKernel {
			state = append(state, "NOT-LOADED")
		}
		if p.HasPSK {
			state = append(state, "psk")
		}
		fmt.Fprintf(&b, "%-18s %-18s %-14s %-22s %-10s %s  key=%s… section=%s\n",
			trunc(orDefault(p.Name, "?"), 18), strings.Join(p.Allowed, ","), hs, orDefault(p.Endpoint, "-"),
			fmt.Sprintf("%s/%s", humanBytes(p.Rx), humanBytes(p.Tx)), strings.Join(state, ","),
			short(p.PubKey), orDefault(p.Section, "-"))
	}
	if dup := duplicateNames(peers); len(dup) > 0 {
		fmt.Fprintf(&b, "\nWARNING: several peers share a name (%s) -- remove by public_key or section.\n", strings.Join(dup, ", "))
	}
	return b.String(), fmt.Sprintf("%d peers on %s", len(peers), srv.Iface), nil
}

func duplicateNames(peers []*wgPeer) []string {
	seen := map[string]int{}
	for _, p := range peers {
		if p.Name != "" {
			seen[p.Name]++
		}
	}
	var out []string
	for n, c := range seen {
		if c > 1 {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func short(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// ------------------------------------------------------------------ wg_new_client

type wgNewClientIn struct {
	Name         string `json:"name" jsonschema:"label for the new client (stored as the peer's description), e.g. 'laptop'"`
	Iface        string `json:"iface,omitempty" jsonschema:"wireguard interface; defaults to the only one"`
	Endpoint     string `json:"endpoint,omitempty" jsonschema:"host[:port] clients dial; defaults to the enabled DDNS name, else the WAN address"`
	DNS          string `json:"dns,omitempty" jsonschema:"DNS server for the client; defaults to the server's own tunnel address"`
	AllowedIPs   string `json:"allowed_ips,omitempty" jsonschema:"routes the client sends down the tunnel; defaults to 0.0.0.0/0 (full tunnel)"`
	MTU          int    `json:"mtu,omitempty" jsonschema:"client MTU; defaults to the interface's MTU, else 1420"`
	Keepalive    int    `json:"persistent_keepalive,omitempty" jsonschema:"seconds; defaults to 25, which keeps NAT bindings alive"`
	PresharedKey bool   `json:"preshared_key,omitempty" jsonschema:"also generate a preshared key (extra symmetric layer)"`
}

func wgNewScope(in wgNewClientIn) []string {
	if in.Iface == "" {
		return []string{"wireguard"}
	}
	return []string{"wireguard." + in.Iface}
}

// nextFreeClientIP picks the lowest host address in the server's subnet that no peer
// already holds, skipping the server itself. Reusing an address silently breaks whichever
// client connects second, so a full subnet is an error rather than a wrap-around.
func nextFreeClientIP(serverCIDR string, used []string) (netip.Addr, error) {
	pfx, err := netip.ParsePrefix(serverCIDR)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("server address %q is not a CIDR: %w", serverCIDR, err)
	}
	taken := map[netip.Addr]bool{pfx.Addr(): true}
	for _, u := range used {
		if a, err := netip.ParsePrefix(u); err == nil {
			taken[a.Addr()] = true
			continue
		}
		if a, err := netip.ParseAddr(u); err == nil {
			taken[a] = true
		}
	}
	for a := pfx.Masked().Addr().Next(); pfx.Contains(a); a = a.Next() {
		if a.Is4() && pfx.Bits() < 31 && isBroadcast(pfx, a) {
			continue
		}
		if !taken[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free address left in %s (%d already assigned)", serverCIDR, len(taken)-1)
}

func isBroadcast(pfx netip.Prefix, a netip.Addr) bool {
	last := pfx.Masked().Addr().As4()
	host := uint32(1)<<(32-pfx.Bits()) - 1
	v := uint32(last[0])<<24 | uint32(last[1])<<16 | uint32(last[2])<<8 | uint32(last[3])
	v |= host
	return a.As4() == [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

type wgClientConfig struct {
	PrivateKey   string
	Address      string
	DNS          string
	MTU          int
	ServerPubKey string
	PresharedKey string
	AllowedIPs   string
	Endpoint     string
	Keepalive    int
}

func (c wgClientConfig) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", c.PrivateKey, c.Address)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\n", c.ServerPubKey)
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\nEndpoint = %s\n", c.AllowedIPs, c.Endpoint)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

// renderQR draws the config as half-block characters, two module rows per text row, so a
// full config still fits a normal terminal. Medium recovery survives the font rendering
// and rounded corners a phone camera sees on a screen.
func renderQR(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("encoding QR: %w", err)
	}
	return q.ToSmallString(false), nil
}

func qrOrNote(conf string) string {
	qr, err := renderQR(conf)
	if err != nil {
		return "(QR could not be rendered: " + err.Error() + " -- use the text config above)"
	}
	return "Scan with the WireGuard app:\n\n" + qr
}

// guardNetworkCommit refuses a direct commit of /etc/config/network while someone else has
// staged edits there, or while a uci_apply on it awaits confirmation (a rollback would then
// silently delete the peer from config while the kernel keeps it).
func (s *Server) guardNetworkCommit(ctx context.Context) error {
	if out, err := uncommitted(ctx, "network"); err == nil && out != "" {
		return fmt.Errorf("refusing: /etc/config/network has uncommitted changes (someone else's edit):\n%s", out)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.pending {
		if contains(p.Configs, "network") {
			return fmt.Errorf("refusing: a uci_apply on network (%s) awaits confirmation; confirm or roll it back first", p.Token)
		}
	}
	return nil
}

func (s *Server) wgNewClient(ctx context.Context, client string, in wgNewClientIn) (string, string, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || strings.ContainsAny(name, "\x00\n\r'") {
		return "", "", fmt.Errorf("a plain name is required")
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if err := s.guardNetworkCommit(ctx); err != nil {
		return "", "", err
	}
	_, srv, peers, err := loadWG(ctx, in.Iface)
	if err != nil {
		return "", "", err
	}
	for _, p := range peers {
		if p.Name == name {
			return "", "", fmt.Errorf("a peer named %q already exists (%s…); pick another name -- "+
				"one config per device, since two devices sharing a key make both connections flap", name, short(p.PubKey))
		}
	}
	var v4 string
	for _, a := range srv.Addrs {
		if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() {
			v4 = a
			break
		}
	}
	if v4 == "" {
		return "", "", fmt.Errorf("%s has no IPv4 address in network.%s.addresses", srv.Iface, srv.Iface)
	}
	if srv.PubKey == "" {
		return "", "", fmt.Errorf("%s is not running (wg show returned nothing); bring it up first", srv.Iface)
	}
	if srv.Port == "" {
		return "", "", fmt.Errorf("%s has no listen_port, so clients have nothing to dial", srv.Iface)
	}
	var used []string
	for _, p := range peers {
		used = append(used, p.Allowed...)
	}
	addr, err := nextFreeClientIP(v4, used)
	if err != nil {
		return "", "", err
	}

	endpoint, warn := in.Endpoint, ""
	if endpoint == "" {
		if endpoint, warn, err = wgEndpoint(ctx); err != nil {
			return "", "", err
		}
	}
	if err := validEndpoint(endpoint); err != nil {
		return "", "", err
	}
	if !strings.Contains(strings.TrimPrefix(endpoint, "["), "]:") && strings.Count(endpoint, ":") != 1 {
		endpoint = joinHostPort(endpoint, srv.Port)
	}

	priv, err := run(ctx, defaultCmdTimeout, "wg", "genkey")
	if err != nil {
		return "", "", fmt.Errorf("generating private key: %w", err)
	}
	priv = strings.TrimSpace(priv)
	pub, err := runStdin(ctx, defaultCmdTimeout, priv+"\n", "wg", "pubkey")
	if err != nil {
		return "", "", fmt.Errorf("deriving public key: %w", err)
	}
	pub = strings.TrimSpace(pub)
	psk := ""
	if in.PresharedKey {
		if psk, err = run(ctx, defaultCmdTimeout, "wg", "genpsk"); err != nil {
			return "", "", fmt.Errorf("generating preshared key: %w", err)
		}
		psk = strings.TrimSpace(psk)
	}

	mtu := srv.MTU
	if mtu == 0 {
		mtu = 1420
	}
	cfg := wgClientConfig{
		PrivateKey:   priv,
		Address:      addr.String() + "/32",
		DNS:          orDefault(in.DNS, firstAddr(v4)),
		MTU:          orDefaultInt(in.MTU, mtu),
		ServerPubKey: srv.PubKey,
		PresharedKey: psk,
		AllowedIPs:   orDefault(in.AllowedIPs, "0.0.0.0/0"),
		Endpoint:     endpoint,
		Keepalive:    orDefaultInt(in.Keepalive, 25),
	}

	sec, err := run(ctx, defaultCmdTimeout, "uci", "add", "network", "wireguard_"+srv.Iface)
	if err != nil {
		return sec, "", fmt.Errorf("adding peer section: %w", err)
	}
	sec = strings.TrimSpace(sec)
	base := "network." + sec
	steps := [][]string{
		{"uci", "set", base + ".description=" + name},
		{"uci", "set", base + ".public_key=" + pub},
		{"uci", "add_list", base + ".allowed_ips=" + cfg.Address},
	}
	for _, argv := range steps {
		if out, err := run(ctx, defaultCmdTimeout, argv...); err != nil {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", "network")
			return out, "", fmt.Errorf("staging peer: %w", err)
		}
	}
	if psk != "" {
		// uci takes the value as an argument; there is no stdin form. It is a root-only
		// process for a few milliseconds, the same exposure LuCI's own save has.
		if out, err := run(ctx, defaultCmdTimeout, "uci", "set", base+".preshared_key="+psk); err != nil {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", "network")
			return out, "", fmt.Errorf("staging peer: %w", err)
		}
	}
	s.recordHistory("network", client, "wg_new_client "+name)
	if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", "network"); err != nil {
		return out, "", fmt.Errorf("committing peer: %w", err)
	}

	// Hot-add so established sessions survive. A failure here is not fatal: the peer is
	// committed and will load at the next interface restart -- say so.
	hot := []string{"wg", "set", srv.Iface, "peer", pub, "allowed-ips", cfg.Address}
	var hotErr error
	if psk != "" {
		hot = append(hot, "preshared-key", "/dev/stdin")
		_, hotErr = runStdin(ctx, defaultCmdTimeout, psk+"\n", hot...)
	} else {
		_, hotErr = run(ctx, defaultCmdTimeout, hot...)
	}
	if hotErr != nil {
		warn += "\nNOTE: the peer is saved but could not be added to the running interface (" + hotErr.Error() +
			"); it will work after `ifup " + srv.Iface + "`."
	}

	body := fmt.Sprintf("Created client %q (section %s) at %s on %s.\n\n%s\n%s\n"+
		"This output contains the client's PRIVATE KEY: show it to the operator, do not store it.%s",
		name, sec, cfg.Address, srv.Iface, cfg.String(), qrOrNote(cfg.String()), warn)
	// Summary is audited; the config and key are not. Keep both out of it.
	return body, fmt.Sprintf("created wireguard client %q (%s) at %s", name, sec, cfg.Address), nil
}

// wgEndpoint picks the address clients should dial: an enabled DDNS name if there is one,
// otherwise the address of the interface holding the default route. A dynamic WAN address
// baked into a client config stops working at the next reconnect, and a CGNAT or private
// one never worked from outside at all -- both are called out rather than silently used.
func wgEndpoint(ctx context.Context) (string, string, error) {
	if d, err := uciShow(ctx, "ddns", false); err == nil {
		for _, sec := range d.sectionsOfType("service") {
			host := orDefault(d.get(sec, "lookup_host"), d.get(sec, "domain"))
			if d.get(sec, "enabled") == "1" && host != "" && !strings.HasSuffix(host, "example.com") {
				return host, "", nil
			}
		}
	}
	ifs, err := interfaceDump(ctx)
	if err != nil {
		return "", "", fmt.Errorf("could not determine a WAN endpoint (%v); pass 'endpoint' explicitly", err)
	}
	best, bestMetric := "", 1<<30
	for _, i := range ifs {
		if !i.Up || len(i.IPv4) == 0 {
			continue
		}
		for _, r := range i.Route {
			if r.Target == "0.0.0.0" && r.Mask == 0 && i.Metric < bestMetric {
				best, bestMetric = i.IPv4[0].Address, i.Metric
			}
		}
	}
	if best == "" {
		return "", "", fmt.Errorf("no interface holds a default route; pass 'endpoint' explicitly")
	}
	warn := "\nNOTE: Endpoint is the current WAN address, which changes if your ISP reassigns it; " +
		"configure DDNS or pass 'endpoint' for a stable name."
	if a, err := netip.ParseAddr(best); err == nil && (a.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(a)) {
		warn = "\nWARNING: the WAN address " + best + " is private/CGNAT, so it is NOT reachable from the " +
			"internet. Unless your ISP forwards the port, pass 'endpoint' with a public name or address."
	}
	return best, warn, nil
}

func validEndpoint(s string) error {
	if strings.TrimSpace(s) == "" || strings.ContainsAny(s, " \t\n\r'\"") {
		return fmt.Errorf("bad endpoint %q", s)
	}
	return nil
}

func joinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// ------------------------------------------------------------------ wg_remove_client

type wgRemoveIn struct {
	Iface     string `json:"iface,omitempty" jsonschema:"wireguard interface; defaults to the only one"`
	Name      string `json:"name,omitempty" jsonschema:"the peer's description"`
	PublicKey string `json:"public_key,omitempty" jsonschema:"the peer's public key (use when names are ambiguous)"`
	Section   string `json:"section,omitempty" jsonschema:"the peer's uci section id (cfgXXXXXX) from wg_list_clients"`
	Force     bool   `json:"force,omitempty" jsonschema:"remove even if the peer completed a handshake in the last 3 minutes"`
}

func wgRemoveScope(in wgRemoveIn) []string {
	who := orDefault(in.Name, orDefault(in.Section, short(in.PublicKey)))
	return []string{"wireguard." + orDefault(in.Iface, "_") + "." + who}
}

func (s *Server) wgRemoveClient(ctx context.Context, client string, in wgRemoveIn) (string, string, error) {
	if in.Name == "" && in.PublicKey == "" && in.Section == "" {
		return "", "", fmt.Errorf("give a name, public_key or section")
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if err := s.guardNetworkCommit(ctx); err != nil {
		return "", "", err
	}
	_, srv, peers, err := loadWG(ctx, in.Iface)
	if err != nil {
		return "", "", err
	}
	var match []*wgPeer
	for _, p := range peers {
		if (in.Name == "" || p.Name == in.Name) && (in.PublicKey == "" || p.PubKey == in.PublicKey) &&
			(in.Section == "" || p.Section == in.Section) {
			match = append(match, p)
		}
	}
	switch len(match) {
	case 0:
		return "", "", fmt.Errorf("no matching peer on %s", srv.Iface)
	case 1:
	default:
		var c []string
		for _, p := range match {
			c = append(c, fmt.Sprintf("%s (section %s, key %s…)", p.Name, p.Section, short(p.PubKey)))
		}
		return "", "", fmt.Errorf("%d peers match; narrow with public_key or section:\n  %s", len(match), strings.Join(c, "\n  "))
	}
	p := match[0]
	if age := time.Now().Unix() - p.Handshake; p.Handshake > 0 && age < 180 && !in.Force {
		return "", "", fmt.Errorf("%q completed a handshake %ds ago -- it is connected right now. If you are "+
			"reaching the router through it you will lose access. Pass force=true to remove it anyway", p.Name, age)
	}
	var notes []string
	if p.InKernel {
		if out, err := run(ctx, defaultCmdTimeout, "wg", "set", srv.Iface, "peer", p.PubKey, "remove"); err != nil {
			notes = append(notes, "live removal failed: "+strings.TrimSpace(out))
		}
	}
	if p.InUCI {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "delete", "network."+p.Section); err != nil {
			return out, "", fmt.Errorf("deleting section: %w", err)
		}
		s.recordHistory("network", client, "wg_remove_client "+p.Name)
		if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", "network"); err != nil {
			return out, "", fmt.Errorf("committing: %w", err)
		}
	}
	msg := fmt.Sprintf("Removed %q (%s, key %s…) from %s.", p.Name, strings.Join(p.Allowed, ","), short(p.PubKey), srv.Iface)
	if len(notes) > 0 {
		msg += "\n" + strings.Join(notes, "\n")
	}
	return msg, fmt.Sprintf("removed wireguard client %q from %s", p.Name, srv.Iface), nil
}

// ------------------------------------------------------------------ helpers

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// firstAddr returns the bare address of a CIDR, e.g. "10.1.0.1/24" -> "10.1.0.1".
func firstAddr(cidr string) string {
	if pfx, err := netip.ParsePrefix(cidr); err == nil {
		return pfx.Addr().String()
	}
	return ""
}
