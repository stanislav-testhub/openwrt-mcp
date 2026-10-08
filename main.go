package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// openwrt-mcp -- an MCP server hosted on an OpenWrt router.
// Copyright (c) 2026 Ian Williams. OpenWrt 25.12 port: see CHANGELOG.md.
//
// Released under the MIT Licence. See the LICENSE file.

var version = "1.4.0"

const sourceURL = "https://github.com/stanislav-testhub/openwrt-mcp (based on github.com/GlassOnTin/openwrt-mcp)"

const (
	defaultConfigPath = "/etc/config/openwrt-mcp"
	defaultStatePath  = "/etc/openwrt-mcp"
)

func randToken() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	log.SetFlags(0)
	configPath := flag.String("config", defaultConfigPath, "path to the UCI config file")
	statePath := flag.String("state", defaultStatePath, "directory for tokens, audit log and pending state")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	// Every command that touches state refuses a web-served directory, not just `serve`: `pair`
	// would otherwise write token digests there.
	must(checkNotWebServed(*statePath))

	switch args[0] {
	case "serve":
		s, err := NewServer(*configPath, *statePath)
		must(err)
		must(s.Serve())

	case "stdio":
		// What an SSH forced command runs: bridges this process's stdin/stdout to the daemon.
		fs := flag.NewFlagSet("stdio", flag.ExitOnError)
		client := fs.String("client", os.Getenv("OPENWRT_MCP_CLIENT"), "client name the policy applies to")
		must(fs.Parse(args[1:]))
		cfg, err := LoadConfig(*configPath)
		must(err)
		if cfg.Socket == "" {
			die("the stdio bridge is disabled (option socket '' in %s)", *configPath)
		}
		must(runBridge(cfg.Socket, *client))

	case "authorize-key":
		if len(args) != 3 {
			die("usage: openwrt-mcp authorize-key <client> '<ssh public key line>'\n" +
				"  binds a dedicated key to the stdio bridge for <client> in /etc/dropbear/authorized_keys")
		}
		line, err := authorizeKey("/etc/dropbear/authorized_keys", args[1], args[2])
		must(err)
		fmt.Printf("added to /etc/dropbear/authorized_keys:\n  %s\n\n"+
			"Point your MCP client at:  ssh -T -i <that key> -p <ssh port> root@<router>\n"+
			"and grant it something:    openwrt-mcp allow %s @readonly 30d\n", line, args[1])

	case "revoke":
		if len(args) != 2 {
			die("usage: openwrt-mcp revoke <client>   (removes every policy for the client)")
		}
		n, err := removePolicies(*configPath, args[1])
		must(err)
		fmt.Printf("removed %d policy block(s) for %q\n", n, args[1])

	case "pair":
		if len(args) != 2 {
			die("usage: openwrt-mcp pair <client-name>")
		}
		ts, err := LoadTokens(tokensPath(*statePath))
		must(err)
		raw, err := ts.Mint(args[1])
		must(err)
		// Printed once and never recoverable: only the SHA-256 digest is stored.
		fmt.Println(raw)

	case "unpair":
		if len(args) != 2 {
			die("usage: openwrt-mcp unpair <client-name>")
		}
		ts, err := LoadTokens(tokensPath(*statePath))
		must(err)
		fmt.Printf("revoked %d token(s) for %q\n", ts.Revoke(args[1]), args[1])

	case "clients":
		ts, err := LoadTokens(tokensPath(*statePath))
		must(err)
		for _, c := range ts.Clients() {
			fmt.Println(c)
		}

	case "allow":
		var shellOK bool
		args, shellOK = takeFlag(args, "--shell-equivalent")
		if len(args) == 4 && strings.HasPrefix(args[2], "@") {
			blocks, err := expandPreset(args[2])
			must(err)
			replaced := 0
			for _, b := range blocks {
				replaced += replaceExpired(*configPath, args[1], b.tools, b.scopes)
				must(appendPolicy(*configPath, args[1], strings.Join(b.tools, ","), strings.Join(b.scopes, " "), args[3]))
			}
			fmt.Printf("granted %s preset %s (%d policy blocks) for %s; the daemon picks it up without a restart\n",
				args[1], args[2], len(blocks), args[3])
			printReplaced(replaced)
			break
		}
		if len(args) != 5 {
			die("usage: openwrt-mcp allow <client> <tool[,tool...]> <scope-glob[ scope-glob...]> <duration|never> [--shell-equivalent]\n" +
				"       openwrt-mcp allow <client> @readonly|@operator <duration|never>\n" +
				"  e.g. openwrt-mcp allow claude-code uci_apply 'dhcp.* wireless.*.disabled' 30d")
		}
		var tools []string
		for _, t := range strings.Split(args[2], ",") {
			if t = strings.TrimSpace(t); t != "" && !validTool(t) {
				die("unknown tool %q (tools: %s)", t, strings.Join(allToolNames, ", "))
			} else if t != "" {
				tools = append(tools, t)
			}
		}
		if hit := shellEquivalentNames(tools, strings.Fields(args[3])); len(hit) > 0 {
			msg := fmt.Sprintf("this grant lets %s run %s, and each of those can run any other program: it is a root shell whatever the other scopes say",
				args[1], describeShellEquivalent(hit))
			if !shellOK {
				die("refusing: %s\n  add --shell-equivalent if that is what you mean", msg)
			}
			fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
		}
		replaced := replaceExpired(*configPath, args[1], tools, strings.Fields(args[3]))
		must(appendPolicy(*configPath, args[1], args[2], args[3], args[4]))
		fmt.Printf("granted %s -> %s on '%s' for %s; the daemon picks it up without a restart\n",
			args[1], args[2], args[3], args[4])
		printReplaced(replaced)

	case "prune":
		fs := flag.NewFlagSet("prune", flag.ExitOnError)
		olderThan := fs.String("older-than", "0s", "keep grants that expired less than this long ago, e.g. 7d")
		must(fs.Parse(args[1:]))
		if fs.NArg() != 0 {
			die("usage: openwrt-mcp prune [--older-than <duration>]   (deletes expired grants)")
		}
		age, err := parseDuration(*olderThan)
		if err != nil {
			die("bad duration %q for --older-than", *olderThan)
		}
		if age < 0 {
			die("--older-than must not be negative: that would delete grants that are still live")
		}
		cfg, err := LoadConfig(*configPath)
		must(err)
		n, err := removeExpired(*configPath, time.Now().Add(-age), func(*Policy) bool { return true })
		must(err)
		if n > 0 {
			NewAuditor(cfg.AuditPath, cfg.AuditMaxMB).Record(AuditEvent{Time: nowISO(), Client: "<cli>", Tool: "prune",
				Outcome: OutcomeOK, Summary: fmt.Sprintf("removed %d expired grant(s), --older-than %s", n, *olderThan)})
		}
		fmt.Printf("removed %d expired grant(s)\n", n)

	case "policies":
		cfg, err := LoadConfig(*configPath)
		must(err)
		if len(cfg.Policies) == 0 {
			fmt.Println("(none -- every gated tool is denied)")
		}
		for _, p := range cfg.Policies {
			exp := "never"
			if !p.Expires.IsZero() {
				exp = p.Expires.Format(time.RFC3339)
				if time.Now().After(p.Expires) {
					exp += " (EXPIRED)"
				}
			}
			state := ""
			if !p.Enabled {
				state = " [disabled]"
			}
			fmt.Printf("%s%s\n  tools:  %s\n  scopes: %s\n  rate:   %d/min\n  expires:%s\n",
				p.Client, state, strings.Join(p.Tools, ", "), strings.Join(p.Scopes, " "), p.MaxPerMin, exp)
			if hit := p.shellEquivalent(); len(hit) > 0 {
				fmt.Printf("  shell-equivalent: %s (a root shell)\n", describeShellEquivalent(hit))
			}
		}

	case "mfa":
		// Enrolment is CLI-only for the same reason pair/allow are: the secret is credential
		// material, and nothing reachable over the network should be able to mint or read it.
		ms, err := LoadMFA(mfaPath(*statePath))
		must(err)
		sub := ""
		if len(args) > 1 {
			sub = args[1]
		}
		switch sub {
		case "enrol", "enroll":
			if len(args) < 3 || len(args) > 4 {
				die("usage: openwrt-mcp mfa enrol <client> [device-label]\n" +
					"  the label names this router in your authenticator; defaults to the hostname")
			}
			device := ""
			if len(args) == 4 {
				device = args[3]
			}
			secret, uri, err := ms.Enrol(args[2], "openwrt-mcp", device)
			must(err)
			// Printed once, like a pairing token -- but unlike one this IS recoverable from
			// the state file, so say plainly that the file is credential material.
			fmt.Printf("Enrolled %q. Scan this in your authenticator app:\n\n  %s\n\n"+
				"  secret: %s\n\n"+
				"Then require it for the tools that matter, e.g. in %s:\n"+
				"  list mfa_tools 'exec'\n"+
				"  list mfa_tools 'uci_apply'\n"+
				"  option mfa_window '15m'\n\n"+
				"The daemon picks this up without a restart.\n"+
				"The secret is stored at %s/mfa (mode 0600); anyone who reads it can generate codes.\n",
				args[2], uri, secret, defaultConfigPath, *statePath)

		case "status", "":
			clients := ms.Clients()
			if len(clients) == 0 {
				fmt.Println("(no clients enrolled -- no tool requires a second factor)")
			}
			for _, c := range clients {
				fmt.Printf("%s: enrolled\n", c)
			}
			cfg, err := LoadConfig(*configPath)
			must(err)
			for _, p := range cfg.Policies {
				if len(p.MFATools) > 0 {
					fmt.Printf("  policy %s requires a code for: %s (window %s)\n",
						p.Client, strings.Join(p.MFATools, ", "), p.MFAWindow)
					if !ms.Enrolled(p.Client) {
						fmt.Printf("  WARNING: %q has no enrolled secret, so those tools cannot be unlocked.\n"+
							"           Run: openwrt-mcp mfa enrol %s\n", p.Client, p.Client)
					}
				}
			}

		default:
			die("usage: openwrt-mcp mfa enrol <client> | openwrt-mcp mfa status")
		}

	case "status":
		// Backs the LuCI status page (via rpcd file.exec); --json is the
		// machine-readable form of exactly what the text output shows.
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		asJSON := fs.Bool("json", false, "emit JSON")
		lines := fs.Int("audit", 20, "how many recent audit entries to include (0 for none)")
		all := fs.Bool("all", false, "list expired grants too, not just their count")
		must(fs.Parse(args[1:]))
		must(runStatus(*configPath, *statePath, *lines, *asJSON, *all))

	case "diag":
		// Paste-ready for a bug report: see diag.go for what is masked and what is left out.
		fs := flag.NewFlagSet("diag", flag.ExitOnError)
		n := fs.Int("audit", 20, "how many recent audit entries to include (0 for none)")
		detail := fs.Bool("detail", false, "also print each entry's scope, summary and error text (masked)")
		must(fs.Parse(args[1:]))
		must(runDiag(os.Stdout, *configPath, *n, *detail))

	case "connect":
		// Runs on the operator's PC, not the router: nothing here reads the router's config.
		must(connectMain(args[1:]))

	case "wg-show":
		// Hands a client config left by wg_new_client to the operator's terminal, so the private
		// key never has to pass through a model's context. Flags may come after the name.
		keep, name := false, ""
		for _, a := range args[1:] {
			switch {
			case a == "--keep" || a == "-keep":
				keep = true
			case name == "" && !strings.HasPrefix(a, "-"):
				name = a
			default:
				die("usage: openwrt-mcp wg-show <client name> [--keep]")
			}
		}
		if name == "" {
			die("usage: openwrt-mcp wg-show <client name> [--keep]")
		}
		cfg, err := LoadConfig(*configPath)
		must(err)
		must(runWGShow(os.Stdout, cfg, name, keep))

	case "version":
		fmt.Printf("openwrt-mcp %s\n", version)

	default:
		die("unknown command %q", args[0])
	}
}

// appendPolicy adds a policy block to the UCI config. Grant management is CLI-only and is
// deliberately not exposed as an MCP tool, so there is no tool for a policy to cover and
// therefore no self-escalation path through the policy system itself.
func appendPolicy(configPath, client, tools, scopes, duration string) error {
	// Every value is written inside single quotes, so a quote or a newline in one would end the
	// value and let the rest be read as more UCI -- corrupting the file that holds every grant.
	// The client name must also be one the stdio bridge can actually present.
	if !reClientName.MatchString(client) {
		return fmt.Errorf("bad client name %q: use letters, digits, '.', '_' or '-' (max 64)", client)
	}
	for _, sc := range strings.Fields(scopes) {
		if strings.ContainsAny(sc, "'\"\x00") {
			return fmt.Errorf("bad scope %q: quotes are not allowed", sc)
		}
	}
	var expires string
	if duration != "never" {
		d, err := parseDuration(duration)
		if err != nil {
			return err
		}
		expires = time.Now().Add(d).Format(time.RFC3339)
	}
	var b strings.Builder
	b.WriteString("\nconfig policy\n")
	fmt.Fprintf(&b, "\toption client\t'%s'\n", client)
	for _, t := range strings.Split(tools, ",") {
		if t = strings.TrimSpace(t); t != "" {
			fmt.Fprintf(&b, "\tlist tools\t'%s'\n", t)
		}
	}
	for _, sc := range strings.Fields(scopes) {
		fmt.Fprintf(&b, "\tlist scopes\t'%s'\n", sc)
	}
	if expires != "" {
		fmt.Fprintf(&b, "\toption expires\t'%s'\n", expires)
	}
	b.WriteString("\toption enabled\t'1'\n")

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(b.String())
	return err
}

// replaceExpired deletes client's expired grants for exactly these tools and scopes, so that
// granting the same thing again (`allow claude-code @operator 2h`, day after day) replaces the
// old block instead of piling up another one.
func replaceExpired(configPath, client string, tools, scopes []string) int {
	n, err := removeExpired(configPath, time.Now(), func(p *Policy) bool {
		return p.Client == client && sameSet(p.Tools, tools) && sameSet(p.Scopes, scopes)
	})
	must(err)
	return n
}

func printReplaced(n int) {
	if n > 0 {
		fmt.Printf("replaced %d expired grant(s) with the same tools and scopes\n", n)
	}
}

// parseDuration extends time.ParseDuration with 'd' for days, since grants are
// naturally expressed in days and Go's parser stops at hours.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%f", &days); err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func usage() {
	fmt.Fprintf(os.Stderr, `openwrt-mcp %s -- an MCP server hosted on the router

  serve                                       run the daemon (loopback TCP + root-only unix socket)
  stdio    --client <name>                    bridge stdin/stdout to the daemon (SSH forced command)
  authorize-key <client> '<pubkey>'           bind a dedicated SSH key to the stdio bridge
  pair     <client>                           mint a bearer token for the HTTP transport, printed once
  unpair   <client>                           revoke every token for a client
  clients                                     list paired (HTTP) clients
  allow    <client> <tools> <scopes> <dur>    grant a standing policy (a shell-like exec needs --shell-equivalent)
  allow    <client> @readonly|@operator <dur> grant a preset
  revoke   <client>                           remove every policy for a client (config: %s)
  policies                                    show current grants
  prune    [--older-than <dur>]               delete expired grants (audited)
  status   [--json] [--audit N] [--all]        daemon state, pairings, grants, recent audit
  mfa      enrol <client> [device] | status   optional TOTP second factor for gated tools
  wg-show  <client name> [--keep]             print a WireGuard client config left by wg_new_client, then delete it
  diag     [--audit N] [--detail]              version, board, policy shape and recent audit, with addresses and names masked
  connect  --client <c> --host <router> ...    (on your PC) make the key and set up an MCP client
  connect doctor --host <router> ...           (on your PC) check key, forced command, daemon and tools
  version

Connect an MCP client either way:
  stdio: ssh -T -i <mcp key> root@router          (key bound with authorize-key)
  http:  ssh -N -L 8730:127.0.0.1:8730 root@router, then http://127.0.0.1:8730/mcp + bearer token
`, version, defaultConfigPath)
	flag.PrintDefaults()
}

func must(err error) {
	if err != nil {
		log.Fatalf("openwrt-mcp: %v", err)
	}
}

func die(format string, a ...any) {
	log.Fatalf("openwrt-mcp: "+format, a...)
}
