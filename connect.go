package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// `openwrt-mcp connect` runs on the operator's PC, not the router. It makes the dedicated SSH key,
// says what to run on the router, and puts the entry that starts the bridge into the client's
// configuration. `connect doctor` (doctor.go) checks the whole chain and names the step that fails.
// It only ever writes files on the PC.

// connectParams is everything the entry and the checks need to know about the router.
type connectParams struct {
	Client string // which MCP client is being configured
	Name   string // the client name the router's policy knows this key by
	Host   string
	Port   int
	User   string
	Key    string // path of the private key on this PC
}

var (
	reHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:%\[\]-]*$`)
	reUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

func (p connectParams) validate() error {
	switch {
	case !reHost.MatchString(p.Host):
		return fmt.Errorf("bad --host %q: a host name or address, not starting with '-'", p.Host)
	case p.Port < 1 || p.Port > 65535:
		return fmt.Errorf("bad --port %d", p.Port)
	case !reUser.MatchString(p.User):
		return fmt.Errorf("bad --user %q", p.User)
	case !reClientName.MatchString(p.Name):
		return fmt.Errorf("bad --name %q: use letters, digits, '.', '_' or '-' (max 64)", p.Name)
	case p.Key == "" || strings.HasPrefix(p.Key, "-"):
		return fmt.Errorf("bad --key %q", p.Key)
	}
	return nil
}

// sshArgs is the command line the client runs, after "ssh": no terminal, only this key, never a
// prompt (a client cannot answer one), and keep-alives so a router that went away is noticed.
func (p connectParams) sshArgs() []string {
	return []string{
		"-T", "-i", p.Key, "-p", strconv.Itoa(p.Port),
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
		"-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
		p.User + "@" + p.Host,
	}
}

// sshCommand and keygenCommand are the programs run on this PC, as variables so a test can
// stand in a fake: the PC's own OpenSSH is the thing we cannot rely on in a test.
var (
	sshCommand    = []string{"ssh"}
	keygenCommand = []string{"ssh-keygen"}
)

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return filepath.Join(home, p[2:])
	}
	return p
}

// connectEnv is the PC the command runs on, made explicit so tests do not touch the real one.
type connectEnv struct {
	goos, home, appdata, cwd string
}

func currentEnv() connectEnv {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	return connectEnv{goos: runtime.GOOS, home: home, appdata: os.Getenv("APPDATA"), cwd: cwd}
}

// ensureKey makes the ed25519 key at path if it is not there; it never overwrites one.
func ensureKey(path, name string, out io.Writer) (created bool, err error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	argv := append(append([]string(nil), keygenCommand...), "-t", "ed25519", "-N", "", "-C", "openwrt-mcp:"+name, "-f", path)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = io.Discard, out
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("ssh-keygen failed: %w (OpenSSH ships with Windows 10 and later, macOS and Linux; "+
			"or make the key yourself and pass --key)", err)
	}
	return true, nil
}

var rePublicKey = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/]+={0,3}$`)

// publicKey returns "<type> <base64>" for the key at path: the .pub next to it, or derived from
// the private key. The comment is dropped on purpose: it is free text that ends up inside a
// command the operator pastes on the router.
func publicKey(path string) (string, error) {
	b, err := os.ReadFile(path + ".pub")
	if err != nil {
		argv := append(append([]string(nil), keygenCommand...), "-y", "-f", path)
		out, derr := exec.Command(argv[0], argv[1:]...).Output()
		if derr != nil {
			return "", fmt.Errorf("no %s.pub and ssh-keygen -y failed: %w", path, derr)
		}
		b = out
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return "", fmt.Errorf("%s.pub is not a public key line", path)
	}
	line := f[0] + " " + f[1]
	if !rePublicKey.MatchString(line) {
		return "", fmt.Errorf("%s.pub is not a public key this server can bind", path)
	}
	return line, nil
}

// runConnect is `openwrt-mcp connect ...`. It prints the plan and, with write, carries out the
// part that touches the client's configuration.
func runConnect(w, errw io.Writer, env connectEnv, p connectParams, write, replace bool, configFile string) error {
	if !contains(connectClients, p.Client) {
		return fmt.Errorf("unknown --client %q (one of: %s)", p.Client, strings.Join(connectClients, ", "))
	}
	p.Key = expandHome(p.Key, env.home)
	if err := p.validate(); err != nil {
		return err
	}
	created, err := ensureKey(p.Key, p.Name, errw)
	if err != nil {
		return err
	}
	pub, err := publicKey(p.Key)
	if err != nil {
		return err
	}
	q := func(a ...string) string { return quoteCommand(env.goos, a) }
	fmt.Fprintf(w, "Connecting %s to openwrt-mcp on %s as client %q.\n\n", p.Client, p.Host, p.Name)
	if created {
		fmt.Fprintf(w, "1. Made the key %s (no passphrase: the client has to start it unattended).\n\n", p.Key)
	} else {
		fmt.Fprintf(w, "1. Using the key %s that is already there.\n\n", p.Key)
	}
	admin := []string{"ssh", "-p", strconv.Itoa(p.Port), "root@" + p.Host}
	fmt.Fprintf(w, "2. On the router, once, as root. This is also where ssh asks you to accept the router's host key,\n"+
		"   which the client cannot do for itself:\n")
	// The remote command is inside double quotes with single quotes within: that reads the same
	// in a POSIX shell, PowerShell and cmd. It holds only characters validated above (the name
	// and the "<type> <base64>" key), so nothing in it needs escaping.
	remote := func(cmd string) string { return q(admin...) + ` "` + cmd + `"` }
	fmt.Fprintf(w, "     %s\n", remote("openwrt-mcp authorize-key "+p.Name+" '"+pub+"'"))
	fmt.Fprintf(w, "     %s\n", remote("openwrt-mcp allow "+p.Name+" @readonly 30d"))
	fmt.Fprintf(w, "   The first binds the key to the MCP bridge: it cannot open a shell or forward ports.\n"+
		"   The second lets it read; ask for @operator only when you want it to change things.\n\n")

	if isWSL() && p.Client != "claude-code" && p.Client != "codex" {
		fmt.Fprintf(w, "   Note: this is WSL. A Windows-side client uses the Windows ssh and the Windows ~/.ssh, not these.\n"+
			"   Run connect from Windows (PowerShell) for that client.\n\n")
	}

	if bin, ok := cliClients[p.Client]; ok {
		argv := cliAddArgv(p.Client, p)
		fmt.Fprintf(w, "3. Register it with %s:\n     %s\n", bin, q(argv...))
		if !write {
			fmt.Fprintf(w, "   Add --write and connect runs that command for you.\n")
		} else if err := runClientCLI(w, errw, argv); err != nil {
			return err
		}
	} else if err := connectJSON(w, env, p, write, replace, configFile); err != nil {
		return err
	}

	fmt.Fprintf(w, "\n4. Check the whole chain:\n     %s\n", q("openwrt-mcp", "connect", "doctor",
		"--host", p.Host, "--port", strconv.Itoa(p.Port), "--user", p.User, "--key", p.Key))
	return nil
}

// clientCLI runs a client's own command. found is false when the program is not on this PC's
// PATH. A variable so a test does not run a real `claude` or `codex`.
var clientCLI = func(argv []string, w, errw io.Writer) (found bool, err error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return false, nil
	}
	cmd := exec.Command(path, argv[1:]...)
	cmd.Stdout, cmd.Stderr = w, errw
	return true, cmd.Run()
}

// runClientCLI runs the client's own `mcp add`. A client that is not installed here is not an
// error: the command was printed, and the operator can run it where the client lives.
func runClientCLI(w, errw io.Writer, argv []string) error {
	found, err := clientCLI(argv, w, errw)
	switch {
	case !found:
		fmt.Fprintf(w, "   %s is not on this PC's PATH, so nothing was run. Run the command above where it is installed.\n", argv[0])
	case err != nil:
		return fmt.Errorf("%s failed: %w", argv[0], err)
	default:
		fmt.Fprintf(w, "   Ran it.\n")
	}
	return nil
}

func connectJSON(w io.Writer, env connectEnv, p connectParams, write, replace bool, configFile string) error {
	spec := jsonClients[p.Client]
	path := configFile
	if path == "" {
		var err error
		if path, err = clientConfigPath(env.goos, p.Client, env.home, env.appdata, env.cwd); err != nil {
			return err
		}
	}
	entry := serverEntry(p, spec.typed)
	fmt.Fprintf(w, "3. Add this to %s (the %q object; other servers there stay as they are):\n", path, spec.key)
	for _, l := range displaySnippet(spec.key, entry) {
		fmt.Fprintf(w, "     %s\n", l)
	}
	if !write {
		fmt.Fprintf(w, "   Add --write and connect merges it into the file for you (the original is kept once as\n"+
			"   %s).\n", filepath.Base(path)+".before-openwrt-mcp")
		return nil
	}
	changed, err := writeClientConfig(path, spec.key, entry, replace)
	switch {
	case errors.Is(err, errExists):
		return fmt.Errorf("%s already has an entry named %q that differs from this one; add --replace to overwrite it", path, serverName)
	case errors.Is(err, errNotJSON):
		return fmt.Errorf("not touching %s: %v\n   Add the snippet above by hand.", path, err)
	case err != nil:
		return err
	case !changed:
		fmt.Fprintf(w, "   %s already has exactly this entry.\n", path)
	default:
		fmt.Fprintf(w, "   Wrote %s. Restart %s to pick it up.\n", path, p.Client)
	}
	return nil
}

// connectMain parses `connect [doctor] ...` and runs it.
func connectMain(args []string) error {
	doctor := len(args) > 0 && args[0] == "doctor"
	if doctor {
		args = args[1:]
	}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	client := fs.String("client", "", "MCP client to configure: "+strings.Join(connectClients, ", "))
	host := fs.String("host", "", "the router's address or name")
	port := fs.Int("port", 22, "the router's SSH port")
	user := fs.String("user", "root", "the SSH user on the router")
	key := fs.String("key", "~/.ssh/openwrt_mcp", "private key for the bridge (made if absent)")
	name := fs.String("name", "", "client name the router's policy uses (default: the --client value)")
	write := fs.Bool("write", false, "change the client's configuration instead of only showing what to add")
	replace := fs.Bool("replace", false, "with --write, overwrite an existing entry of the same name")
	file := fs.String("file", "", "with --write, the client's configuration file, when it is not in the usual place")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *host == "" || (!doctor && *client == "") {
		return errors.New("usage: openwrt-mcp connect --client <" + strings.Join(connectClients, "|") + "> --host <router> [--port 22] [--user root] [--key PATH] [--name NAME] [--write [--replace] [--file PATH]]\n" +
			"       openwrt-mcp connect doctor --host <router> [--port 22] [--user root] [--key PATH] [--name NAME]")
	}
	env := currentEnv()
	p := connectParams{Client: *client, Name: *name, Host: *host, Port: *port, User: *user, Key: expandHome(*key, env.home)}
	if p.Name == "" {
		p.Name = orDefault(*client, "claude-code")
	}
	if doctor {
		return runDoctor(context.Background(), os.Stdout, p)
	}
	return runConnect(os.Stdout, os.Stderr, env, p, *write, *replace, *file)
}
