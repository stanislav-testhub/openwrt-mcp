package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The doctor (ROADMAP 4.2). Each check reads what it needs through the snapshot, which fetches
// every source once and only when a check asks, so a check that cannot get its data is reported
// as not checked and the others still run.

// lazy memoises one fetch, error included.
type lazy[T any] struct {
	done bool
	v    T
	err  error
}

func (l *lazy[T]) get(f func() (T, error)) (T, error) {
	if !l.done {
		l.v, l.err = f()
		l.done = true
	}
	return l.v, l.err
}

type radioStatus struct {
	Up               bool `json:"up"`
	Disabled         bool `json:"disabled"`
	RetrySetupFailed bool `json:"retry_setup_failed"`
}

type procdInstance struct {
	Running  bool `json:"running"`
	ExitCode *int `json:"exit_code"`
}

type procdService struct {
	Instances map[string]procdInstance `json:"instances"`
}

type snapshot struct {
	ctx      context.Context
	limits   []string
	board    lazy[ubusBoard]
	info     lazy[ubusSysInfo]
	ifaces   lazy[[]ubusIface]
	wireless lazy[map[string]radioStatus]
	procd    lazy[map[string]procdService]
	rc       lazy[map[string]rcEntry]
	uci      map[string]*lazy[*uciTree]
	ids      bool // read configs with section ids, so an unnamed section keeps its name across two snapshots
}

func newSnapshot(ctx context.Context) *snapshot {
	return &snapshot{ctx: ctx, uci: map[string]*lazy[*uciTree]{}}
}

func (sn *snapshot) limit(s string) { sn.limits = append(sn.limits, s) }

func (sn *snapshot) getBoard() (ubusBoard, error) {
	return sn.board.get(func() (b ubusBoard, err error) {
		err = runJSON(sn.ctx, &b, "ubus", "call", "system", "board")
		return
	})
}

func (sn *snapshot) getInfo() (ubusSysInfo, error) {
	return sn.info.get(func() (i ubusSysInfo, err error) {
		err = runJSON(sn.ctx, &i, "ubus", "call", "system", "info")
		return
	})
}

func (sn *snapshot) getIfaces() ([]ubusIface, error) {
	return sn.ifaces.get(func() ([]ubusIface, error) { return interfaceDump(sn.ctx) })
}

func (sn *snapshot) getWireless() (map[string]radioStatus, error) {
	return sn.wireless.get(func() (m map[string]radioStatus, err error) {
		err = runJSON(sn.ctx, &m, "ubus", "call", "network.wireless", "status")
		return
	})
}

func (sn *snapshot) getProcd() (map[string]procdService, error) {
	return sn.procd.get(func() (m map[string]procdService, err error) {
		err = runJSON(sn.ctx, &m, "ubus", "call", "service", "list")
		return
	})
}

func (sn *snapshot) getRC() (map[string]rcEntry, error) {
	return sn.rc.get(func() (map[string]rcEntry, error) { return rcList(sn.ctx) })
}

// getUCI loads one config, once.
func (sn *snapshot) getUCI(config string) (*uciTree, error) {
	l := sn.uci[config]
	if l == nil {
		l = &lazy[*uciTree]{}
		sn.uci[config] = l
	}
	return l.get(func() (*uciTree, error) { return uciShow(sn.ctx, config, sn.ids) })
}

type check struct {
	name string
	run  func(sn *snapshot) ([]finding, error)
}

// runChecks runs every check against one snapshot. A check that returns an error is listed under
// "not checked" with the reason, not turned into a finding.
func runChecks(ctx context.Context, title string, checks []check) *findingsRun {
	return runChecksOn(newSnapshot(ctx), title, checks)
}

func runChecksOn(sn *snapshot, title string, checks []check) *findingsRun {
	r := &findingsRun{title: title}
	for _, c := range checks {
		fs, err := c.run(sn)
		if err != nil {
			reason := strings.TrimSpace(strings.SplitN(err.Error(), "\n", 2)[0])
			r.skipped = append(r.skipped, fmt.Sprintf("%s (%s)", c.name, trunc(reason, 100)))
			continue
		}
		r.checked = append(r.checked, c.name)
		r.findings = append(r.findings, fs...)
	}
	r.limits = sn.limits
	return r
}

func healthFindings(ctx context.Context) *findingsRun {
	return runChecks(ctx, "doctor", []check{
		{"radios", checkRadios},
		{"interfaces", checkInterfaces},
		{"services", checkServices},
		{"conntrack", checkConntrack},
		{"storage", checkStorage},
		{currentPkgManager().name() + "-new", checkNewConfigs},
		{"ntp", checkNTP},
		{"kernel", checkKernel},
	})
}

func checkRadios(sn *snapshot) ([]finding, error) {
	wl, err := sn.getWireless()
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, name := range sortedKeys(wl) {
		r := wl[name]
		if r.Disabled || r.Up {
			continue
		}
		sev, msg := sevMedium, fmt.Sprintf("radio %s is configured but not up", name)
		if r.RetrySetupFailed {
			sev, msg = sevHigh, fmt.Sprintf("radio %s is configured but not up, and setup failed and was given up", name)
		}
		out = append(out, newFinding("radio-down", sev, msg,
			fmt.Sprintf("network.wireless status: %s up=false retry_setup_failed=%t", name, r.RetrySetupFailed)))
	}
	return out, nil
}

// Protocols that must end up with an address when the interface is up. dhcpv6 is left out: a link
// with no IPv6 from the provider is up without one and that is normal.
var addressedProtos = map[string]bool{"static": true, "dhcp": true, "pppoe": true, "pppoa": true}

func checkInterfaces(sn *snapshot) ([]finding, error) {
	ifs, err := sn.getIfaces()
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, i := range ifs {
		if i.Interface == "loopback" {
			continue
		}
		if i.Up && addressedProtos[i.Proto] && len(i.IPv4) == 0 && len(i.IPv6) == 0 {
			out = append(out, newFinding("iface-no-address", sevMedium,
				fmt.Sprintf("interface %s is up but has no address", i.Interface),
				fmt.Sprintf("network.interface dump: %s proto=%s up=true, no ipv4-address or ipv6-address", i.Interface, i.Proto)))
		}
		var codes []string
		for _, e := range i.Errors {
			codes = append(codes, e.Code)
		}
		if len(codes) > 0 {
			out = append(out, newFinding("iface-error", sevMedium,
				fmt.Sprintf("interface %s reports an error", i.Interface),
				fmt.Sprintf("network.interface dump: %s %s", i.Interface, strings.Join(codes, " "))))
		}
	}
	return out, nil
}

// checkServices flags a procd service that is enabled at boot, has instances, and none of them
// is running, with a non-zero exit code on at least one. A one-shot init script that ran and
// exited with 0 looks like a stopped daemon in `rc list`; the exit code is what tells them apart.
func checkServices(sn *snapshot) ([]finding, error) {
	procd, err := sn.getProcd()
	if err != nil {
		return nil, err
	}
	sn.limit("services: only daemons that procd started and that then died are reported; one that never started has no instance (service_list shows it as stopped)")
	rc, err := sn.getRC()
	if err != nil {
		return nil, err
	}
	var out []finding
	for _, name := range sortedKeys(procd) {
		svc := procd[name]
		if len(svc.Instances) == 0 || !rc[name].Enabled {
			continue
		}
		running, failed := false, -1
		for _, inst := range svc.Instances {
			if inst.Running {
				running = true
			}
			if inst.ExitCode != nil && *inst.ExitCode != 0 {
				failed = *inst.ExitCode
			}
		}
		if !running && failed >= 0 {
			out = append(out, newFinding("service-crashed", sevMedium,
				fmt.Sprintf("service %s is enabled but its process is not running", name),
				fmt.Sprintf("%s: exit code %d (procd service list)", name, failed)))
		}
	}
	return out, nil
}

func checkConntrack(sn *snapshot) ([]finding, error) {
	cs, err := readSys("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return nil, fmt.Errorf("no nf_conntrack_count")
	}
	ms, err := readSys("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return nil, fmt.Errorf("no nf_conntrack_max")
	}
	count, e1 := strconv.ParseInt(strings.TrimSpace(cs), 10, 64)
	max, e2 := strconv.ParseInt(strings.TrimSpace(ms), 10, 64)
	if e1 != nil || e2 != nil || max <= 0 {
		return nil, fmt.Errorf("unreadable conntrack counters")
	}
	if count*100 < max*80 {
		return nil, nil
	}
	sev := sevMedium
	if count*100 >= max*95 {
		sev = sevHigh
	}
	return []finding{newFinding("conntrack-high", sev,
		fmt.Sprintf("the connection tracking table is %d%% full; new connections are dropped when it fills", count*100/max),
		fmt.Sprintf("nf_conntrack_count/nf_conntrack_max = %d/%d", count, max))}, nil
}

func checkStorage(sn *snapshot) ([]finding, error) {
	info, err := sn.getInfo()
	if err != nil {
		return nil, err
	}
	var out []finding
	free := func(id string, total, avail int64, high severity, what string) {
		if total <= 0 || avail*100 >= total*10 {
			return
		}
		sev := sevMedium
		if id == "tmp-full" {
			sev = sevLow
		}
		if avail*100 < total*5 {
			sev = high
		}
		out = append(out, newFinding(id, sev, fmt.Sprintf("%s has %d%% free", what, avail*100/total),
			fmt.Sprintf("system info: %d of %d KiB free (%d%%)", avail, total, avail*100/total)))
	}
	free("overlay-full", info.Root.Total, info.Root.Avail, sevHigh, "the flash overlay")
	free("tmp-full", info.Tmp.Total, info.Tmp.Avail, sevLow, "/tmp (RAM)")
	return out, nil
}

func checkNewConfigs(sn *snapshot) ([]finding, error) {
	files := findNewConfigs()
	if len(files) == 0 {
		return nil, nil
	}
	shown := files
	if len(shown) > 3 {
		shown = shown[:3]
	}
	ev := strings.Join(shown, ", ")
	if len(files) > len(shown) {
		ev += fmt.Sprintf(" (+%d more)", len(files)-len(shown))
	}
	return []finding{newFinding(currentPkgManager().name()+"-new-pending", sevLow,
		fmt.Sprintf("%d package config file(s) wait for a merge: an upgrade left the new default beside yours", len(files)), ev)}, nil
}

// earliestPlausible is the first moment a router running this software can have been told the
// time: before it, the clock was never set. (25.12 was released at the end of 2025.)
const earliestPlausible = 1735689600 // 2025-01-01 00:00 UTC

// checkNTP asks chrony when it is installed. Anything else cannot be asked through a stable
// interface, so it only judges whether the clock was ever set, and says that is all it did.
func checkNTP(sn *snapshot) ([]finding, error) {
	if _, err := os.Stat(sysPath("/usr/bin/chronyc")); err == nil {
		out, err := run(sn.ctx, defaultCmdTimeout, "chronyc", "-c", "tracking")
		if err != nil {
			return nil, fmt.Errorf("chronyc: %w", err)
		}
		f := strings.Split(strings.TrimSpace(out), ",")
		if len(f) < 14 {
			return nil, fmt.Errorf("unexpected chronyc output")
		}
		stratum, leap := f[2], f[13]
		if leap == "Not synchronised" {
			return []finding{newFinding("ntp-unsynced", sevMedium, "chrony is running but has no time source",
				fmt.Sprintf("chronyc tracking: stratum %s, leap status %s", stratum, leap))}, nil
		}
		return nil, nil
	}
	info, err := sn.getInfo()
	if err != nil {
		return nil, err
	}
	sn.limit("ntp: no chronyc, so only whether the clock was ever set was checked")
	if info.LocalTime < earliestPlausible {
		return []finding{newFinding("clock-unset", sevMedium, "the router's clock was never set: it reads a date before 2025",
			fmt.Sprintf("system info: localtime %d = %s UTC", info.LocalTime, time.Unix(info.LocalTime, 0).UTC().Format("2006-01-02 15:04:05")))}, nil
	}
	return nil, nil
}

var reKernelPkg = regexp.MustCompile(`(?m)^kernel-([0-9]+(?:\.[0-9]+)+)`)

// checkKernel compares the kernel that is running with the one the package manager has
// installed. After an upgrade they differ until the router restarts.
func checkKernel(sn *snapshot) ([]finding, error) {
	board, err := sn.getBoard()
	if err != nil {
		return nil, err
	}
	installed, err := currentPkgManager().installedKernel(sn.ctx)
	if err != nil {
		return nil, err
	}
	if board.Kernel == "" || board.Kernel == installed {
		return nil, nil
	}
	return []finding{newFinding("reboot-needed", sevMedium,
		"a newer kernel is installed than the one running; it loads at the next restart",
		fmt.Sprintf("running %s, installed %s", board.Kernel, installed))}, nil
}
