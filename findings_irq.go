package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// irqbalance finding (ROADMAP 9.4): on a multi-core router the network and Wi-Fi interrupts often
// all land on CPU0, which then caps throughput while the other cores idle. irqbalance spreads them.
// The finding fires only on evidence from /proc/interrupts -- one CPU handles nearly every device
// interrupt after real traffic -- and is informational: it is a tuning hint, not a fault.

const (
	irqMinTotal  = 100000 // device interrupts seen since boot before the split means anything
	irqShareOver = 90     // percent on one CPU
)

func init() {
	findingHints["irq-one-cpu"] = findingHint{"pkg_query action=search with irqbalance (name to install); pkg_change adds it (simulates first), then service_control name=irqbalance action=enable and start", ""}
}

// irqSpread sums the per-CPU counts of device interrupts in a /proc/interrupts dump. Timers and
// inter-processor interrupts are left out: they are per-CPU by design.
func irqSpread(text string) (perCPU []uint64, total uint64) {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return nil, 0
	}
	cpus := 0
	for _, f := range strings.Fields(lines[0]) {
		if strings.HasPrefix(f, "CPU") {
			cpus++
		}
	}
	if cpus < 2 {
		return nil, 0
	}
	perCPU = make([]uint64, cpus)
	for _, l := range lines[1:] {
		f := strings.Fields(l)
		if len(f) < cpus+1 || !strings.HasSuffix(f[0], ":") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSuffix(f[0], ":")); err != nil {
			continue // IPI0:, ERR:, MIS: and the like
		}
		desc := strings.ToLower(strings.Join(f[cpus+1:], " "))
		if strings.Contains(desc, "timer") || strings.Contains(desc, "ipi") {
			continue
		}
		counts := make([]uint64, cpus)
		ok := true
		for i := 0; i < cpus; i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				ok = false
				break
			}
			counts[i] = n
		}
		if !ok {
			continue
		}
		for i, n := range counts {
			perCPU[i] += n
			total += n
		}
	}
	return perCPU, total
}

func checkIRQBalance(sn *snapshot) ([]finding, error) {
	text, err := readSys("/proc/interrupts")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no interrupt table (not a Linux /proc): nothing to say
	}
	if err != nil {
		return nil, err
	}
	perCPU, total := irqSpread(text)
	if total < irqMinTotal {
		return nil, nil
	}
	busy := 0
	for i, n := range perCPU {
		if n > perCPU[busy] {
			busy = i
		}
	}
	share := int(perCPU[busy] * 100 / total)
	if share < irqShareOver {
		return nil, nil
	}
	rc, err := sn.getRC()
	if err != nil {
		return nil, err
	}
	if e, ok := rc["irqbalance"]; ok && e.Running {
		return nil, nil
	}
	state := "irqbalance is not installed"
	if _, ok := rc["irqbalance"]; ok {
		state = "irqbalance is installed but not running"
	}
	return []finding{newFinding("irq-one-cpu", sevInfo,
		fmt.Sprintf("CPU%d handles %d%% of the device interrupts on this %d-core router", busy, share, len(perCPU)),
		fmt.Sprintf("/proc/interrupts: %d device interrupts since boot, %d%% on CPU%d; %s", total, share, busy, state))}, nil
}
