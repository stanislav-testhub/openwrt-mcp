//go:build realtarget

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Run on a router (or a VM) that has the add-ons installed: every adapter whose init script exists
// answers for itself, and the test prints what it said so a person can read it against the
// package. It fails only when an adapter panics or returns nothing. ADDON_QUERY="svc=value,..."
// also runs queries.
//
//	go test -c -tags realtarget -o realtarget.test . && scp realtarget.test router: && ssh router ./realtarget.test -test.v -test.run RealAddon
func TestRealAddonAdaptersAnswerOnThisRouter(t *testing.T) {
	ctx := context.Background()
	rc, err := rcList(ctx)
	if err != nil {
		t.Skipf("no rc list here: %v", err)
	}
	n := 0
	for _, a := range adapters {
		if _, ok := rc[a.service]; !ok {
			continue
		}
		n++
		out, _, err := serviceDetail(ctx, rc, a.service, "")
		if err != nil || strings.TrimSpace(out) == "" {
			t.Errorf("%s: %v %q", a.service, err, out)
		}
		t.Logf("---- %s\n%s", a.service, out)
	}
	for _, q := range strings.Split(os.Getenv("ADDON_QUERY"), ",") {
		svc, val, ok := strings.Cut(q, "=")
		if !ok {
			continue
		}
		out, _, err := serviceDetail(ctx, rc, svc, val)
		t.Logf("---- query %s=%s (err %v)\n%s", svc, val, err, out)
	}
	if n == 0 {
		t.Skip("no add-on with an adapter is installed here")
	}
}

// ADDON_VERBS="svc.verb=arg,..." runs add-on verbs for real and logs what the router said, then
// the add-on's status again. Meant for a test VM: mwan3.ifdown=wan really takes the interface down.
func TestRealAddonVerbsOnThisRouter(t *testing.T) {
	ctx := context.Background()
	spec := os.Getenv("ADDON_VERBS")
	if spec == "" {
		t.Skip("ADDON_VERBS is not set")
	}
	rc, err := rcList(ctx)
	if err != nil {
		t.Skipf("no rc list here: %v", err)
	}
	for _, q := range strings.Split(spec, ",") {
		name, arg, _ := strings.Cut(q, "=")
		svc, verb, _ := strings.Cut(name, ".")
		v, ok := verbFor(svc, verb)
		if !ok {
			t.Errorf("no verb %s", name)
			continue
		}
		out, _, err := runVerb(ctx, v, arg)
		t.Logf("---- %s %s (err %v)\n%s", name, arg, err, out)
		after, _, _ := serviceDetail(ctx, rc, svc, "")
		t.Logf("after:\n%s", after)
	}
}

// The doctor and the audit with the add-ons this router really has: logs what they say, fails on a
// panic only.
func TestRealDoctorAndAuditWithAddons(t *testing.T) {
	ctx := context.Background()
	if _, err := rcList(ctx); err != nil {
		t.Skipf("no rc list here: %v", err)
	}
	t.Logf("---- doctor\n%s", healthFindings(ctx).render())
	t.Logf("---- audit\n%s", auditFindings(ctx).render())
}

// NETDIAG_IFACE=eth1 [NETDIAG_IPERF=host] runs capture (and throughput) for real and logs the summary.
// Generate traffic on that interface while it runs.
func TestRealNetDiagCaptureAndThroughput(t *testing.T) {
	ctx := context.Background()
	if iface := os.Getenv("NETDIAG_IFACE"); iface != "" {
		out, _, err := netDiag(ctx, netDiagIn{Action: "capture", Target: iface, Count: 6, Filter: os.Getenv("NETDIAG_FILTER")})
		t.Logf("---- capture %s (err %v)\n%s", iface, err, out)
	}
	if h := os.Getenv("NETDIAG_IPERF"); h != "" {
		out, _, err := netDiag(ctx, netDiagIn{Action: "throughput", Target: h, Count: 3})
		t.Logf("---- throughput %s (err %v)\n%s", h, err, out)
	}
	if os.Getenv("NETDIAG_IFACE") == "" && os.Getenv("NETDIAG_IPERF") == "" {
		t.Skip("NETDIAG_IFACE / NETDIAG_IPERF not set")
	}
}
