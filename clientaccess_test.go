package main

import (
	"fmt"
	"strings"
	"testing"
)

// render is the golden form: one line per change, as uci would be told.
func render(cs []UCIChange) string {
	var b strings.Builder
	for _, c := range cs {
		switch {
		case c.op() == opDelete:
			fmt.Fprintf(&b, "delete %s\n", uciKey(c))
		case c.op() == opCreate:
			fmt.Fprintf(&b, "%s=%s\n", uciKey(c), c.Type)
		case c.op() == opSetList:
			fmt.Fprintf(&b, "%s=%s\n", uciKey(c), strings.Join(c.Values, ","))
		default:
			fmt.Fprintf(&b, "%s=%s\n", uciKey(c), c.Value)
		}
	}
	return b.String()
}

const dev = "AA:BB:CC:DD:EE:01"

func TestClientAccessGolden(t *testing.T) {
	cases := []struct {
		name string
		in   clientAccessIn
		old  []string
		want string
	}{
		{"block", clientAccessIn{Action: "block", MAC: dev}, nil,
			"firewall.mcpdev_aabbccddee01_0=rule\n" +
				"firewall.mcpdev_aabbccddee01_0.name=mcp-block aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.src=lan\n" +
				"firewall.mcpdev_aabbccddee01_0.src_mac=aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.dest=wan\n" +
				"firewall.mcpdev_aabbccddee01_0.target=REJECT\n"},
		{"block again replaces its own rules", clientAccessIn{Action: "block", MAC: dev, Zone: "iot"},
			[]string{"mcpdev_aabbccddee01_0", "mcpdev_aabbccddee01_1"},
			"delete firewall.mcpdev_aabbccddee01_0\ndelete firewall.mcpdev_aabbccddee01_1\n" +
				"firewall.mcpdev_aabbccddee01_0=rule\n" +
				"firewall.mcpdev_aabbccddee01_0.name=mcp-block aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.src=iot\n" +
				"firewall.mcpdev_aabbccddee01_0.src_mac=aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.dest=wan\n" +
				"firewall.mcpdev_aabbccddee01_0.target=REJECT\n"},
		{"allow", clientAccessIn{Action: "allow", MAC: dev}, []string{"mcpdev_aabbccddee01_0"},
			"delete firewall.mcpdev_aabbccddee01_0\n"},
		{"schedule inside one day", clientAccessIn{Action: "schedule", MAC: dev, From: "08:00", Until: "15:30", Days: []string{"mon", "Fri"}}, nil,
			"firewall.mcpdev_aabbccddee01_0=rule\n" +
				"firewall.mcpdev_aabbccddee01_0.name=mcp-schedule aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.src=lan\n" +
				"firewall.mcpdev_aabbccddee01_0.src_mac=aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.dest=wan\n" +
				"firewall.mcpdev_aabbccddee01_0.target=REJECT\n" +
				"firewall.mcpdev_aabbccddee01_0.start_time=08:00:00\n" +
				"firewall.mcpdev_aabbccddee01_0.stop_time=15:30:00\n" +
				"firewall.mcpdev_aabbccddee01_0.weekdays=Mon Fri\n"},
		{"schedule past midnight on Sunday night", clientAccessIn{Action: "schedule", MAC: dev, From: "22:00", Until: "06:00", Days: []string{"sun"}}, nil,
			"firewall.mcpdev_aabbccddee01_0=rule\n" +
				"firewall.mcpdev_aabbccddee01_0.name=mcp-schedule aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.src=lan\n" +
				"firewall.mcpdev_aabbccddee01_0.src_mac=aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_0.dest=wan\n" +
				"firewall.mcpdev_aabbccddee01_0.target=REJECT\n" +
				"firewall.mcpdev_aabbccddee01_0.start_time=22:00:00\n" +
				"firewall.mcpdev_aabbccddee01_0.stop_time=23:59:59\n" +
				"firewall.mcpdev_aabbccddee01_0.weekdays=Sun\n" +
				"firewall.mcpdev_aabbccddee01_1=rule\n" +
				"firewall.mcpdev_aabbccddee01_1.name=mcp-schedule aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_1.src=lan\n" +
				"firewall.mcpdev_aabbccddee01_1.src_mac=aa:bb:cc:dd:ee:01\n" +
				"firewall.mcpdev_aabbccddee01_1.dest=wan\n" +
				"firewall.mcpdev_aabbccddee01_1.target=REJECT\n" +
				"firewall.mcpdev_aabbccddee01_1.start_time=00:00:00\n" +
				"firewall.mcpdev_aabbccddee01_1.stop_time=06:00:00\n" +
				"firewall.mcpdev_aabbccddee01_1.weekdays=Mon\n"},
	}
	for _, c := range cases {
		got, err := accessChanges(c.in, c.old)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if r := render(got); r != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, r, c.want)
		}
		for _, ch := range got {
			if err := validateChange(ch); err != nil {
				t.Errorf("%s: uci_apply would refuse %+v: %v", c.name, ch, err)
			}
		}
	}
}

// A block of one MAC must never delete, rewrite or match another device's rule.
func TestClientAccessCannotLeakToAnotherMAC(t *testing.T) {
	others := []string{"mcpdev_aabbccddee02_0", "mcpdev_aabbccddee011_0", "mcpdev_aabbccddee01x_0",
		"mcpdev_aabbccddee01_", "mcpdev_aabbccddee01_a", "mcpdev_aabbccddee01", "lan_rule", "mcpdev_aabbccddee01_0_1"}
	for _, action := range []string{"block", "allow"} {
		cs, err := accessChanges(clientAccessIn{Action: action, MAC: dev}, append(others, "mcpdev_aabbccddee01_0"))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			if c.Delete && c.Section != "mcpdev_aabbccddee01_0" {
				t.Errorf("%s deleted %s", action, c.Section)
			}
			if c.Option == "src_mac" && c.Value != "aa:bb:cc:dd:ee:01" {
				t.Errorf("%s wrote src_mac %s", action, c.Value)
			}
		}
	}
	if _, err := accessChanges(clientAccessIn{Action: "allow", MAC: dev}, others); err == nil {
		t.Error("allow with no rule of its own should say there is nothing to allow")
	}
}

func TestClientAccessRefusesBadInput(t *testing.T) {
	for name, in := range map[string]clientAccessIn{
		"bad mac":         {Action: "block", MAC: "aa:bb"},
		"multicast":       {Action: "block", MAC: "01:00:5e:00:00:01"},
		"broadcast":       {Action: "block", MAC: "ff:ff:ff:ff:ff:ff"},
		"zero":            {Action: "block", MAC: "00:00:00:00:00:00"},
		"unknown action":  {Action: "pause", MAC: dev},
		"window on block": {Action: "block", MAC: dev, From: "22:00"},
		"no window":       {Action: "schedule", MAC: dev},
		"empty window":    {Action: "schedule", MAC: dev, From: "22:00", Until: "22:00"},
		"bad time":        {Action: "schedule", MAC: dev, From: "25:00", Until: "06:00"},
		"bad day":         {Action: "schedule", MAC: dev, From: "22:00", Until: "06:00", Days: []string{"funday"}},
		"bad zone":        {Action: "block", MAC: dev, Zone: "lan wan"},
	} {
		if err := in.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClientAccessThroughTheServer(t *testing.T) {
	f := newFakeRouter(t)
	f.on("uci -q show firewall", "firewall.mcpdev_aabbccddee02_0=rule\nfirewall.mcpdev_aabbccddee02_0.src_mac='aa:bb:cc:dd:ee:02'\n")
	s := testServer(t, "\nconfig policy\n\toption client 'c'\n\tlist tools 'client_access'\n\tlist scopes 'client.aa:bb:cc:dd:ee:01'\n")
	cs := connectClient(t, s, "c")
	// The grant names one device: another MAC is denied before anything runs.
	out, isErr := callText(t, cs, "client_access", map[string]any{"action": "block", "mac": "aa:bb:cc:dd:ee:02", "dry_run": true})
	if !isErr || !strings.Contains(out, "client.aa:bb:cc:dd:ee:02") {
		t.Errorf("other device not denied by scope: %v %s", isErr, out)
	}
	if strings.Contains(f.allCalls(), "ee:02") {
		t.Errorf("a denied call reached the router:\n%s", f.allCalls())
	}
}
