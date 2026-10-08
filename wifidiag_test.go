package main

import (
	"context"
	"strings"
	"testing"
)

// net_diag wifi_survey and the airtime column of network_clients (ROADMAP 4.4, the passive
// half). `iwinfo survey` only has real data for a channel the radio has stayed on: every other
// channel holds the few milliseconds of a boot-time scan. So the survey reports the channels
// with at least ten seconds observed, says plainly that the rest are unmeasured, and never
// recommends a channel -- that needs a scan, which is not read-only.
//
// The numbers are a capture from a real 25.12 router (the percentages below were worked out by
// hand from them): 2.4 GHz ch 11 busy 78209022 of 250461980 ms = 31.2%, rx 66938467 = 26.7%,
// tx 8898750 = 3.6%; 5 GHz ch 48 busy 32151803 of 250469886 ms = 12.8%, rx 24559763 = 9.8%,
// tx 7301113 = 2.9%. The noise byte is a signed dBm value: 170 is -86, 164 is -92.

const survey24 = `{"results":[
 {"mhz":2412,"noise":172,"active_time":19,"busy_time":4,"busy_time_ext":0,"rx_time":4,"tx_time":0},
 {"mhz":2462,"noise":170,"active_time":250461980,"busy_time":78209022,"busy_time_ext":0,"rx_time":66938467,"tx_time":8898750},
 {"mhz":2467,"noise":171,"active_time":112,"busy_time":22,"busy_time_ext":0,"rx_time":20,"tx_time":0}]}`

const survey5 = `{"results":[
 {"mhz":5180,"noise":164,"active_time":19,"busy_time":2,"busy_time_ext":0,"rx_time":2,"tx_time":0},
 {"mhz":5200,"noise":0,"active_time":0,"busy_time":0,"busy_time_ext":0,"rx_time":0,"tx_time":0},
 {"mhz":5240,"noise":164,"active_time":250469886,"busy_time":32151803,"busy_time_ext":0,"rx_time":24559763,"tx_time":7301113}]}`

func surveyFake(t *testing.T) *fakeRouter {
	t.Helper()
	f := newFakeRouter(t)
	f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0","phy1-ap0","phy1-tor","phy0-ap1"]}`)
	f.on(`ubus call iwinfo survey {"device":"phy0-ap0"}`, survey24)
	f.on(`ubus call iwinfo survey {"device":"phy1-ap0"}`, survey5)
	f.on(`ubus call iwinfo info {"device":"phy0-ap0"}`, `{"channel":11,"frequency":2462,"mode":"Master"}`)
	f.on(`ubus call iwinfo info {"device":"phy1-ap0"}`, `{"channel":48,"frequency":5240,"mode":"Master"}`)
	return f
}

func TestWifiSurveyReportsTheChannelTheRadioStaysOn(t *testing.T) {
	f := surveyFake(t)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "wifi_survey"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"phy0 (via phy0-ap0): 2.4 GHz",
		"ch 11 (2462 MHz) current: busy 31.2%  rx 26.7%  tx 3.6%  noise -86 dBm  observed 69.6 h",
		"phy1 (via phy1-ap0): 5 GHz",
		"ch 48 (5240 MHz) current: busy 12.8%  rx 9.8%  tx 2.9%  noise -92 dBm  observed 69.6 h",
		"other channels: not measured",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"ch 1 (2412", "ch 14 (2467", "ch 36 (5180", "ch 40 (5200", "recommend"} {
		if strings.Contains(out, not) {
			t.Errorf("output must not contain %q (an unmeasured channel, or advice the data cannot support):\n%s", not, out)
		}
	}
	// One survey per radio: the second SSID on phy0 and the Tor AP on phy1 share a radio with one
	// that was already asked.
	for _, dev := range []string{"phy0-ap1", "phy1-tor"} {
		if f.ran(`ubus call iwinfo survey {"device":"` + dev + `"}`) {
			t.Errorf("surveyed %s although its radio was already surveyed", dev)
		}
	}
}

func TestWifiSurveyOfOneDevice(t *testing.T) {
	surveyFake(t)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "wifi_survey", Target: "phy1-ap0"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "phy1 (via phy1-ap0)") || strings.Contains(out, "phy0") {
		t.Errorf("a target must limit the survey to that device:\n%s", out)
	}
	if got := netDiagScope(netDiagIn{Action: "wifi_survey", Target: "phy1-ap0"}); len(got) != 1 || got[0] != "wifi_survey.phy1-ap0" {
		t.Errorf("scope = %v, want wifi_survey.phy1-ap0", got)
	}
}

// Ten seconds is the line between measured and not: 9,999 ms of observation is a scan's leftovers,
// 10,000 ms is a channel the radio has been on.
func TestWifiSurveyMeasuredLineIsTenSeconds(t *testing.T) {
	for _, c := range []struct {
		active   int
		measured bool
	}{{9999, false}, {10000, true}, {10001, true}} {
		f := newFakeRouter(t)
		f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0"]}`)
		f.on(`ubus call iwinfo survey {"device":"phy0-ap0"}`,
			`{"results":[{"mhz":2437,"noise":170,"active_time":`+itoa(int64(c.active))+`,"busy_time":1000,"rx_time":500,"tx_time":100}]}`)
		out, _, err := netDiag(context.Background(), netDiagIn{Action: "wifi_survey"})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out, "ch 6 (2437 MHz)"); got != c.measured {
			t.Errorf("active %d ms: measured = %v, want %v:\n%s", c.active, got, c.measured, out)
		}
		if !c.measured && !strings.Contains(out, "no channel observed for 10 s or more") {
			t.Errorf("a radio with nothing measured must say so:\n%s", out)
		}
	}
}

func TestWifiSurveyNoiseByteIsASignedDBm(t *testing.T) {
	for _, c := range []struct {
		raw  int
		want string
	}{{170, "noise -86 dBm"}, {164, "noise -92 dBm"}, {128, "noise -128 dBm"}, {255, "noise -1 dBm"}, {0, "noise n/a"}} {
		f := newFakeRouter(t)
		f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0"]}`)
		f.on(`ubus call iwinfo survey {"device":"phy0-ap0"}`,
			`{"results":[{"mhz":2437,"noise":`+itoa(int64(c.raw))+`,"active_time":20000,"busy_time":1000,"rx_time":500,"tx_time":100}]}`)
		out, _, _ := netDiag(context.Background(), netDiagIn{Action: "wifi_survey"})
		if !strings.Contains(out, c.want) {
			t.Errorf("noise byte %d: want %q in\n%s", c.raw, c.want, out)
		}
	}
}

func TestWifiSurveyNamesWhatItCouldNotAsk(t *testing.T) {
	f := newFakeRouter(t)
	f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0","phy1-ap0"]}`)
	f.on(`ubus call iwinfo survey {"device":"phy1-ap0"}`, survey5)
	out, _, err := netDiag(context.Background(), netDiagIn{Action: "wifi_survey"})
	if err != nil {
		t.Fatalf("one radio failing must not fail the call: %v", err)
	}
	if !strings.Contains(out, "phy0 (via phy0-ap0): survey unavailable") || !strings.Contains(out, "ch 48 (5240 MHz)") {
		t.Errorf("want a note for phy0 and the result for phy1:\n%s", out)
	}
}

func TestWifiSurveyRefusesABadDeviceName(t *testing.T) {
	newFakeRouter(t)
	for _, target := range []string{"bad name!", "-x", "../x", strings.Repeat("a", 40)} {
		_, _, err := netDiag(context.Background(), netDiagIn{Action: "wifi_survey", Target: target})
		if err == nil || errCode(err) != "VALIDATION" {
			t.Errorf("target %q: err = %v, want VALIDATION", target, err)
		}
	}
}

// ---------------------------------------------------------------- airtime in network_clients

func TestNetworkClientsShowsEachClientsShareOfTheRadiosAirtime(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "tmp/dhcp.leases",
		"0 00:00:5e:00:53:01 192.0.2.11 alpha *\n0 00:00:5e:00:53:02 192.0.2.12 bravo *\n0 00:00:5e:00:53:03 192.0.2.13 charlie *\n0 00:00:5e:00:53:04 192.0.2.14 delta *\n")
	f := newFakeRouter(t)
	f.on("uci -q show dhcp", "")
	f.on("ip -j neigh show", "[]")
	f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0","phy0-ap1","phy1-ap0"]}`)
	for _, dev := range []string{"phy0-ap0", "phy0-ap1", "phy1-ap0"} {
		f.on(`ubus call iwinfo info {"device":"`+dev+`"}`, `{"ssid":"S","mode":"Master"}`)
	}
	assoc := func(mac string) string {
		return `{"results":[{"mac":"` + mac + `","signal":-60,"connected_time":100,"rx":{"rate":1000},"tx":{"rate":1000}}]}`
	}
	f.on(`ubus call iwinfo assoclist {"device":"phy0-ap0"}`,
		`{"results":[{"mac":"00:00:5E:00:53:01","signal":-60,"connected_time":100,"rx":{"rate":1000},"tx":{"rate":1000}},`+
			`{"mac":"00:00:5E:00:53:02","signal":-60,"connected_time":100,"rx":{"rate":1000},"tx":{"rate":1000}}]}`)
	f.on(`ubus call iwinfo assoclist {"device":"phy0-ap1"}`, assoc("00:00:5E:00:53:03"))
	f.on(`ubus call iwinfo assoclist {"device":"phy1-ap0"}`, assoc("00:00:5E:00:53:04"))
	// Airtime on phy0 (two SSIDs, one radio): 300 + 100 + 100 = 500, so 60%, 20%, 20%. phy1 is a
	// different radio and its only client is 100% of it.
	f.on("ubus call hostapd.phy0-ap0 get_clients", `{"freq":2462,"clients":{
		"00:00:5e:00:53:01":{"airtime":{"rx":200,"tx":100}},"00:00:5e:00:53:02":{"airtime":{"rx":50,"tx":50}}}}`)
	f.on("ubus call hostapd.phy0-ap1 get_clients", `{"freq":2462,"clients":{"00:00:5e:00:53:03":{"airtime":{"rx":60,"tx":40}}}}`)
	f.on("ubus call hostapd.phy1-ap0 get_clients", `{"freq":5240,"clients":{"00:00:5e:00:53:04":{"airtime":{"rx":7,"tx":3}}}}`)

	out, _, err := networkClients(context.Background(), networkClientsIn{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, " AIR ") {
		t.Errorf("header lacks the AIR column:\n%s", out)
	}
	for host, want := range map[string]string{"alpha": "60%", "bravo": "20%", "charlie": "20%", "delta": "100%"} {
		row := ""
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, host+" ") {
				row = l
			}
		}
		if !strings.Contains(row, " "+want+" ") {
			t.Errorf("%s: want airtime share %s in %q", host, want, row)
		}
	}
}

// Without hostapd's answer the column is a dash and nothing else changes.
func TestNetworkClientsWithoutAirtimeDataStillWorks(t *testing.T) {
	root := withFixtureRoot(t)
	writeFixture(t, root, "tmp/dhcp.leases", "0 00:00:5e:00:53:01 192.0.2.11 alpha *\n")
	f := newFakeRouter(t)
	f.on("uci -q show dhcp", "")
	f.on("ip -j neigh show", "[]")
	f.on("ubus call iwinfo devices", `{"devices":["phy0-ap0"]}`)
	f.on(`ubus call iwinfo info {"device":"phy0-ap0"}`, `{"ssid":"S","mode":"Master"}`)
	f.on(`ubus call iwinfo assoclist {"device":"phy0-ap0"}`,
		`{"results":[{"mac":"00:00:5E:00:53:01","signal":-60,"connected_time":100,"rx":{"rate":1000},"tx":{"rate":1000}}]}`)
	out, _, err := networkClients(context.Background(), networkClientsIn{})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "alpha ") && !strings.Contains(l, " - ") {
			t.Errorf("row has no dash for the missing airtime: %q", l)
		}
	}
}
