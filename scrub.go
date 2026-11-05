package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Fixture scrubbing (ROADMAP 9.2). A capture from a real router goes through scrubCapture before
// it is saved under testdata/: addresses, MACs, host names and secrets are rewritten to stable
// stand-ins, so the same input always scrubs to the same output and a diff of two captures stays
// readable. The rules are in this file (compiled into every build, used by the capture build and
// by the hygiene test); only the `scrub` command is behind the `capture` build tag.

var (
	reFixtureIPv4     = regexp.MustCompile(`(?:^|[^0-9.])((?:\d{1,3}\.){3}\d{1,3})(?:$|[^0-9.]|\.(?:$|[^0-9]))`)
	reFixtureMAC      = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b`)
	reV6Token  = regexp.MustCompile(`[0-9a-fA-F:.]{3,}`)
	reWGKey    = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)
	reBearer   = regexp.MustCompile(`(?i)(bearer\s+|token[=:]\s*|apikey[=:]\s*|api_key[=:]\s*|password[=:]\s*)[^\s'",]+`)
	standInMAC = regexp.MustCompile(`(?i)^(?:02:00:00:00:00:[0-9a-f]{2}|00:00:5e:00:5[23]:[0-9a-f]{2})$`) // ours, and the RFC 7042 documentation range
)

type scrubber struct {
	hosts []string
	v4    map[string]string
	v6    map[string]string
	mac   map[string]string
	name  map[string]string
}

func newScrubber(hosts []string) *scrubber {
	return &scrubber{hosts: hosts, v4: map[string]string{}, v6: map[string]string{}, mac: map[string]string{}, name: map[string]string{}}
}

// keepV4 is what stays: the documented lab subnet, loopback, the unspecified address and masks.
func keepV4(a netip.Addr) bool {
	b := a.As4()
	switch {
	case a.IsLoopback(), a.IsUnspecified(), b[0] == 255:
		return true
	case b[0] == 192 && b[1] == 168 && b[2] == 1:
		return true
	case b[0] == 192 && b[1] == 0 && b[2] == 2, b[0] == 198 && b[1] == 51 && b[2] == 100, b[0] == 203 && b[1] == 0 && b[2] == 113:
		return true // documentation ranges: already stand-ins
	}
	return false
}

func (s *scrubber) addr4(raw string) string {
	a, err := netip.ParseAddr(raw)
	if err != nil || !a.Is4() || keepV4(a) {
		return raw
	}
	if v, ok := s.v4[raw]; ok {
		return v
	}
	var v string
	if a.IsPrivate() || a.IsLinkLocalUnicast() {
		v = fmt.Sprintf("192.168.1.%d", 100+len(s.v4)%100)
	} else {
		v = fmt.Sprintf("198.51.100.%d", 1+len(s.v4)%250)
	}
	s.v4[raw] = v
	return v
}

func (s *scrubber) scrubV4(text string) string {
	for {
		changed := false
		for _, m := range reFixtureIPv4.FindAllStringSubmatchIndex(text, -1) {
			raw := text[m[2]:m[3]]
			if strings.HasPrefix(text[m[3]:], "/") {
				continue // a range names no host
			}
			if n := s.addr4(raw); n != raw {
				text = text[:m[2]] + n + text[m[3]:]
				changed = true
				break
			}
		}
		if !changed {
			return text
		}
	}
}

func (s *scrubber) scrubV6(text string) string {
	return reV6Token.ReplaceAllStringFunc(text, func(tok string) string {
		if strings.Count(tok, ":") < 2 {
			return tok
		}
		a, err := netip.ParseAddr(strings.Trim(tok, ".:")+"")
		if err != nil || !a.Is6() || a.Is4In6() || a.IsLoopback() || a.IsUnspecified() {
			return tok
		}
		if p := netip.MustParsePrefix("2001:db8::/32"); p.Contains(a) {
			return tok
		}
		if v, ok := s.v6[a.String()]; ok {
			return v
		}
		v := fmt.Sprintf("2001:db8::%x", 1+len(s.v6))
		s.v6[a.String()] = v
		return v
	})
}

func (s *scrubber) scrubMAC(text string) string {
	return reFixtureMAC.ReplaceAllStringFunc(text, func(m string) string {
		if standInMAC.MatchString(m) {
			return m
		}
		key := strings.ToLower(m)
		if v, ok := s.mac[key]; ok {
			return v
		}
		v := fmt.Sprintf("02:00:00:00:00:%02x", 1+len(s.mac))
		s.mac[key] = v
		return v
	})
}

func (s *scrubber) scrubHosts(text string) string {
	for _, h := range s.hosts {
		if h == "" {
			continue
		}
		v, ok := s.name[strings.ToLower(h)]
		if !ok {
			v = fmt.Sprintf("host-%d", len(s.name)+1)
			s.name[strings.ToLower(h)] = v
		}
		text = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(h)).ReplaceAllString(text, v)
	}
	return text
}

// scrubCapture rewrites one captured output. Secrets go first so that nothing below sees them.
func (s *scrubber) scrubCapture(text string) string {
	text = maskUCIText(text, nil)
	text = reWGKey.ReplaceAllString(text, "<key>")
	text = reBearer.ReplaceAllString(text, "${1}<secret>")
	text = s.scrubHosts(text)
	text = s.scrubMAC(text)
	text = s.scrubV6(text)
	return s.scrubV4(text)
}

// fixtureProblems lists what a fixture still holds that a capture must not: a private address
// outside the lab subnet, a MAC that is not a stand-in, a WireGuard-shaped key, a bearer secret.
func fixtureProblems(text string) []string {
	var out []string
	for _, m := range reFixtureIPv4.FindAllStringSubmatchIndex(text, -1) {
		raw := text[m[2]:m[3]]
		if strings.HasPrefix(text[m[3]:], "/") {
			continue // a network range such as 10.0.0.0/8 names no host
		}
		a, err := netip.ParseAddr(raw)
		if err == nil && a.Is4() && (a.IsPrivate() || a.IsLinkLocalUnicast()) && !keepV4(a) {
			out = append(out, "private address "+raw)
		}
	}
	for _, m := range reFixtureMAC.FindAllString(text, -1) {
		if !standInMAC.MatchString(m) {
			out = append(out, "MAC "+m)
		}
	}
	if reWGKey.MatchString(text) {
		out = append(out, "a key-shaped value")
	}
	for _, m := range reBearer.FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[0], "<secret>") && !strings.Contains(m[0], "Canary") { // Canary: planted by a leak test, on purpose
			out = append(out, "a secret: "+m[0])
		}
	}
	return out
}
