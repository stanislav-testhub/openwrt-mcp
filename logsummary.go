package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// logread mode=summary and baselines (ROADMAP 4.1).
//
// After a restart-triggering change the useful question is "what is new in the log", not "show
// me 500 lines". A summary collapses the log to its distinct messages: numbers, addresses and
// ids are replaced by placeholders, so "DHCPACK ... 192.0.2.10 ..." and "DHCPACK ... 192.0.2.11
// ..." are one message seen twice. A baseline remembers which messages existed at one moment,
// so a later call can show only the ones that were not there.

// logLine is one line of `logread`, taken apart.
type logLine struct {
	when    time.Time
	hasTime bool
	sev     string // "-" when the line did not parse
	rank    int    // syslog level, 0 (emerg) .. 7 (debug); rankUnknown when the line did not parse
	proc    string // the program, without its pid
	msg     string
}

const rankUnknown = 8

var sevRank = map[string]int{"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warn": 4, "warning": 4, "notice": 5, "info": 6, "debug": 7}

// parseLogLine reads "Mon Jan _2 15:04:05 2006 facility.level proc[pid]: message". A line that
// does not have that shape is kept whole, under the process "-", rather than dropped.
func parseLogLine(line string) logLine {
	unparsed := logLine{sev: "-", rank: rankUnknown, proc: "-", msg: line}
	if len(line) < 25 || line[24] != ' ' {
		return unparsed
	}
	when, err := time.Parse("Mon Jan _2 15:04:05 2006", line[:24])
	if err != nil {
		return unparsed
	}
	facLevel, rest, ok := strings.Cut(strings.TrimLeft(line[25:], " "), " ")
	if !ok {
		return unparsed
	}
	dot := strings.LastIndexByte(facLevel, '.')
	if dot < 0 {
		return unparsed
	}
	sev := facLevel[dot+1:]
	rank, ok := sevRank[sev]
	if !ok {
		return unparsed
	}
	tag, msg, _ := strings.Cut(strings.TrimLeft(rest, " "), " ")
	if !strings.HasSuffix(tag, ":") || len(tag) < 2 {
		return unparsed
	}
	proc := strings.TrimSuffix(tag, ":")
	if i := strings.IndexByte(proc, '['); i > 0 && strings.HasSuffix(proc, "]") {
		proc = proc[:i]
	}
	return logLine{when: when, hasTime: true, sev: sev, rank: rank, proc: proc, msg: strings.TrimLeft(msg, " ")}
}

var (
	reKernelStamp = regexp.MustCompile(`^\[\s*\d+\.\d+\]\s*`)
	reLogMAC      = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b`)
	reLogClock    = regexp.MustCompile(`\b\d{1,2}:\d{2}:\d{2}\b`)
	reLogIPv4     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	reLogIPv6     = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?`)
	reLogHex0x    = regexp.MustCompile(`\b0[xX][0-9a-fA-F]+\b`)
	reLogLongHex  = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	reLogSpace    = regexp.MustCompile(`\s+`)
)

// normaliseLogMessage replaces what varies between two occurrences of the same message with a
// placeholder. The placeholders contain no digits, so normalising twice changes nothing more.
// A number that is part of a name (phy0-ap1, eth1) is kept: a summary that merged phy0 and phy1
// would hide which radio misbehaves.
func normaliseLogMessage(s string) string {
	for reKernelStamp.MatchString(s) {
		s = reKernelStamp.ReplaceAllString(s, "")
	}
	s = reLogMAC.ReplaceAllString(s, "<mac>")
	s = reLogClock.ReplaceAllString(s, "<time>")
	s = reLogIPv4.ReplaceAllString(s, "<ip>")
	s = reLogIPv6.ReplaceAllString(s, "<ip>")
	s = reLogHex0x.ReplaceAllString(s, "<hex>")
	s = reLogLongHex.ReplaceAllStringFunc(s, func(m string) string {
		// An id has both digits and letters; a plain number is left to the number rule, a plain
		// word (deadbeef) is just a word.
		if strings.ContainsAny(m, "0123456789") && strings.Trim(m, "0123456789") != "" {
			return "<hex>"
		}
		return m
	})
	s = replaceStandaloneNumbers(s)
	return strings.TrimSpace(reLogSpace.ReplaceAllString(s, " "))
}

// replaceStandaloneNumbers turns every run of digits into <n> unless a letter or underscore
// comes right before it.
func replaceStandaloneNumbers(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] < '0' || s[i] > '9' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if i > 0 && isWordByte(s[i-1]) {
			b.WriteString(s[i:j])
		} else {
			b.WriteString("<n>")
		}
		i = j
	}
	return b.String()
}

func isWordByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// logKey is what makes two log lines "the same message": the process and the normalised text.
func logKey(l logLine) string { return l.proc + "\x00" + normaliseLogMessage(l.msg) }

func keyHash(key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(key))
	return h.Sum64()
}

// ---------------------------------------------------------------- summary

type logMessage struct {
	proc, sev, msg string
	rank, count    int
	first, last    time.Time
	hasTime        bool
}

const maxSummaryMsgBytes = 200

func cutRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// summariseLog renders the distinct messages of lines, grouped by process: the processes with the
// worst severity first, then the busiest, and inside a process the commonest message first. n
// bounds the messages returned and offset pages through them.
func summariseLog(lines []string, header string, n, offset int) string {
	byKey := map[string]*logMessage{}
	var oldest, newest time.Time
	for _, raw := range lines {
		l := parseLogLine(raw)
		key := logKey(l)
		m := byKey[key]
		if m == nil {
			m = &logMessage{proc: l.proc, sev: l.sev, rank: l.rank, msg: cutRunes(normaliseLogMessage(l.msg), maxSummaryMsgBytes)}
			byKey[key] = m
		}
		m.count++
		if l.rank < m.rank {
			m.rank, m.sev = l.rank, l.sev
		}
		if l.hasTime {
			if !m.hasTime || l.when.Before(m.first) {
				m.first = l.when
			}
			if !m.hasTime || l.when.After(m.last) {
				m.last = l.when
			}
			m.hasTime = true
			if oldest.IsZero() || l.when.Before(oldest) {
				oldest = l.when
			}
			if l.when.After(newest) {
				newest = l.when
			}
		}
	}

	type group struct {
		proc  string
		rank  int
		total int
		msgs  []*logMessage
	}
	groups := map[string]*group{}
	for _, m := range byKey {
		g := groups[m.proc]
		if g == nil {
			g = &group{proc: m.proc, rank: rankUnknown}
			groups[m.proc] = g
		}
		g.msgs = append(g.msgs, m)
		g.total += m.count
		if m.rank < g.rank {
			g.rank = m.rank
		}
	}
	ordered := make([]*group, 0, len(groups))
	for _, g := range groups {
		sort.Slice(g.msgs, func(i, j int) bool {
			if g.msgs[i].count != g.msgs[j].count {
				return g.msgs[i].count > g.msgs[j].count
			}
			return g.msgs[i].msg < g.msgs[j].msg
		})
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.total != b.total {
			return a.total > b.total
		}
		return a.proc < b.proc
	})

	const stamp = "Jan _2 15:04:05"
	var rows []string
	for _, g := range ordered {
		for _, m := range g.msgs {
			first, last := "-", "-"
			if m.hasTime {
				first, last = m.first.Format(stamp), m.last.Format(stamp)
			}
			rows = append(rows, fmt.Sprintf("%-14s %-7s %5d  %-15s  %-15s  %s", m.proc, m.sev, m.count, first, last, m.msg))
		}
	}

	var b strings.Builder
	if header != "" {
		b.WriteString(header + "\n")
	}
	fmt.Fprintf(&b, "%d lines, %d distinct messages, processes: %d", len(lines), len(byKey), len(groups))
	if !oldest.IsZero() {
		fmt.Fprintf(&b, "; oldest %s, newest %s", oldest.Format(stamp), newest.Format(stamp))
	}
	b.WriteString("\n")
	if len(rows) == 0 {
		return strings.TrimRight(b.String(), "\n")
	}
	fmt.Fprintf(&b, "%-14s %-7s %5s  %-15s  %-15s  %s\n", "PROCESS", "SEV", "COUNT", "FIRST", "LAST", "MESSAGE")
	page, notice := pageLines(rows, offset, n, "messages")
	b.WriteString(strings.Join(page, "\n"))
	if notice != "" {
		b.WriteString("\n" + notice)
	}
	return b.String()
}

// ---------------------------------------------------------------- baselines

const (
	maxBaselines    = 8     // kept at once; the least recently used goes first
	maxBaselineKeys = 20000 // distinct messages in one baseline
)

var reBaselineToken = regexp.MustCompile(`^[0-9a-f]{8}$`)

// baseline is the set of messages that existed when it was saved, as 64-bit fingerprints. It
// holds no log text on purpose: a log line can carry a secret, and a fingerprint cannot be read
// back.
type baseline struct {
	token string
	keys  map[uint64]struct{}
}

// logBook keeps baselines in memory only. A restart of the daemon, which the weekly reboot
// includes, loses them; the error for an unknown token says so. Nothing is written to disk, so
// there is no state file to protect or to clean up.
type logBook struct {
	mu    sync.Mutex
	saved []baseline // oldest use first
}

var defaultLogBook = &logBook{}

func logread(ctx context.Context, in logreadIn) (string, string, error) {
	return defaultLogBook.logread(ctx, in)
}

func distinctKeys(lines []string) map[uint64]struct{} {
	keys := map[uint64]struct{}{}
	for _, raw := range lines {
		keys[keyHash(logKey(parseLogLine(raw)))] = struct{}{}
	}
	return keys
}

func (b *logBook) saveBaseline(lines []string) (string, string, error) {
	keys := distinctKeys(lines)
	if len(keys) > maxBaselineKeys {
		return "", "", invalid("%d distinct messages is too many for a baseline (limit %d); narrow it with pattern or since_minutes",
			len(keys), maxBaselineKeys)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	token := ""
	for token == "" || b.indexLocked(token) >= 0 {
		var raw [4]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", "", fmt.Errorf("no randomness for a baseline token: %w", err)
		}
		token = hex.EncodeToString(raw[:])
	}
	b.saved = append(b.saved, baseline{token: token, keys: keys})
	if len(b.saved) > maxBaselines {
		b.saved = b.saved[len(b.saved)-maxBaselines:]
	}
	return fmt.Sprintf("baseline %s saved: %d distinct messages from %d lines; call logread with baseline=%s to see only what is new "+
		"(kept in memory, lost when the daemon restarts)", token, len(keys), len(lines), token), "saved a baseline", nil
}

func (b *logBook) indexLocked(token string) int {
	for i, s := range b.saved {
		if s.token == token {
			return i
		}
	}
	return -1
}

// onlyNew keeps the lines whose message the baseline did not hold, and says how many messages
// that is. Using a baseline counts as using it: it is the last to be evicted.
func (b *logBook) onlyNew(token string, lines []string) ([]string, string, error) {
	b.mu.Lock()
	i := b.indexLocked(token)
	if i < 0 {
		b.mu.Unlock()
		return nil, "", withCode(codeNotFound, fmt.Errorf("no baseline %s: baselines are kept in the daemon's memory, so a restart "+
			"(the weekly reboot included) or %d newer baselines drop them; save a new one with baseline=save", token, maxBaselines))
	}
	s := b.saved[i]
	b.saved = append(append(b.saved[:i:i], b.saved[i+1:]...), s)
	b.mu.Unlock()

	var fresh []string
	all, added := map[uint64]struct{}{}, map[uint64]struct{}{}
	for _, raw := range lines {
		h := keyHash(logKey(parseLogLine(raw)))
		all[h] = struct{}{}
		if _, seen := s.keys[h]; !seen {
			fresh = append(fresh, raw)
			added[h] = struct{}{}
		}
	}
	return fresh, fmt.Sprintf("since baseline %s: %d of %d distinct messages are new", token, len(added), len(all)), nil
}
