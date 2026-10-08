package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Config history (ROADMAP 2.4). When a change is confirmed, the version of each config from
// BEFORE it is kept, so "what did this look like before last week's change" has an answer.
// The newest history_keep versions per config are kept; uci_get history=list|diff:<id> reads
// them and uci_apply restore=<id> puts one back through the normal rollback-armed apply.
//
// A rollback-armed writer (uci_apply, a restore, pkg_config_resolve) already snapshots the old
// file, so confirming promotes that snapshot instead of deleting it; a rolled-back change
// leaves nothing, and failed experiments cannot push real history out. The WireGuard tools
// commit straight away with no rollback, so they record the file just before committing.
//
// Entries are whole config files, secrets included, so they get the snapshots' protection: a
// 0700 directory under the state dir, 0600 files, and they are masked when shown.

const (
	defaultHistoryKeep = 5
	maxHistoryKeep     = 20
)

// historyNow is the clock for entry names; tests replace it.
var historyNow = time.Now

// An id is "<config>:<UTC yyyymmdd-HHMMSS.mmm>-<8 hex>". It names a file under the state dir,
// so the grammar is strict: nothing in it can be a path separator or a dot-dot.
var reHistoryID = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_-]*):([0-9]{8}-[0-9]{6}\.[0-9]{3}-[0-9a-f]{8})$`)

func parseHistoryID(id string) (config, stamp string, err error) {
	m := reHistoryID.FindStringSubmatch(id)
	if m == nil {
		return "", "", invalid("bad history id %q: use one listed by uci_get history=list", id)
	}
	return m[1], m[2], nil
}

type historyEntry struct {
	Config string `json:"-"`
	Stamp  string `json:"-"`
	Time   string `json:"time"`
	Client string `json:"client"`
	What   string `json:"what"`
	Mode   uint32 `json:"mode"`
}

func (e historyEntry) id() string { return e.Config + ":" + e.Stamp }

func (s *Server) historyPath(config string) string { return path.Join(historyDir(s.statePath), config) }

// saveHistory stores body, the content of config before a change, as its newest entry and
// prunes the rest. Failing to record history never fails the change it belongs to.
func (s *Server) saveHistory(config string, body []byte, mode uint32, client, what, seed string) {
	keep := s.cfg().HistoryKeep
	if keep <= 0 {
		return
	}
	s.histMu.Lock()
	defer s.histMu.Unlock()
	dir := s.historyPath(config)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("openwrt-mcp: history for %s: %v", config, err)
		return
	}
	now := historyNow().UTC()
	sum := sha256.Sum256([]byte(seed))
	stamp := now.Format("20060102-150405.000") + "-" + hex.EncodeToString(sum[:4])
	meta, _ := json.Marshal(historyEntry{Time: now.Format(time.RFC3339), Client: client, What: what, Mode: mode})
	if err := writeSynced(path.Join(dir, stamp), body, 0o600); err != nil {
		log.Printf("openwrt-mcp: history for %s: %v", config, err)
		return
	}
	if err := writeSynced(path.Join(dir, stamp+".json"), meta, 0o600); err != nil {
		log.Printf("openwrt-mcp: history for %s: %v", config, err)
	}
	for i, e := range s.listHistory(config) {
		if i >= keep {
			_ = os.Remove(path.Join(dir, e.Stamp))
			_ = os.Remove(path.Join(dir, e.Stamp+".json"))
		}
	}
}

// promoteHistory keeps the pre-change snapshot of a confirmed apply.
func (s *Server) promoteHistory(p *pendingApply) {
	for _, c := range p.Configs {
		if contains(p.Missing, c) {
			continue
		}
		b, err := os.ReadFile(path.Join(p.Dir, c))
		if err != nil {
			log.Printf("openwrt-mcp: history for %s: %v", c, err)
			continue
		}
		s.saveHistory(c, b, p.Modes[c], p.Client, p.What, p.Token)
	}
}

// recordHistory keeps the live file as it is now, for writers that commit with no snapshot.
func (s *Server) recordHistory(config, client, what string) {
	p := filepath.Join(uciConfDir, config)
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	mode := uint32(0o644)
	if st, err := os.Stat(p); err == nil {
		mode = uint32(st.Mode().Perm())
	}
	s.saveHistory(config, b, mode, client, what, randToken())
}

// historyEntries returns a config's entries, newest first.
func (s *Server) historyEntries(config string) []historyEntry {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	return s.listHistory(config)
}

// listHistory is historyEntries for a caller that already holds histMu.
func (s *Server) listHistory(config string) []historyEntry {
	files, err := os.ReadDir(s.historyPath(config))
	if err != nil {
		return nil
	}
	var out []historyEntry
	for _, f := range files {
		if _, _, err := parseHistoryID(config + ":" + f.Name()); err != nil {
			continue // the .json sidecars, and anything that is not ours
		}
		e := historyEntry{Config: config, Stamp: f.Name()}
		if b, err := os.ReadFile(path.Join(s.historyPath(config), f.Name()+".json")); err == nil {
			_ = json.Unmarshal(b, &e)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stamp > out[j].Stamp })
	return out
}

func (s *Server) loadHistory(id string) (historyEntry, []byte, error) {
	config, stamp, err := parseHistoryID(id)
	if err != nil {
		return historyEntry{}, nil, err
	}
	for _, e := range s.historyEntries(config) {
		if e.Stamp == stamp {
			b, err := os.ReadFile(path.Join(s.historyPath(config), stamp))
			return e, b, err
		}
	}
	return historyEntry{}, nil, fmt.Errorf("no history entry %q (list them with uci_get history=list)", id)
}

// uciHistory serves uci_get history=list and history=diff:<id>.
func (s *Server) uciHistory(ctx context.Context, in uciGetIn) (string, string, error) {
	if in.Config == "" || !reUCIConfig.MatchString(in.Config) {
		return "", "", fmt.Errorf("history needs a config name")
	}
	if in.Section != "" || in.Option != "" || in.IDs {
		return "", "", fmt.Errorf("history covers a whole config: give only config and history")
	}
	switch {
	case in.History == "list":
		return s.historyList(in.Config), "history of " + in.Config, nil
	case strings.HasPrefix(in.History, "diff:"):
		id := strings.TrimPrefix(in.History, "diff:")
		config, _, err := parseHistoryID(id)
		if err != nil {
			return "", "", err
		}
		if config != in.Config {
			return "", "", fmt.Errorf("%s is a version of %s, not %s", id, config, in.Config)
		}
		_, body, err := s.loadHistory(id)
		if err != nil {
			return "", "", err
		}
		cur, err := os.ReadFile(filepath.Join(uciConfDir, config))
		if err != nil {
			return "", "", notFound("no such UCI config %q", config)
		}
		return fmt.Sprintf("--- %s (before that change)  +++ current\n%s", id, settingsDiff(ctx, config, string(body), string(cur))),
			"history diff of " + id, nil
	}
	return "", "", invalid("history must be 'list' or 'diff:<id>'")
}

func (s *Server) historyList(config string) string {
	keep := s.cfg().HistoryKeep
	if keep <= 0 {
		return fmt.Sprintf("history is off (history_keep is 0), so %s has no recorded versions.", config)
	}
	es := s.historyEntries(config)
	if len(es) == 0 {
		return fmt.Sprintf("no confirmed change of %s is recorded yet (the newest %d are kept).", config, keep)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "versions of %s from before each confirmed change, newest first (the newest %d are kept).\n"+
		"Compare one with history=diff:<id>; put one back with uci_apply restore=<id>.\n", config, keep)
	for _, e := range es {
		fmt.Fprintf(&b, "  %s  %s  %s  %s\n", e.id(), e.Time, e.Client, e.What)
	}
	return strings.TrimRight(b.String(), "\n")
}

// settingsDiff diffs two versions of a config by setting, through `uci show` on private
// copies (formatting noise disappears and nobody's staged edits leak in), and falls back to
// the raw lines when uci cannot parse one of them.
func settingsDiff(ctx context.Context, config, from, to string) string {
	a, errA := uciNormalised(ctx, config, from)
	b, errB := uciNormalised(ctx, config, to)
	if errA != nil || errB != nil {
		a, b = strings.Split(from, "\n"), strings.Split(to, "\n")
	}
	if d := unifiedDiff(a, b, 2); d != "" {
		return d
	}
	return "(no difference in the settings)"
}
