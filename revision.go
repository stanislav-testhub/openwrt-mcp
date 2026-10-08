package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// A config's revision identifies its committed content: the first 12 hex digits of the sha256
// of /etc/config/<name>. uci_get prints it, uci_apply can require it (expected_revisions), and
// a config edited in between -- in LuCI, or by another client -- is refused instead of being
// silently overwritten. It comes from the file, so the server keeps no state for it.
var reRevision = regexp.MustCompile(`^[0-9a-f]{12}$`)

func configRevision(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(uciConfDir, name))
	if err != nil {
		return "", notFound("no such UCI config %q", name)
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))[:12], nil
}

// validateExpectedRevisions checks the shape of the input only. A revision for a config the
// call does not change is refused rather than ignored: a typo in the name would otherwise
// switch the protection off without a word.
func validateExpectedRevisions(exp map[string]string, changed []string) error {
	for _, c := range sortedKeys(exp) {
		if !contains(changed, c) {
			return fmt.Errorf("expected_revisions names %q, which this call does not change (changing: %s)",
				c, strings.Join(changed, ", "))
		}
		if !reRevision.MatchString(exp[c]) {
			return fmt.Errorf("expected_revisions[%s] = %q is not a revision: pass the 12 hex digits uci_get printed", c, exp[c])
		}
	}
	return nil
}

// checkRevisions compares the live revisions with the expected ones.
func checkRevisions(exp map[string]string) error {
	for _, c := range sortedKeys(exp) {
		cur, err := configRevision(c)
		if err != nil {
			return err
		}
		if cur != exp[c] {
			return conflict("CONFLICT: %s changed since revision %s (now %s). Re-read it with uci_get and redo the change "+
				"against what is there now", c, exp[c], cur)
		}
	}
	return nil
}

// revisionList renders "dhcp=abc,network=def" for the configs that have a readable file.
func revisionList(configs []string) string {
	var out []string
	for _, c := range configs {
		if rev, err := configRevision(c); err == nil {
			out = append(out, c+"="+rev)
		}
	}
	return strings.Join(out, ",")
}
