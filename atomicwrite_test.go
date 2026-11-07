package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file replaced by write-then-rename must be flushed before the rename, or a power cut on flash
// leaves the new name pointing at an empty file. writeSynced does the flush; os.WriteFile does not.
// So a source that renames a temp file into place must not write that temp file with os.WriteFile.
func TestAtomicReplacesAreSynced(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for i, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "os.WriteFile(tmp") && strings.Contains(string(b), "os.Rename(tmp") {
				t.Errorf("%s:%d writes a temp file with os.WriteFile and renames it: use writeSynced", f, i+1)
			}
		}
	}
}
