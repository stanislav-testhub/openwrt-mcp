package main

import "testing"

// A pattern that does not compile would panic at its first use, in production; compile them all here.
func TestLazyRegexpsCompile(t *testing.T) {
	if len(lazyRegexps) < 50 {
		t.Fatalf("only %d lazy patterns registered", len(lazyRegexps))
	}
	for _, l := range lazyRegexps {
		l.get()
	}
}
