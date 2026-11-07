package main

import (
	"regexp"
	"sync"
)

// lazyRE is a package-level regexp compiled on first use (ROADMAP 10.2). Every bridge and `call`
// runs the package initialisers, and compiling ~100 patterns there cost over 1 MB of heap that those
// paths never use. A pattern that does not compile panics at its first use instead of at start-up;
// TestLazyRegexpsCompile compiles them all.
type lazyRE struct {
	src  string
	once sync.Once
	re   *regexp.Regexp
}

var lazyRegexps []*lazyRE

func lazyRegexp(src string) *lazyRE {
	l := &lazyRE{src: src}
	lazyRegexps = append(lazyRegexps, l)
	return l
}

func (l *lazyRE) get() *regexp.Regexp {
	l.once.Do(func() { l.re = regexp.MustCompile(l.src) })
	return l.re
}

func (l *lazyRE) MatchString(s string) bool              { return l.get().MatchString(s) }
func (l *lazyRE) FindString(s string) string             { return l.get().FindString(s) }
func (l *lazyRE) FindStringIndex(s string) []int         { return l.get().FindStringIndex(s) }
func (l *lazyRE) FindStringSubmatch(s string) []string   { return l.get().FindStringSubmatch(s) }
func (l *lazyRE) FindAllString(s string, n int) []string { return l.get().FindAllString(s, n) }
func (l *lazyRE) FindAllStringSubmatch(s string, n int) [][]string {
	return l.get().FindAllStringSubmatch(s, n)
}
func (l *lazyRE) ReplaceAllString(s, r string) string { return l.get().ReplaceAllString(s, r) }
func (l *lazyRE) ReplaceAllStringFunc(s string, f func(string) string) string {
	return l.get().ReplaceAllStringFunc(s, f)
}
func (l *lazyRE) ReplaceAllLiteralString(s, r string) string {
	return l.get().ReplaceAllLiteralString(s, r)
}
func (l *lazyRE) Split(s string, n int) []string { return l.get().Split(s, n) }
func (l *lazyRE) SubexpNames() []string          { return l.get().SubexpNames() }
func (l *lazyRE) String() string                 { return l.src }
func (l *lazyRE) Match(b []byte) bool            { return l.get().Match(b) }
func (l *lazyRE) FindSubmatch(b []byte) [][]byte { return l.get().FindSubmatch(b) }
func (l *lazyRE) FindAllStringSubmatchIndex(s string, n int) [][]int {
	return l.get().FindAllStringSubmatchIndex(s, n)
}
