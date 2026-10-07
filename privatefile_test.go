package main

import (
	"os"
	"path/filepath"
	"testing"
)

type openCall struct {
	name string
	flag int
	perm os.FileMode
}

// recordOpens wraps openFile and chmodFile so a test sees the flags and mode a private file is
// created with, on any OS: a Windows file system reports its own mode bits, not the ones asked for.
func recordOpens(t *testing.T) (opens *[]openCall, chmods *[]os.FileMode) {
	t.Helper()
	var o []openCall
	var c []os.FileMode
	oldOpen, oldChmod := openFile, chmodFile
	openFile = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		o = append(o, openCall{name, flag, perm})
		return oldOpen(name, flag, perm)
	}
	chmodFile = func(name string, mode os.FileMode) error {
		c = append(c, mode)
		return oldChmod(name, mode)
	}
	t.Cleanup(func() { openFile, chmodFile = oldOpen, oldChmod })
	return &o, &c
}

// A credential file is created 0600 and never replaces what is there. The numbers are the
// spec (owner read/write only; O_EXCL so an existing file or a planted symlink is refused).
func TestWritePrivateCreatesOwnerOnlyAndNeverReplaces(t *testing.T) {
	opens, _ := recordOpens(t)
	p := filepath.Join(t.TempDir(), "k.conf")
	if err := writePrivate(p, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if len(*opens) != 1 {
		t.Fatalf("%d opens, want 1", len(*opens))
	}
	got := (*opens)[0]
	if got.perm != 0o600 {
		t.Errorf("created with mode %o, want 600", got.perm)
	}
	if got.flag&os.O_EXCL == 0 || got.flag&os.O_CREATE == 0 {
		t.Errorf("flags %#x lack O_CREATE|O_EXCL", got.flag)
	}
	if b, _ := os.ReadFile(p); string(b) != "secret" {
		t.Errorf("content %q", b)
	}

	if err := writePrivate(p, []byte("other")); err == nil {
		t.Error("an existing file was overwritten")
	}
	if b, _ := os.ReadFile(p); string(b) != "secret" {
		t.Errorf("the existing file changed to %q", b)
	}
}

func TestWritePrivateRefusesASymlinkAtThePath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlink privilege here: %v", err)
	}
	if err := writePrivate(link, []byte("secret")); err == nil {
		t.Error("wrote through a symlink")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the symlink target changed to %q", b)
	}
}

func TestPrivateDirRefusesAFileAndASymlink(t *testing.T) {
	dir := t.TempDir()
	if err := privateDir(filepath.Join(dir, "a", "b")); err != nil {
		t.Fatalf("a new nested directory: %v", err)
	}
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(file); err == nil {
		t.Error("a regular file was accepted as the directory")
	}
	link := filepath.Join(dir, "l")
	if err := os.Symlink(filepath.Join(dir, "a"), link); err != nil {
		t.Skipf("no symlink privilege here: %v", err)
	}
	if err := privateDir(link); err == nil {
		t.Error("a symlink was accepted as the directory")
	}
}
