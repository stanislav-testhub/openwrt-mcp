package main

import (
	"fmt"
	"os"
)

// privateMode is the mode of every file we create that holds a credential outside UCI: a
// WireGuard client config (its private key) and a sysupgrade backup (every secret on the router).
const privateMode = 0o600

// openFile and chmodFile are os.OpenFile and os.Chmod, as variables so a test can see the flags
// and mode a private file is created with on any OS (Windows ignores mode bits, so the file
// system cannot show them).
var (
	openFile  = os.OpenFile
	chmodFile = os.Chmod
)

// writePrivate creates the file at path with mode 0600 and writes data to it. O_EXCL means it
// never replaces an existing file, and on POSIX it does not follow a symlink planted at path.
// A failed write removes the file again.
func writePrivate(path string, data []byte) error {
	f, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// privateDir makes sure dir exists as a real directory (not a symlink) with mode 0700.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}
