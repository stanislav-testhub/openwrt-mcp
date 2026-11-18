//go:build !windows

package main

import (
	"os"
	"syscall"
)

// copyOwner gives dst the owner and group of src. A missing src (the first write) is not an error.
func copyOwner(src, dst string) {
	fi, err := os.Lstat(src)
	if err != nil {
		return
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(dst, int(st.Uid), int(st.Gid))
	}
}
