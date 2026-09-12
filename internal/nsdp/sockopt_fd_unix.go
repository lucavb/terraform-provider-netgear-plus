//go:build !windows

package nsdp

import "syscall"

func setSockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(int(fd), level, opt, value)
}
