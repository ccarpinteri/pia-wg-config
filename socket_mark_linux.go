//go:build linux

package main

import "syscall"

const socketMarkSupported = true

// socketMarkControl sets SO_MARK on the socket. The kernel requires
// CAP_NET_ADMIN (or, from Linux 5.17, CAP_NET_RAW); without it the dial fails
// with EPERM.
func socketMarkControl(mark uint32) dialControl {
	return socketMarkControlWith(syscall.SOL_SOCKET, syscall.SO_MARK, mark, syscall.SetsockoptInt)
}
