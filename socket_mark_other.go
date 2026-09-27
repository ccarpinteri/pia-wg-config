//go:build !linux

package main

import (
	"fmt"
	"syscall"
)

// SO_MARK is Linux-only. --socket-mark is rejected on other platforms before
// any socket is opened; socketMarkControl still fails closed if reached.
const socketMarkSupported = false

func socketMarkControl(mark uint32) dialControl {
	return func(string, string, syscall.RawConn) error {
		return fmt.Errorf("%w: %w", errSocketMarkRefused, errSocketMarkUnsupported)
	}
}
