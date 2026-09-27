//go:build !linux

package main

import (
	"errors"
	"testing"
)

// Off Linux there is no SO_MARK. The flag must be refused, and the control
// must fail closed if anything ever reached it.
func TestSocketMarkIsUnsupportedOffLinux(t *testing.T) {
	if socketMarkSupported {
		t.Fatal("socketMarkSupported is true on a platform without SO_MARK")
	}
	if err := socketMarkControl(0x10000)("tcp4", "x", fakeRawConn{fd: 42}); !errors.Is(err, errSocketMarkUnsupported) {
		t.Fatalf("control error = %v, want errSocketMarkUnsupported", err)
	}
}
