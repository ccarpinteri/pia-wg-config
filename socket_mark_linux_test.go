//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

// TestSocketMarkControlReachesTheKernel runs the real control on a real
// socket. With CAP_NET_ADMIN the kernel stores the mark and getsockopt reads it
// back; without it the kernel refuses with EPERM, which must fail the bind
// rather than leave the socket unmarked. Either outcome proves the control
// calls setsockopt(SOL_SOCKET, SO_MARK) on the socket itself.
func TestSocketMarkControlReachesTheKernel(t *testing.T) {
	const mark = 0x10000
	var readBack int
	var readErr error
	config := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		if err := socketMarkControl(mark)(network, address, c); err != nil {
			return err
		}
		return c.Control(func(fd uintptr) {
			readBack, readErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		})
	}}
	conn, err := config.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Logf("unprivileged: SO_MARK refused with EPERM and the socket was not opened, as required")
			return
		}
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	if readErr != nil || readBack != mark {
		t.Fatalf("SO_MARK read back = 0x%x, %v; want 0x%x", readBack, readErr, mark)
	}
}

// TestRawInvocationWithInvalidSocketMarkWritesTheResult is the whole raw path:
// argv parsing, descriptor validation, and the runner's failure written to the
// inherited result pipe - with the bad mark placed before --result-fd, which
// the raw parser's own error path could not have reported.
func TestRawInvocationWithInvalidSocketMarkWritesTheResult(t *testing.T) {
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	var readers []*os.File
	fds := map[string]*os.File{}
	for _, name := range []string{"constrained-plan-fd", "credentials-fd", "public-ca-fd", "regional-ca-fd"} {
		reader, _ := testPipe(t)
		fds[name] = reader
	}
	for _, name := range []string{"config-fd", "result-fd"} {
		reader, writer := testPipe(t)
		fds[name] = writer
		readers = append(readers, reader)
	}
	args := []string{"--socket-mark", "0"}
	for _, name := range []string{"constrained-plan-fd", "credentials-fd", "public-ca-fd", "regional-ca-fd", "config-fd", "result-fd"} {
		args = append(args, "--"+name, fdString(fds[name]))
	}
	os.Args = append([]string{"pia-wg-config"}, args...)

	err := constrainedActionFromRawArgs(args)
	if err == nil {
		t.Fatal("expected a failure exit")
	}
	raw, err := os.ReadFile("/proc/self/fd/" + fdString(readers[1]))
	if err != nil {
		t.Fatal(err)
	}
	var result constrainedFailure
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("result %q: %v", raw, err)
	}
	if result.FailureClass != string(classInvalidInvocation) || result.FailureDetail != detailSocketMarkInvalid {
		t.Fatalf("result = %+v, want invalid_invocation / %s", result, detailSocketMarkInvalid)
	}
}

func TestSocketMarkIsSupportedOnLinux(t *testing.T) {
	if !socketMarkSupported {
		t.Fatal("socketMarkSupported is false on Linux")
	}
}
