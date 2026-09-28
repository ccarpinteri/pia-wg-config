package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	cli "github.com/urfave/cli/v2"
)

// dialControl is the net.Dialer.Control hook: it runs on each socket after it
// is created and before it connects.
type dialControl = func(network, address string, c syscall.RawConn) error

// setsockoptIntFunc has syscall.SetsockoptInt's signature, so the control
// function can be tested without privilege or a Linux kernel.
type setsockoptIntFunc func(fd, level, opt, value int) error

const (
	detailSocketMarkInvalid     = "socket_mark_invalid"
	detailSocketMarkUnsupported = "socket_mark_unsupported"
	// detailSocketMarkRefused marks a request that failed because the kernel
	// would not set the mark (typically EPERM without CAP_NET_ADMIN), so it
	// is not mistaken for a network failure.
	detailSocketMarkRefused = "socket_mark_refused"
)

var (
	errSocketMarkUnsupported = errors.New("--socket-mark requires Linux SO_MARK support")
	// errSocketMarkRefused wraps every failure to set the mark on a socket.
	errSocketMarkRefused = errors.New("socket mark refused")
)

// parseSocketMark accepts a non-zero 32-bit mark written in decimal, or in
// hexadecimal with a 0x prefix. Nothing else: no sign, no whitespace, no digit
// separators, and no leading zero on a decimal value, so no value can be read
// as octal or binary by accident.
func parseSocketMark(raw string) (uint32, error) {
	digits, base := raw, 10
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		digits, base = raw[2:], 16
	}
	if digits == "" {
		return 0, errors.New("empty socket mark")
	}
	for _, r := range digits {
		isDecimal := r >= '0' && r <= '9'
		isHex := (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isDecimal && !(base == 16 && isHex) {
			return 0, errors.New("invalid socket mark")
		}
	}
	if base == 10 && digits[0] == '0' {
		return 0, errors.New("invalid socket mark")
	}
	value, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		return 0, errors.New("socket mark out of range")
	}
	if value == 0 {
		return 0, errors.New("socket mark must be non-zero")
	}
	return uint32(value), nil
}

// socketMarkControlWith returns a dial control that sets the mark on the
// socket with set, at the given level and option. A mark that cannot be set
// fails the dial: the socket never connects unmarked.
func socketMarkControlWith(level, opt int, mark uint32, set setsockoptIntFunc) dialControl {
	return func(network, address string, c syscall.RawConn) error {
		var setErr error
		if err := c.Control(func(fd uintptr) {
			// int(mark) keeps all 32 bits; SetsockoptInt passes them to the
			// kernel as the 4-byte value SO_MARK reads.
			setErr = set(int(fd), level, opt, int(mark))
		}); err != nil {
			return fmt.Errorf("%w: %w", errSocketMarkRefused, err)
		}
		if setErr != nil {
			return fmt.Errorf("%w: %w", errSocketMarkRefused, setErr)
		}
		return nil
	}
}

// constrainedSocketControl validates --socket-mark and returns the dial
// control every constrained-mode socket uses, or nil when the flag is absent.
// It runs before the plan is read, so an invalid or unsupported mark is
// reported through the result descriptor and nothing touches the network.
func constrainedSocketControl(c *cli.Context) (dialControl, constrainedFailureReason) {
	if !c.IsSet("socket-mark") {
		return nil, constrainedFailureReason{}
	}
	mark, err := parseSocketMark(c.String("socket-mark"))
	if err != nil {
		return nil, constrainedFailureWithDetail(classInvalidInvocation, detailSocketMarkInvalid)
	}
	if !socketMarkSupported {
		return nil, constrainedFailureWithDetail(classInvalidInvocation, detailSocketMarkUnsupported)
	}
	return socketMarkControl(mark), constrainedFailureReason{}
}

// rejectSocketMarkOutsideConstrainedMode refuses --socket-mark on the ordinary
// generation paths, whose sockets it does not reach. Accepting it there would
// be a mark silently ignored.
func rejectSocketMarkOutsideConstrainedMode(c *cli.Context) error {
	if c.IsSet("socket-mark") {
		return cli.Exit("--socket-mark is only supported with the constrained descriptor flags", 1)
	}
	return nil
}
