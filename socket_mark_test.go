package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	cli "github.com/urfave/cli/v2"
)

var constrainedFDArgs = []string{
	"--constrained-plan-fd", "3",
	"--credentials-fd", "4",
	"--public-ca-fd", "5",
	"--regional-ca-fd", "6",
	"--config-fd", "7",
	"--result-fd", "8",
}

func TestParseSocketMark(t *testing.T) {
	valid := map[string]uint32{
		"65536":      0x10000,
		"0x10000":    0x10000,
		"0X10000":    0x10000,
		"1":          1,
		"4294967295": 0xffffffff,
		"0xffffffff": 0xffffffff,
		"0xCA6C":     0xca6c,
	}
	for raw, want := range valid {
		t.Run("valid "+raw, func(t *testing.T) {
			got, err := parseSocketMark(raw)
			if err != nil || got != want {
				t.Fatalf("parseSocketMark(%q) = 0x%x, %v; want 0x%x", raw, got, err, want)
			}
		})
	}
	invalid := []string{
		"", "0", "00", "0x0", "0x", "-1", "+1", " 65536", "65536 ", "1_000",
		"0o20", "0b1", "010", "4294967296", "0x100000000", "0x1_0000", "abc", "0xg",
	}
	for _, raw := range invalid {
		t.Run("invalid "+strconv.Quote(raw), func(t *testing.T) {
			if got, err := parseSocketMark(raw); err == nil {
				t.Fatalf("parseSocketMark(%q) = 0x%x, want an error", raw, got)
			}
		})
	}
}

func TestParseRawConstrainedArgsAcceptsSocketMark(t *testing.T) {
	for _, form := range [][]string{{"--socket-mark", "0x10000"}, {"--socket-mark=0x10000"}} {
		fds, strs, err := parseRawConstrainedArgs(append(append([]string{}, constrainedFDArgs...), form...))
		if err != nil {
			t.Fatalf("%v: parseRawConstrainedArgs returned error: %v", form, err)
		}
		if strs["socket-mark"] != "0x10000" {
			t.Fatalf("%v: socket-mark = %q, want the raw value 0x10000", form, strs["socket-mark"])
		}
		if fds["result-fd"] != 8 {
			t.Fatalf("%v: result-fd = %d, want 8", form, fds["result-fd"])
		}
	}
	// Syntax is validated later, in the runner, so the failure reaches the
	// result descriptor however the flags are ordered.
	if _, strs, err := parseRawConstrainedArgs(append([]string{"--socket-mark", "bogus"}, constrainedFDArgs...)); err != nil || strs["socket-mark"] != "bogus" {
		t.Fatalf("raw parse of an unvalidated mark = %q, %v; want it carried to the runner", strs["socket-mark"], err)
	}
	for name, args := range map[string][]string{
		"duplicate":     append(append([]string{}, constrainedFDArgs...), "--socket-mark", "1", "--socket-mark", "2"),
		"missing value": append(append([]string{}, constrainedFDArgs...), "--socket-mark"),
		"mark only":     {"--socket-mark", "1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseRawConstrainedArgs(args); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
	if rawConstrainedRequested([]string{"--socket-mark", "1"}) {
		t.Fatal("--socket-mark alone must not select constrained mode")
	}
}

// fakeRawConn hands a fixed descriptor to Control, as a real socket would.
type fakeRawConn struct {
	fd         uintptr
	controlErr error
}

func (c fakeRawConn) Control(f func(fd uintptr)) error {
	if c.controlErr != nil {
		return c.controlErr
	}
	f(c.fd)
	return nil
}
func (c fakeRawConn) Read(func(uintptr) bool) error  { return errors.New("unused") }
func (c fakeRawConn) Write(func(uintptr) bool) error { return errors.New("unused") }

type setsockoptCall struct{ fd, level, opt, value int }

func TestSocketMarkControlSetsTheMarkOnTheSocket(t *testing.T) {
	var calls []setsockoptCall
	set := func(fd, level, opt, value int) error {
		calls = append(calls, setsockoptCall{fd, level, opt, value})
		return nil
	}
	control := socketMarkControlWith(11, 22, 0x10000, set)
	if err := control("tcp4", "203.0.113.7:443", fakeRawConn{fd: 42}); err != nil {
		t.Fatalf("control returned error: %v", err)
	}
	if len(calls) != 1 || calls[0] != (setsockoptCall{fd: 42, level: 11, opt: 22, value: 0x10000}) {
		t.Fatalf("setsockopt calls = %+v, want one on fd 42 with the given level, option and mark", calls)
	}

	// The whole 32-bit range survives the int conversion bit for bit.
	calls = nil
	if err := socketMarkControlWith(11, 22, 0xffffffff, set)("tcp4", "x", fakeRawConn{fd: 1}); err != nil {
		t.Fatal(err)
	}
	if got := uint32(int32(calls[0].value)); got != 0xffffffff {
		t.Fatalf("mark 0xffffffff reached setsockopt as 0x%x", got)
	}
}

func TestSocketMarkControlFailsTheDialWhenTheMarkCannotBeSet(t *testing.T) {
	control := socketMarkControlWith(11, 22, 0x10000, func(int, int, int, int) error { return syscall.EPERM })
	if err := control("tcp4", "x", fakeRawConn{fd: 42}); !errors.Is(err, syscall.EPERM) || !errors.Is(err, errSocketMarkRefused) {
		t.Fatalf("control error = %v, want EPERM wrapped as errSocketMarkRefused", err)
	}
	rawErr := errors.New("raw conn closed")
	called := false
	control = socketMarkControlWith(11, 22, 0x10000, func(int, int, int, int) error { called = true; return nil })
	if err := control("tcp4", "x", fakeRawConn{controlErr: rawErr}); !errors.Is(err, rawErr) {
		t.Fatalf("control error = %v, want the RawConn error", err)
	}
	if called {
		t.Fatal("setsockopt ran although RawConn.Control failed")
	}
}

// TestConstrainedHTTPClientRunsTheDialControlOnItsSocket proves the one socket
// constrained mode opens goes through the control hook, and that a failing
// hook fails the dial instead of sending unmarked.
func TestConstrainedHTTPClientRunsTheDialControlOnItsSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepts := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
			accepts <- struct{}{}
		}
	}()
	host, rawPort, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)

	var seen []string
	recording := func(network, address string, c syscall.RawConn) error {
		seen = append(seen, network+" "+address)
		return nil
	}
	client := constrainedHTTPClient(host, port, "example.privateinternetaccess.com", nil, 5*time.Second, false, recording)
	conn, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", "ignored:1")
	if err != nil {
		t.Fatalf("dial with a succeeding control: %v", err)
	}
	conn.Close()
	select {
	case <-accepts:
	case <-time.After(5 * time.Second):
		t.Fatal("the marked dial never reached the listener")
	}
	if want := "tcp4 " + listener.Addr().String(); len(seen) != 1 || seen[0] != want {
		t.Fatalf("control saw %v, want exactly [%s]", seen, want)
	}

	denied := errors.New("mark refused")
	failing := func(string, string, syscall.RawConn) error { return denied }
	client = constrainedHTTPClient(host, port, "example.privateinternetaccess.com", nil, 5*time.Second, false, failing)
	if conn, err := client.Transport.(*http.Transport).DialContext(t.Context(), "tcp", "ignored:1"); !errors.Is(err, denied) {
		if conn != nil {
			conn.Close()
		}
		t.Fatalf("dial with a failing control = %v, want the control's error", err)
	}
	select {
	case <-accepts:
		t.Fatal("the refused dial connected to the listener")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestInvalidSocketMarkFailsThroughTheResultDescriptor drives the runner with
// an invalid mark: the failure is written to the result descriptor as
// invalid_invocation with a detail, and nothing after invocation validation -
// reading the plan, any network call - runs. A valid mark is rejected the same
// way where SO_MARK is unsupported, never silently ignored.
func TestInvalidSocketMarkFailsThroughTheResultDescriptor(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"pia-wg-config"}
	t.Cleanup(func() { os.Args = oldArgs })

	cases := []struct {
		mark       string
		wantClass  constrainedClass
		wantDetail string
	}{
		{mark: "0", wantClass: classInvalidInvocation, wantDetail: detailSocketMarkInvalid},
		{mark: "0x", wantClass: classInvalidInvocation, wantDetail: detailSocketMarkInvalid},
		{mark: "4294967296", wantClass: classInvalidInvocation, wantDetail: detailSocketMarkInvalid},
	}
	if socketMarkSupported {
		// Past invocation validation the runner reads the plan, which this
		// test does not supply: invalid_plan proves the valid mark was accepted.
		cases = append(cases, struct {
			mark       string
			wantClass  constrainedClass
			wantDetail string
		}{mark: "0x10000", wantClass: classInvalidPlan})
	} else {
		cases = append(cases, struct {
			mark       string
			wantClass  constrainedClass
			wantDetail string
		}{mark: "0x10000", wantClass: classInvalidInvocation, wantDetail: detailSocketMarkUnsupported})
	}
	for _, tc := range cases {
		t.Run(tc.mark, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			c := constrainedContextFromValues(map[string]int{"result-fd": 8}, map[string]string{"socket-mark": tc.mark})
			run := constrainedRunner{ctx: t.Context(), files: constrainedFiles{resultWriter: writer}, deadline: time.Now().Add(60 * time.Second)}

			failure := run.execute(c)
			if failure.class != tc.wantClass || failure.detail != tc.wantDetail {
				t.Fatalf("execute = %+v, want class %s detail %q", failure, tc.wantClass, tc.wantDetail)
			}
			err = run.writeFailure(failure)
			var exitErr cli.ExitCoder
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("writeFailure = %v, want exit code 1", err)
			}
			writer.Close()
			raw, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			var result constrainedFailure
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatalf("result %q: %v", raw, err)
			}
			if result.Schema != constrainedSchema || result.Status != "failure" || result.FailureClass != string(tc.wantClass) || result.FailureDetail != tc.wantDetail {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestSocketMarkIsRejectedOutsideConstrainedMode(t *testing.T) {
	set := constrainedContextFromValues(nil, map[string]string{"socket-mark": "0x10000"})
	if err := rejectSocketMarkOutsideConstrainedMode(set); err == nil {
		t.Fatal("--socket-mark was accepted outside constrained mode")
	}
	if err := rejectSocketMarkOutsideConstrainedMode(constrainedContextFromValues(nil, nil)); err != nil {
		t.Fatalf("no --socket-mark: %v", err)
	}
}

// TestBothConstrainedRequestsDialThroughTheControl covers the two callers of
// constrainedHTTPClient. The control refuses, so neither request connects, and
// each must report its own request failure having run the control on a socket
// bound for its planned destination.
func TestBothConstrainedRequestsDialThroughTheControl(t *testing.T) {
	var seen []string
	refusing := func(network, address string, c syscall.RawConn) error {
		seen = append(seen, network+" "+address)
		return errors.New("mark refused")
	}
	_, failure := constrainedTokenRequest(t.Context(), "127.0.0.1", credentials{username: "user", password: "pass"}, x509.NewCertPool(), refusing)
	if failure.class != classTokenFailed {
		t.Fatalf("token request failure = %+v, want %s", failure, classTokenFailed)
	}
	candidate := constrainedRegistrationCandidate{IPv4: "127.0.0.1", TLSCommonName: "Server-11736-3a"}
	_, failure = constrainedAddKeyRequest(t.Context(), candidate, "token", "public-key", x509.NewCertPool(), refusing)
	if failure.class != classAddKeyFailed {
		t.Fatalf("addKey request failure = %+v, want %s", failure, classAddKeyFailed)
	}
	want := []string{"tcp4 127.0.0.1:443", "tcp4 127.0.0.1:1337"}
	if len(seen) != len(want) || seen[0] != want[0] || seen[1] != want[1] {
		t.Fatalf("control saw %v, want %v", seen, want)
	}

	// A mark the kernel refuses is reported as such, not as a network failure.
	eperm := socketMarkControlWith(11, 22, 0x10000, func(int, int, int, int) error { return syscall.EPERM })
	if _, failure := constrainedTokenRequest(t.Context(), "127.0.0.1", credentials{username: "user", password: "pass"}, x509.NewCertPool(), eperm); failure.class != classTokenFailed || failure.detail != detailSocketMarkRefused {
		t.Fatalf("token request with a refused mark = %+v, want %s / %s", failure, classTokenFailed, detailSocketMarkRefused)
	}
	if _, failure := constrainedAddKeyRequest(t.Context(), candidate, "token", "public-key", x509.NewCertPool(), eperm); failure.class != classAddKeyFailed || failure.detail != detailSocketMarkRefused {
		t.Fatalf("addKey request with a refused mark = %+v, want %s / %s", failure, classAddKeyFailed, detailSocketMarkRefused)
	}
}
