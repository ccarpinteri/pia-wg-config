//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	cli "github.com/urfave/cli/v2"
)

func TestValidateConstrainedDescriptorAcceptsPipeDirection(t *testing.T) {
	reader, writer := testPipe(t)
	if err := validateConstrainedDescriptor(reader, constrainedFDRead); err != nil {
		t.Fatalf("read pipe validation returned error: %v", err)
	}
	if err := validateConstrainedDescriptor(writer, constrainedFDWrite); err != nil {
		t.Fatalf("write pipe validation returned error: %v", err)
	}
}

func TestConstrainedDeadlineHelpersTolerateNoDeadlinePipes(t *testing.T) {
	reader, writer := testPipe(t)
	if err := reader.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		t.Skip("pipe deadlines are supported in this environment")
	}
	if err := writer.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		t.Skip("pipe deadlines are supported in this environment")
	}
	if err := setConstrainedReadDeadline(reader, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("read deadline helper rejected no-deadline pipe: %v", err)
	}
	if err := setConstrainedWriteDeadline(writer, time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write deadline helper rejected no-deadline pipe: %v", err)
	}
}

func TestValidateConstrainedDescriptorRejectsWrongDirection(t *testing.T) {
	reader, writer := testPipe(t)
	if err := validateConstrainedDescriptor(reader, constrainedFDWrite); err == nil {
		t.Fatal("expected read pipe to fail write validation")
	}
	if err := validateConstrainedDescriptor(writer, constrainedFDRead); err == nil {
		t.Fatal("expected write pipe to fail read validation")
	}
}

func TestValidateConstrainedDescriptorRejectsRegularFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateConstrainedDescriptor(file, constrainedFDRead); err == nil {
		t.Fatal("expected regular file rejection")
	}
}

func TestWriteInvalidInvocationFailureWritesResultWhenPossible(t *testing.T) {
	reader, writer := testPipe(t)

	err := writeInvalidInvocationFailureFD(int(writer.Fd()))
	var exitErr cli.ExitCoder
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("error = %v, want exit code 1", err)
	}
	raw, err := os.ReadFile("/proc/self/fd/" + fdString(reader))
	if err != nil {
		t.Fatal(err)
	}
	var result constrainedFailure
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != constrainedSchema || result.Status != "failure" || result.FailureClass != string(classInvalidInvocation) {
		t.Fatalf("failure result = %#v", result)
	}
}

func TestWriteInvalidInvocationFailureDoesNotLeakDetails(t *testing.T) {
	reader, writer := testPipe(t)

	err := writeInvalidInvocationFailureFD(int(writer.Fd()))
	if err == nil || strings.Contains(err.Error(), "fd") || strings.Contains(err.Error(), "descriptor") {
		t.Fatalf("error leaked invocation details: %v", err)
	}
	raw, err := os.ReadFile("/proc/self/fd/" + fdString(reader))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fd") || strings.Contains(string(raw), "descriptor") {
		t.Fatalf("result leaked invocation details: %s", raw)
	}
}

func testPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	return reader, writer
}

func fdString(file *os.File) string {
	return strconv.Itoa(int(file.Fd()))
}
