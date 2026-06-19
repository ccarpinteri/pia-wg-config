package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestReadLimitedFileTimesOutOnBlockedPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	start := time.Now()
	if _, err := readLimitedFile(reader, 1024, 20*time.Millisecond); err == nil {
		t.Fatal("expected blocked read timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("blocked read took too long: %s", elapsed)
	}
}

func TestReadLimitedFileRejectsOversizedInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readLimitedFile(reader, 5, time.Second); err == nil {
		t.Fatal("expected oversized input error")
	}
}

func TestWriteLimitedFileRejectsOversizedOutput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	if err := writeLimitedFile(writer, []byte("abcdef"), 5, time.Second); err == nil {
		t.Fatal("expected oversized output error")
	}
}

func TestWriteLimitedFileFailsOnBrokenPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	if err := writeLimitedFile(writer, []byte("x"), 5, time.Second); err == nil {
		t.Fatal("expected broken pipe error")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected broken pipe, got deadline: %v", err)
	}
}
