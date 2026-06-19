package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestCredentialsFromInvocationPositionalCompatibility(t *testing.T) {
	got, err := credentialsFromInvocation(false, -1, []string{"user", "pass"})
	if err != nil {
		t.Fatalf("credentialsFromInvocation returned error: %v", err)
	}
	if got.username != "user" || got.password != "pass" {
		t.Fatalf("credentials = %#v", got)
	}
}

func TestCredentialsFromInvocationFD(t *testing.T) {
	readFD := credentialPipe(t, `{"username":"user","password":"pass"}`)

	got, err := credentialsFromInvocation(true, readFD, nil)
	if err != nil {
		t.Fatalf("credentialsFromInvocation returned error: %v", err)
	}
	if got.username != "user" || got.password != "pass" {
		t.Fatalf("credentials = %#v", got)
	}
	if _, err := syscall.Read(readFD, make([]byte, 1)); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("descriptor read error = %v, want EBADF", err)
	}
}

func TestCredentialsFromInvocationRejectsMixedModeBeforeClosingFD(t *testing.T) {
	readFD := credentialPipe(t, `{"username":"user","password":"pass"}`)

	_, err := credentialsFromInvocation(true, readFD, []string{"user", "pass"})
	if !errors.Is(err, errInvalidCredentialDescriptor) {
		t.Fatalf("error = %v, want invalid descriptor", err)
	}
	if _, err := syscall.Read(readFD, make([]byte, 1)); err != nil {
		t.Fatalf("descriptor was closed before ownership transfer: %v", err)
	}
}

func TestCredentialsFromInvocationRejectsInvalidDescriptor(t *testing.T) {
	for _, fd := range []int{-1, 0, 1, 2} {
		t.Run(strconv.Itoa(fd), func(t *testing.T) {
			if _, err := credentialsFromInvocation(true, fd, nil); !errors.Is(err, errInvalidCredentialDescriptor) {
				t.Fatalf("error = %v, want invalid descriptor", err)
			}
		})
	}
}

func TestCredentialsFromInvocationRejectsClosedDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	readFD := int(reader.Fd())
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := credentialsFromInvocation(true, readFD, nil); !errors.Is(err, errReadCredentials) {
		t.Fatalf("error = %v, want failed to read credentials", err)
	}
}

func TestCredentialsFromInvocationRejectsUnreadableDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	writeFD := int(writer.Fd())

	if _, err := credentialsFromInvocation(true, writeFD, nil); !errors.Is(err, errReadCredentials) {
		t.Fatalf("error = %v, want failed to read credentials", err)
	}
	if _, err := syscall.Write(writeFD, []byte("x")); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("descriptor write error = %v, want EBADF", err)
	}
}

func TestCredentialsFromInvocationRejectsOversizedInput(t *testing.T) {
	readFD := credentialPipe(t, strings.Repeat("x", maxCredentialInputSize+1))
	if _, err := credentialsFromInvocation(true, readFD, nil); !errors.Is(err, errCredentialInputTooLarge) {
		t.Fatalf("error = %v, want input-too-large", err)
	}
}

func TestCredentialsFromInvocationAcceptsExactlyMaximumInputSize(t *testing.T) {
	template := `{"username":"%s","password":"p"}`
	username := strings.Repeat("u", maxCredentialInputSize-len(fmt.Sprintf(template, "")))
	body := fmt.Sprintf(template, username)
	if len(body) != maxCredentialInputSize {
		t.Fatalf("input length = %d, want %d", len(body), maxCredentialInputSize)
	}

	readFD := credentialPipe(t, body)
	got, err := credentialsFromInvocation(true, readFD, nil)
	if err != nil {
		t.Fatalf("credentialsFromInvocation returned error: %v", err)
	}
	if got.username != username || got.password != "p" {
		t.Fatal("credentials did not match maximum-size input")
	}
}

func TestCredentialsFromInvocationClosesDescriptorBeforeDecodeFailure(t *testing.T) {
	readFD := credentialPipe(t, `{"username":"user"}`)
	if _, err := credentialsFromInvocation(true, readFD, nil); !errors.Is(err, errInvalidCredentialInput) {
		t.Fatalf("error = %v, want invalid credential input", err)
	}
	if _, err := syscall.Read(readFD, make([]byte, 1)); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("descriptor read error = %v, want EBADF", err)
	}
}

func TestCredentialsFromInvocationClosesOnlyOwnedDuplicate(t *testing.T) {
	originalFD := credentialPipe(t, `{"username":"user","password":"pass"}`)
	ownedFD, err := syscall.Dup(originalFD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credentialsFromInvocation(true, ownedFD, nil); err != nil {
		t.Fatalf("credentialsFromInvocation returned error: %v", err)
	}
	if _, err := syscall.Read(ownedFD, make([]byte, 1)); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("owned descriptor read error = %v, want EBADF", err)
	}
	if _, err := syscall.Read(originalFD, make([]byte, 1)); err != nil {
		t.Fatalf("original descriptor was closed: %v", err)
	}
}

func TestParseCredentialsRejectsInvalidInput(t *testing.T) {
	tests := map[string][]byte{
		"empty":            nil,
		"malformed":        []byte(`{"username":`),
		"invalid utf8":     {0xff},
		"unknown field":    []byte(`{"username":"u","password":"p","token":"x"}`),
		"duplicate field":  []byte(`{"username":"u","username":"u2","password":"p"}`),
		"missing field":    []byte(`{"username":"u"}`),
		"empty field":      []byte(`{"username":"u","password":""}`),
		"trailing data":    []byte(`{"username":"u","password":"p"} trailing`),
		"trailing space":   []byte(`{"username":"u","password":"p"} `),
		"multiple objects": []byte(`{"username":"u","password":"p"}{"username":"u","password":"p"}`),
		"non-string":       []byte(`{"username":"u","password":1}`),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCredentials(raw); !errors.Is(err, errInvalidCredentialInput) {
				t.Fatalf("error = %v, want invalid credential input", err)
			}
		})
	}
}

func TestCredentialErrorsDoNotContainInput(t *testing.T) {
	secret := "credential-canary"
	readFD := credentialPipe(t, `{"username":"`+secret+`"}`)
	_, err := credentialsFromInvocation(true, readFD, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error contains credential input: %q", err)
	}
}

func credentialPipe(t *testing.T, body string) int {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	if _, err := writer.WriteString(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return int(reader.Fd())
}
