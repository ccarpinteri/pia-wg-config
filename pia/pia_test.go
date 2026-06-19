package pia

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetTokenDoesNotLogToken(t *testing.T) {
	const token = "token-canary"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"` + token + `"}`))
	}))
	t.Cleanup(server.Close)

	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	client := &PIAClient{username: "user", password: "pass", verbose: true}
	got, err := client.getToken(server.URL)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got != token {
		t.Fatalf("token = %q, want %q", got, token)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("verbose output contains PIA auth token")
	}
	if !strings.Contains(logs.String(), "Requesting token") {
		t.Fatal("verbose output missing non-secret request message")
	}
}
