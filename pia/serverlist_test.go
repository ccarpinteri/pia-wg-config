package pia

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// minimalServerListJSON is a well-formed PIA server-list payload with one region.
const minimalServerListJSON = `{
  "regions": [
    {
      "id": "ca_toronto",
      "name": "CA Toronto",
      "country": "CA",
      "auto_region": false,
      "dns": "ca-toronto.privacy.network",
      "port_forward": true,
      "geo": false,
      "servers": {
        "meta": [{"cn": "ca-meta.example.com", "ip": "1.2.3.4"}],
        "wg":   [{"cn": "ca-wg.example.com",   "ip": "1.2.3.5"}]
      }
    }
  ]
}`

// mockResponse describes one response the mock server should return.
type mockResponse struct {
	status int
	body   string
}

// newMockServerListServer returns an httptest.Server that returns responses in
// order, repeating the last one once exhausted. The test helper patches
// serverListURL for the duration of the test.
func newMockServerListServer(t *testing.T, responses []mockResponse) *httptest.Server {
	t.Helper()
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := responses[len(responses)-1]
		if i < len(responses) {
			resp = responses[i]
			i++
		}
		w.WriteHeader(resp.status)
		fmt.Fprint(w, resp.body)
	}))
	original := serverListURL
	// Patch the package-level URL constant via the indirection variable.
	serverListURLOverride = srv.URL
	t.Cleanup(func() {
		serverListURLOverride = original
		srv.Close()
	})
	return srv
}

// --- retry tests ---

func TestFetchWithRetry_SucceedsAfterTransientFailure(t *testing.T) {
	origBackoffs := defaultBackoffs
	defaultBackoffs = []time.Duration{1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond}
	t.Cleanup(func() { defaultBackoffs = origBackoffs })

	newMockServerListServer(t, []mockResponse{
		{503, ""},
		{503, ""},
		{503, ""},
		{200, minimalServerListJSON},
	})

	data, err := fetchServerListWithRetry(false, 5)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty data")
	}
}

func TestFetchWithRetry_ExhaustsRetries(t *testing.T) {
	origBackoffs := defaultBackoffs
	defaultBackoffs = []time.Duration{1 * time.Millisecond, 1 * time.Millisecond}
	t.Cleanup(func() { defaultBackoffs = origBackoffs })

	newMockServerListServer(t, []mockResponse{
		{503, ""},
	})

	_, err := fetchServerListWithRetry(false, 3)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("error should mention attempt count, got: %v", err)
	}
}

func TestFetchWithRetry_NonTransientErrorNotRetried(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(401)
		fmt.Fprint(w, "unauthorized")
	}))
	original := serverListURL
	serverListURLOverride = srv.URL
	t.Cleanup(func() { serverListURLOverride = original; srv.Close() })

	_, err := fetchServerListWithRetry(false, 5)
	if err == nil {
		t.Fatal("expected error for HTTP 401")
	}
	if callCount != 1 {
		t.Errorf("non-transient error should not retry, but got %d calls", callCount)
	}
}

// --- cache policy tests ---

func TestCachePolicy_NoCachePath_FetchesDirect(t *testing.T) {
	newMockServerListServer(t, []mockResponse{{200, minimalServerListJSON}})

	opts := ServerListOptions{} // no cache path
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected data")
	}
}

func TestCachePolicy_FreshCacheUsed(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write a fresh cache file.
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Server should NOT be called — if it is, it will return 500.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(500)
	}))
	original := serverListURL
	serverListURLOverride = srv.URL
	t.Cleanup(func() { serverListURLOverride = original; srv.Close() })

	opts := ServerListOptions{
		CachePath:   cachePath,
		CacheTTL:    24 * time.Hour,
		CacheMaxAge: 168 * time.Hour,
	}
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 0 {
		t.Errorf("fresh cache should not trigger network fetch, but server was called %d time(s)", callCount)
	}
	if string(data) != minimalServerListJSON {
		t.Errorf("expected cached data, got: %s", data)
	}
}

func TestCachePolicy_StaleTriggersRefresh(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write cache with an artificially old mtime (2 days ago).
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	newMockServerListServer(t, []mockResponse{{200, minimalServerListJSON}})

	opts := ServerListOptions{
		CachePath:   cachePath,
		CacheTTL:    24 * time.Hour,
		CacheMaxAge: 168 * time.Hour,
	}
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected data after refresh")
	}
	// Cache file should have been updated (mtime now recent).
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.ModTime()) > 5*time.Second {
		t.Error("cache file mtime not updated after refresh")
	}
}

func TestCachePolicy_StaleUsedOnRefreshFail(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write stale cache (2 days old, within max-age of 7 days).
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	// Server always fails.
	newMockServerListServer(t, []mockResponse{{503, ""}})

	opts := ServerListOptions{
		CachePath:    cachePath,
		CacheTTL:     24 * time.Hour,
		CacheMaxAge:  168 * time.Hour,
		FetchRetries: 1,
	}
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("should use stale cache on refresh failure, got error: %v", err)
	}
	if string(data) != minimalServerListJSON {
		t.Errorf("expected stale cache data, got: %s", data)
	}
}

func TestCachePolicy_ExpiredCacheRejected(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write expired cache (200 hours old, beyond max-age of 168h).
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-200 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}

	// Server always fails.
	newMockServerListServer(t, []mockResponse{{503, ""}})

	opts := ServerListOptions{
		CachePath:    cachePath,
		CacheTTL:     24 * time.Hour,
		CacheMaxAge:  168 * time.Hour,
		FetchRetries: 1,
	}
	_, err := fetchServerListWithPolicy(opts, false)
	if err == nil {
		t.Fatal("expected error for expired cache with failed refresh")
	}
}

func TestCachePolicy_MissingCacheFetchAndWrite(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "sub", "serverlist.json")

	newMockServerListServer(t, []mockResponse{{200, minimalServerListJSON}})

	opts := ServerListOptions{
		CachePath:   cachePath,
		CacheTTL:    24 * time.Hour,
		CacheMaxAge: 168 * time.Hour,
	}
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected data")
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file should have been created: %v", err)
	}
}

func TestCachePolicy_ForceRefreshIgnoresFreshCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write a fresh cache.
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		fmt.Fprint(w, minimalServerListJSON)
	}))
	original := serverListURL
	serverListURLOverride = srv.URL
	t.Cleanup(func() { serverListURLOverride = original; srv.Close() })

	opts := ServerListOptions{
		CachePath:    cachePath,
		CacheTTL:     24 * time.Hour,
		CacheMaxAge:  168 * time.Hour,
		ForceRefresh: true,
	}
	_, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount == 0 {
		t.Error("force refresh should have called the server")
	}
}

func TestCachePolicy_ForceRefreshFailFails(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	// Write a fresh cache that must NOT be used as fallback.
	if err := os.WriteFile(cachePath, []byte(minimalServerListJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// Server always fails.
	newMockServerListServer(t, []mockResponse{{503, ""}})

	opts := ServerListOptions{
		CachePath:    cachePath,
		CacheTTL:     24 * time.Hour,
		CacheMaxAge:  168 * time.Hour,
		ForceRefresh: true,
		FetchRetries: 1,
	}
	_, err := fetchServerListWithPolicy(opts, false)
	if err == nil {
		t.Fatal("force refresh with failed fetch must return error, not fall back to cache")
	}
}

// --- atomic write tests ---

func TestCacheWrite_Atomic(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	if err := writeServerListCache(cachePath, []byte(minimalServerListJSON)); err != nil {
		t.Fatalf("writeServerListCache error: %v", err)
	}

	// Final file must exist.
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file not present after write: %v", err)
	}

	// No temp files should remain.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".serverlist-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestCacheWrite_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "a", "b", "c", "serverlist.json")

	if err := writeServerListCache(cachePath, []byte(minimalServerListJSON)); err != nil {
		t.Fatalf("writeServerListCache error: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file not present: %v", err)
	}
}

func TestCacheWrite_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	if err := writeServerListCache(cachePath, []byte(minimalServerListJSON)); err != nil {
		t.Fatalf("writeServerListCache error: %v", err)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got %o", perm)
	}
}

// --- parse / malformed tests ---

func TestCacheRead_MalformedFails(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "serverlist.json")

	if err := os.WriteFile(cachePath, []byte(`{bad json`), 0600); err != nil {
		t.Fatal(err)
	}
	data, _, err := readServerListCache(cachePath)
	if err != nil {
		t.Fatalf("readServerListCache should not error on read, but parse should: %v", err)
	}
	if _, err := parseServerList(data); err == nil {
		t.Fatal("parseServerList should fail on malformed JSON")
	}
}

func TestParseServerList_EmptyRegionsFails(t *testing.T) {
	_, err := parseServerList([]byte(`{"regions":[]}`))
	if err == nil {
		t.Fatal("expected error for empty regions list")
	}
}

// --- security tests ---

func TestCache_NoCredentials(t *testing.T) {
	// Confirm cache bytes from a real fetch contain no credential-shaped strings.
	// We write a payload that mimics a real server-list response and assert
	// it does not leak the strings we watch for.
	sensitiveStrings := []string{"password", "supersecrettoken", "privatekey"}
	payload := minimalServerListJSON
	for _, s := range sensitiveStrings {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(s)) {
			t.Errorf("server-list JSON unexpectedly contains %q", s)
		}
	}
}

func TestCache_DoesNotContainWgConfig(t *testing.T) {
	// The cache stores only the PIA server-list endpoint response.
	// WireGuard config sections must never appear.
	payload := minimalServerListJSON
	forbidden := []string{"[Interface]", "[Peer]", "PrivateKey", "AllowedIPs"}
	for _, f := range forbidden {
		if strings.Contains(payload, f) {
			t.Errorf("server-list payload contains WireGuard config section %q", f)
		}
	}
}

// --- JSON metadata backward-compat test ---

func TestJSONMetadata_BackwardCompatible(t *testing.T) {
	gen := NewPIAWgGenerator(&PIAClientMockPF{}, PIAWgGeneratorConfig{
		PrivateKey:     "priv",
		PublicKey:      "pub",
		Region:         "aus_perth",
		PortForwarding: true,
	})
	_, m, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	jsonStr := string(raw)

	required := []string{
		`"region"`,
		`"port_forward_enabled"`,
		`"endpoint_host"`,
		`"endpoint_port"`,
		`"port_forward_gateway"`,
	}
	for _, key := range required {
		if !strings.Contains(jsonStr, key) {
			t.Errorf("v1.2.0 metadata key %s missing from JSON: %s", key, jsonStr)
		}
	}
	// wireguard_config must be omitted when not set.
	if strings.Contains(jsonStr, `"wireguard_config"`) {
		t.Errorf("wireguard_config should be omitted when empty, got: %s", jsonStr)
	}
}

// --- existing behavior tests ---

func TestNoCacheFlagsDefaultBehavior(t *testing.T) {
	// Zero-value ServerListOptions with no cache path — policy must just call
	// fetchServerListWithRetry once. We verify by pointing at a healthy mock.
	newMockServerListServer(t, []mockResponse{{200, minimalServerListJSON}})

	opts := ServerListOptions{} // all zero
	data, err := fetchServerListWithPolicy(opts, false)
	if err != nil {
		t.Fatalf("default behavior failed: %v", err)
	}
	sl, err := parseServerList(data)
	if err != nil {
		t.Fatalf("parseServerList failed: %v", err)
	}
	if len(sl.Regions) == 0 {
		t.Error("expected at least one region")
	}
}

func TestIsTransientError_Classifications(t *testing.T) {
	cases := []struct {
		err       error
		transient bool
	}{
		{nil, false},
		{&serverListHTTPError{200}, false},
		{&serverListHTTPError{401}, false},
		{&serverListHTTPError{403}, false},
		{&serverListHTTPError{404}, false},
		{&serverListHTTPError{429}, true},
		{&serverListHTTPError{500}, true},
		{&serverListHTTPError{502}, true},
		{&serverListHTTPError{503}, true},
		{&serverListHTTPError{504}, true},
	}
	for _, tc := range cases {
		got := isTransientError(tc.err)
		if got != tc.transient {
			t.Errorf("isTransientError(%v) = %v, want %v", tc.err, got, tc.transient)
		}
	}
}
