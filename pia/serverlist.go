package pia

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ServerListOptions controls how the PIA server list is fetched and cached.
type ServerListOptions struct {
	CachePath    string        // empty = no cache
	CacheTTL     time.Duration // how long a cached file is used without refresh; default 24h
	CacheMaxAge  time.Duration // how old a cache can be before it is treated as invalid; default 168h
	ForceRefresh bool          // bypass fresh cache and force a network fetch
	FetchRetries int           // max fetch attempts; 0 = use default (5)
}

const serverListURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

// serverListURLOverride is the URL used by fetchServerListRaw.
// It equals serverListURL at runtime; tests patch it to point at a mock server.
var serverListURLOverride = serverListURL

var defaultBackoffs = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}

// fetchServerListRaw performs a single HTTP GET, strips the trailing base64 tail,
// and returns the raw JSON bytes. It carries no credentials.
func fetchServerListRaw() ([]byte, error) {
	resp, err := http.Get(serverListURLOverride)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &serverListHTTPError{statusCode: resp.StatusCode}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Strip trailing base64 garbage after the closing brace.
	s := string(body)
	lastBrace := strings.LastIndex(s, "}")
	if lastBrace < 0 {
		return nil, fmt.Errorf("server list response contains no JSON object")
	}
	return []byte(s[:lastBrace+1]), nil
}

// serverListHTTPError carries an HTTP status code so isTransientError can classify it.
type serverListHTTPError struct {
	statusCode int
}

func (e *serverListHTTPError) Error() string {
	return fmt.Sprintf("server list fetch returned HTTP %d", e.statusCode)
}

// isTransientError returns true when the error is worth retrying.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	// HTTP-level transient codes.
	if httpErr, ok := err.(*serverListHTTPError); ok {
		switch httpErr.statusCode {
		case 429, 500, 502, 503, 504:
			return true
		}
		return false
	}
	// Network-level timeouts.
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	if os.IsTimeout(err) {
		return true
	}
	// Treat all other net errors (DNS, connection refused, etc.) as transient.
	if _, ok := err.(*net.OpError); ok {
		return true
	}
	return false
}

// fetchServerListWithRetry calls fetchServerListRaw up to maxAttempts times,
// sleeping between attempts using defaultBackoffs. Credential values are never logged.
func fetchServerListWithRetry(verbose bool, maxAttempts int) ([]byte, error) {
	if maxAttempts <= 0 {
		maxAttempts = len(defaultBackoffs) + 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		data, err := fetchServerListRaw()
		if err == nil {
			return data, nil
		}
		lastErr = err

		if !isTransientError(err) {
			return nil, fmt.Errorf("server list fetch failed (non-retryable): %w", err)
		}

		if attempt == maxAttempts {
			break
		}

		backoff := defaultBackoffs[len(defaultBackoffs)-1]
		if attempt-1 < len(defaultBackoffs) {
			backoff = defaultBackoffs[attempt-1]
		}

		if verbose {
			log.Printf("server-list fetch attempt %d/%d failed: %v — retrying in %s", attempt, maxAttempts, err, backoff)
		} else {
			log.Printf("server-list fetch attempt %d/%d failed, retrying in %s", attempt, maxAttempts, backoff)
		}

		time.Sleep(backoff)
	}

	return nil, fmt.Errorf("server list fetch failed after %d attempt(s): %w", maxAttempts, lastErr)
}

// readServerListCache reads the cache file and returns the raw bytes and file mtime.
// Returns os.ErrNotExist (via os.IsNotExist) if the file does not exist.
func readServerListCache(path string) ([]byte, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime(), nil
}

// writeServerListCache atomically writes data to path.
// Creates the parent directory (0700) if it does not exist.
// Uses write-to-temp + rename for atomicity.
func writeServerListCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating cache directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".serverlist-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp cache file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() { os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("writing temp cache file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("syncing temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing temp cache file: %w", err)
	}

	if err := os.Chmod(tmpName, 0600); err != nil {
		cleanup()
		return fmt.Errorf("setting cache file permissions: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming cache file: %w", err)
	}
	return nil
}

// parseServerList unmarshals raw JSON bytes into a piaServerList.
// Returns an explicit error on malformed input.
func parseServerList(data []byte) (piaServerList, error) {
	var sl piaServerList
	if err := json.Unmarshal(data, &sl); err != nil {
		return piaServerList{}, fmt.Errorf("parsing server list: %w", err)
	}
	if len(sl.Regions) == 0 {
		return piaServerList{}, fmt.Errorf("server list parsed but contains no regions")
	}
	return sl, nil
}

// ListRegions fetches the PIA server list and returns region metadata sorted by country then ID.
// No authentication is required. Supports the same cache/retry options as NewPIAClient.
func ListRegions(opts ServerListOptions, verbose bool) ([]RegionInfo, error) {
	data, err := fetchServerListWithPolicy(opts, verbose)
	if err != nil {
		return nil, err
	}
	sl, err := parseServerList(data)
	if err != nil {
		return nil, err
	}
	regions := make([]RegionInfo, 0, len(sl.Regions))
	for _, r := range sl.Regions {
		regions = append(regions, RegionInfo{
			ID:          r.ID,
			Name:        r.Name,
			Country:     r.Country,
			PortForward: r.PortForward,
			Geo:         r.Geo,
			Offline:     r.Offline,
		})
	}
	sort.Slice(regions, func(i, j int) bool {
		if regions[i].Country != regions[j].Country {
			return regions[i].Country < regions[j].Country
		}
		return regions[i].ID < regions[j].ID
	})
	return regions, nil
}

// fetchServerListWithPolicy implements the cache state machine described in the brief.
// Returns stripped JSON bytes ready for parseServerList.
func fetchServerListWithPolicy(opts ServerListOptions, verbose bool) ([]byte, error) {
	ttl := opts.CacheTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	maxAge := opts.CacheMaxAge
	if maxAge == 0 {
		maxAge = 168 * time.Hour
	}

	// No cache configured — just fetch with retry.
	if opts.CachePath == "" {
		return fetchServerListWithRetry(verbose, opts.FetchRetries)
	}

	// Force refresh: ignore any existing cache.
	if opts.ForceRefresh {
		if verbose {
			log.Print("server-list: force refresh requested, bypassing cache")
		}
		data, err := fetchServerListWithRetry(verbose, opts.FetchRetries)
		if err != nil {
			return nil, fmt.Errorf("server-list force refresh failed: %w", err)
		}
		if writeErr := writeServerListCache(opts.CachePath, data); writeErr != nil {
			log.Printf("server-list: warning: could not write cache: %v", writeErr)
		}
		return data, nil
	}

	// Attempt to read existing cache.
	cached, modTime, readErr := readServerListCache(opts.CachePath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("reading server-list cache: %w", readErr)
	}

	now := time.Now()

	// Cache missing: fetch and populate.
	if os.IsNotExist(readErr) {
		if verbose {
			log.Print("server-list: cache not found, fetching fresh copy")
		}
		data, err := fetchServerListWithRetry(verbose, opts.FetchRetries)
		if err != nil {
			return nil, fmt.Errorf("server-list fetch failed (no cache): %w", err)
		}
		if writeErr := writeServerListCache(opts.CachePath, data); writeErr != nil {
			log.Printf("server-list: warning: could not write cache: %v", writeErr)
		}
		return data, nil
	}

	age := now.Sub(modTime)

	// Fresh cache: use without network.
	if age <= ttl {
		if verbose {
			log.Printf("server-list: using fresh cache (age %s <= TTL %s)", age.Round(time.Second), ttl)
		}
		return cached, nil
	}

	// Expired cache (beyond max age): must refresh.
	if age > maxAge {
		if verbose {
			log.Printf("server-list: cache too old (age %s > max-age %s), fetching fresh copy", age.Round(time.Second), maxAge)
		}
		data, err := fetchServerListWithRetry(verbose, opts.FetchRetries)
		if err != nil {
			return nil, fmt.Errorf("server-list fetch failed (cache expired, age %s > max-age %s): %w", age.Round(time.Second), maxAge, err)
		}
		if writeErr := writeServerListCache(opts.CachePath, data); writeErr != nil {
			log.Printf("server-list: warning: could not write cache: %v", writeErr)
		}
		return data, nil
	}

	// Stale cache (between TTL and max age): try to refresh, fall back to stale.
	if verbose {
		log.Printf("server-list: cache stale (age %s, TTL %s), attempting refresh", age.Round(time.Second), ttl)
	}
	data, err := fetchServerListWithRetry(verbose, opts.FetchRetries)
	if err != nil {
		log.Printf("server-list: warning: refresh failed (%v), using stale cache (age %s)", err, age.Round(time.Second))
		return cached, nil
	}
	if writeErr := writeServerListCache(opts.CachePath, data); writeErr != nil {
		log.Printf("server-list: warning: could not write cache: %v", writeErr)
	}
	return data, nil
}
