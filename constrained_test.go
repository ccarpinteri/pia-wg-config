package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	cli "github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestConstrainedRequestedOnlyForConstrainedFlags(t *testing.T) {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.IntFlag{Name: "constrained-plan-fd"},
			&cli.IntFlag{Name: "credentials-fd"},
			&cli.IntFlag{Name: "public-ca-fd"},
			&cli.IntFlag{Name: "regional-ca-fd"},
			&cli.IntFlag{Name: "config-fd"},
			&cli.IntFlag{Name: "result-fd"},
			&cli.StringFlag{Name: "region"},
		},
		Action: func(c *cli.Context) error {
			if constrainedRequested(c) {
				return errors.New("constrained")
			}
			return nil
		},
	}
	if err := app.Run([]string{"pia-wg-config", "--region", "aus_perth"}); err != nil {
		t.Fatalf("ordinary flag selected constrained mode: %v", err)
	}
	if err := app.Run([]string{"pia-wg-config", "--constrained-plan-fd", "3"}); err == nil || err.Error() != "constrained" {
		t.Fatalf("constrained flag did not select constrained mode: %v", err)
	}
}

func TestRawConstrainedRequested(t *testing.T) {
	if !rawConstrainedRequested([]string{"--constrained-plan-fd", "3"}) {
		t.Fatal("raw constrained request not detected")
	}
	if rawConstrainedRequested([]string{"--credentials-fd", "3"}) {
		t.Fatal("legacy credentials-fd alone should not select constrained mode")
	}
	if rawConstrainedRequested([]string{"--", "--constrained-plan-fd", "3"}) {
		t.Fatal("flags after -- should not select constrained mode")
	}
}

func TestParseRawConstrainedArgsAcceptsOnlyCompleteConstrainedFDSet(t *testing.T) {
	values, err := parseRawConstrainedArgs([]string{
		"--constrained-plan-fd", "3",
		"--credentials-fd=4",
		"--public-ca-fd", "5",
		"--regional-ca-fd", "6",
		"--config-fd", "7",
		"--result-fd", "8",
	})
	if err != nil {
		t.Fatalf("parseRawConstrainedArgs returned error: %v", err)
	}
	for name, want := range map[string]int{
		"constrained-plan-fd": 3,
		"credentials-fd":      4,
		"public-ca-fd":        5,
		"regional-ca-fd":      6,
		"config-fd":           7,
		"result-fd":           8,
	} {
		if values[name] != want {
			t.Fatalf("%s = %d, want %d", name, values[name], want)
		}
	}
}

func TestParseRawConstrainedArgsRejectsBeforeCLIHandling(t *testing.T) {
	base := []string{
		"--constrained-plan-fd", "3",
		"--credentials-fd", "4",
		"--public-ca-fd", "5",
		"--regional-ca-fd", "6",
		"--config-fd", "7",
		"--result-fd", "8",
	}
	tests := map[string][]string{
		"unknown flag":        append(append([]string{}, base...), "--unknown"),
		"help flag":           append(append([]string{}, base...), "--help"),
		"short help":          append(append([]string{}, base...), "-h"),
		"ordinary flag":       append(append([]string{}, base...), "--region", "aus_perth"),
		"duplicate flag":      append(append([]string{}, base...), "--result-fd", "9"),
		"positional argument": append(append([]string{}, base...), "user"),
		"missing value":       {"--constrained-plan-fd"},
		"bad value":           append(append([]string{}, base[:1]...), "not-an-int"),
		"missing fd":          base[:len(base)-2],
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRawConstrainedArgs(args); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestValidateConstrainedInvocationRejectsIncompatibleInputs(t *testing.T) {
	tests := map[string][]string{
		"positional args":   {"user", "pass"},
		"ordinary flag":     {"--region", "aus_perth"},
		"list regions":      {"--list-regions"},
		"duplicate fd flag": {"--constrained-plan-fd", "3", "--constrained-plan-fd", "4"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			c := constrainedCLIContext(t, args...)
			oldArgs := os.Args
			os.Args = append([]string{"pia-wg-config"}, args...)
			t.Cleanup(func() { os.Args = oldArgs })
			if err := validateConstrainedInvocation(c); err == nil {
				t.Fatal("expected invocation validation error")
			}
		})
	}
}

func TestValidateConstrainedInvocationAllowsOnlyConstrainedInputs(t *testing.T) {
	args := []string{
		"--constrained-plan-fd", "3",
		"--credentials-fd", "4",
		"--public-ca-fd", "5",
		"--regional-ca-fd", "6",
		"--config-fd", "7",
		"--result-fd", "8",
	}
	c := constrainedCLIContext(t, args...)
	oldArgs := os.Args
	os.Args = append([]string{"pia-wg-config"}, args...)
	t.Cleanup(func() { os.Args = oldArgs })
	if err := validateConstrainedInvocation(c); err != nil {
		t.Fatalf("validateConstrainedInvocation returned error: %v", err)
	}
}

func TestParseConstrainedPlanAcceptsCompletePlan(t *testing.T) {
	plan, err := parseConstrainedPlan([]byte(validConstrainedPlanJSON()))
	if err != nil {
		t.Fatalf("parseConstrainedPlan returned error: %v", err)
	}
	if plan.Schema != constrainedSchema || plan.Region != "aus_perth" || !plan.PortForwarding {
		t.Fatalf("plan = %#v", plan)
	}
	if plan.TokenDestinationIPv4 != "203.0.113.10" {
		t.Fatalf("token destination = %q", plan.TokenDestinationIPv4)
	}
	if plan.RegistrationCandidate.IPv4 != "203.0.113.20" || plan.RegistrationCandidate.TLSCommonName != "example.privateinternetaccess.com" {
		t.Fatalf("candidate = %#v", plan.RegistrationCandidate)
	}
	if !plan.ExcludedWireguardEndpointSet || plan.ExcludedWireguardEndpoint.UDPPort != 51820 {
		t.Fatalf("excluded endpoint = %#v set=%v", plan.ExcludedWireguardEndpoint, plan.ExcludedWireguardEndpointSet)
	}
}

func TestParseConstrainedPlanAcceptsRealPIARegistrationCommonName(t *testing.T) {
	body := `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"158.173.66.79","tls_common_name":"Server-11736-3a"},"excluded_wireguard_endpoint":{"ipv4":"158.173.66.79","udp_port":1337}}`

	plan, err := parseConstrainedPlan([]byte(body))
	if err != nil {
		t.Fatalf("parseConstrainedPlan returned error: %v", err)
	}
	if plan.RegistrationCandidate.TLSCommonName != "Server-11736-3a" {
		t.Fatalf("candidate CN = %q, want real PIA common name", plan.RegistrationCandidate.TLSCommonName)
	}
}

func TestParseConstrainedPlanRejectsStrictJSONViolations(t *testing.T) {
	tests := map[string]string{
		"missing schema":   `{"region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"}}`,
		"unknown field":    `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"},"extra":true}`,
		"duplicate field":  `{"schema":"pia-wg-config-constrained-plan/v1","schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"}}`,
		"nested duplicate": `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","ipv4":"203.0.113.21","tls_common_name":"example.privateinternetaccess.com"}}`,
		"trailing space":   `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"}} `,
		"invalid utf8":     string([]byte{0xff}),
		"bad region":       `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus/perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"}}`,
		"bad token ip":     `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"2001:db8::1","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"}}`,
		"bad cn":           `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"127.0.0.1"}}`,
		"empty cn":         `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":""}}`,
		"space cn":         `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"Server 11736"}}`,
		"slash cn":         `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"Server/11736"}}`,
		"colon cn":         `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"Server:11736"}}`,
		"at cn":            `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"Server@11736"}}`,
		"overlong cn":      `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"` + strings.Repeat("a", 254) + `"}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConstrainedPlan([]byte(body)); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseConstrainedCredentialsReusesStrictCredentialParser(t *testing.T) {
	got, err := parseConstrainedCredentials([]byte(`{"username":"user","password":"pass"}`))
	if err != nil {
		t.Fatalf("parseConstrainedCredentials returned error: %v", err)
	}
	if got.username != "user" || got.password != "pass" {
		t.Fatalf("credentials = %#v", got)
	}
	if _, err := parseConstrainedCredentials([]byte(`{"username":"user","username":"other","password":"pass"}`)); !errors.Is(err, errInvalidCredentialInput) {
		t.Fatalf("duplicate credential error = %v", err)
	}
}

func TestParseConstrainedCABundleAcceptsSingleCA(t *testing.T) {
	raw := testCABundle(t)
	pool, err := parseConstrainedCABundle(raw)
	if err != nil {
		t.Fatalf("parseConstrainedCABundle returned error: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
}

func TestParseConstrainedCABundleAcceptsMultipleCAs(t *testing.T) {
	raw := append(testCABundle(t), testCABundle(t)...)
	pool, err := parseConstrainedCABundle(raw)
	if err != nil {
		t.Fatalf("parseConstrainedCABundle returned error: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
}

func TestParseConstrainedCABundleRejectsInvalidTrust(t *testing.T) {
	tests := map[string][]byte{
		"empty":          nil,
		"trailing":       append(testCABundle(t), []byte("trailing")...),
		"too many certs": bytes.Repeat(testCABundle(t), 5),
		"not pem":        []byte("not a cert"),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConstrainedCABundle(raw); err == nil {
				t.Fatal("expected CA parse error")
			}
		})
	}
}

func TestParseConstrainedAddKeyRejectsStrictJSONViolations(t *testing.T) {
	body := validAddKeyJSON(t)
	if _, err := parseConstrainedAddKey([]byte(body)); err != nil {
		t.Fatalf("parseConstrainedAddKey returned error: %v", err)
	}
	tests := map[string]string{
		"unknown":   strings.Replace(body, `"dns_servers":["1.1.1.1"]`, `"dns_servers":["1.1.1.1"],"extra":true`, 1),
		"duplicate": strings.Replace(body, `"status":"OK"`, `"status":"OK","status":"OK"`, 1),
		"missing":   strings.Replace(body, `,"dns_servers":["1.1.1.1"]`, ``, 1),
		"trailing":  body + " ",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseConstrainedAddKey([]byte(raw)); err == nil {
				t.Fatal("expected addKey parse error")
			}
		})
	}
}

func TestValidateConstrainedAddKey(t *testing.T) {
	plan, err := parseConstrainedPlan([]byte(validConstrainedPlanJSON()))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testWGPublicKey(t)
	result := validAddKeyResult(t, publicKey)
	if class := validateConstrainedAddKey(plan, result, publicKey); class != "" {
		t.Fatalf("validateConstrainedAddKey class = %s", class)
	}

	t.Run("requires port forward vip", func(t *testing.T) {
		bad := result
		bad.ServerVIP = ""
		if class := validateConstrainedAddKey(plan, bad, publicKey); class != classResponseInvalid {
			t.Fatalf("class = %s", class)
		}
	})

	t.Run("rejects peer public key mismatch", func(t *testing.T) {
		bad := result
		bad.PeerPubKey = testWGPublicKey(t)
		if class := validateConstrainedAddKey(plan, bad, publicKey); class != classResponseInvalid {
			t.Fatalf("class = %s", class)
		}
	})

	t.Run("rejects endpoint reuse", func(t *testing.T) {
		reused := result
		reused.ServerIP = plan.ExcludedWireguardEndpoint.IPv4
		reused.ServerPort = plan.ExcludedWireguardEndpoint.UDPPort
		if class := validateConstrainedAddKey(plan, reused, publicKey); class != "" {
			t.Fatalf("validation class before reuse check = %s", class)
		}
		if !(plan.ExcludedWireguardEndpointSet &&
			plan.ExcludedWireguardEndpoint.IPv4 == reused.ServerIP &&
			plan.ExcludedWireguardEndpoint.UDPPort == reused.ServerPort) {
			t.Fatal("reuse condition was not detected")
		}
	})
}

func TestRenderConstrainedConfigUsesValidatedEndpointPort(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testWGPublicKey(t)
	result := validAddKeyResult(t, publicKey)
	result.ServerPort = 51820

	config, err := renderConstrainedConfig(privateKey.String(), result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "Endpoint = 203.0.113.40:51820") {
		t.Fatalf("config did not use validated endpoint port:\n%s", config)
	}
	if strings.Contains(config, ":1337") {
		t.Fatalf("config used hardcoded registration port:\n%s", config)
	}
}

func validConstrainedPlanJSON() string {
	return `{"schema":"pia-wg-config-constrained-plan/v1","region":"aus_perth","port_forwarding":true,"token_destination_ipv4":"203.0.113.10","registration_candidate":{"ipv4":"203.0.113.20","tls_common_name":"example.privateinternetaccess.com"},"excluded_wireguard_endpoint":{"ipv4":"203.0.113.30","udp_port":51820}}`
}

func validAddKeyJSON(t *testing.T) string {
	t.Helper()
	serverKey := testWGPublicKey(t)
	peerKey := testWGPublicKey(t)
	return `{"status":"OK","server_key":"` + serverKey + `","server_port":51820,"server_ip":"203.0.113.40","server_vip":"10.0.0.1","peer_ip":"10.0.0.2/32","peer_pubkey":"` + peerKey + `","dns_servers":["1.1.1.1"]}`
}

func validAddKeyResult(t *testing.T, publicKey string) constrainedAddKeyResult {
	t.Helper()
	return constrainedAddKeyResult{
		Status:     "OK",
		ServerKey:  testWGPublicKey(t),
		ServerPort: 51820,
		ServerIP:   "203.0.113.40",
		ServerVIP:  "10.0.0.1",
		PeerIP:     "10.0.0.2/32",
		PeerPubKey: publicKey,
		DNSServers: []string{"1.1.1.1"},
	}
}

func testWGPublicKey(t *testing.T) string {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey().String()
}

func testCABundle(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func constrainedCLIContext(t *testing.T, args ...string) *cli.Context {
	t.Helper()
	set := flag.NewFlagSet("constrained-test", flag.ContinueOnError)
	set.SetOutput(ioDiscard{})
	flags := []cli.Flag{
		&cli.StringFlag{Name: "outfile"},
		&cli.StringFlag{Name: "region"},
		&cli.BoolFlag{Name: "verbose"},
		&cli.BoolFlag{Name: "server"},
		&cli.BoolFlag{Name: "port-forwarding"},
		&cli.BoolFlag{Name: "json"},
		&cli.StringFlag{Name: "metadata-file"},
		&cli.StringFlag{Name: "serverlist-cache"},
		&cli.StringFlag{Name: "serverlist-cache-ttl"},
		&cli.StringFlag{Name: "serverlist-cache-max-age"},
		&cli.BoolFlag{Name: "serverlist-force-refresh"},
		&cli.IntFlag{Name: "serverlist-fetch-retries"},
		&cli.BoolFlag{Name: "list-regions"},
		&cli.IntFlag{Name: "credentials-fd"},
		&cli.IntFlag{Name: "constrained-plan-fd"},
		&cli.IntFlag{Name: "public-ca-fd"},
		&cli.IntFlag{Name: "regional-ca-fd"},
		&cli.IntFlag{Name: "config-fd"},
		&cli.IntFlag{Name: "result-fd"},
	}
	for _, cliFlag := range flags {
		if err := cliFlag.Apply(set); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return cli.NewContext(nil, set, nil)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
