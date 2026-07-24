package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	cli "github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	constrainedSchema = "pia-wg-config-constrained-plan/v1"

	maxConstrainedPlanSize        = 16 * 1024
	maxConstrainedCredentialSize  = 8 * 1024
	maxConstrainedCABundleSize    = 128 * 1024
	maxConstrainedDERCertSize     = 32 * 1024
	maxConstrainedTokenBodySize   = 8 * 1024
	maxConstrainedTokenSize       = 4 * 1024
	maxConstrainedAddKeyBodySize  = 64 * 1024
	maxConstrainedConfigSize      = 64 * 1024
	maxConstrainedResultSize      = 4 * 1024
	maxConstrainedCredentialBytes = 256
)

type constrainedFDMode int

const (
	constrainedFDRead constrainedFDMode = iota
	constrainedFDWrite
)

type constrainedPlan struct {
	Schema                       string
	Region                       string
	PortForwarding               bool
	TokenDestinationIPv4         string
	RegistrationCandidate        constrainedRegistrationCandidate
	ExcludedWireguardEndpoint    *constrainedEndpoint
	ExcludedWireguardEndpointSet bool
}

type constrainedRegistrationCandidate struct {
	IPv4          string
	TLSCommonName string
}

type constrainedEndpoint struct {
	IPv4    string
	UDPPort int
}

type constrainedFiles struct {
	plan          *os.File
	credentials   *os.File
	publicCA      *os.File
	regionalCA    *os.File
	configWriter  *os.File
	resultWriter  *os.File
	closeOnReturn []*os.File
}

type constrainedAddKeyResult struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVIP  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubKey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
}

type constrainedFailure struct {
	Schema        string `json:"schema"`
	Status        string `json:"status"`
	FailureClass  string `json:"failure_class"`
	FailureDetail string `json:"failure_detail,omitempty"`
}

type constrainedSuccess struct {
	Schema                   string `json:"schema"`
	Status                   string `json:"status"`
	Region                   string `json:"region"`
	PortForwardEnabled       bool   `json:"port_forward_enabled"`
	SelectedRegistrationCN   string `json:"selected_registration_cn"`
	SelectedRegistrationIPv4 string `json:"selected_registration_ipv4"`
	WireguardEndpointIPv4    string `json:"wireguard_endpoint_ipv4"`
	WireguardEndpointUDPPort int    `json:"wireguard_endpoint_udp_port"`
	PortForwardGatewayIPv4   string `json:"port_forward_gateway_ipv4,omitempty"`
}

type constrainedClass string

const (
	classInvalidInvocation  constrainedClass = "invalid_invocation"
	classInvalidPlan        constrainedClass = "invalid_plan"
	classInvalidCredentials constrainedClass = "invalid_credentials"
	classInvalidTrust       constrainedClass = "invalid_trust"
	classTokenFailed        constrainedClass = "token_request_failed"
	classAddKeyFailed       constrainedClass = "add_key_request_failed"
	classResponseInvalid    constrainedClass = "response_invalid"
	classEndpointReused     constrainedClass = "endpoint_reused"
	classConfigWriteFailed  constrainedClass = "config_write_failed"
	classDeadlineExceeded   constrainedClass = "deadline_exceeded"
	classCancelled          constrainedClass = "cancelled"
	classResultWriteFailed  constrainedClass = "result_write_failed"
	classInternalFailure    constrainedClass = "internal_failure"
)

const (
	detailTokenHTTPStatus         = "token_http_status"
	detailTokenBodyReadFailed     = "token_body_read_failed"
	detailTokenBodyTooLarge       = "token_body_too_large"
	detailTokenJSONParseFailed    = "token_json_parse_failed"
	detailTokenMissingField       = "token_missing_field"
	detailTokenInvalidToken       = "token_invalid_token"
	detailAddKeyHTTPStatus        = "add_key_http_status"
	detailAddKeyBodyReadFailed    = "add_key_body_read_failed"
	detailAddKeyBodyTooLarge      = "add_key_body_too_large"
	detailAddKeyJSONParseFailed   = "add_key_json_parse_failed"
	detailAddKeyMissingField      = "add_key_missing_field"
	detailAddKeyInvalidStatus     = "add_key_invalid_status"
	detailAddKeyInvalidServerKey  = "add_key_invalid_server_key"
	detailAddKeyInvalidServerPort = "add_key_invalid_server_port"
	detailAddKeyInvalidServerIP   = "add_key_invalid_server_ip"
	detailAddKeyInvalidServerVIP  = "add_key_invalid_server_vip"
	detailAddKeyInvalidPeerIP     = "add_key_invalid_peer_ip"
	detailAddKeyInvalidPeerPubKey = "add_key_invalid_peer_pubkey"
	detailAddKeyInvalidDNS        = "add_key_invalid_dns"
)

type constrainedFailureReason struct {
	class  constrainedClass
	detail string
}

func constrainedFailureFor(class constrainedClass) constrainedFailureReason {
	return constrainedFailureReason{class: class}
}

func constrainedFailureWithDetail(class constrainedClass, detail string) constrainedFailureReason {
	return constrainedFailureReason{class: class, detail: validConstrainedFailureDetail(detail)}
}

func (r constrainedFailureReason) empty() bool {
	return r.class == ""
}

func constrainedRequested(c *cli.Context) bool {
	for _, name := range []string{"constrained-plan-fd", "public-ca-fd", "regional-ca-fd", "config-fd", "result-fd"} {
		if c.IsSet(name) {
			return true
		}
	}
	return false
}

func rawConstrainedRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		name := rawFlagName(arg)
		switch name {
		case "constrained-plan-fd", "public-ca-fd", "regional-ca-fd", "config-fd", "result-fd":
			return true
		}
	}
	return false
}

func constrainedActionFromRawArgs(args []string) error {
	values, err := parseRawConstrainedArgs(args)
	if err != nil {
		return writeInvalidInvocationFailureFD(values["result-fd"])
	}
	c := constrainedContextFromValues(values)
	return constrainedAction(c)
}

func parseRawConstrainedArgs(args []string) (map[string]int, error) {
	values := map[string]int{}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return values, errors.New("invalid positional argument")
		}
		name := rawFlagName(arg)
		if name == "" {
			return values, errors.New("invalid flag")
		}
		if seen[name] {
			return values, errors.New("duplicate flag")
		}
		seen[name] = true
		if !rawConstrainedFDFlag(name) {
			return values, errors.New("incompatible flag")
		}
		var rawValue string
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			rawValue = arg[eq+1:]
		} else {
			i++
			if i >= len(args) {
				return values, errors.New("missing flag value")
			}
			rawValue = args[i]
		}
		value, err := strconv.Atoi(rawValue)
		if err != nil {
			return values, errors.New("invalid fd value")
		}
		values[name] = value
	}
	for _, name := range []string{"constrained-plan-fd", "credentials-fd", "public-ca-fd", "regional-ca-fd", "config-fd", "result-fd"} {
		if _, ok := values[name]; !ok {
			return values, errors.New("missing constrained fd")
		}
	}
	return values, nil
}

func rawFlagName(arg string) string {
	if strings.HasPrefix(arg, "--") && len(arg) > 2 {
		name := strings.TrimPrefix(arg, "--")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		return name
	}
	if strings.HasPrefix(arg, "-") {
		return strings.TrimPrefix(arg, "-")
	}
	return ""
}

func rawConstrainedFDFlag(name string) bool {
	switch name {
	case "constrained-plan-fd", "credentials-fd", "public-ca-fd", "regional-ca-fd", "config-fd", "result-fd":
		return true
	default:
		return false
	}
}

func constrainedContextFromValues(values map[string]int) *cli.Context {
	set := flag.NewFlagSet("constrained", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	flags := []cli.Flag{
		&cli.IntFlag{Name: "constrained-plan-fd"},
		&cli.IntFlag{Name: "credentials-fd"},
		&cli.IntFlag{Name: "public-ca-fd"},
		&cli.IntFlag{Name: "regional-ca-fd"},
		&cli.IntFlag{Name: "config-fd"},
		&cli.IntFlag{Name: "result-fd"},
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
	}
	for _, cliFlag := range flags {
		_ = cliFlag.Apply(set)
	}
	for name, value := range values {
		_ = set.Set(name, strconv.Itoa(value))
	}
	return cli.NewContext(nil, set, nil)
}

func constrainedAction(c *cli.Context) error {
	files, err := openConstrainedFiles(c)
	if err != nil {
		return writeInvalidInvocationFailureFD(c.Int("result-fd"))
	}
	defer files.close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	run := constrainedRunner{ctx: ctx, files: files, deadline: time.Now().Add(60 * time.Second)}

	if failure := run.execute(c); !failure.empty() {
		return run.writeFailure(failure)
	}
	return nil
}

type constrainedRunner struct {
	ctx      context.Context
	files    constrainedFiles
	deadline time.Time
}

func (r constrainedRunner) execute(c *cli.Context) constrainedFailureReason {
	if err := validateConstrainedInvocation(c); err != nil {
		return constrainedFailureFor(classInvalidInvocation)
	}
	if !r.admit(45 * time.Second) {
		return constrainedFailureFor(r.contextClass())
	}

	planRaw, err := readLimitedFile(r.files.plan, maxConstrainedPlanSize, 5*time.Second)
	if err != nil {
		return constrainedFailureFor(classInvalidPlan)
	}
	plan, err := parseConstrainedPlan(planRaw)
	if err != nil {
		return constrainedFailureFor(classInvalidPlan)
	}

	credentialRaw, err := readLimitedFile(r.files.credentials, maxConstrainedCredentialSize, 5*time.Second)
	if err != nil {
		return constrainedFailureFor(classInvalidCredentials)
	}
	creds, err := parseConstrainedCredentials(credentialRaw)
	if err != nil || !validConstrainedCredential(creds.username) || !validConstrainedCredential(creds.password) {
		return constrainedFailureFor(classInvalidCredentials)
	}

	publicCARaw, err := readLimitedFile(r.files.publicCA, maxConstrainedCABundleSize, 5*time.Second)
	if err != nil {
		return constrainedFailureWithDetail(classInvalidTrust, "public_ca_bundle")
	}
	publicPool, err := parseConstrainedCABundle(publicCARaw)
	if err != nil {
		return constrainedFailureWithDetail(classInvalidTrust, "public_ca_bundle")
	}
	regionalCARaw, err := readLimitedFile(r.files.regionalCA, maxConstrainedCABundleSize, 5*time.Second)
	if err != nil {
		return constrainedFailureWithDetail(classInvalidTrust, "regional_ca_bundle")
	}
	regionalPool, err := parseConstrainedCABundle(regionalCARaw)
	if err != nil {
		return constrainedFailureWithDetail(classInvalidTrust, "regional_ca_bundle")
	}

	if !r.admit(45 * time.Second) {
		return constrainedFailureFor(r.contextClass())
	}
	token, tokenFailure := constrainedTokenRequest(r.ctx, plan.TokenDestinationIPv4, creds, publicPool)
	if !tokenFailure.empty() {
		return tokenFailure
	}

	if !r.admit(30 * time.Second) {
		return constrainedFailureFor(r.contextClass())
	}
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return constrainedFailureFor(classInternalFailure)
	}
	publicKey := privateKey.PublicKey().String()
	addKey, failure := constrainedAddKeyRequest(r.ctx, plan.RegistrationCandidate, token, publicKey, regionalPool)
	if !failure.empty() {
		return failure
	}
	if failure := validateConstrainedAddKey(plan, addKey, publicKey); !failure.empty() {
		return failure
	}
	if plan.ExcludedWireguardEndpointSet &&
		plan.ExcludedWireguardEndpoint.IPv4 == addKey.ServerIP &&
		plan.ExcludedWireguardEndpoint.UDPPort == addKey.ServerPort {
		return constrainedFailureFor(classEndpointReused)
	}

	if !r.admit(15 * time.Second) {
		return constrainedFailureFor(r.contextClass())
	}
	config, err := renderConstrainedConfig(privateKey.String(), addKey)
	if err != nil || len(config) > maxConstrainedConfigSize {
		return constrainedFailureFor(classInternalFailure)
	}
	if err := writeLimitedFile(r.files.configWriter, []byte(config), maxConstrainedConfigSize, 5*time.Second); err != nil {
		return constrainedFailureFor(classConfigWriteFailed)
	}

	if !r.admit(10 * time.Second) {
		return constrainedFailureFor(r.contextClass())
	}
	success := constrainedSuccess{
		Schema:                   constrainedSchema,
		Status:                   "success",
		Region:                   plan.Region,
		PortForwardEnabled:       plan.PortForwarding,
		SelectedRegistrationCN:   plan.RegistrationCandidate.TLSCommonName,
		SelectedRegistrationIPv4: plan.RegistrationCandidate.IPv4,
		WireguardEndpointIPv4:    addKey.ServerIP,
		WireguardEndpointUDPPort: addKey.ServerPort,
	}
	if plan.PortForwarding {
		success.PortForwardGatewayIPv4 = addKey.ServerVIP
	}
	result, err := json.Marshal(success)
	if err != nil || len(result) > maxConstrainedResultSize {
		return constrainedFailureFor(classInternalFailure)
	}
	if err := writeLimitedFile(r.files.resultWriter, append(result, '\n'), maxConstrainedResultSize, 5*time.Second); err != nil {
		return constrainedFailureFor(classResultWriteFailed)
	}
	return constrainedFailureReason{}
}

func (r constrainedRunner) writeFailure(failure constrainedFailureReason) error {
	result, err := json.Marshal(constrainedFailure{
		Schema:        constrainedSchema,
		Status:        "failure",
		FailureClass:  string(failure.class),
		FailureDetail: failure.detail,
	})
	if err != nil {
		return constrainedExit(classInternalFailure)
	}
	if r.files.resultWriter == nil {
		return constrainedExit(failure.class)
	}
	if err := writeLimitedFile(r.files.resultWriter, append(result, '\n'), maxConstrainedResultSize, 5*time.Second); err != nil {
		return constrainedExit(classResultWriteFailed)
	}
	return constrainedExit(failure.class)
}

func (r constrainedRunner) admit(remaining time.Duration) bool {
	return time.Until(r.deadline) >= remaining && r.ctx.Err() == nil
}

func (r constrainedRunner) contextClass() constrainedClass {
	if errors.Is(r.ctx.Err(), context.Canceled) {
		return classCancelled
	}
	return classDeadlineExceeded
}

func constrainedExit(class constrainedClass) error {
	return cli.Exit(string(class), 1)
}

func openConstrainedFiles(c *cli.Context) (constrainedFiles, error) {
	type fdSpec struct {
		name string
		mode constrainedFDMode
	}
	specs := []fdSpec{
		{"constrained-plan-fd", constrainedFDRead},
		{"credentials-fd", constrainedFDRead},
		{"public-ca-fd", constrainedFDRead},
		{"regional-ca-fd", constrainedFDRead},
		{"config-fd", constrainedFDWrite},
		{"result-fd", constrainedFDWrite},
	}
	files := constrainedFiles{}
	seen := map[int]bool{}
	for _, spec := range specs {
		if !c.IsSet(spec.name) {
			return constrainedFiles{}, fmt.Errorf("missing %s", spec.name)
		}
		fd := c.Int(spec.name)
		if fd < 3 || seen[fd] {
			return constrainedFiles{}, fmt.Errorf("invalid %s", spec.name)
		}
		seen[fd] = true
		file := os.NewFile(uintptr(fd), spec.name)
		if file == nil {
			return constrainedFiles{}, fmt.Errorf("invalid %s", spec.name)
		}
		files.closeOnReturn = append(files.closeOnReturn, file)
		if err := validateConstrainedDescriptor(file, spec.mode); err != nil {
			files.close()
			return constrainedFiles{}, fmt.Errorf("invalid %s", spec.name)
		}
		switch spec.name {
		case "constrained-plan-fd":
			files.plan = file
		case "credentials-fd":
			files.credentials = file
		case "public-ca-fd":
			files.publicCA = file
		case "regional-ca-fd":
			files.regionalCA = file
		case "config-fd":
			files.configWriter = file
		case "result-fd":
			files.resultWriter = file
		}
	}
	return files, nil
}

func (f constrainedFiles) close() {
	for _, file := range f.closeOnReturn {
		_ = file.Close()
	}
}

func validateConstrainedInvocation(c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("positional arguments are incompatible with constrained mode")
	}
	for _, name := range []string{
		"outfile", "region", "verbose", "server", "port-forwarding", "json",
		"metadata-file", "serverlist-cache", "serverlist-cache-ttl",
		"serverlist-cache-max-age", "serverlist-force-refresh",
		"serverlist-fetch-retries", "list-regions",
	} {
		if c.IsSet(name) {
			return fmt.Errorf("%s is incompatible with constrained mode", name)
		}
	}
	return rejectDuplicateLongFlags(os.Args[1:])
}

func rejectDuplicateLongFlags(args []string) error {
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			continue
		}
		name := strings.TrimPrefix(arg, "--")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if seen[name] {
			return fmt.Errorf("duplicate flag %s", name)
		}
		seen[name] = true
	}
	return nil
}

func readLimitedFile(file *os.File, limit int64, timeout time.Duration) ([]byte, error) {
	if err := file.SetReadDeadline(time.Now().Add(timeout)); err == nil {
		defer file.SetReadDeadline(time.Time{})
		return readLimitedFileBody(file, limit)
	} else if !unsupportedDeadline(err) {
		return nil, err
	}
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := readLimitedFileBody(file, limit)
		done <- result{body: body, err: err}
	}()
	select {
	case result := <-done:
		return result.body, result.err
	case <-time.After(timeout):
		_ = file.Close()
		return nil, os.ErrDeadlineExceeded
	}
}

func readLimitedFileBody(file *os.File, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("input exceeds limit")
	}
	return raw, nil
}

func writeLimitedFile(file *os.File, body []byte, limit int, timeout time.Duration) error {
	if len(body) > limit {
		return errors.New("output exceeds limit")
	}
	if err := file.SetWriteDeadline(time.Now().Add(timeout)); err == nil {
		defer file.SetWriteDeadline(time.Time{})
		return writeLimitedFileBody(file, body)
	} else if !unsupportedDeadline(err) {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- writeLimitedFileBody(file, body)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = file.Close()
		return os.ErrDeadlineExceeded
	}
}

func writeLimitedFileBody(file *os.File, body []byte) error {
	n, err := file.Write(body)
	if err != nil {
		return err
	}
	if n != len(body) {
		return io.ErrShortWrite
	}
	return nil
}

func setConstrainedReadDeadline(file *os.File, deadline time.Time) error {
	err := file.SetReadDeadline(deadline)
	if unsupportedDeadline(err) {
		return nil
	}
	return err
}

func setConstrainedWriteDeadline(file *os.File, deadline time.Time) error {
	err := file.SetWriteDeadline(deadline)
	if unsupportedDeadline(err) {
		return nil
	}
	return err
}

func unsupportedDeadline(err error) bool {
	return errors.Is(err, os.ErrNoDeadline) || (err != nil && strings.Contains(err.Error(), "file type does not support deadline"))
}

func writeInvalidInvocationFailureFD(fd int) error {
	if fd < 3 {
		return constrainedExit(classInvalidInvocation)
	}
	file := os.NewFile(uintptr(fd), "result-fd")
	if file == nil {
		return constrainedExit(classInvalidInvocation)
	}
	defer file.Close()
	if err := validateConstrainedDescriptor(file, constrainedFDWrite); err != nil {
		return constrainedExit(classInvalidInvocation)
	}
	result, err := json.Marshal(constrainedFailure{
		Schema:       constrainedSchema,
		Status:       "failure",
		FailureClass: string(classInvalidInvocation),
	})
	if err != nil {
		return constrainedExit(classInternalFailure)
	}
	if err := writeLimitedFile(file, append(result, '\n'), maxConstrainedResultSize, 5*time.Second); err != nil {
		return constrainedExit(classResultWriteFailed)
	}
	return constrainedExit(classInvalidInvocation)
}

func parseConstrainedPlan(raw []byte) (constrainedPlan, error) {
	fields, err := strictJSONObject(raw, map[string]bool{
		"schema": true, "region": true, "port_forwarding": true, "token_destination_ipv4": true,
		"registration_candidate": true, "excluded_wireguard_endpoint": true,
	})
	if err != nil {
		return constrainedPlan{}, err
	}
	required := []string{"schema", "region", "port_forwarding", "token_destination_ipv4", "registration_candidate"}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return constrainedPlan{}, errors.New("missing field")
		}
	}
	var plan constrainedPlan
	if err := decodeJSONString(fields["schema"], &plan.Schema); err != nil || plan.Schema != constrainedSchema {
		return constrainedPlan{}, errors.New("invalid schema")
	}
	if err := decodeJSONString(fields["region"], &plan.Region); err != nil || !validConstrainedRegion(plan.Region) {
		return constrainedPlan{}, errors.New("invalid region")
	}
	if err := json.Unmarshal(fields["port_forwarding"], &plan.PortForwarding); err != nil {
		return constrainedPlan{}, err
	}
	if err := decodeJSONString(fields["token_destination_ipv4"], &plan.TokenDestinationIPv4); err != nil || !validIPv4(plan.TokenDestinationIPv4) {
		return constrainedPlan{}, errors.New("invalid token destination")
	}
	candidate, err := parseConstrainedCandidate(fields["registration_candidate"])
	if err != nil {
		return constrainedPlan{}, err
	}
	plan.RegistrationCandidate = candidate
	if rawEndpoint, ok := fields["excluded_wireguard_endpoint"]; ok {
		endpoint, err := parseConstrainedEndpoint(rawEndpoint)
		if err != nil {
			return constrainedPlan{}, err
		}
		plan.ExcludedWireguardEndpoint = &endpoint
		plan.ExcludedWireguardEndpointSet = true
	}
	return plan, nil
}

func parseConstrainedCandidate(raw []byte) (constrainedRegistrationCandidate, error) {
	fields, err := strictJSONObject(raw, map[string]bool{"ipv4": true, "tls_common_name": true})
	if err != nil {
		return constrainedRegistrationCandidate{}, err
	}
	if len(fields) != 2 {
		return constrainedRegistrationCandidate{}, errors.New("missing candidate field")
	}
	var candidate constrainedRegistrationCandidate
	if err := decodeJSONString(fields["ipv4"], &candidate.IPv4); err != nil || !validIPv4(candidate.IPv4) {
		return constrainedRegistrationCandidate{}, errors.New("invalid candidate ipv4")
	}
	if err := decodeJSONString(fields["tls_common_name"], &candidate.TLSCommonName); err != nil || !validTLSCommonName(candidate.TLSCommonName) {
		return constrainedRegistrationCandidate{}, errors.New("invalid candidate common name")
	}
	return candidate, nil
}

func parseConstrainedEndpoint(raw []byte) (constrainedEndpoint, error) {
	fields, err := strictJSONObject(raw, map[string]bool{"ipv4": true, "udp_port": true})
	if err != nil {
		return constrainedEndpoint{}, err
	}
	if len(fields) != 2 {
		return constrainedEndpoint{}, errors.New("missing endpoint field")
	}
	var endpoint constrainedEndpoint
	if err := decodeJSONString(fields["ipv4"], &endpoint.IPv4); err != nil || !validIPv4(endpoint.IPv4) {
		return constrainedEndpoint{}, errors.New("invalid endpoint ipv4")
	}
	if err := json.Unmarshal(fields["udp_port"], &endpoint.UDPPort); err != nil || endpoint.UDPPort < 1 || endpoint.UDPPort > 65535 {
		return constrainedEndpoint{}, errors.New("invalid endpoint port")
	}
	return endpoint, nil
}

func parseConstrainedCredentials(raw []byte) (credentials, error) {
	return parseCredentials(raw)
}

func strictJSONObject(raw []byte, allowed map[string]bool) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return nil, errors.New("invalid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("json object required")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] {
			return nil, errors.New("invalid field")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errors.New("duplicate field")
		}
		var rawValue json.RawMessage
		if err := decoder.Decode(&rawValue); err != nil {
			return nil, err
		}
		fields[key] = append([]byte(nil), rawValue...)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid object close")
	}
	if decoder.InputOffset() != int64(len(raw)) {
		return nil, errors.New("trailing data")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return fields, nil
}

func decodeJSONString(raw json.RawMessage, out *string) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	if !utf8.ValidString(*out) {
		return errors.New("invalid utf8 string")
	}
	return nil
}

func parseConstrainedCABundle(raw []byte) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > maxConstrainedCABundleSize {
		return nil, errors.New("invalid ca bundle")
	}
	pool := x509.NewCertPool()
	remaining := raw
	count := 0
	for len(remaining) > 0 {
		block, rest := pemDecode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) > maxConstrainedDERCertSize {
			return nil, errors.New("invalid certificate block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, errors.New("invalid ca certificate")
		}
		if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("invalid ca key usage")
		}
		pool.AddCert(cert)
		count++
		if count > 4 {
			return nil, errors.New("too many certificates")
		}
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("empty ca bundle")
	}
	return pool, nil
}

type pemBlock struct {
	Type  string
	Bytes []byte
}

func pemDecode(raw []byte) (*pemBlock, []byte) {
	const begin = "-----BEGIN CERTIFICATE-----\n"
	if !bytes.HasPrefix(raw, []byte(begin)) {
		return nil, nil
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, nil
	}
	return &pemBlock{Type: block.Type, Bytes: block.Bytes}, rest
}

func constrainedTokenRequest(ctx context.Context, destinationIPv4 string, creds credentials, roots *x509.CertPool) (string, constrainedFailureReason) {
	form := url.Values{"username": {creds.username}, "password": {creds.password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.privateinternetaccess.com/api/client/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", constrainedFailureFor(classInternalFailure)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := constrainedHTTPClient(destinationIPv4, 443, "www.privateinternetaccess.com", roots, 15*time.Second, false)
	resp, err := client.Do(req)
	if err != nil {
		if isConstrainedTrustError(err) {
			return "", constrainedFailureFor(classInvalidTrust)
		}
		return "", constrainedFailureFor(classifyNetworkError(ctx, classTokenFailed))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", constrainedFailureWithDetail(classTokenFailed, detailTokenHTTPStatus)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxConstrainedTokenBodySize+1))
	if err != nil {
		return "", constrainedFailureWithDetail(classResponseInvalid, detailTokenBodyReadFailed)
	}
	if len(raw) > maxConstrainedTokenBodySize {
		return "", constrainedFailureWithDetail(classResponseInvalid, detailTokenBodyTooLarge)
	}
	fields, err := strictJSONObject(raw, map[string]bool{"token": true})
	if err != nil {
		return "", constrainedFailureWithDetail(classResponseInvalid, detailTokenJSONParseFailed)
	}
	if len(fields) != 1 {
		return "", constrainedFailureWithDetail(classResponseInvalid, detailTokenMissingField)
	}
	var token string
	if err := decodeJSONString(fields["token"], &token); err != nil || !validVisibleASCII(token, maxConstrainedTokenSize) {
		return "", constrainedFailureWithDetail(classResponseInvalid, detailTokenInvalidToken)
	}
	return token, constrainedFailureReason{}
}

func constrainedAddKeyRequest(ctx context.Context, candidate constrainedRegistrationCandidate, token string, publicKey string, roots *x509.CertPool) (constrainedAddKeyResult, constrainedFailureReason) {
	query := url.Values{"pt": {token}, "pubkey": {publicKey}}
	reqURL := "https://" + candidate.TLSCommonName + ":1337/addKey?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return constrainedAddKeyResult{}, constrainedFailureFor(classInternalFailure)
	}
	client := constrainedHTTPClient(candidate.IPv4, 1337, candidate.TLSCommonName, roots, 15*time.Second, true)
	resp, err := client.Do(req)
	if err != nil {
		if isConstrainedTrustError(err) {
			return constrainedAddKeyResult{}, constrainedFailureWithDetail(classInvalidTrust, constrainedTrustDetail(err))
		}
		return constrainedAddKeyResult{}, constrainedFailureFor(classifyNetworkError(ctx, classAddKeyFailed))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return constrainedAddKeyResult{}, constrainedFailureWithDetail(classAddKeyFailed, detailAddKeyHTTPStatus)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxConstrainedAddKeyBodySize+1))
	if err != nil {
		return constrainedAddKeyResult{}, constrainedFailureWithDetail(classResponseInvalid, detailAddKeyBodyReadFailed)
	}
	if len(raw) > maxConstrainedAddKeyBodySize {
		return constrainedAddKeyResult{}, constrainedFailureWithDetail(classResponseInvalid, detailAddKeyBodyTooLarge)
	}
	result, detail := parseConstrainedAddKeyDetailed(raw)
	if detail != "" {
		return constrainedAddKeyResult{}, constrainedFailureWithDetail(classResponseInvalid, detail)
	}
	return result, constrainedFailureReason{}
}

func constrainedHTTPClient(ip string, port int, serverName string, roots *x509.CertPool, timeout time.Duration, allowCommonNameIdentity bool) *http.Client {
	dialCount := 0
	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
			// The PIA registration endpoint uses server-list registration names that
			// may be CN-only identities rather than DNS SANs. We still verify the
			// certificate chain and exact intended registration identity below.
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
			VerifyConnection: func(state tls.ConnectionState) error {
				return verifyConstrainedTLSConnection(state, serverName, roots, allowCommonNameIdentity)
			},
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" {
				return nil, errors.New("invalid network")
			}
			if dialCount > 0 {
				return nil, errors.New("retry denied")
			}
			dialCount++
			dialer := net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, strconv.Itoa(port)))
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type constrainedTrustError struct {
	detail string
	err    error
}

func (e constrainedTrustError) Error() string {
	return e.err.Error()
}

func (e constrainedTrustError) Unwrap() error {
	return e.err
}

func verifyConstrainedTLSConnection(state tls.ConnectionState, serverName string, roots *x509.CertPool, allowCommonNameIdentity bool) error {
	if roots == nil {
		return constrainedTrustError{detail: "missing_ca_bundle", err: errors.New("trusted CA bundle is missing")}
	}
	if len(state.PeerCertificates) == 0 {
		return constrainedTrustError{detail: "missing_certificate", err: errors.New("server certificate is missing")}
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   time.Now(),
	}
	if _, err := leaf.Verify(opts); err != nil {
		return constrainedTrustError{detail: "ca_chain", err: err}
	}
	if err := leaf.VerifyHostname(serverName); err == nil {
		return nil
	}
	if allowCommonNameIdentity && len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 && validTLSCommonName(serverName) && leaf.Subject.CommonName == serverName {
		return nil
	}
	return constrainedTrustError{detail: "endpoint_identity", err: errors.New("server certificate identity does not match registration name")}
}

func isConstrainedTrustError(err error) bool {
	var trustErr constrainedTrustError
	return errors.As(err, &trustErr)
}

func constrainedTrustDetail(err error) string {
	var trustErr constrainedTrustError
	if errors.As(err, &trustErr) {
		return trustErr.detail
	}
	return "trust_validation"
}

func validConstrainedFailureDetail(value string) string {
	if value == "" || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return ""
	}
	return value
}

func classifyNetworkError(ctx context.Context, fallback constrainedClass) constrainedClass {
	if errors.Is(ctx.Err(), context.Canceled) {
		return classCancelled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return classDeadlineExceeded
	}
	return fallback
}

func parseConstrainedAddKey(raw []byte) (constrainedAddKeyResult, error) {
	result, detail := parseConstrainedAddKeyDetailed(raw)
	if detail != "" {
		return constrainedAddKeyResult{}, errors.New("invalid add key response")
	}
	return result, nil
}

func parseConstrainedAddKeyDetailed(raw []byte) (constrainedAddKeyResult, string) {
	fields, err := strictJSONObject(raw, map[string]bool{
		"status": true, "server_key": true, "server_port": true, "server_ip": true,
		"server_vip": true, "peer_ip": true, "peer_pubkey": true, "dns_servers": true,
	})
	if err != nil || len(fields) != 8 {
		if err != nil {
			return constrainedAddKeyResult{}, detailAddKeyJSONParseFailed
		}
		return constrainedAddKeyResult{}, detailAddKeyMissingField
	}
	var result constrainedAddKeyResult
	for name, target := range map[string]*string{
		"status": &result.Status, "server_key": &result.ServerKey, "server_ip": &result.ServerIP,
		"server_vip": &result.ServerVIP, "peer_ip": &result.PeerIP, "peer_pubkey": &result.PeerPubKey,
	} {
		if err := decodeJSONString(fields[name], target); err != nil {
			return constrainedAddKeyResult{}, detailAddKeyJSONParseFailed
		}
	}
	if err := json.Unmarshal(fields["server_port"], &result.ServerPort); err != nil {
		return constrainedAddKeyResult{}, detailAddKeyJSONParseFailed
	}
	if err := json.Unmarshal(fields["dns_servers"], &result.DNSServers); err != nil {
		return constrainedAddKeyResult{}, detailAddKeyJSONParseFailed
	}
	return result, ""
}

func validateConstrainedAddKey(plan constrainedPlan, result constrainedAddKeyResult, publicKey string) constrainedFailureReason {
	if result.Status != "OK" {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidStatus)
	}
	if _, err := wgtypes.ParseKey(result.ServerKey); err != nil {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidServerKey)
	}
	if result.ServerPort < 1 || result.ServerPort > 65535 {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidServerPort)
	}
	if !validIPv4(result.ServerIP) {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidServerIP)
	}
	if !validConstrainedPeerIP(result.PeerIP) {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidPeerIP)
	}
	if _, err := wgtypes.ParseKey(result.PeerPubKey); err != nil || result.PeerPubKey != publicKey {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidPeerPubKey)
	}
	if len(result.DNSServers) < 1 || len(result.DNSServers) > 8 {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidDNS)
	}
	for _, dns := range result.DNSServers {
		if !validIPv4(dns) {
			return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidDNS)
		}
	}
	if plan.PortForwarding {
		if !validIPv4(result.ServerVIP) {
			return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidServerVIP)
		}
	} else if result.ServerVIP != "" {
		return constrainedFailureWithDetail(classResponseInvalid, detailAddKeyInvalidServerVIP)
	}
	return constrainedFailureReason{}
}

func validConstrainedPeerIP(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.To4() != nil
	}
	ip, _, err := net.ParseCIDR(value)
	return err == nil && ip.To4() != nil
}

func constrainedPeerAddress(value string) string {
	if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
		return ip.String() + "/32"
	}
	return value
}

func renderConstrainedConfig(privateKey string, result constrainedAddKeyResult) (string, error) {
	tmpl, err := template.New("constrained-config").Parse(constrainedWireguardConfigTemplate)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, struct {
		PrivateKey string
		Address    string
		DNS        string
		PublicKey  string
		Endpoint   string
	}{
		PrivateKey: privateKey,
		Address:    constrainedPeerAddress(result.PeerIP),
		DNS:        result.DNSServers[0],
		PublicKey:  result.ServerKey,
		Endpoint:   net.JoinHostPort(result.ServerIP, strconv.Itoa(result.ServerPort)),
	})
	return out.String(), err
}

const constrainedWireguardConfigTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
DNS = {{.DNS}}
[Peer]
PublicKey = {{.PublicKey}}
AllowedIPs = 0.0.0.0/0
Endpoint = {{.Endpoint}}
PersistentKeepalive = 25
`

func validConstrainedCredential(value string) bool {
	if value == "" || len(value) > maxConstrainedCredentialBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func validConstrainedRegion(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validTLSCommonName(value string) bool {
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil {
		return false
	}
	for _, r := range value {
		if r > 127 || r <= 32 || strings.ContainsRune("/: @", r) {
			return false
		}
	}
	return true
}

func validDNSName(value string) bool {
	if strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validIPv4(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil && ip.String() == value
}

func validVisibleASCII(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}
