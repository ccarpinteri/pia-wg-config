package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestConstrainedHTTPClientDialsSuppliedIPv4WithoutDNSProxyOrHTTP2(t *testing.T) {
	cert, pool := testServerCertificate(t, "example.privateinternetaccess.com")
	var sawRequest atomic.Bool
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRequest.Store(true)
		if r.Proto != "HTTP/1.1" {
			t.Errorf("request proto = %s, want HTTP/1.1", r.Proto)
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))

	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "example.privateinternetaccess.com", pool, 5*time.Second, false)
	resp, err := client.Get("https://definitely.invalid.example/")
	if err != nil {
		t.Fatalf("client.Get returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !sawRequest.Load() {
		t.Fatal("server did not receive request")
	}
	if got := server.AcceptCount(); got != 1 {
		t.Fatalf("accepted connections = %d, want 1", got)
	}
}

func TestConstrainedHTTPClientAcceptsRealPIARegistrationCommonName(t *testing.T) {
	cert, pool := testServerCertificateWithoutDNSName(t, "Server-11736-3a")
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "Server-11736-3a", pool, 5*time.Second, true)
	resp, err := client.Get("https://Server-11736-3a/")
	if err != nil {
		t.Fatalf("client.Get returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestConstrainedHTTPClientRejectsCommonNameFallbackWhenDisabled(t *testing.T) {
	cert, pool := testServerCertificateWithoutDNSName(t, "www.privateinternetaccess.com")
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach handler")
	}))

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "www.privateinternetaccess.com", pool, 5*time.Second, false)
	resp, err := client.Get("https://www.privateinternetaccess.com/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("client.Get returned nil error, want hostname verification failure")
	}
	if !isConstrainedTrustError(err) {
		t.Fatalf("error = %T %[1]v, want constrained trust error", err)
	}
}

func TestConstrainedHTTPClientRejectsWrongRegistrationCommonName(t *testing.T) {
	cert, pool := testServerCertificateWithoutDNSName(t, "Server-11519-4a")
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach handler")
	}))

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "Server-11736-3a", pool, 5*time.Second, true)
	resp, err := client.Get("https://Server-11736-3a/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("client.Get returned nil error, want registration identity failure")
	}
	if !isConstrainedTrustError(err) {
		t.Fatalf("error = %T %[1]v, want constrained trust error", err)
	}
	if detail := constrainedTrustDetail(err); detail != "endpoint_identity" {
		t.Fatalf("trust detail = %q, want endpoint_identity", detail)
	}
}

func TestConstrainedHTTPClientRejectsCommonNameFallbackWhenSANsArePresent(t *testing.T) {
	cert, pool := testServerCertificateWithOptions(t, "Server-11736-3a", true)
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach handler")
	}))

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "Server-11519-4a", pool, 5*time.Second, true)
	resp, err := client.Get("https://Server-11519-4a/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("client.Get returned nil error, want SAN identity failure")
	}
	if !isConstrainedTrustError(err) {
		t.Fatalf("error = %T %[1]v, want constrained trust error", err)
	}
	if detail := constrainedTrustDetail(err); detail != "endpoint_identity" {
		t.Fatalf("trust detail = %q, want endpoint_identity", detail)
	}
}

func TestConstrainedHTTPClientRejectsUntrustedRegistrationCA(t *testing.T) {
	cert, _ := testServerCertificateWithoutDNSName(t, "Server-11736-3a")
	_, pool := testServerCertificateWithoutDNSName(t, "Server-11736-3a")
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach handler")
	}))

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "Server-11736-3a", pool, 5*time.Second, true)
	resp, err := client.Get("https://Server-11736-3a/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("client.Get returned nil error, want untrusted CA failure")
	}
	if !isConstrainedTrustError(err) {
		t.Fatalf("error = %T %[1]v, want constrained trust error", err)
	}
	if detail := constrainedTrustDetail(err); detail != "ca_chain" {
		t.Fatalf("trust detail = %q, want ca_chain", detail)
	}
}

func TestConstrainedHTTPClientDoesNotRetryFailedDial(t *testing.T) {
	cert, pool := testServerCertificate(t, "example.privateinternetaccess.com")
	server := testTLSServer(t, cert, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not reach handler")
	}))
	server.CloseFirstConnection()

	host, rawPort, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	client := constrainedHTTPClient(host, port, "example.privateinternetaccess.com", pool, 5*time.Second, false)
	resp, err := client.Get("https://example.privateinternetaccess.com/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected request failure")
	}
	if got := server.AcceptCount(); got != 1 {
		t.Fatalf("accepted connections = %d, want 1", got)
	}
}

type countedTLSServer struct {
	listener   *countingListener
	httpServer *http.Server
}

func testTLSServer(t *testing.T, cert tls.Certificate, handler http.Handler) *countedTLSServer {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	counting := &countingListener{Listener: listener}
	tlsListener := tls.NewListener(counting, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	server := &http.Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(tlsListener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		<-done
	})
	return &countedTLSServer{listener: counting, httpServer: server}
}

func (s *countedTLSServer) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *countedTLSServer) AcceptCount() int64 {
	return s.listener.count.Load()
}

func (s *countedTLSServer) CloseFirstConnection() {
	s.listener.closeFirst.Store(true)
}

type countingListener struct {
	net.Listener
	count      atomic.Int64
	closeFirst atomic.Bool
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	count := l.count.Add(1)
	if count == 1 && l.closeFirst.Load() {
		_ = conn.Close()
	}
	return conn, nil
}

func testServerCertificate(t *testing.T, serverName string) (tls.Certificate, *x509.CertPool) {
	return testServerCertificateWithOptions(t, serverName, true)
}

func testServerCertificateWithoutDNSName(t *testing.T, commonName string) (tls.Certificate, *x509.CertPool) {
	return testServerCertificateWithOptions(t, commonName, false)
}

func testServerCertificateWithOptions(t *testing.T, serverName string, includeDNSName bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if includeDNSName {
		serverTemplate.DNSNames = []string{serverName}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{serverDER},
		PrivateKey:  serverKey,
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("failed to append CA cert")
	}
	return cert, pool
}
