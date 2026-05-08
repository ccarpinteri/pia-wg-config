package pia

import (
	"encoding/json"
	"strings"
	"testing"
)

// PIAClientMock is the baseline mock — no port forwarding, no server_vip.
type PIAClientMock struct{}

func (p *PIAClientMock) getMetadataServerForRegion() Server {
	return Server{
		Cn: "mock-server",
		IP: "0.0.0.0",
	}
}

func (p *PIAClientMock) GetToken() (string, error) {
	return "", nil
}

func (p *PIAClientMock) AddKey(token, publickey string) (AddKeyResult, error) {
	return AddKeyResult{
		ServerIP:   "1.2.3.4",
		ServerPort: 1337,
		DNSServers: []string{"1.1.1.1"},
		PeerIP:     "4.5.6.7",
		ServerKey:  publickey,
	}, nil
}

// PIAClientMockPF returns a server_vip to simulate a port-forwarding-capable server.
type PIAClientMockPF struct{}

func (p *PIAClientMockPF) getMetadataServerForRegion() Server {
	return Server{Cn: "mock-pf-server", IP: "0.0.0.0"}
}

func (p *PIAClientMockPF) GetToken() (string, error) {
	return "", nil
}

func (p *PIAClientMockPF) AddKey(token, publickey string) (AddKeyResult, error) {
	return AddKeyResult{
		ServerIP:   "146.70.1.2",
		ServerPort: 1337,
		ServerVip:  "10.4.128.1",
		DNSServers: []string{"1.1.1.1"},
		PeerIP:     "10.0.0.2",
		ServerKey:  publickey,
	}, nil
}

// --- existing config generation tests ---

func TestPIAWgGenerator_Generate(t *testing.T) {
	tests := []struct {
		name   string
		config PIAWgGeneratorConfig
		want   string
	}{
		{
			name: "basic generate",
			config: PIAWgGeneratorConfig{
				Verbose:    false,
				ServerName: false,
				PrivateKey: "test_privatekey",
				PublicKey:  "test_publickey",
			},
			want: `[Interface]
PrivateKey = test_privatekey
Address = 4.5.6.7
DNS = 1.1.1.1
[Peer]
PublicKey = test_publickey
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:1337
PersistentKeepalive = 25`,
		},
		{
			name: "generate with serverCommonName",
			config: PIAWgGeneratorConfig{
				Verbose:    false,
				ServerName: true,
				PrivateKey: "test_privatekey",
				PublicKey:  "test_publickey",
			},
			want: `[Interface]
PrivateKey = test_privatekey
Address = 4.5.6.7
DNS = 1.1.1.1
[Peer]
PublicKey = test_publickey
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:1337
PersistentKeepalive = 25
ServerCommonName = mock-server`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPIAWgGenerator(&PIAClientMock{}, tt.config)
			got, _, err := p.Generate()
			if err != nil {
				t.Fatalf("Generate() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Generate() config\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestPIAWgGenerator_generateKeys(t *testing.T) {
	p := &PIAWgGenerator{pia: &PIAClientMock{}}
	priv, pub, err := p.generateKeys()
	if err != nil {
		t.Fatalf("generateKeys() error = %v", err)
	}
	if priv == "" || pub == "" {
		t.Error("generateKeys() returned empty key(s)")
	}
}

// --- metadata tests ---

func TestGenerate_ReturnsMetadata(t *testing.T) {
	gen := NewPIAWgGenerator(&PIAClientMock{}, PIAWgGeneratorConfig{
		PrivateKey: "priv",
		PublicKey:  "pub",
		Region:     "ca_toronto",
	})
	_, m, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if m.Region != "ca_toronto" {
		t.Errorf("Region = %q, want %q", m.Region, "ca_toronto")
	}
	if m.PortForwardEnabled {
		t.Error("PortForwardEnabled should be false")
	}
	if m.EndpointHost != "1.2.3.4" {
		t.Errorf("EndpointHost = %q, want 1.2.3.4", m.EndpointHost)
	}
	if m.EndpointPort != 1337 {
		t.Errorf("EndpointPort = %d, want 1337", m.EndpointPort)
	}
	if m.PortForwardGateway != "" {
		t.Errorf("PortForwardGateway should be empty, got %q", m.PortForwardGateway)
	}
}

func TestGenerate_PFGateway_WithServerVip(t *testing.T) {
	gen := NewPIAWgGenerator(&PIAClientMockPF{}, PIAWgGeneratorConfig{
		PrivateKey:     "priv",
		PublicKey:      "pub",
		Region:         "aus_perth",
		PortForwarding: true,
	})
	_, m, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	want := "https://10.4.128.1:19999"
	if m.PortForwardGateway != want {
		t.Errorf("PortForwardGateway = %q, want %q", m.PortForwardGateway, want)
	}
	if !m.PortForwardEnabled {
		t.Error("PortForwardEnabled should be true")
	}
}

func TestGenerate_PFGateway_ErrorWhenVipMissing(t *testing.T) {
	// port_forwarding=true but baseline mock returns no server_vip — must error.
	gen := NewPIAWgGenerator(&PIAClientMock{}, PIAWgGeneratorConfig{
		PrivateKey:     "priv",
		PublicKey:      "pub",
		Region:         "ca_toronto",
		PortForwarding: true,
	})
	_, _, err := gen.Generate()
	if err == nil {
		t.Error("expected error when port_forwarding=true and server_vip is empty")
	}
}

func TestMetadata_NoSecrets(t *testing.T) {
	const secret = "SUPERSECRETPRIVATEKEY"
	gen := NewPIAWgGenerator(&PIAClientMockPF{}, PIAWgGeneratorConfig{
		PrivateKey:     secret,
		PublicKey:      "pub",
		Region:         "aus_perth",
		PortForwarding: true,
	})
	_, m, err := gen.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Errorf("metadata JSON contains private key material: %s", raw)
	}
}

func TestBuildMetadata_JSONKeys(t *testing.T) {
	m, err := buildMetadata("ireland", true, AddKeyResult{
		ServerIP:   "146.70.1.1",
		ServerPort: 1337,
		ServerVip:  "10.4.128.2",
	})
	if err != nil {
		t.Fatalf("buildMetadata error = %v", err)
	}

	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	jsonStr := string(raw)

	expectedKeys := []string{
		`"region"`,
		`"port_forward_enabled"`,
		`"endpoint_host"`,
		`"endpoint_port"`,
		`"port_forward_gateway"`,
	}
	for _, key := range expectedKeys {
		if !strings.Contains(jsonStr, key) {
			t.Errorf("JSON output missing key %s: %s", key, jsonStr)
		}
	}
}
