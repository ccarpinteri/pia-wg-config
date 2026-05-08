package pia

import "fmt"

// Metadata is the machine-readable output contract for a completed config generation run.
// Keys are stable — do not rename without a version bump.
type Metadata struct {
	Region             string `json:"region"`
	PortForwardEnabled bool   `json:"port_forward_enabled"`
	WireguardConfig    string `json:"wireguard_config,omitempty"`
	EndpointHost       string `json:"endpoint_host"`
	EndpointPort       int    `json:"endpoint_port"`
	PortForwardGateway string `json:"port_forward_gateway,omitempty"`
}

// buildMetadata constructs a Metadata value from an AddKey API response.
// portForwardGateway is only set when server_vip is non-empty.
// Returns an error if portForwarding is true but server_vip is missing.
func buildMetadata(region string, portForwarding bool, key AddKeyResult) (Metadata, error) {
	m := Metadata{
		Region:             region,
		PortForwardEnabled: portForwarding,
		EndpointHost:       key.ServerIP,
		EndpointPort:       key.ServerPort,
	}

	if key.ServerVip != "" {
		m.PortForwardGateway = fmt.Sprintf("https://%s:19999", key.ServerVip)
	} else if portForwarding {
		return Metadata{}, fmt.Errorf("port forwarding requested but server_vip was empty in PIA response")
	}

	return m, nil
}
