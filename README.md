# pia-wg-config

A WireGuard config generator for Private Internet Access (PIA).

This is a fork of [kylegrantlucas/pia-wg-config](https://github.com/kylegrantlucas/pia-wg-config) via [Ephemeral-Dust/pia-wg-config](https://github.com/Ephemeral-Dust/pia-wg-config), maintained at [ccarpinteri/pia-wg-config](https://github.com/ccarpinteri/pia-wg-config).

## Usage

### Docker (recommended)

```bash
docker run --rm \
  -v /path/to/output:/output \
  ghcr.io/ccarpinteri/pia-wg-config:latest \
  -r ca_toronto -s -p -o /output/wg0.conf USERNAME PASSWORD
```

### Go install

```bash
go install github.com/ccarpinteri/pia-wg-config@latest
pia-wg-config -r ca_toronto -s -p -o wg0.conf USERNAME PASSWORD
```

You can now use `wg0.conf` to connect using your favorite WireGuard client.

## Flags

| Flag | Alias | Default | Description |
| ------ | ------- | --------- | ------------- |
| `--outfile` | `-o` | stdout | File to write the WireGuard config to |
| `--region` | `-r` | `ca_toronto` | PIA region to connect to |
| `--verbose` | `-v` | `false` | Print verbose output |
| `--server` | `-s` | `false` | Add server common name to the config (required for Gluetun port forwarding) |
| `--port-forwarding` | `-p` | `false` | Only use servers that support port forwarding |

## Gluetun

This tool is designed for use with [Gluetun](https://github.com/qdm12/gluetun). Use `-s` to include the server common name in the config, which Gluetun requires in `SERVER_NAMES` when using port forwarding with `VPN_SERVICE_PROVIDER=custom`.

See [pia-wg-refresh](https://github.com/ccarpinteri/pia-wg-refresh) for a Docker container that automatically refreshes PIA WireGuard configs for Gluetun.

## Background

Based on the [manual-connections](https://github.com/pia-foss/manual-connections) scripts provided by Private Internet Access.

Go was chosen for stability and portability. `pia-wg-config` is self-contained and does not require any external files.

## Regions

Pass any PIA region ID as the `-r` value, e.g. `ireland`, `de-frankfurt`, `us_chicago`. Not all regions support port forwarding — if `-p` is set and the region has no port-forwarding servers, the tool exits with a clear error.
