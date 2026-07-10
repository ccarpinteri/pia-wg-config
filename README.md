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
| `--json` | `-j` | `false` | Print machine-readable metadata as JSON to stdout after a successful run |
| `--metadata-file` | | | Write machine-readable metadata as JSON to this file |
| `--list-regions` | | `false` | List all available PIA regions and exit (no credentials required) |
| `--credentials-fd` | | | Read credentials from an inherited file descriptor |
| `--constrained-plan-fd` | | | Read an experimental constrained generation plan from an inherited file descriptor |
| `--public-ca-fd` | | | Read the constrained token API CA bundle from an inherited file descriptor |
| `--regional-ca-fd` | | | Read the constrained regional API CA bundle from an inherited file descriptor |
| `--config-fd` | | | Write constrained WireGuard config output to an inherited file descriptor |
| `--result-fd` | | | Write constrained result JSON to an inherited file descriptor |
| `--serverlist-cache` | | | Path to server-list cache file |
| `--serverlist-cache-ttl` | | `24h` | Max age to use cache without refresh |
| `--serverlist-cache-max-age` | | `168h` | Max age before cache is treated as invalid |
| `--serverlist-force-refresh` | | `false` | Force fresh server-list fetch even if cache is fresh |
| `--serverlist-fetch-retries` | | `5` | Max server-list fetch attempts |

### Credential input

Positional `USERNAME PASSWORD` credentials remain supported for compatibility,
but they may be visible to process-inspection tooling and should be treated as
legacy.

For reviewed automation, `--credentials-fd <number>` accepts exactly one JSON
object from an inherited descriptor:

```json
{"username":"USERNAME","password":"PASSWORD"}
```

FD mode and positional credentials are mutually exclusive. FD mode does not
fall back to positional or environment credentials. The caller owns descriptor
provenance, writer closure, invocation timeout, cancellation, and child
reaping.

### Experimental constrained mode

The `--constrained-plan-fd`, `--public-ca-fd`, `--regional-ca-fd`,
`--config-fd`, and `--result-fd` flags are for reviewed automation that
launches `pia-wg-config` with inherited Linux pipe descriptors. This mode is
PIA-only and does not use the ordinary region lookup, server-list cache,
metadata, stdout config output, positional credentials, or system certificate
trust path.

Constrained mode requires all of these descriptors plus `--credentials-fd`. It
rejects positional arguments, ordinary generation flags, unknown flags, and
duplicate flags. Results are written as bounded JSON to `--result-fd`; on
failure the result contains `schema`, `status`, `failure_class`, and sometimes
a bounded non-secret `failure_detail` for coarse diagnostics such as CA bundle,
certificate chain, or endpoint identity failures.

This mode is intentionally not the general CLI interface. It exists for a
separately reviewed launcher that supplies the plan, credentials, CA bundles,
output pipe, and lifecycle controls.

## Regions

Use `--list-regions` to discover available region IDs without credentials:

```bash
# List all regions
pia-wg-config --list-regions

# Filter to a specific country
pia-wg-config --list-regions | grep "country=AU"

# List only port-forwarding capable regions, as JSON
pia-wg-config --list-regions -p --json
```

Pass any region ID as the `-r` value, e.g. `ireland`, `de-frankfurt`, `us_chicago`. Not all regions support port forwarding — if `-p` is set and the region has no port-forwarding servers, the tool exits with a clear error.

## Metadata Output

After a successful config generation, `--json` and `--metadata-file` expose machine-readable metadata:

```bash
pia-wg-config -r ireland -s -p -o wg0.conf --json USERNAME PASSWORD
```

```json
{
  "region": "ireland",
  "port_forward_enabled": true,
  "wireguard_config": "wg0.conf",
  "endpoint_host": "1.2.3.4",
  "endpoint_port": 1337,
  "port_forward_gateway": "https://10.x.x.x:19999"
}
```

`--metadata-file` writes the same JSON to a file instead of (or in addition to) stdout.

## Gluetun

This tool is designed for use with [Gluetun](https://github.com/qdm12/gluetun). Use `-s` to include the server common name in the config, which Gluetun requires in `SERVER_NAMES` when using port forwarding with `VPN_SERVICE_PROVIDER=custom`.

See [pia-wg-refresh](https://github.com/ccarpinteri/pia-wg-refresh) for a Docker container that automatically refreshes PIA WireGuard configs for Gluetun.

## Background

Based on the [manual-connections](https://github.com/pia-foss/manual-connections) scripts provided by Private Internet Access.

Go was chosen for stability and portability. `pia-wg-config` is self-contained and does not require any external files.
