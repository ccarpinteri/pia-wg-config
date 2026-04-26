# pia-wg-config - Project Context for Claude

## Working with Claude

- **Evidence only — no speculation.** Do not assert causes, states, or behaviors that are not directly supported by observed data (logs, command output, code). If something is unknown, say so explicitly.

## Project Overview

**pia-wg-config** is a Go CLI binary that generates WireGuard configs for Private Internet Access (PIA). It is a fork of [kylegrantlucas/pia-wg-config](https://github.com/kylegrantlucas/pia-wg-config) via [Ephemeral-Dust/pia-wg-config](https://github.com/Ephemeral-Dust/pia-wg-config), maintained at [ccarpinteri/pia-wg-config](https://github.com/ccarpinteri/pia-wg-config).

**Primary consumer**: [pia-wg-refresh](https://github.com/ccarpinteri/pia-wg-refresh) — bundles this binary to periodically regenerate WireGuard configs for Gluetun.

**Repository**: This repository

## Branching & Release Strategy

### Branches
- `main` - Stable, production-ready code
- `fix/*` - Bug fix branches (e.g., `fix/central-token-api`)
- `feature/*` - Feature branches

### Tags
- `v*` (e.g., `v1.0.6`) - Stable releases
  - Triggers Docker build with `:<version>` AND `:latest` tags
  - Creates GitHub Release
- `dev-*` (e.g., `dev-fix-token`) - Dev/test releases
  - Triggers Docker build with only `:<tag>` tag
  - No `:latest`, no GitHub Release

### Release Flow
1. Create branch from `main` (e.g., `fix/something`)
2. Make changes and test locally with `go build` and manual runs
3. Push branch, then tag as `dev-<description>` for integration testing with pia-wg-refresh
4. If good → merge to `main` → tag as `vX.Y.Z`

### Hotfix Workflow
Always branch hotfixes from `main`, never from a feature branch. See pia-wg-refresh CLAUDE.md for full details — same rules apply here.

## Key Components

### Files
- `main.go` - CLI entrypoint (flags: `--outfile`, `--region`, `--verbose`, `--server`, `--port-forwarding`)
- `pia/pia.go` - PIA client: token generation, server selection, WireGuard key registration
- `pia/wg.go` - WireGuard config template generation
- `pia/wg_test.go` - Tests for config generation
- `go.mod` / `go.sum` - Module definition (module path: `github.com/Ephemeral-Dust/pia-wg-config`)
- `vendor/` - Vendored dependencies
- `Dockerfile` - Multi-stage build: Go 1.23 Alpine builder → Alpine 3.20 runtime

## CLI Flags

| Flag | Alias | Default | Description |
|------|-------|---------|-------------|
| `--outfile` | `-o` | (stdout) | File to write config to |
| `--region` | `-r` | `ca_toronto` | PIA region |
| `--verbose` | `-v` | `false` | Print verbose output |
| `--server` | `-s` | `false` | Add server common name to config |
| `--port-forwarding` | `-p` | `false` | Only use servers with port forwarding |

Usage: `pia-wg-config -r ireland -s -p -o wg0.conf USERNAME PASSWORD`

## Key Fix: Central Token API (v1.0.6)

### The Problem
PIA new-format servers (`Server-XXXXX-Xa`) — affecting 75+ regions as of April 2026 — accept TLS but never respond to `/authv3/generateToken`. The original code tried each meta server in the selected region, panicking when none responded (empty slice index `[0]`).

### The Fix
Use PIA's central token API at `https://www.privateinternetaccess.com/gtoken/generateToken` instead of going through region-specific meta servers. This matches PIA's own [manual-connections](https://github.com/pia-foss/manual-connections) scripts.

### Key location
- `pia/pia.go` — `generateToken()` function

### Filed upstream
- [kylegrantlucas/pia-wg-config#12](https://github.com/kylegrantlucas/pia-wg-config/issues/12)

## Docker Image

The Docker image packages just the binary:
- Base: `alpine:3.20` with `ca-certificates`
- Binary at `/usr/local/bin/pia-wg-config`
- Built multi-arch: `linux/amd64`, `linux/arm64`
- Published to `ghcr.io/ccarpinteri/pia-wg-config`

**Used by pia-wg-refresh** which currently builds from source via `git clone`. Future: may switch to copying binary from this image.

## Vendored Dependencies

- `golang.zx2c4.com/wireguard/wgctrl` - WireGuard key types
- `golang.org/x/crypto` - Curve25519 key generation
- `github.com/urfave/cli/v2` - CLI framework
- `github.com/pkg/errors` - Error wrapping
- `github.com/benburkert/dns` - DNS resolution

Build with `-mod=vendor` to use vendored deps without network access.

## Testing

```bash
# Build locally
go build -mod=vendor -o pia-wg-config .

# Run (outputs config to stdout)
./pia-wg-config -r ireland USERNAME PASSWORD

# Run with port forwarding filter and server name
./pia-wg-config -r ca_toronto -s -p -o wg0.conf USERNAME PASSWORD

# Run tests
go test ./pia/...
```

## Common Issues

### Token generation failure (new-format servers)
If you see timeout errors on token generation, the region likely uses `Server-XXXXX-Xa` format servers. The fix in v1.0.6 routes through the central token API. Confirm the fix is in place in `pia/pia.go`.

### Region has no port-forwarding servers
Not all regions support port forwarding. If `-p` flag returns no servers, try a different region (e.g., `ca_toronto`, `ireland`, `de-frankfurt`).
