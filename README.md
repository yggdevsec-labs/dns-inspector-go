# DNS Inspector (Go)

A lightweight CLI for inspecting DNS records. Built for technical OSINT and DNS troubleshooting.

## Features

- **A** (IPv4) and **AAAA** (IPv6) lookups
- Five-second lookup timeout
- Exit codes: **0** for success, **1** for lookup, output, or no-record errors, and **2** for usage errors or unsupported record types
- No external dependencies for DNS resolution

MX, NS, TXT, CNAME and JSON output are planned, not yet implemented.

## Usage

```bash
go run ./cmd/dns-inspector example.com
go run ./cmd/dns-inspector --type A example.com
go run ./cmd/dns-inspector --type AAAA example.com
```

Build a standalone binary:

```bash
go build -o dns-inspector ./cmd/dns-inspector
./dns-inspector example.com
```

## Development

Install the Go version specified in `go.mod`, or use the **optional** Docker development environment.

```bash
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
docker run --rm -it --mount type=bind,source="$(pwd)",target=/workspace dns-inspector-go-dev
```

Run formatting, tests with race detection, and linting:

```bash
./scripts/check.sh
```

The script formats Go files in place. Review changes before committing.

## CI

GitHub Actions checks formatting, linting, tests, vulnerabilities (govulncheck), secrets (Gitleaks), and workflow syntax (actionlint).

## Scope

DNS Inspector performs standard DNS lookups. It does not perform port scanning, brute-forcing, or automated subdomain enumeration.
