> **Status: Work in Progress (WIP)**
>
> This project is under active development. Features may change.

# DNS Inspector (Go)

A lightweight DNS inspection CLI for technical OSINT and DNS troubleshooting.

## Features

- **A** (IPv4), **AAAA** (IPv6), **MX** (mail servers), **NS** (name servers), and **TXT** lookups
- Five-second DNS lookup timeout
- Exit codes: `0` success, `1` lookup/output/no-record error, `2` invalid arguments
- DNS resolution using Go's standard library

CNAME lookup and JSON output are planned.

## Usage

```bash
go run ./cmd/dns-inspector example.com
go run ./cmd/dns-inspector --type AAAA example.com
go run ./cmd/dns-inspector --type MX example.com
go run ./cmd/dns-inspector --type NS example.com
go run ./cmd/dns-inspector --type TXT example.com
```

Build a standalone binary (Docker not required):

```bash
go build -o dns-inspector ./cmd/dns-inspector
./dns-inspector --type TXT example.com
```

## Development with Docker (optional)

Requires a Docker-compatible container engine and Docker CLI. Docker Desktop and VS Code are **not** required. Run from the repository root in a Bash-compatible shell:

```bash
docker info
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
docker run --rm -it \
  --mount type=bind,source="$(pwd)",target=/workspace \
  dns-inspector-go-dev
```

Inside the container, run all local checks:

```bash
./scripts/check.sh
```

The script formats Go files, runs tests with race detection, and runs golangci-lint. Formatting may modify source files. Run `exit` to leave the container; source files remain on the host.

Docker is for development only. End users can run the compiled binary without Docker or Go.

## CI

GitHub Actions checks formatting, linting, tests, vulnerabilities (govulncheck), secrets (Gitleaks), and workflow syntax (actionlint).

## Scope

Standard DNS lookups only. No port scanning, brute-forcing, or automated subdomain enumeration.
