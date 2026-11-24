> **Status: Work in Progress (WIP)**
>
> This project is under active development. Features may change.

# DNS Inspector (Go)

A lightweight DNS inspection CLI for technical OSINT and DNS troubleshooting.

## Features

- **A** (IPv4), **AAAA** (IPv6), **MX** (mail servers), **NS** (name servers), **TXT**, **CNAME**, **SRV**, **PTR**, **SOA**, and **CAA** lookups
- Five-second DNS lookup timeout
- Exit codes: `0` success, `1` lookup/output/no-record error, `2` invalid arguments
- DNS resolution using Go's standard library and `github.com/miekg/dns`
- Optional JSON output (`--json`) for scripting and automation

## Planned Features

### CLI Improvements

- **File output (`--output`)** — Save DNS lookup results as text or JSON.
- **Overwrite protection (`--force`)** — Prevent accidental overwriting of existing files. Require `--force` to replace them.
- **Multiple record types (`--types`)** — Query selected DNS record types in a single command, for example `--types A,AAAA,MX,NS`.
- **Common record preset (`--common`)** — Query a predefined set of common DNS record types. PTR and SRV are excluded because they require different input formats.
- **DNS server selection (`--server`)** — Specify a DNS resolver instead of relying on the system default.
- **Transport selection (`--tcp`)** — Allow explicit TCP selection for DNS queries.
- **Help and version flags (`--help`, `--version`)** — Improve CLI usability.

### DNS Record Support

- **CAA** — Certificate Authority Authorization records.
- **DS and DNSKEY** — DNSSEC delegation and public-key inspection.
- **RRSIG, NSEC, and NSEC3** — Additional DNSSEC record inspection.
- **HTTPS and SVCB** — Modern service binding and HTTPS connection metadata.
- **TLSA** — DANE-related TLS certificate information.
- **SSHFP** — SSH public-key fingerprints.
- **NAPTR** — Naming Authority Pointer records.

### Output and Reporting

- Structured JSON output for queries containing multiple record types.
- Individual lookup results and error status for each requested record type.
- Safe file writing that avoids partially written reports.
- Structured SOA and CAA fields in JSON output.

## Usage

```bash
go run ./cmd/dns-inspector example.com
go run ./cmd/dns-inspector --type AAAA example.com
go run ./cmd/dns-inspector --type MX example.com
go run ./cmd/dns-inspector --type NS example.com
go run ./cmd/dns-inspector --type TXT example.com
go run ./cmd/dns-inspector --type CNAME www.example.com
go run ./cmd/dns-inspector --type SRV _sip._tcp.example.com
go run ./cmd/dns-inspector --type PTR 8.8.8.8
go run ./cmd/dns-inspector --type PTR 2001:4860:4860::8888
go run ./cmd/dns-inspector --type SOA example.com
go run ./cmd/dns-inspector --type CAA cloudflare.com
```
CNAME lookups display the canonical target name. If the resolved name
matches the queried domain, the CLI reports that no CNAME alias was found.

SRV lookups use a fully qualified service name, such as
`_sip._tcp.example.com`. Results contain priority, weight,
port, and target in that order.

PTR lookups perform reverse DNS resolution for IPv4 and IPv6 addresses.
The input must be a valid IP address rather than a domain name.

SOA lookups retrieve authority information for a DNS zone.
Results include the primary name server, responsible mailbox, serial number,
refresh interval, retry interval, expiration interval, and minimum TTL.

CAA lookups retrieve Certificate Authority Authorization records for a domain.

Each record contains a flag, a property tag, and a value. Common tags
include `issue`, `issuewild`, and `iodef`.

CAA lookups query the specified domain directly. They do not evaluate
inherited CAA policies from parent domains or determine the effective
certificate issuance policy.

The CLI displays these fields in that order. Time intervals are expressed
in seconds. SOA queries use the DNS servers configured in `/etc/resolv.conf`.

Build a standalone binary (Docker not required):


```bash
go build -o dns-inspector ./cmd/dns-inspector
./dns-inspector --type TXT example.com
```


### JSON Output

Use `--json` to return structured DNS results.


```bash
go run ./cmd/dns-inspector --json example.com
go run ./cmd/dns-inspector --type MX --json example.com
go run ./cmd/dns-inspector --json --type TXT example.com
go run ./cmd/dns-inspector --type SOA --json example.com
go run ./cmd/dns-inspector --type CAA --json cloudflare.com
```

Example response:

```json
{
  "domain": "example.com",
  "type": "A",
  "records": ["192.0.2.1"]
}
```

JSON output is supported for A, AAAA, MX, NS, TXT, CNAME, SRV, PTR, SOA, and CAA.
All records are represented as strings. Errors are written to stderr,
and existing exit codes are preserved.




## Development with Docker (optional)

Requires a Docker-compatible container engine and Docker CLI. Docker Desktop and VS Code are **not** required. Run from the repository root in a Bash-compatible shell:

```bash
docker info
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
docker run --rm -it \
  --mount "type=bind,source=$PWD,target=/workspace" \
  dns-inspector-go-dev
```

If the default Docker DNS resolver does not return expected records,
the development container can be started with an explicit DNS server,
for example by adding `--dns 1.1.1.1` to `docker run`.

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
