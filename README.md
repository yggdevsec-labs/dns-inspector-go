
> **Status: Work in Progress (WIP)**
>
> DNS Inspector is under active development. Features and interfaces may change.

# DNS Inspector (Go)

A lightweight command-line tool for DNS inspection, troubleshooting, and technical OSINT. Query individual DNS record types and read results as text or JSON.

## Features

- Look up **A, AAAA, MX, NS, TXT, CNAME, SRV, PTR, SOA, and CAA** records.
- Use plain-text output for interactive inspection or `--json` for scripts and automation.
- Validate domain names and PTR IP-address inputs before performing lookups.
- Return meaningful exit codes and send errors to standard error (`stderr`).

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

- **DS and DNSKEY** — DNSSEC delegation and public-key inspection.
- **RRSIG, NSEC, and NSEC3** — Additional DNSSEC record inspection.
- **HTTPS and SVCB** — Modern service binding and HTTPS connection metadata.
- **TLSA** — DANE-related TLS certificate information.
- **SSHFP** — SSH public-key fingerprints.
- **NAPTR** — Naming Authority Pointer records.

## Requirements

- **Go 1.27.3 or newer** to install or build from source (as declared in `go.mod`).
- Access to a working DNS resolver.
- **Linux or a compatible environment with `/etc/resolv.conf` for SOA and CAA lookups.** Other platforms have not been verified for these two record types.

## Installation

### Install with Go

```bash
go install github.com/yggdevsec-labs/dns-inspector-go/cmd/dns-inspector@latest
```

Ensure your Go binary directory (usually `$(go env GOPATH)/bin`) is in your `PATH` so you can run `dns-inspector` from any directory.

**Note:** No tagged releases or prebuilt binaries are currently published. `@latest` installs the latest version resolved by Go, not a pinned release.

### Build from source

```bash
git clone https://github.com/yggdevsec-labs/dns-inspector-go.git
cd dns-inspector-go
go build -o dns-inspector ./cmd/dns-inspector
./dns-inspector --type A example.com
```

The commands in the Usage section assume that `dns-inspector` is available in your `PATH`. If you built it locally and have not installed it, use `./dns-inspector` instead.

## Usage

An A-record lookup is the default when `--type` is omitted.

```bash
dns-inspector example.com
dns-inspector --type AAAA example.com
dns-inspector --type MX example.com
dns-inspector --type NS example.com
dns-inspector --type TXT example.com
dns-inspector --type CNAME www.example.com
dns-inspector --type SRV _sip._tcp.example.com
dns-inspector --type PTR 8.8.8.8
dns-inspector --type PTR 2001:4860:4860::8888
dns-inspector --type SOA example.com
dns-inspector --type CAA cloudflare.com
```

Record type names are case-insensitive. Each invocation queries one record type.

**Record-specific behavior:**

- **CNAME:** Displays the canonical target. If the target matches the queried name, the CLI reports that no CNAME alias was found.
- **SRV:** Requires a service-specific DNS name such as `_sip._tcp.example.com`. Each result contains priority, weight, port, and target.
- **PTR:** Requires a valid IPv4 or IPv6 address rather than a domain name.
- **SOA:** Displays primary name server, responsible mailbox, serial, refresh, retry, expire, and minimum TTL, in that order. Time values are in seconds.
- **CAA:** Displays each record's flag, tag, and value. This is a direct lookup only; the tool does **not** evaluate inherited CAA policies or determine the effective certificate-issuance policy.

### Example text output

Example A and MX responses observed for `example.com` (live DNS answers can change):

```text
$ dns-inspector --type A example.com
104.20.23.154
172.66.147.243

$ dns-inspector --type MX example.com
0 .
```

The MX response `0 .` is a **Null MX** record, indicating that the domain does not accept email.

### JSON output

Add `--json` to return machine-readable results:

```bash
dns-inspector --json example.com
dns-inspector --type MX --json example.com
dns-inspector --json --type TXT example.com
dns-inspector --type SOA --json example.com
dns-inspector --type CAA --json cloudflare.com
```

Example JSON for the A records shown above, formatted for readability (the CLI emits compact JSON):

```json
{
  "domain": "example.com",
  "type": "A",
  "records": [
    "104.20.23.154",
    "172.66.147.243"
  ]
}
```

All ten supported record types use the same JSON structure. Entries in `records` are strings, including formatted SOA and CAA records.

### DNS resolution and exit codes

The CLI uses the machine's configured DNS resolution settings; an explicit `--server` option is **not yet supported**. There are two implementation paths:

- **A, AAAA, MX, NS, TXT, CNAME, SRV, and PTR:** Use Go's standard-library resolver, which follows the system resolver configuration.
- **SOA and CAA:** Use `github.com/miekg/dns` and read DNS servers directly from `/etc/resolv.conf`. These queries use UDP with TCP fallback for truncated responses.

A lookup has a **five-second timeout**. The CLI returns the following exit codes:

| Exit code | Meaning |
| --- | --- |
| `0` | Lookup succeeded and output was written. |
| `1` | DNS lookup failed, no matching records were found, or output could not be written. |
| `2` | Invalid arguments, unsupported record type, or invalid input. |

Errors are written to `stderr`.

## Development

From a checked-out repository, use `go run` for development and testing:

```bash
go run ./cmd/dns-inspector --type A example.com
go run ./cmd/dns-inspector --type CAA cloudflare.com
./scripts/check.sh
```

The check script formats Go files, runs tests with race detection, and runs golangci-lint. Formatting may modify source files.

### Development with Docker (optional)

A Docker-compatible container engine and Docker CLI are required. Run from the repository root in a Bash-compatible shell:

```bash
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
docker run --rm -it \
  --mount "type=bind,source=$PWD,target=/workspace" \
  dns-inspector-go-dev
```

If Docker's default DNS server fails to return expected records, start the container with an explicit DNS server:

```bash
docker run --rm -it \
  --dns 1.1.1.1 \
  --mount "type=bind,source=$PWD,target=/workspace" \
  dns-inspector-go-dev
```

Inside the container, run `./scripts/check.sh`. Type `exit` to leave the container. Docker is only a development option; it is not required to run the compiled executable.

## Roadmap

The following features are **planned, not currently implemented**. Priorities and interfaces may change.

### CLI improvements

- **`--help` and `--version`:** Built-in usage information and version reporting.
- **`--output`:** Save text or JSON results to a file.
- **`--force`:** Explicitly allow overwriting an existing output file.
- **`--server`:** Query a user-selected DNS server.
- **`--tcp`:** Explicitly select TCP for DNS queries.
- **`--types`:** Query selected record types in one command, such as `--types A,AAAA,MX,NS`.
- **`--common`:** Query a documented set of common record types; exclude PTR and SRV because their inputs differ.

### Additional DNS record types

- **DNSSEC and delegation:** DS, DNSKEY, RRSIG, NSEC, NSEC3, CDS, CDNSKEY, ZONEMD, and CSYNC.
- **Modern services and transport security:** HTTPS, SVCB, TLSA, SSHFP, DNAME, and NAPTR.
- **Certificate and email security:** CERT, SMIMEA, and OPENPGPKEY.
- **Other specialized records:** URI, LOC, RP, HINFO, and DHCID, subject to demand.

DNSSEC record inspection would not, by itself, provide full cryptographic DNSSEC validation.

### Output and reporting

- Structured JSON values for SOA and CAA instead of a single formatted record string.
- Per-type results, errors, and status for multi-record queries.
- Safe file writing that avoids partial reports.

### Design decisions

A general `--all` flag is **not currently planned**. DNS record types do not all accept the same inputs: PTR requires an IP address, and SRV usually requires a service-specific name. Explicit `--types` selection and a documented `--common` preset are more predictable.

`ANY` is a special DNS query type, not a reliable way to retrieve every record type.

## CI

GitHub Actions checks formatting, linting, tests, vulnerabilities (govulncheck), secrets (Gitleaks), and workflow syntax (actionlint).


## License


