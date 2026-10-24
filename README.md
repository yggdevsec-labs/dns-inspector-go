# DNS Inspector – Go

A lightweight command-line tool for collecting and inspecting publicly available DNS information.

**Category:** Technical OSINT / Passive Reconnaissance  

## Overview

DNS Inspector is a CLI application designed to retrieve and display DNS records for a specified domain.

The project focuses on simplicity, reliable DNS resolution, input validation, structured output, and maintainable code.

The tool is intended for technical OSINT, DNS troubleshooting, and reconnaissance.

## Planned Features

The initial version (v1.0) will support:

- DNS lookups for individual domains.
- A, AAAA, MX, NS, TXT, and CNAME records.
- Domain input validation.
- Clear terminal output.
- JSON output.
- DNS error and timeout handling.

Port scanning, DNS brute-forcing, and automated subdomain enumeration are outside the scope of v1.0.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Go 1.27.3 |
| Development Container | Docker |
| Container OS | Ubuntu 26.04 LTS |
| Formatting | gofmt |
| Linting | golangci-lint |
| Static Analysis | go vet / Staticcheck |
| Unit Testing | go test |
| Race Detection | go test -race |
| Vulnerability Scanning | govulncheck |
| Secret Scanning | Gitleaks (CI) |
| CI | GitHub Actions |

## Project Structure

```text
dns-inspector-go/
├── .devcontainer/
│   ├── devcontainer.json
│   └── Dockerfile
├── .github/
│   └── workflows/
│       └── ci.yml
├── .golangci.yml
├── go.mod
└── README.md
```

Additional directories and source files will be introduced as development progresses.

## Development Environment

The project provides an optional containerized development environment.

The container includes the Go toolchain and the required development, testing, linting, and vulnerability scanning tools.

Using Docker is not required to develop or run the Go application.

### Prerequisites

For container-based development:

- Docker CLI
- A running, compatible Docker container engine

Docker Engine on Linux and other compatible Docker environments are supported. Docker Desktop is not required.

The following commands use a POSIX-compatible shell, such as Bash, on Linux or macOS.

### 1. Verify Docker

Check that the Docker CLI can communicate with the container engine:

```bash
docker info
```

### 2. Build the Development Image

Run from the project root directory:

```bash
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
```

### 3. Start the Development Container

```bash
docker run --rm -it --mount type=bind,source="$(pwd)",target=/workspace dns-inspector-go-dev
```

The current project directory is mounted at `/workspace` inside the container.

Changes to source files remain available on the host system.

### 4. Verify the Development Tools

Run the following commands inside the container:

```bash
go version
golangci-lint version
govulncheck -version
```

### 5. Development Commands

Once Go source code has been added, the following commands can be used inside the container:

| Command | Description |
|---|---|
| `golangci-lint fmt` | Format source code |
| `golangci-lint run` | Run configured linters |
| `go vet ./...` | Perform static analysis |
| `go test ./...` | Run unit tests |
| `go test -race ./...` | Run race detection |
| `go test -cover ./...` | Run tests with coverage |
| `govulncheck ./...` | Scan for known vulnerabilities |

### 6. Stop the Development Container

Exit the container shell:

```bash
exit
```

The container is automatically removed because it was started with `--rm`.

The locally built Docker image remains available for reuse.

### 7. Rebuild the Development Image

After changing the Dockerfile, rebuild the image:

```bash
docker build -f .devcontainer/Dockerfile -t dns-inspector-go-dev .
```

## Alternative: Local Development

Docker is optional.

Developers can install a compatible Go toolchain directly on their operating system.

Verify the installation:

```bash
go version
```

Standard Go commands, including `go test`, `go vet`, and `gofmt`, can then be executed without a container.

Additional tools such as golangci-lint and govulncheck must be installed separately if needed.

## Optional: VS Code Dev Containers

The project includes `.devcontainer/devcontainer.json` for developers using Visual Studio Code or another compatible development environment.

To use it:

1. Install a compatible container engine.
2. Install the Dev Containers extension in VS Code.
3. Open the project directory.
4. Run `Dev Containers: Reopen in Container`.

This setup is optional and is not required for building or using DNS Inspector.

## Continuous Integration

GitHub Actions is configured to perform automated quality and security checks.

The CI configuration includes:

- Code formatting and linting.
- Static analysis.
- Unit tests and race detection.
- Vulnerability scanning with govulncheck.
- Secret scanning with Gitleaks.
- GitHub Actions workflow validation.

CI checks will become fully applicable as Go source code and tests are added.

## Project Goals

- Keep the codebase small and maintainable.
- Use standard Go libraries where practical.
- Avoid unnecessary dependencies.
- Implement reliable error handling and input validation.
- Provide consistent output suitable for both humans and automation.
- Maintain automated tests and security checks.

## Development Status

DNS Inspector is currently in its initial development phase.

The development environment and CI configuration are being prepared before implementation of the DNS inspection functionality.