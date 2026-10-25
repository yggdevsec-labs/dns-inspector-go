#!/usr/bin/env bash
set -euo pipefail

# Run checks from the project root.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> Formatting Go files"
gofmt -w .

echo "==> Running tests with race detection"
go test -race ./...

echo "==> Running GolangCI-Lint"
golangci-lint run

echo "==> All checks passed"