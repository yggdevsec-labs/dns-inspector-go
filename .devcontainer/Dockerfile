
FROM golang:1.27.3 AS go-toolchain

FROM golangci/golangci-lint:v2.15.0 AS lint-tool

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTOOLCHAIN=local
ENV CGO_ENABLED=1
ENV GOPATH=/home/developer/go
ENV PATH="/usr/local/go/bin:/home/developer/go/bin:${PATH}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        git && \
    rm -rf /var/lib/apt/lists/*

COPY --from=go-toolchain /usr/local/go /usr/local/go
COPY --from=lint-tool /usr/bin/golangci-lint /usr/local/bin/golangci-lint

RUN GOBIN=/usr/local/bin \
    go install golang.org/x/vuln/cmd/govulncheck@v1.9.0

RUN useradd -m -s /bin/bash developer && \
    mkdir -p /workspace /home/developer/go /home/developer/.cache/go-build && \
    chown -R developer:developer /workspace /home/developer

USER developer

WORKDIR /workspace

CMD ["/bin/bash"]
