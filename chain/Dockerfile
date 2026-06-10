# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

# =============================================================================
# ThreatAttest Chain — Multi-stage Dockerfile
# =============================================================================
#
# Stage 1 (builder): Compile the threatattestd binary using the official Go
#                    image with all build dependencies.
# Stage 2 (runner):  Minimal Debian slim image with only the binary and
#                    runtime dependencies.
#
# Build:
#   docker build -t threatattest/threatattestd:latest .
#
# Run (single-node devnet):
#   docker run --rm -it \
#     -p 26656:26656 -p 26657:26657 -p 1317:1317 -p 9090:9090 \
#     threatattest/threatattestd:latest
#
# Build args:
#   GIT_VERSION   — version string   (default: dev)
#   GIT_COMMIT    — short commit hash (default: unknown)
#   BUILD_DATE    — ISO-8601 build timestamp
#   BUILD_TAGS    — Go build tags
# =============================================================================

# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM golang:1.23-bullseye AS builder

ARG GIT_VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=""
ARG BUILD_TAGS=""

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (gcc for CGO, git for version detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Cache dependency downloads ────────────────────────────────────────────────
# Copy module files first so Docker layer cache is preserved when only source
# files change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go \
    --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

# ── Copy source and build ─────────────────────────────────────────────────────
COPY . .

ENV COSMOS_VERSION_PKG=github.com/cosmos/cosmos-sdk/version
ENV BINARY=threatattestd
ENV CGO_ENABLED=1

RUN --mount=type=cache,target=/root/.cache/go \
    --mount=type=cache,target=/root/go/pkg/mod \
    go build \
      -mod=readonly \
      -tags "${BUILD_TAGS}" \
      -ldflags " \
        -X ${COSMOS_VERSION_PKG}.Name=${BINARY} \
        -X ${COSMOS_VERSION_PKG}.AppName=${BINARY} \
        -X ${COSMOS_VERSION_PKG}.Version=${GIT_VERSION} \
        -X ${COSMOS_VERSION_PKG}.Commit=${GIT_COMMIT} \
        -X ${COSMOS_VERSION_PKG}.BuildTags=${BUILD_TAGS} \
      " \
      -o /usr/local/bin/threatattestd \
      ./cmd/threatattestd

# Sanity check
RUN threatattestd version 2>&1 || true

# ─── Stage 2: Runner ─────────────────────────────────────────────────────────
FROM debian:bullseye-slim AS runner

ARG GIT_VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=""

# OCI image labels
LABEL org.opencontainers.image.title="ThreatAttest Chain"
LABEL org.opencontainers.image.description="ThreatAttest threat intelligence blockchain node"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://github.com/threatattest/chain"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        jq \
        bash \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r threatattest && useradd -r -g threatattest -m -d /home/threatattest threatattest

# Copy binary from builder
COPY --from=builder /usr/local/bin/threatattestd /usr/local/bin/threatattestd
RUN chmod 755 /usr/local/bin/threatattestd

# Copy docker entrypoint
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Data directory (chain home)
ENV CHAIN_HOME=/home/threatattest/.threatattestd
VOLUME ["${CHAIN_HOME}"]

USER threatattest
WORKDIR /home/threatattest

# ── Ports ─────────────────────────────────────────────────────────────────────
# 26656 — P2P
# 26657 — RPC (Tendermint/CometBFT)
# 1317  — REST API
# 9090  — gRPC
# 9091  — gRPC-web
EXPOSE 26656 26657 1317 9090 9091

# ── Healthcheck ────────────────────────────────────────────────────────────────
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
    CMD curl -sf http://localhost:26657/status > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["start"]