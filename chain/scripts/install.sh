#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/install.sh — Install threatattestd to GOPATH/bin
# =============================================================================
#
# Usage:
#   bash scripts/install.sh              # install to $(go env GOPATH)/bin
#   bash scripts/install.sh --prefix /usr/local/bin
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

BINARY="threatattestd"
CMD_PATH="./cmd/threatattestd"
MODULE="github.com/threatattest/chain"
COSMOS_VERSION_PKG="github.com/cosmos/cosmos-sdk/version"

GO="${GO:-/usr/local/go/bin/go}"
command -v go &>/dev/null && GO="go"

PREFIX="${PREFIX:-$(${GO} env GOPATH)/bin}"
BUILD_TAGS="${BUILD_TAGS:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --tags)   BUILD_TAGS="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [--prefix DIR] [--tags TAGS]"
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

GIT_VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

LDFLAGS="-X ${COSMOS_VERSION_PKG}.Name=${BINARY} \
         -X ${COSMOS_VERSION_PKG}.AppName=${BINARY} \
         -X ${COSMOS_VERSION_PKG}.Version=${GIT_VERSION} \
         -X ${COSMOS_VERSION_PKG}.Commit=${GIT_COMMIT} \
         -X ${COSMOS_VERSION_PKG}.BuildTags=${BUILD_TAGS}"

${GO} mod verify || die "Module verification failed"

info "Installing ${BINARY} ${GIT_VERSION} → ${PREFIX}/${BINARY}"

mkdir -p "${PREFIX}"

GOBIN="${PREFIX}" ${GO} install \
  -mod=readonly \
  -tags "${BUILD_TAGS}" \
  -ldflags "${LDFLAGS}" \
  "${CMD_PATH}"

success "Installed: ${PREFIX}/${BINARY}"

# Quick sanity check
if "${PREFIX}/${BINARY}" version &>/dev/null; then
  echo -e "  Version: $("${PREFIX}/${BINARY}" version 2>&1 | head -1)"
fi