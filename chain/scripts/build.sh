#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/build.sh — Cross-platform build script for threatattestd
# =============================================================================
#
# Usage:
#   bash scripts/build.sh                  # build for current OS/arch
#   bash scripts/build.sh --all            # build all release platforms
#   bash scripts/build.sh --os linux --arch amd64
#   bash scripts/build.sh --static         # fully static linux/amd64 binary
#   bash scripts/build.sh --race           # build with race detector
#
# Output:
#   bin/threatattestd                      (current platform)
#   dist/threatattestd-<os>-<arch>[.exe]  (--all mode)
# =============================================================================

set -euo pipefail

# ─── Defaults ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

BINARY="threatattestd"
CMD_PATH="./cmd/threatattestd"
BIN_DIR="./bin"
DIST_DIR="./dist"
MODULE="github.com/threatattest/chain"
COSMOS_VERSION_PKG="github.com/cosmos/cosmos-sdk/version"

GO="${GO:-/usr/local/go/bin/go}"
command -v go &>/dev/null && GO="go"

BUILD_TAGS="${BUILD_TAGS:-}"
BUILD_ALL=false
STATIC=false
RACE=false
TARGET_OS="$(go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')"
TARGET_ARCH="$(go env GOARCH 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

# ─── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)    BUILD_ALL=true ;;
    --static) STATIC=true ;;
    --race)   RACE=true ;;
    --os)     TARGET_OS="$2"; shift ;;
    --arch)   TARGET_ARCH="$2"; shift ;;
    --tags)   BUILD_TAGS="$2"; shift ;;
    -h|--help)
      echo "Usage: $0 [--all] [--static] [--race] [--os OS] [--arch ARCH] [--tags TAGS]"
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ─── Version stamping ────────────────────────────────────────────────────────
GIT_VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

LDFLAGS="-X ${COSMOS_VERSION_PKG}.Name=${BINARY} \
         -X ${COSMOS_VERSION_PKG}.AppName=${BINARY} \
         -X ${COSMOS_VERSION_PKG}.Version=${GIT_VERSION} \
         -X ${COSMOS_VERSION_PKG}.Commit=${GIT_COMMIT} \
         -X ${COSMOS_VERSION_PKG}.BuildTags=${BUILD_TAGS}"

if $STATIC; then
  LDFLAGS="-w -s -extldflags '-static' ${LDFLAGS}"
fi

# ─── Release platform matrix ─────────────────────────────────────────────────
# Format: "os/arch[/suffix]"
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64/.exe"
)

# ─── Build functions ─────────────────────────────────────────────────────────

build_binary() {
  local goos="$1"
  local goarch="$2"
  local suffix="${3:-}"
  local output_dir="$4"
  local out_name="${BINARY}${suffix}"
  local out_path="${output_dir}/${out_name}"

  info "Building ${out_name} (${goos}/${goarch})"

  local cgo_enabled="1"
  local extra_tags="${BUILD_TAGS}"

  # CGO must be disabled for cross-compilation unless we have the right toolchain
  if [[ "${goos}" != "$(go env GOOS)" ]] || [[ "${goarch}" != "$(go env GOARCH)" ]]; then
    cgo_enabled="0"
    warn "Cross-compilation: CGO disabled for ${goos}/${goarch}"
  fi

  if $STATIC; then
    cgo_enabled="0"
    extra_tags="${extra_tags:+${extra_tags},}osusergo,netgo"
  fi

  local race_flag=""
  if $RACE; then
    race_flag="-race"
    if [[ "${goos}" == "windows" ]]; then
      warn "Race detector not supported on windows — skipping for this target"
      race_flag=""
    fi
  fi

  local go_flags="-mod=readonly"
  [[ -n "${race_flag}" ]] && go_flags="${go_flags} ${race_flag}"

  mkdir -p "${output_dir}"

  CGO_ENABLED="${cgo_enabled}" \
  GOOS="${goos}" \
  GOARCH="${goarch}" \
  ${GO} build \
    ${go_flags} \
    -tags "${extra_tags}" \
    -ldflags "${LDFLAGS}" \
    -o "${out_path}" \
    "${CMD_PATH}"

  local size
  size="$(du -sh "${out_path}" 2>/dev/null | cut -f1)"
  success "${out_path} (${size})"

  # Write checksum
  (cd "${output_dir}" && sha256sum "${out_name}" > "${out_name}.sha256")
  success "${output_dir}/${out_name}.sha256"
}

# ─── Main ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Build${RESET}"
echo -e "  Version : ${GIT_VERSION}"
echo -e "  Commit  : ${GIT_COMMIT}"
echo -e "  Date    : ${BUILD_DATE}"
echo -e "  Go      : $(${GO} version | awk '{print $3}')"
echo ""

# Verify module
${GO} mod verify || die "Module verification failed — run: go mod tidy"

if $BUILD_ALL; then
  info "Building for all platforms"
  mkdir -p "${DIST_DIR}"

  for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r goos goarch suffix <<< "${platform}/"
    suffix="${suffix:-}"
    # Remove trailing slash artifact
    suffix="${suffix%/}"
    build_binary "${goos}" "${goarch}" "${suffix}" "${DIST_DIR}"
  done

  echo ""
  success "All platform builds complete → ${DIST_DIR}/"
  ls -lh "${DIST_DIR}"/

else
  mkdir -p "${BIN_DIR}"
  build_binary "${TARGET_OS}" "${TARGET_ARCH}" "" "${BIN_DIR}"
  echo ""
  success "Build complete → ${BIN_DIR}/${BINARY}"
fi