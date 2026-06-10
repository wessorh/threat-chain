#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/protocgen.sh — Regenerate protobuf Go bindings
# =============================================================================
#
# Uses buf (preferred) if available, otherwise falls back to protoc with
# cosmos/proto-builder Docker image.
#
# Requirements (one of):
#   Option A — buf CLI:    https://buf.build/docs/installation
#   Option B — Docker:     docker pull ghcr.io/cosmos/proto-builder:0.14.0
#   Option C — Local:      protoc + protoc-gen-go + protoc-gen-go-grpc
#                          + protoc-gen-gocosmos + protoc-gen-grpc-gateway
#
# Usage:
#   bash scripts/protocgen.sh
#   bash scripts/protocgen.sh --module attestation
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

PROTO_DIR="./proto"
THIRD_PARTY_PROTO="${THIRD_PARTY_PROTO:-}"

# Docker image for cosmos proto-builder
PROTO_BUILDER_IMAGE="ghcr.io/cosmos/proto-builder:0.14.0"

# Buf config
BUF_CONFIG="${PROTO_DIR}/buf.yaml"
BUF_GEN_CONFIG="${PROTO_DIR}/buf.gen.yaml"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

TARGET_MODULE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --module) TARGET_MODULE="$2"; shift ;;
    -h|--help) echo "Usage: $0 [--module MODULE_NAME]"; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ─── Write buf.yaml if missing ───────────────────────────────────────────────
write_buf_yaml() {
  if [[ -f "${BUF_CONFIG}" ]]; then return; fi
  info "Writing ${BUF_CONFIG}"
  cat > "${BUF_CONFIG}" << 'EOF'
version: v1
name: buf.build/threatattest/chain
deps:
  - buf.build/cosmos/cosmos-sdk
  - buf.build/cosmos/cosmos-proto
  - buf.build/googleapis/googleapis
  - buf.build/gogoproto/protobuf
breaking:
  use:
    - FILE
lint:
  use:
    - DEFAULT
  except:
    - UNARY_RPC
    - COMMENT_ENUM
    - COMMENT_MESSAGE
    - COMMENT_SERVICE
    - COMMENT_FIELD
  rpc_allow_same_request_response: true
  rpc_allow_google_protobuf_empty_requests: true
  rpc_allow_google_protobuf_empty_responses: true
EOF
}

# ─── Write buf.gen.yaml if missing ────────────────────────────────────────────
write_buf_gen_yaml() {
  if [[ -f "${BUF_GEN_CONFIG}" ]]; then return; fi
  info "Writing ${BUF_GEN_CONFIG}"
  cat > "${BUF_GEN_CONFIG}" << 'EOF'
version: v1
managed:
  enabled: true
  go_package_prefix:
    default: github.com/threatattest/chain
    except:
      - buf.build/googleapis/googleapis
      - buf.build/cosmos/cosmos-sdk
      - buf.build/cosmos/cosmos-proto
plugins:
  - plugin: buf.build/cosmos/go
    out: .
    opt:
      - paths=source_relative
  - plugin: buf.build/cosmos/go-grpc
    out: .
    opt:
      - paths=source_relative
  - plugin: buf.build/grpc-ecosystem/grpc-gateway
    out: .
    opt:
      - paths=source_relative
      - logtostderr=true
      - allow_colon_final_segments=true
EOF
}

# ─── Generation via buf ───────────────────────────────────────────────────────
gen_with_buf() {
  info "Using buf to generate protobuf bindings"
  write_buf_yaml
  write_buf_gen_yaml

  if [[ -n "${TARGET_MODULE}" ]]; then
    buf generate "${PROTO_DIR}/threatattest/${TARGET_MODULE}"
  else
    buf generate "${PROTO_DIR}"
  fi
}

# ─── Generation via Docker (cosmos/proto-builder) ─────────────────────────────
gen_with_docker() {
  info "Using Docker (${PROTO_BUILDER_IMAGE}) to generate protobuf bindings"

  local proto_dirs
  if [[ -n "${TARGET_MODULE}" ]]; then
    proto_dirs="${PROTO_DIR}/threatattest/${TARGET_MODULE}"
  else
    proto_dirs="${PROTO_DIR}"
  fi

  docker run --rm \
    -v "${ROOT_DIR}:/workspace" \
    -w /workspace \
    "${PROTO_BUILDER_IMAGE}" \
    sh -c "
      find ${proto_dirs} -name '*.proto' | while read -r proto_file; do
        echo '  Generating: '\$proto_file
        protoc \
          -I /workspace/proto \
          -I /workspace/third_party/proto \
          --gocosmos_out=. \
          --gocosmos_opt=paths=source_relative \
          --grpc-gateway_out=. \
          --grpc-gateway_opt=logtostderr=true,paths=source_relative \
          \"\$proto_file\"
      done
    "
}

# ─── Generation via local protoc ──────────────────────────────────────────────
gen_with_protoc() {
  info "Using local protoc to generate protobuf bindings"
  command -v protoc &>/dev/null || die "protoc not found — install from https://github.com/protocolbuffers/protobuf/releases"

  local proto_files
  if [[ -n "${TARGET_MODULE}" ]]; then
    proto_files=$(find "${PROTO_DIR}/threatattest/${TARGET_MODULE}" -name "*.proto" 2>/dev/null)
  else
    proto_files=$(find "${PROTO_DIR}" -name "*.proto" 2>/dev/null)
  fi

  [[ -z "${proto_files}" ]] && die "No .proto files found in ${PROTO_DIR}"

  while IFS= read -r proto_file; do
    info "  → $proto_file"
    protoc \
      -I "${PROTO_DIR}" \
      ${THIRD_PARTY_PROTO:+-I "${THIRD_PARTY_PROTO}"} \
      --go_out=. --go_opt=paths=source_relative \
      --go-grpc_out=. --go-grpc_opt=paths=source_relative \
      "${proto_file}"
  done <<< "${proto_files}"
}

# ─── Dispatch ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Proto Generation${RESET}"
echo ""

if command -v buf &>/dev/null; then
  gen_with_buf
elif command -v docker &>/dev/null && docker image inspect "${PROTO_BUILDER_IMAGE}" &>/dev/null 2>&1; then
  gen_with_docker
elif command -v protoc &>/dev/null; then
  gen_with_protoc
else
  warn "No proto generation tool found."
  warn "Install one of:"
  warn "  • buf CLI:      https://buf.build/docs/installation"
  warn "  • Docker image: docker pull ${PROTO_BUILDER_IMAGE}"
  warn "  • protoc:       https://github.com/protocolbuffers/protobuf/releases"
  exit 1
fi

echo ""
success "Protobuf generation complete"