#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/start-localnet.sh — Start the local devnet node
# =============================================================================
#
# Usage:
#   bash scripts/start-localnet.sh [OPTIONS]
#
# Options:
#   --binary  PATH       path to threatattestd binary  [default: ./bin/threatattestd]
#   --home    DIR        node home directory            [default: ~/.threatattestd-local]
#   --log     FILE       log file                       [default: /tmp/threatattestd-local.log]
#   --fg                 run in foreground (default: background)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="${ROOT_DIR}/bin/threatattestd"
HOME_DIR="${HOME}/.threatattestd-local"
LOG_FILE="/tmp/threatattestd-local.log"
FOREGROUND=false
PID_FILE="/tmp/threatattestd-local.pid"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BINARY="$2"; shift ;;
    --home)   HOME_DIR="$2"; shift ;;
    --log)    LOG_FILE="$2"; shift ;;
    --pid)    PID_FILE="$2"; shift ;;
    --fg)     FOREGROUND=true ;;
    -h|--help)
      sed -n 's/^# //p' "$0" | head -20
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

[[ -x "${BINARY}" ]] || die "Binary not found: ${BINARY}\n  Run: make build"
[[ -d "${HOME_DIR}/config" ]] || die "Home not initialised: ${HOME_DIR}\n  Run: make localnet-init"

# ─── Check if already running ─────────────────────────────────────────────────
if [[ -f "${PID_FILE}" ]]; then
  OLD_PID=$(cat "${PID_FILE}")
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    warn "Node already running (PID ${OLD_PID})"
    warn "Stop with: make localnet-stop"
    exit 0
  else
    rm -f "${PID_FILE}"
  fi
fi

echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Localnet Start${RESET}"
echo -e "  Binary  : ${BINARY}"
echo -e "  Home    : ${HOME_DIR}"
echo -e "  Log     : ${LOG_FILE}"
echo ""

START_CMD="${BINARY} start --home ${HOME_DIR} \
  --rpc.laddr tcp://0.0.0.0:26657 \
  --grpc.address 0.0.0.0:9090 \
  --api.address tcp://0.0.0.0:1317 \
  --api.enable \
  --api.swagger \
  --minimum-gas-prices 0utatst \
  --log_level info"

if $FOREGROUND; then
  info "Starting node in foreground (Ctrl+C to stop)"
  exec ${START_CMD}
else
  info "Starting node in background"
  # shellcheck disable=SC2086
  nohup ${START_CMD} > "${LOG_FILE}" 2>&1 &
  NODE_PID=$!
  echo "${NODE_PID}" > "${PID_FILE}"
  info "PID: ${NODE_PID} → ${PID_FILE}"

  # ── Wait for RPC to come up ──────────────────────────────────────────────
  info "Waiting for RPC (tcp://localhost:26657)..."
  RETRIES=30
  for i in $(seq 1 $RETRIES); do
    if curl -sf http://localhost:26657/status &>/dev/null; then
      success "RPC is ready"
      break
    fi
    if ! kill -0 "${NODE_PID}" 2>/dev/null; then
      die "Node process died — check log: ${LOG_FILE}"
    fi
    sleep 1
    if [[ $i -eq $RETRIES ]]; then
      warn "RPC not ready after ${RETRIES}s — check log: ${LOG_FILE}"
    fi
  done

  # ── Wait for REST API ────────────────────────────────────────────────────
  info "Waiting for REST API (http://localhost:1317)..."
  for i in $(seq 1 15); do
    if curl -sf http://localhost:1317/cosmos/base/tendermint/v1beta1/node_info &>/dev/null; then
      success "REST API is ready"
      break
    fi
    sleep 1
  done

  echo ""
  echo -e "${BOLD}${GREEN}✓ Localnet running${RESET}"
  echo ""
  echo "  PID      : ${NODE_PID}"
  echo "  Log      : tail -f ${LOG_FILE}"
  echo "  RPC      : http://localhost:26657"
  echo "  REST API : http://localhost:1317"
  echo "  Swagger  : http://localhost:1317/swagger/"
  echo "  gRPC     : localhost:9090"
  echo ""
  echo "  Stop     : make localnet-stop"
  echo "  Status   : make localnet-status"
  echo ""

  # Print first block info
  sleep 2
  BLOCK=$(curl -sf http://localhost:26657/block 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); \
      print('Block #'+d.get('result',{}).get('block',{}).get('header',{}).get('height','?'))" \
    2>/dev/null || echo "Block: pending")
  info "${BLOCK}"

  # Emit the running app version so a stale binary is caught immediately.
  # abci_info returns the version the app committed to the chain; a bare
  # `go build` (no -ldflags version stamp) reports it as empty/None.
  APP_VERSION=$(curl -sf http://localhost:26657/abci_info 2>/dev/null | \
    python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('response',{}).get('version','?'))" \
    2>/dev/null || echo "unknown")
  info "App version: ${APP_VERSION}"
fi