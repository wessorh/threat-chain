#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/reset-localnet.sh — Wipe state and reinitialise the local devnet
# =============================================================================
#
# Stops the node if running, removes the home directory, then delegates to
# init-localnet.sh to create a fresh chain from scratch.
#
# Usage:
#   bash scripts/reset-localnet.sh [same options as init-localnet.sh]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BINARY="${ROOT_DIR}/bin/threatattestd"
HOME_DIR="${HOME}/.threatattestd-local"
PID_FILE="/tmp/threatattestd-local.pid"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

# Pass-through args to init-localnet.sh (also capture --home override)
PASSTHROUGH_ARGS=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) HOME_DIR="$2" ;;
  esac
  shift
done

echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Localnet Reset${RESET}"
echo ""

# ─── Stop running node ────────────────────────────────────────────────────────
if [[ -f "${PID_FILE}" ]]; then
  OLD_PID=$(cat "${PID_FILE}")
  if kill -0 "${OLD_PID}" 2>/dev/null; then
    info "Stopping running node (PID ${OLD_PID})"
    kill "${OLD_PID}" 2>/dev/null || true
    sleep 2
    kill -9 "${OLD_PID}" 2>/dev/null || true
    success "Node stopped"
  fi
  rm -f "${PID_FILE}"
fi

# Also catch any stray processes
pkill -f "threatattestd [s]tart" 2>/dev/null || true

# ─── Wipe home directory ──────────────────────────────────────────────────────
if [[ -d "${HOME_DIR}" ]]; then
  info "Removing ${HOME_DIR}"
  rm -rf "${HOME_DIR}"
  success "State wiped"
else
  warn "Home directory not found: ${HOME_DIR} (nothing to wipe)"
fi

# ─── Wipe log ────────────────────────────────────────────────────────────────
rm -f /tmp/threatattestd-local.log
info "Log cleared"

# ─── Re-initialise ───────────────────────────────────────────────────────────
echo ""
exec bash "${SCRIPT_DIR}/init-localnet.sh" "${PASSTHROUGH_ARGS[@]+"${PASSTHROUGH_ARGS[@]}"}"