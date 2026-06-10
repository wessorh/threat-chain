#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# docker/entrypoint.sh — Docker container entrypoint for threatattestd
# =============================================================================
#
# Supports two modes:
#   1. "start" (default) — initialises chain if needed, then starts node
#   2. Pass-through      — run any threatattestd sub-command directly
#
# Environment variables:
#   CHAIN_HOME       node home directory  [default: ~/.threatattestd]
#   CHAIN_ID         chain ID             [default: threatattest-1]
#   MONIKER          node moniker         [default: docker-node]
#   KEY_NAME         validator key name   [default: validator]
#   DENOM            token denom          [default: utatst]
#   STAKE_AMOUNT     gentx stake          [default: 100000000utatst]
#   SUPPLY_AMOUNT    genesis balance      [default: 200000000utatst]
#   KEYRING_BACKEND  keyring backend      [default: test]
#   EXTERNAL_IP      advertised P2P IP    [default: auto-detected]
#   LOG_LEVEL        log level            [default: info]
#   MINIMUM_GAS      minimum gas prices   [default: 0utatst]
# =============================================================================

set -euo pipefail

BINARY="threatattestd"
CHAIN_HOME="${CHAIN_HOME:-${HOME}/.threatattestd}"
CHAIN_ID="${CHAIN_ID:-threatattest-1}"
MONIKER="${MONIKER:-docker-node}"
KEY_NAME="${KEY_NAME:-validator}"
DENOM="${DENOM:-utatst}"
STAKE_AMOUNT="${STAKE_AMOUNT:-100000000${DENOM}}"
SUPPLY_AMOUNT="${SUPPLY_AMOUNT:-200000000${DENOM}}"
KEYRING_BACKEND="${KEYRING_BACKEND:-test}"
LOG_LEVEL="${LOG_LEVEL:-info}"
MINIMUM_GAS="${MINIMUM_GAS:-0${DENOM}}"

# Auto-detect external IP for P2P advertising
EXTERNAL_IP="${EXTERNAL_IP:-$(curl -sf --max-time 3 https://api.ipify.org 2>/dev/null || echo '')}"

TA="${BINARY} --home ${CHAIN_HOME}"

# ─── Colours ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'
info() { echo -e "${CYAN}[entrypoint]${RESET} $*"; }
ok()   { echo -e "${GREEN}[entrypoint]${RESET} $*"; }
warn() { echo -e "${YELLOW}[entrypoint]${RESET} ⚠  $*"; }

# ─── Pass-through for non-start commands ─────────────────────────────────────
if [[ "${1:-start}" != "start" ]]; then
  exec "${BINARY}" "$@"
fi

# ─── Init if home doesn't exist ──────────────────────────────────────────────
if [[ ! -d "${CHAIN_HOME}/config" ]]; then
  info "Initialising chain home: ${CHAIN_HOME}"
  info "Chain ID: ${CHAIN_ID} | Moniker: ${MONIKER} | Denom: ${DENOM}"

  ${TA} init "${MONIKER}" \
    --chain-id "${CHAIN_ID}" \
    --default-denom "${DENOM}" 2>/dev/null

  # Create validator key
  ${TA} keys add "${KEY_NAME}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --output json 2>/dev/null | \
    python3 -c "
import sys, json
try:
    d=json.load(sys.stdin)
    print('[entrypoint] Key created:', d.get('address',''))
    with open('/tmp/validator_mnemonic.txt','w') as f:
        f.write(d.get('mnemonic',''))
    print('[entrypoint] ⚠  Mnemonic saved to /tmp/validator_mnemonic.txt — DELETE after use')
except: pass
" 2>/dev/null || true

  VALIDATOR_ADDR=$(${TA} keys show "${KEY_NAME}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --address 2>/dev/null)

  info "Validator address: ${VALIDATOR_ADDR}"

  # Add genesis account
  ${TA} genesis add-genesis-account "${VALIDATOR_ADDR}" "${SUPPLY_AMOUNT}" \
    --keyring-backend "${KEYRING_BACKEND}" 2>/dev/null

  # Create gentx
  ${TA} genesis gentx "${KEY_NAME}" "${STAKE_AMOUNT}" \
    --chain-id "${CHAIN_ID}" \
    --moniker "${MONIKER}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --commission-rate "0.10" \
    --commission-max-rate "0.20" \
    --commission-max-change-rate "0.01" \
    --min-self-delegation "1" \
    2>/dev/null

  ${TA} genesis collect-gentxs 2>/dev/null

  # Patch config
  GENESIS="${CHAIN_HOME}/config/genesis.json"
  python3 << PYEOF
import json
with open("${GENESIS}") as f:
    g = json.load(f)
app = g.setdefault("app_state", {})
app.setdefault("staking",{}).setdefault("params",{})["bond_denom"] = "${DENOM}"
app.setdefault("crisis",{}).setdefault("constant_fee",{})["denom"] = "${DENOM}"
app.setdefault("gov",{}).setdefault("params",{})["min_deposit"] = [{"denom":"${DENOM}","amount":"10000000"}]
app.setdefault("gov",{})["params"]["voting_period"] = "120s"
attest = app.setdefault("attestation",{}).setdefault("params",{})
attest["min_attester_delegation"] = "1000000"
attest["min_ttl_seconds"] = 3600
attest["max_ttl_seconds"] = 2592000
attest["timestamp_tolerance_seconds"] = 300
with open("${GENESIS}", "w") as f:
    json.dump(g, f, indent=2)
PYEOF

  # Patch app.toml: enable REST + gRPC + swagger
  APP_CFG="${CHAIN_HOME}/config/app.toml"
  python3 << PYEOF
import re
with open("${APP_CFG}") as f: a = f.read()
patches = {
    r'address = "tcp://localhost:1317"': 'address = "tcp://0.0.0.0:1317"',
    r'swagger = false': 'swagger = true',
    r'address = "localhost:9090"': 'address = "0.0.0.0:9090"',
    r'enabled-unsafe-cors = false': 'enabled-unsafe-cors = true',
}
for p, r in patches.items():
    a = a.replace(p, r)
with open("${APP_CFG}", "w") as f: f.write(a)
PYEOF

  # Patch config.toml: open RPC + CORS
  CMTCFG="${CHAIN_HOME}/config/config.toml"
  python3 << PYEOF
import re
with open("${CMTCFG}") as f: c = f.read()
c = c.replace('laddr = "tcp://127.0.0.1:26657"', 'laddr = "tcp://0.0.0.0:26657"')
c = c.replace('cors_allowed_origins = []', 'cors_allowed_origins = ["*"]')
c = c.replace('timeout_commit = "5s"', 'timeout_commit = "1s"')
if "${EXTERNAL_IP}":
    c = re.sub(r'^external_address = ""', 'external_address = "${EXTERNAL_IP}:26656"', c, flags=re.MULTILINE)
with open("${CMTCFG}", "w") as f: f.write(c)
PYEOF

  ok "Chain initialised"
else
  info "Using existing chain home: ${CHAIN_HOME}"
fi

# ─── Start node ───────────────────────────────────────────────────────────────
ok "Starting ${BINARY} (chain: ${CHAIN_ID}, log: ${LOG_LEVEL})"

exec "${BINARY}" start \
  --home "${CHAIN_HOME}" \
  --rpc.laddr "tcp://0.0.0.0:26657" \
  --grpc.address "0.0.0.0:9090" \
  --api.address "tcp://0.0.0.0:1317" \
  --api.enable \
  --api.swagger \
  --minimum-gas-prices "${MINIMUM_GAS}" \
  --log_level "${LOG_LEVEL}"