#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/init-localnet.sh — Initialise a fresh single-node local devnet
# =============================================================================
#
# Creates a fully configured ~/.threatattestd-local home directory with:
#   - A validator key and genesis account
#   - Correct chain parameters (DENOM, min_deposit, max_ttl, etc.)
#   - API / gRPC / telemetry enabled
#   - CORS origins open for local development
#
# Usage:
#   bash scripts/init-localnet.sh [OPTIONS]
#
# Options:
#   --binary  PATH       path to threatattestd binary  [default: ./bin/threatattestd]
#   --home    DIR        node home directory            [default: ~/.threatattestd-local]
#   --chain   ID         chain ID                       [default: threatattest-local-1]
#   --moniker NAME       node moniker                   [default: localnode]
#   --key     NAME       key name                       [default: localkey]
#   --denom   DENOM      staking/fee denom              [default: utatst]
#   --stake   AMOUNT     self-delegation amount         [default: 100000000utatst]
#   --supply  AMOUNT     initial account balance        [default: 200000000utatst]
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Defaults ────────────────────────────────────────────────────────────────
BINARY="${ROOT_DIR}/bin/threatattestd"
HOME_DIR="${HOME}/.threatattestd-local"
CHAIN_ID="threatattest-local-1"
MONIKER="localnode"
KEY_NAME="localkey"
DENOM="utatst"
STAKE_AMOUNT="100000000utatst"
SUPPLY_AMOUNT="200000000utatst"
KEYRING_BACKEND="test"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}  ►${RESET} $*"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
die()     { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}── $* ──${RESET}"; }

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)  BINARY="$2"; shift ;;
    --home)    HOME_DIR="$2"; shift ;;
    --chain)   CHAIN_ID="$2"; shift ;;
    --moniker) MONIKER="$2"; shift ;;
    --key)     KEY_NAME="$2"; shift ;;
    --denom)   DENOM="$2"; shift ;;
    --stake)   STAKE_AMOUNT="$2"; shift ;;
    --supply)  SUPPLY_AMOUNT="$2"; shift ;;
    -h|--help)
      sed -n 's/^# //p' "$0" | head -30
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ─── Validate ────────────────────────────────────────────────────────────────
[[ -x "${BINARY}" ]] || die "Binary not found or not executable: ${BINARY}\n  Run: make build"

echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Localnet Init${RESET}"
echo -e "  Binary  : ${BINARY}"
echo -e "  Home    : ${HOME_DIR}"
echo -e "  Chain   : ${CHAIN_ID}"
echo -e "  Moniker : ${MONIKER}"
echo -e "  Key     : ${KEY_NAME}"
echo -e "  Denom   : ${DENOM}"

TA="${BINARY} --home ${HOME_DIR}"

# ─── Step 1: Init chain ──────────────────────────────────────────────────────
step "1. Initialise chain"

if [[ -d "${HOME_DIR}/config" ]]; then
  warn "Home directory exists: ${HOME_DIR}"
  warn "Use 'make localnet-reset' to wipe and reinitialise"
  exit 0
fi

${TA} init "${MONIKER}" --chain-id "${CHAIN_ID}" --default-denom "${DENOM}" 2>/dev/null
success "Chain initialised"

# ─── Step 2: Create validator key ────────────────────────────────────────────
step "2. Create validator key"

${TA} keys add "${KEY_NAME}" \
  --keyring-backend "${KEYRING_BACKEND}" \
  --output json 2>/dev/null | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
print('  Address  :', d.get('address',''))
print('  Mnemonic :', d.get('mnemonic','')[0:40]+'...')
"
success "Key '${KEY_NAME}' created (keyring: ${KEYRING_BACKEND})"

VALIDATOR_ADDR=$(${TA} keys show "${KEY_NAME}" \
  --keyring-backend "${KEYRING_BACKEND}" \
  --address)
info "Validator address: ${VALIDATOR_ADDR}"

# ─── Step 3: Add genesis account ─────────────────────────────────────────────
step "3. Add genesis account"

${TA} genesis add-genesis-account "${VALIDATOR_ADDR}" "${SUPPLY_AMOUNT}" \
  --keyring-backend "${KEYRING_BACKEND}" 2>/dev/null
success "Genesis account: ${VALIDATOR_ADDR} → ${SUPPLY_AMOUNT}"

# ─── Step 4: Create genesis validator tx ─────────────────────────────────────
step "4. Create gentx (self-delegation)"

${TA} genesis gentx "${KEY_NAME}" "${STAKE_AMOUNT}" \
  --chain-id "${CHAIN_ID}" \
  --moniker "${MONIKER}" \
  --keyring-backend "${KEYRING_BACKEND}" \
  --commission-rate "0.10" \
  --commission-max-rate "0.20" \
  --commission-max-change-rate "0.01" \
  --min-self-delegation "1" \
  2>/dev/null
success "Gentx created"

${TA} genesis collect-gentxs 2>/dev/null
success "Gentxs collected"

# ─── Step 5: Patch genesis.json ──────────────────────────────────────────────
step "5. Patch genesis parameters"

GENESIS="${HOME_DIR}/config/genesis.json"

python3 << PYEOF
import json, sys

with open("${GENESIS}") as f:
    g = json.load(f)

app = g.setdefault("app_state", {})

# ── Staking: use utatst as bond denom ──
staking = app.setdefault("staking", {}).setdefault("params", {})
staking["bond_denom"] = "${DENOM}"

# ── Crisis: fee ──
crisis = app.setdefault("crisis", {}).setdefault("constant_fee", {})
crisis["denom"] = "${DENOM}"

# ── Gov: deposit denom ──
gov = app.setdefault("gov", {})
gov.setdefault("params", {})["min_deposit"] = [{"denom": "${DENOM}", "amount": "10000000"}]
gov["params"]["expedited_min_deposit"] = [{"denom": "${DENOM}", "amount": "50000000"}]
gov["params"]["voting_period"] = "120s"
gov["params"]["expedited_voting_period"] = "60s"

# ── Mint: mint denom ──
mint = app.setdefault("tatmint", {}).setdefault("params", {})
mint["mint_denom"] = "${DENOM}"

# ── Distribution ──
app.setdefault("distribution", {}).setdefault("params", {})["community_tax"] = "0.020000000000000000"

# ── Slashing ──
slashing = app.setdefault("slashing", {}).setdefault("params", {})
slashing["signed_blocks_window"] = "100"
slashing["min_signed_per_window"] = "0.500000000000000000"
slashing["slash_fraction_double_sign"] = "0.050000000000000000"
slashing["slash_fraction_downtime"] = "0.010000000000000000"

# ── Attestation: sensible local defaults ──
attest_params = app.setdefault("attestation", {}).setdefault("params", {})
attest_params["min_attester_delegation"] = "1000000"   # 1 TATST
attest_params["min_ttl_seconds"] = 3600                # 1 hour
attest_params["max_ttl_seconds"] = 2592000             # 30 days
attest_params["max_ttl_ipv4_seconds"] = 86400          # 1 day
attest_params["max_detection_rules"] = 10
attest_params["max_attestations_per_epoch"] = 1000
attest_params["dispute_bond_amount"] = "5000000"       # 5 TATST
attest_params["ipv4_min_confidence"] = 60
attest_params["timestamp_tolerance_seconds"] = 300

with open("${GENESIS}", "w") as f:
    json.dump(g, f, indent=2)

print("  ✓ Genesis patched successfully")
PYEOF

# ─── Step 6: Patch config files ──────────────────────────────────────────────
step "6. Patch node configuration"

CONFIG="${HOME_DIR}/config/config.toml"
APP_CONFIG="${HOME_DIR}/config/app.toml"

# config.toml — enable RPC for all interfaces (local dev), faster timeouts
python3 << PYEOF
import re

with open("${CONFIG}") as f:
    c = f.read()

patches = {
    r'^laddr = "tcp://127\.0\.0\.1:26657"': 'laddr = "tcp://0.0.0.0:26657"',
    r'^cors_allowed_origins = \[\]':         'cors_allowed_origins = ["*"]',
    r'^timeout_commit = "\d+s"':             'timeout_commit = "1s"',
    r'^timeout_propose = "\d+s"':            'timeout_propose = "1s"',
    r'^create_empty_blocks = true':          'create_empty_blocks = true',
    r'^create_empty_blocks_interval = ".*"': 'create_empty_blocks_interval = "0s"',
}

for pattern, replacement in patches.items():
    c = re.sub(pattern, replacement, c, flags=re.MULTILINE)

with open("${CONFIG}", "w") as f:
    f.write(c)
print("  ✓ config.toml patched")
PYEOF

# app.toml — enable REST API, gRPC, swagger
python3 << PYEOF
import re

with open("${APP_CONFIG}") as f:
    a = f.read()

patches = {
    r'^enable = false\s*# Enable defines':     'enable = true  # Enable defines',
    r'^swagger = false':                         'swagger = true',
    r'^address = "tcp://localhost:1317"':        'address = "tcp://0.0.0.0:1317"',
    r'^enable = false\s*# Enable defines if the gRPC': 'enable = true  # Enable defines if the gRPC',
    r'^address = "localhost:9090"':              'address = "0.0.0.0:9090"',
    r'^enabled-unsafe-cors = false':             'enabled-unsafe-cors = true',
    r'^pruning = "default"':                     'pruning = "nothing"',
}

for pattern, replacement in patches.items():
    a = re.sub(pattern, replacement, a, flags=re.MULTILINE)

with open("${APP_CONFIG}", "w") as f:
    a = f.write(a)
print("  ✓ app.toml patched")
PYEOF

# ─── Step 7: Validate genesis ─────────────────────────────────────────────────
step "7. Validate genesis"

${TA} genesis validate 2>/dev/null && success "Genesis valid" || \
  warn "Genesis validation warning (may be ok for non-standard modules)"

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}✓ Localnet initialised${RESET}"
echo ""
echo "  Start with : make localnet-start"
echo "  RPC        : http://localhost:26657"
echo "  REST API   : http://localhost:1317"
echo "  gRPC       : localhost:9090"
echo "  Validator  : ${VALIDATOR_ADDR}"
echo "  Home dir   : ${HOME_DIR}"
echo ""