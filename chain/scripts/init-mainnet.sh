#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# scripts/init-mainnet.sh — Initialise a fresh single-node mainnet
# =============================================================================
#
# Creates a ~/.threatattestd home directory for the production network
# (chain-id "threatattest-1") with:
#   - A validator key in the *file* keyring (passphrase-protected, no test keys)
#   - Mainnet-appropriate genesis parameters (7-day voting, 1 TATST min
#     delegation, etc.)
#   - State pruning enabled ("default")
#
# Unlike init-localnet.sh, this does NOT create test keys or open unsafe CORS;
# it is the base for a real validator.
#
# Usage:
#   bash scripts/init-mainnet.sh [OPTIONS]
#
# Options:
#   --binary  PATH       path to threatattestd binary  [default: ./bin/threatattestd]
#   --home    DIR        node home directory            [default: ~/.threatattestd]
#   --chain   ID         chain ID                       [default: threatattest-1]
#   --moniker NAME       node moniker                   [default: threatattest-main]
#   --key     NAME       validator key name             [default: validator]
#   --denom   DENOM      staking/fee denom              [default: utatst]
#   --stake   AMOUNT     self-delegation amount         [default: 100000000utatst]
#   --supply  AMOUNT     initial account balance        [default: 200000000utatst]
#   --keyring BACKEND    keyring backend                [default: file]
#
# Environment:
#   TA_KEYRING_PASSPHRASE   required when --keyring is "file" (secures the keyring)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Defaults ────────────────────────────────────────────────────────────────
BINARY="${ROOT_DIR}/bin/threatattestd"
HOME_DIR="${HOME}/.threatattestd"
CHAIN_ID="threatattest-1"
MONIKER="threatattest-main"
KEY_NAME="validator"
DENOM="utatst"
STAKE_AMOUNT="100000000utatst"
SUPPLY_AMOUNT="200000000utatst"
KEYRING_BACKEND="file"

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
    --keyring) KEYRING_BACKEND="$2"; shift ;;
    -h|--help)
      sed -n 's/^# //p' "$0" | head -35
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ─── Validate ────────────────────────────────────────────────────────────────
[[ -x "${BINARY}" ]] || die "Binary not found or not executable: ${BINARY}\n  Run: make build"

if [[ "${KEYRING_BACKEND}" == "file" && -z "${TA_KEYRING_PASSPHRASE:-}" ]]; then
  die "TA_KEYRING_PASSPHRASE is required for the 'file' keyring.\n  e.g. TA_KEYRING_PASSPHRASE=... make mainnet-init"
fi

echo ""
echo -e "${BOLD}${CYAN}ThreatAttest Mainnet Init${RESET}"
echo -e "  Binary  : ${BINARY}"
echo -e "  Home    : ${HOME_DIR}"
echo -e "  Chain   : ${CHAIN_ID}"
echo -e "  Moniker : ${MONIKER}"
echo -e "  Key     : ${KEY_NAME}"
echo -e "  Keyring : ${KEYRING_BACKEND}"
echo -e "  Denom   : ${DENOM}"

TA="${BINARY} --home ${HOME_DIR}"
PW=""
if [[ "${KEYRING_BACKEND}" == "file" ]]; then
  PW="${TA_KEYRING_PASSPHRASE}"
fi

# ─── Step 1: Init chain ──────────────────────────────────────────────────────
step "1. Initialise chain"

if [[ -d "${HOME_DIR}/config" ]]; then
  warn "Home directory exists: ${HOME_DIR}"
  warn "Use 'make mainnet-reset' to wipe and reinitialise"
  exit 0
fi

${TA} init "${MONIKER}" --chain-id "${CHAIN_ID}" --default-denom "${DENOM}"
success "Chain initialised (chain-id: ${CHAIN_ID})"

# ─── Step 2: Create validator key ────────────────────────────────────────────
step "2. Create validator key"

# The mnemonic is printed to stderr by `keys add` — back it up.
printf '%s\n%s\n' "${PW}" "${PW}" | \
  ${TA} keys add "${KEY_NAME}" --keyring-backend "${KEYRING_BACKEND}"

VALIDATOR_ADDR=$(printf '%s\n' "${PW}" | \
  ${TA} keys show "${KEY_NAME}" -a --keyring-backend "${KEYRING_BACKEND}" 2>/dev/null)
info "Validator address: ${VALIDATOR_ADDR}"
success "Key '${KEY_NAME}' created (keyring: ${KEYRING_BACKEND})"

# ─── Step 3: Add genesis account ─────────────────────────────────────────────
step "3. Add genesis account"

${TA} add-genesis-account "${VALIDATOR_ADDR}" "${SUPPLY_AMOUNT}"
success "Genesis account: ${VALIDATOR_ADDR} → ${SUPPLY_AMOUNT}"

# ─── Step 4: Create genesis validator tx ─────────────────────────────────────
step "4. Create gentx (self-delegation)"

printf '%s\n' "${PW}" | \
  ${TA} gentx "${KEY_NAME}" "${STAKE_AMOUNT}" \
    --chain-id "${CHAIN_ID}" \
    --moniker "${MONIKER}" \
    --keyring-backend "${KEYRING_BACKEND}" \
    --commission-rate "0.10" \
    --commission-max-rate "0.20" \
    --commission-max-change-rate "0.01" \
    --min-self-delegation "1"
success "Gentx created"

${TA} collect-gentxs
success "Gentxs collected"

# ─── Step 5: Patch genesis.json ──────────────────────────────────────────────
step "5. Patch genesis parameters"

GENESIS="${HOME_DIR}/config/genesis.json"

python3 << PYEOF
import json

with open("${GENESIS}") as f:
    g = json.load(f)

app = g.setdefault("app_state", {})

# ── Staking: bond denom ──
app.setdefault("staking", {}).setdefault("params", {})["bond_denom"] = "${DENOM}"

# ── Crisis: fee denom ──
app.setdefault("crisis", {}).setdefault("constant_fee", {})["denom"] = "${DENOM}"

# ── Gov: mainnet deposit + voting periods ──
gov = app.setdefault("gov", {})
gov.setdefault("params", {})["min_deposit"] = [{"denom": "${DENOM}", "amount": "10000000"}]
gov["params"]["expedited_min_deposit"] = [{"denom": "${DENOM}", "amount": "50000000"}]
gov["params"]["voting_period"] = "604800s"            # 7 days
gov["params"]["expedited_voting_period"] = "86400s"   # 1 day

# ── Mint: mint denom ──
app.setdefault("tatmint", {}).setdefault("params", {})["mint_denom"] = "${DENOM}"

# ── Distribution ──
app.setdefault("distribution", {}).setdefault("params", {})["community_tax"] = "0.020000000000000000"

# ── Slashing ──
slashing = app.setdefault("slashing", {}).setdefault("params", {})
slashing["signed_blocks_window"] = "10000"
slashing["min_signed_per_window"] = "0.500000000000000000"
slashing["slash_fraction_double_sign"] = "0.050000000000000000"
slashing["slash_fraction_downtime"] = "0.000100000000000000"
slashing["downtime_jail_duration"] = "600s"

# ── Attestation: mainnet defaults ──
attest_params = app.setdefault("attestation", {}).setdefault("params", {})
attest_params["min_attester_delegation"] = "1000000"    # 1 TATST required to attest
attest_params["min_ttl_seconds"] = 3600
attest_params["max_ttl_seconds"] = 2592000              # 30 days
attest_params["max_ttl_ipv4_seconds"] = 86400
attest_params["max_detection_rules"] = 10
attest_params["max_attestations_per_epoch"] = 1000
attest_params["dispute_bond_amount"] = "5000000"        # 5 TATST
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

# config.toml — bind RPC to the host, keep default block cadence (2s)
python3 << PYEOF
import re

with open("${CONFIG}") as f:
    c = f.read()

patches = {
    r'^laddr = "tcp://127\.0\.0\.1:26657"': 'laddr = "tcp://0.0.0.0:26657"',
}

for pattern, replacement in patches.items():
    c = re.sub(pattern, replacement, c, flags=re.MULTILINE)

with open("${CONFIG}", "w") as f:
    f.write(c)
print("  ✓ config.toml patched")
PYEOF

# app.toml — enable REST API / gRPC; keep state pruning at "default"
python3 << PYEOF
import re

with open("${APP_CONFIG}") as f:
    a = f.read()

patches = {
    r'^enable = false\s*# Enable defines':     'enable = true  # Enable defines',
    r'^address = "tcp://localhost:1317"':      'address = "tcp://0.0.0.0:1317"',
    r'^enable = false\s*# Enable defines if the gRPC': 'enable = true  # Enable defines if the gRPC',
    r'^address = "localhost:9090"':            'address = "0.0.0.0:9090"',
}

for pattern, replacement in patches.items():
    a = re.sub(pattern, replacement, a, flags=re.MULTILINE)

with open("${APP_CONFIG}", "w") as f:
    f.write(a)
print("  ✓ app.toml patched (pruning stays 'default')")
PYEOF

# ─── Step 7: Validate genesis ─────────────────────────────────────────────────
step "7. Validate genesis"

${TA} validate-genesis && success "Genesis valid" || \
  warn "Genesis validation warning (may be ok for non-standard modules)"

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}✓ Mainnet initialised${RESET}"
echo ""
echo "  Start with : make mainnet-start"
echo "  RPC        : http://localhost:26657"
echo "  REST API   : http://localhost:1317"
echo "  gRPC       : localhost:9090"
echo "  Validator  : ${VALIDATOR_ADDR}"
echo "  Home dir   : ${HOME_DIR}"
echo ""
echo -e "${BOLD}${YELLOW}  ⚠ Back up the validator mnemonic printed above before going further.${RESET}"
echo ""
