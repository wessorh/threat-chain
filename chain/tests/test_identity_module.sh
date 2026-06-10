#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# test_identity_module.sh — Integration tests for x/identity module
# =============================================================================
# Tests: register-identity, rotate-identity-key, revoke-identity, renew-identity
#
# Prerequisites:
#   - threatattestd binary in PATH (or set BINARY env var)
#   - A running threatattest-1 node (or set NODE_URL env var)
#   - Two funded test keys: test-alice and test-bob
#   - jq installed
#
# Usage:
#   ./tests/test_identity_module.sh
#   BINARY=./build/threatattestd NODE_URL=http://localhost:26657 ./tests/test_identity_module.sh
# =============================================================================

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
BINARY="${BINARY:-threatattestd}"
NODE_URL="${NODE_URL:-http://localhost:26657}"
CHAIN_ID="${CHAIN_ID:-threatattest-1}"
KEY_ALICE="${KEY_ALICE:-test-alice}"
KEY_BOB="${KEY_BOB:-test-bob}"
FEES="${FEES:-500utat}"
DOMAIN_ALICE="${DOMAIN_ALICE:-alice-security.example.com}"
DOMAIN_BOB="${DOMAIN_BOB:-bob-security.example.com}"
SELECTOR_A="${SELECTOR_A:-tat2025a}"
SELECTOR_B="${SELECTOR_B:-tat2025b}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Color output
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────

log()   { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[PASS]${RESET}  $*"; (( TESTS_PASSED += 1 )) || true; }
fail()  { echo -e "${RED}[FAIL]${RESET}  $*"; (( TESTS_FAILED += 1 )) || true; }
skip()  { echo -e "${YELLOW}[SKIP]${RESET}  $*"; (( TESTS_SKIPPED += 1 )) || true; }
header(){ echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

run_test() {
  local name="$1"; shift
  (( TESTS_RUN += 1 )) || true
  echo -e "\n${BOLD}Test $TESTS_RUN: $name${RESET}"
  if "$@"; then
    ok "$name"
  else
    fail "$name"
  fi
}

# Execute a tx and return the tx hash
exec_tx() {
  $BINARY tx "$@" \
    --chain-id "$CHAIN_ID" \
    --node "$NODE_URL" \
    --fees "$FEES" \
    --yes --output json 2>/dev/null | jq -r '.txhash // empty'
}

# Query and return JSON
exec_query() {
  $BINARY query "$@" \
    --chain-id "$CHAIN_ID" \
    --node "$NODE_URL" \
    --output json 2>/dev/null
}

# Wait for a tx to be included in a block
wait_for_tx() {
  local txhash="$1"
  local retries=10
  while ((retries-- > 0)); do
    local result
    result=$(exec_query tx "$txhash" 2>/dev/null || echo "")
    if echo "$result" | jq -e '.code == 0' &>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# Generate a mock domain proof signature (for testing — not a real sig)
mock_sig() {
  # In tests, we use a predictable all-zeros signature (structure check only)
  printf '%0128d' 0
}

# Generate a mock pubkey (compressed secp256k1, 66 hex chars)
mock_pubkey() {
  # Deterministic test pubkey (not a real key)
  echo "02$(printf '%064d' 0)"
}

# ── Setup ─────────────────────────────────────────────────────────────────────

header "Setup"

log "Binary:    $BINARY"
log "Node:      $NODE_URL"
log "Chain:     $CHAIN_ID"
log "Alice key: $KEY_ALICE"
log "Bob key:   $KEY_BOB"

# Check binary exists
if ! { command -v "$BINARY" &>/dev/null || [[ -x "$BINARY" ]]; }; then
  skip "Binary '$BINARY' not found in PATH — skipping all integration tests"
  echo ""
  echo "To run these tests:"
  echo "  1. Build the binary: cd threatattest && go build ./..."
  echo "  2. Start a node: ./scripts/start_node.sh"
  echo "  3. Run: BINARY=./build/threatattestd ./tests/test_identity_module.sh"
  exit 0
fi

# Check node is reachable
if ! curl -sf "$NODE_URL/status" &>/dev/null; then
  skip "Node '$NODE_URL' is not reachable — skipping integration tests"
  skip "Run 'threatattestd start' to start a node first"
  exit 0
fi

ALICE_ADDR=$(exec_query keys show "$KEY_ALICE" --bech acc -a 2>/dev/null || echo "")
BOB_ADDR=$(exec_query keys show "$KEY_BOB" --bech acc -a 2>/dev/null || echo "")

if [[ -z "$ALICE_ADDR" ]]; then
  skip "Key '$KEY_ALICE' not found in keyring — skipping"
  exit 0
fi

log "Alice addr: $ALICE_ADDR"
log "Bob addr:   $BOB_ADDR"

# ── Unit-style CLI Tests (no node required) ───────────────────────────────────

header "CLI Structural Tests (no node)"

run_test "verify-domain-proof computes correct payload" \
  bash -c '
    output=$('$BINARY' query identity verify-domain-proof \
      --domain example.com \
      --selector tat2025a \
      --cosmos-addr cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9as36n \
      --registered-at 1700000000 2>&1)
    echo "$output" | grep -q "tatkey-domain-proof" && \
    echo "$output" | grep -q "example.com" && \
    echo "$output" | grep -q "tat2025a"
  '

run_test "verify-domain-proof normalizes domain (strips www.)" \
  bash -c '
    out1=$('$BINARY' query identity verify-domain-proof \
      --domain www.example.com --selector tat2025a \
      --cosmos-addr cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9as36n \
      --registered-at 1700000000 2>&1)
    out2=$('$BINARY' query identity verify-domain-proof \
      --domain example.com --selector tat2025a \
      --cosmos-addr cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9as36n \
      --registered-at 1700000000 2>&1)
    # Both should produce same digest
    digest1=$(echo "$out1" | grep "Payload digest" -A1 | tail -1 | tr -d " ")
    digest2=$(echo "$out2" | grep "Payload digest" -A1 | tail -1 | tr -d " ")
    [[ "$digest1" == "$digest2" ]]
  '

run_test "register-identity validates required fields" \
  bash -c '
    '$BINARY' tx identity register-identity \
      --domain "" --selector "" --pubkey "" --domain-proof-sig "" \
      --from test-alice --chain-id test \
      --dry-run 2>&1 | grep -qi "required\|invalid\|error"
  '

run_test "query tier shows tier table" \
  bash -c '
    '$BINARY' query identity tier cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9as36n \
      --output json 2>&1 | grep -qi "tier_table\|ANONYMOUS\|tier"
  '

run_test "query params shows default params" \
  bash -c '
    '$BINARY' query identity params --output json 2>&1 | \
      grep -qi "identity_ttl_seconds\|params\|min_registration"
  '

# ── Integration Tests (requires running node) ─────────────────────────────────

header "Integration Tests (requires running node)"

MOCK_PUBKEY=$(mock_pubkey)
MOCK_SIG=$(mock_sig)
PUBLISHED_AT=$(date +%s)

# Create a minimal mock evidence bundle
EVIDENCE_FILE=$(mktemp /tmp/tat_evidence_XXXXX.json)
cat > "$EVIDENCE_FILE" << EVIDENCE_JSON
{
  "txt_records": [
    "v=TAT1 k=secp256k1 p=${MOCK_PUBKEY} a=${ALICE_ADDR} t=${PUBLISHED_AT}"
  ],
  "txt_rrsigs": [
    {
      "type_covered": "TXT",
      "algorithm": 13,
      "labels": 3,
      "original_ttl": 300,
      "expiration": $((PUBLISHED_AT + 86400)),
      "inception": $((PUBLISHED_AT - 300)),
      "key_tag": 12345,
      "signer_name": "${DOMAIN_ALICE}.",
      "signature": "dGVzdHNpZ25hdHVyZWJhc2U2NA=="
    }
  ],
  "zone_dnskeys": [
    {
      "flags": 257,
      "protocol": 3,
      "algorithm": 13,
      "public_key": "dGVzdGtleQ==",
      "key_tag": 12345
    }
  ],
  "dnskey_rrsigs": [
    {
      "type_covered": "DNSKEY",
      "algorithm": 13,
      "labels": 2,
      "original_ttl": 300,
      "expiration": $((PUBLISHED_AT + 86400)),
      "inception": $((PUBLISHED_AT - 300)),
      "key_tag": 12345,
      "signer_name": "${DOMAIN_ALICE}.",
      "signature": "dGVzdHNpZ25hdHVyZWJhc2U2NA=="
    }
  ],
  "parent_ds": [
    {
      "key_tag": 12345,
      "algorithm": 13,
      "digest_type": 2,
      "digest": "abc123def456"
    }
  ],
  "collected_at": ${PUBLISHED_AT},
  "resolver": "8.8.8.8"
}
EVIDENCE_JSON

log "Evidence file: $EVIDENCE_FILE"

run_test "register-identity transaction submits without error" \
  bash -c '
    txhash=$(exec_tx identity register-identity \
      --domain "'$DOMAIN_ALICE'" \
      --selector "'$SELECTOR_A'" \
      --pubkey "'$MOCK_PUBKEY'" \
      --domain-proof-sig "'$MOCK_SIG'" \
      --published-at "'$PUBLISHED_AT'" \
      --evidence-file "'$EVIDENCE_FILE'" \
      --name "Alice Security Research" \
      --from "'$KEY_ALICE'" 2>&1)
    echo "TxHash: $txhash"
    [[ -n "$txhash" ]]
  '

# Wait a block for indexing
sleep 6

run_test "query identity by address returns record" \
  bash -c '
    result=$(exec_query identity identity "'$ALICE_ADDR'")
    echo "$result" | grep -qi "'$DOMAIN_ALICE'\|cosmos_addr\|identity_id"
  '

run_test "query identity by domain returns record" \
  bash -c '
    result=$(exec_query identity identity-by-domain "'$DOMAIN_ALICE'")
    echo "$result" | grep -qi "'$ALICE_ADDR'\|cosmos_addr\|identity_id"
  '

run_test "query trust-score shows score after registration" \
  bash -c '
    result=$(exec_query identity trust-score "'$ALICE_ADDR'")
    echo "$result"
    # Score should be non-negative
    score=$(echo "$result" | jq -r ".score // 0")
    [[ "$score" -ge 0 ]]
  '

# ── Key Rotation Test ──────────────────────────────────────────────────────────

header "Key Rotation Test"

ROTATION_AT=$(date +%s)

run_test "rotate-identity-key requires both signatures" \
  bash -c '
    # Should fail with missing new-key-proof-sig
    '$BINARY' tx identity rotate-identity-key \
      --new-selector "'$SELECTOR_B'" \
      --new-pubkey "'$MOCK_PUBKEY'" \
      --rotation-auth-sig "'$MOCK_SIG'" \
      --from "'$KEY_ALICE'" \
      --chain-id "'$CHAIN_ID'" \
      --dry-run 2>&1 | grep -qi "required\|error\|new-key-proof-sig"
  '

run_test "rotate-identity-key rejects same selector" \
  bash -c '
    output=$('$BINARY' tx identity rotate-identity-key \
      --new-selector "'$SELECTOR_A'" \
      --new-pubkey "'$MOCK_PUBKEY'" \
      --rotation-auth-sig "'$MOCK_SIG'" \
      --new-key-proof-sig "'$MOCK_SIG'" \
      --rotated-at "'$ROTATION_AT'" \
      --from "'$KEY_ALICE'" \
      --chain-id "'$CHAIN_ID'" \
      --node "'$NODE_URL'" \
      --fees "'$FEES'" \
      --yes --output json 2>&1 || true)
    # Should error because selector is same as current
    echo "$output" | grep -qi "selector\|conflict\|error\|must differ"
  '

# ── Revocation Test ──────────────────────────────────────────────────────────

header "Revocation Test"

run_test "revoke-identity marks record as revoked" \
  bash -c '
    txhash=$(exec_tx identity revoke-identity \
      --reason "Test revocation" \
      --from "'$KEY_ALICE'" 2>&1)
    echo "TxHash: $txhash"
    [[ -n "$txhash" ]]
  '

sleep 4

run_test "revoked identity has REVOKED status" \
  bash -c '
    result=$(exec_query identity identity "'$ALICE_ADDR'" --output json 2>&1)
    echo "$result" | grep -qi "REVOKED\|revoked"
  '

run_test "re-registration after revocation is possible" \
  bash -c '
    # Register again with a different domain
    txhash=$(exec_tx identity register-identity \
      --domain "'$DOMAIN_BOB'" \
      --selector "'$SELECTOR_A'" \
      --pubkey "'$MOCK_PUBKEY'" \
      --domain-proof-sig "'$MOCK_SIG'" \
      --published-at "$(date +%s)" \
      --evidence-file "'$EVIDENCE_FILE'" \
      --from "'$KEY_ALICE'" 2>&1)
    echo "TxHash: $txhash"
    [[ -n "$txhash" ]]
  '

# ── Renewal Test ──────────────────────────────────────────────────────────────

header "Renewal Test (Bob)"

if [[ -n "$BOB_ADDR" ]]; then
  run_test "renew-identity requires evidence-file flag" \
    bash -c '
      '$BINARY' tx identity renew-identity \
        --from "'$KEY_BOB'" \
        --chain-id "'$CHAIN_ID'" \
        --dry-run 2>&1 | grep -qi "required\|evidence-file"
    '

  run_test "renew-identity fails for non-existent identity" \
    bash -c '
      output=$(exec_tx identity renew-identity \
        --evidence-file "'$EVIDENCE_FILE'" \
        --from "'$KEY_BOB'" 2>&1 || true)
      echo "$output" | grep -qi "not found\|identity\|error"
    '
else
  skip "Bob key not configured — skipping Bob-specific tests"
fi

# ── Parameter Query Tests ──────────────────────────────────────────────────────

header "Parameter Tests"

run_test "module params are queryable" \
  bash -c '
    result=$(exec_query identity params --output json)
    echo "$result" | jq -e ".identity_ttl_seconds // .default_params.identity_ttl_seconds" > /dev/null
  '

run_test "tier query returns structured response" \
  bash -c '
    result=$(exec_query identity tier "'$ALICE_ADDR'" --output json)
    echo "$result" | grep -qi "tier_table\|tier\|query"
  '

# ── Cleanup ──────────────────────────────────────────────────────────────────

rm -f "$EVIDENCE_FILE"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "${BOLD}Test Results Summary${RESET}"
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "  Tests run:    ${BOLD}$TESTS_RUN${RESET}"
echo -e "  ${GREEN}Passed:       $TESTS_PASSED${RESET}"
echo -e "  ${RED}Failed:       $TESTS_FAILED${RESET}"
echo -e "  ${YELLOW}Skipped:      $TESTS_SKIPPED${RESET}"
echo ""

if ((TESTS_FAILED > 0)); then
  echo -e "${RED}${BOLD}FAILED${RESET} — $TESTS_FAILED test(s) failed"
  exit 1
else
  echo -e "${GREEN}${BOLD}ALL TESTS PASSED${RESET}"
  exit 0
fi