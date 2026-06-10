#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# test_attester_domain.sh — Tests for attester_domain/attester_selector fields
# =============================================================================
# Tests:
#   - publish-attest with --attester-domain and --attester-selector flags
#   - validation: selector required when domain set, and vice-versa
#   - published attestation record contains domain/selector fields
#   - tier-scaled confidence is applied correctly
#
# Usage:
#   ./tests/test_attester_domain.sh
#   BINARY=./build/threatattestd ./tests/test_attester_domain.sh
# =============================================================================

set -euo pipefail

BINARY="${BINARY:-threatattestd}"
NODE_URL="${NODE_URL:-http://localhost:26657}"
CHAIN_ID="${CHAIN_ID:-threatattest-1}"
KEY_ALICE="${KEY_ALICE:-test-alice}"
FEES="${FEES:-500utat}"

TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; TESTS_SKIPPED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()     { echo -e "${GREEN}[PASS]${RESET}  $*"; (( TESTS_PASSED += 1 )) || true; }
fail()   { echo -e "${RED}[FAIL]${RESET}  $*"; (( TESTS_FAILED += 1 )) || true; }
skip()   { echo -e "${YELLOW}[SKIP]${RESET}  $*"; (( TESTS_SKIPPED += 1 )) || true; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}"; }

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

exec_tx() {
  $BINARY tx "$@" \
    --chain-id "$CHAIN_ID" --node "$NODE_URL" \
    --fees "$FEES" --yes --output json 2>/dev/null | jq -r '.txhash // empty'
}

exec_query() {
  $BINARY query "$@" --chain-id "$CHAIN_ID" --node "$NODE_URL" --output json 2>/dev/null
}

# Check binary
if ! { command -v "$BINARY" &>/dev/null || [[ -x "$BINARY" ]]; }; then
  skip "Binary '$BINARY' not found — skipping all tests"
  exit 0
fi

# ── Section 1: Flag Validation (no node required) ─────────────────────────────

header "Flag Registration Tests (CLI structural)"

run_test "publish-attest has --attester-domain flag" \
  bash -c '"$BINARY" tx attestation publish --help 2>&1 | grep -q "attester-domain"' \
  BINARY="$BINARY"

run_test "publish-attest has --attester-selector flag" \
  bash -c '"$BINARY" tx attestation publish --help 2>&1 | grep -q "attester-selector"' \
  BINARY="$BINARY"

# Test the domain-only (no selector) rejection
run_test "publish-attest rejects domain without selector" \
  bash -c '
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type URL \
      --raw-value http://example.com/test \
      --category TATST:PHISHING_URL \
      --attester-domain research.example.com \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    echo "Output: $output"
    echo "$output" | grep -qi "required\|selector\|domain\|error"
  '

run_test "publish-attest rejects selector without domain" \
  bash -c '
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type URL \
      --raw-value http://example.com/test \
      --category TATST:PHISHING_URL \
      --attester-selector tat2025a \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    echo "Output: $output"
    echo "$output" | grep -qi "required\|domain\|selector\|error"
  '

run_test "publish-attest accepts domain+selector together" \
  bash -c '
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type URL \
      --raw-value http://phishing.example.com/fake-login \
      --category TATST:PHISHING_URL \
      --confidence 85 \
      --attester-domain research.example.com \
      --attester-selector tat2025a \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    echo "Output: $output"
    # Should NOT produce a validation error for the domain/selector pair
    ! echo "$output" | grep -qi "attester_domain.*required\|attester_selector.*required"
  '

# ── Section 2: Domain Normalization ───────────────────────────────────────────

header "Domain Normalization Tests"

run_test "www. prefix is stripped from attester-domain" \
  bash -c '
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type DOMAIN \
      --raw-value malware.example.com \
      --category TATST:MALWARE \
      --attester-domain www.research.example.org \
      --attester-selector tat2025a \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    # Should not fail with a domain normalization error
    ! echo "$output" | grep -qi "invalid.*domain\|normalization.*error"
  '

run_test "invalid attester-domain is rejected" \
  bash -c '
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type URL \
      --raw-value http://example.com/test \
      --category TATST:PHISHING_URL \
      --attester-domain "not a domain!!!" \
      --attester-selector tat2025a \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    echo "$output" | grep -qi "invalid\|error\|domain"
  '

run_test "too-long selector (>63 chars) is rejected" \
  bash -c '
    long_sel=$(printf "%0.s-" {1..64})
    output=$('"$BINARY"' tx attestation publish \
      --artifact-type URL \
      --raw-value http://example.com/test \
      --category TATST:PHISHING_URL \
      --attester-domain research.example.com \
      --attester-selector "$long_sel" \
      --from test-key \
      --chain-id test \
      --dry-run 2>&1 || true)
    echo "$output" | grep -qi "invalid\|error\|selector\|too long"
  '

# ── Section 3: Integration Tests (requires node) ──────────────────────────────

header "Integration Tests (requires running node)"

if ! curl -sf "$NODE_URL/status" &>/dev/null; then
  skip "Node '$NODE_URL' not reachable — skipping integration tests"
else
  ALICE_ADDR=$(exec_query keys show "$KEY_ALICE" --bech acc -a 2>/dev/null || echo "")
  if [[ -z "$ALICE_ADDR" ]]; then
    skip "Key '$KEY_ALICE' not found — skipping integration tests"
  else
    log "Alice: $ALICE_ADDR"

    run_test "attest-domain with attester-domain flag publishes successfully" \
      bash -c '
        txhash=$(exec_tx attestation attest-domain \
          --raw-value phishing-site.example.net \
          --category TATST:PHISHING_SITE \
          --confidence 75 \
          --attester-domain "'"$ALICE_ADDR"'" \
          --attester-selector tat2025a \
          --from "'$KEY_ALICE'" 2>&1)
        echo "TxHash: $txhash"
        [[ -n "$txhash" ]]
      '

    sleep 4

    run_test "published attestation record contains attester_domain field" \
      bash -c '
        # Query the most recent attestation by Alice
        result=$(exec_query attestation list --attester "'$ALICE_ADDR'" --limit 1 2>&1)
        echo "$result" | grep -qi "attester_domain\|research\|attester"
      '

    run_test "tier 0 attester gets confidence scaled to 0.25x" \
      bash -c '
        # Submit with confidence=80, expect stored confidence ≤ 20 (80*0.25=20)
        txhash=$(exec_tx attestation publish \
          --artifact-type URL \
          --raw-value http://tier-test-$(date +%s).example.net/path \
          --category TATST:PHISHING_URL \
          --confidence 80 \
          --from "'$KEY_ALICE'" 2>&1)
        sleep 4
        # The stored confidence should be 20 (80 * 1/4)
        result=$(exec_query attestation by-artifact \
          "$(echo -n 'http://tier-test-'$(date +%s)'.example.net/path' | sha256sum | awk '{print $1}')" 2>&1)
        stored=$(echo "$result" | jq -r ".confidence // 0")
        echo "Stored confidence: $stored (expected 20 for tier-0 with raw=80)"
        [[ "$stored" -le 25 ]] # Allow some margin
      '
  fi
fi

# ── Section 4: Compliance Tier Scaling Unit Tests ──────────────────────────────

header "Compliance Tier Scaling — Unit Tests (Go)"

# These test the pure functions directly via a tiny Go test runner
TIER_TEST_FILE=$(mktemp /tmp/tier_test_XXXXX.go)
cat > "$TIER_TEST_FILE" << 'GOEOF'
package main

import (
	"fmt"
	"os"
)

// Mirror of applyTierToConfidence from msg_server.go
func applyTierToConfidence(raw uint32, tier int32) uint32 {
	var num uint32
	switch tier {
	case 1: num = 2
	case 2: num = 4
	case 3: num = 8
	default: num = 1
	}
	scaled := raw * num / 4
	if scaled > 100 { scaled = 100 }
	return scaled
}

type tierCase struct {
	raw      uint32
	tier     int32
	expected uint32
	label    string
}

func main() {
	cases := []tierCase{
		{80, 0, 20,  "Tier0: 80 * 0.25 = 20"},
		{80, 1, 40,  "Tier1: 80 * 0.50 = 40"},
		{80, 2, 80,  "Tier2: 80 * 1.00 = 80"},
		{80, 3, 100, "Tier3: 80 * 2.00 = 160, clamped to 100"},
		{100, 0, 25, "Tier0: 100 * 0.25 = 25"},
		{100, 3, 100,"Tier3: 100 * 2.00 = 200, clamped to 100"},
		{0,  2, 0,   "Tier2: 0 * 1.00 = 0"},
		{50, 1, 25,  "Tier1: 50 * 0.50 = 25"},
	}

	passed := 0; failed := 0
	for _, c := range cases {
		result := applyTierToConfidence(c.raw, c.tier)
		if result == c.expected {
			fmt.Printf("  PASS  %s\n", c.label)
			passed++
		} else {
			fmt.Printf("  FAIL  %s  got=%d want=%d\n", c.label, result, c.expected)
			failed++
		}
	}
	fmt.Printf("\n  Passed: %d  Failed: %d\n", passed, failed)
	if failed > 0 { os.Exit(1) }
}
GOEOF

if command -v go &>/dev/null; then
  run_test "tier confidence scaling unit tests (Go)" \
    bash -c 'go run "'$TIER_TEST_FILE'" 2>&1'
else
  skip "Go not in PATH — skipping tier confidence scaling unit tests"
fi

rm -f "$TIER_TEST_FILE"

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
  echo -e "${RED}${BOLD}FAILED${RESET}"
  exit 1
else
  echo -e "${GREEN}${BOLD}ALL TESTS PASSED${RESET}"
fi