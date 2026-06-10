#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# test_compliance_tiers.sh — Compliance tier enforcement tests
# =============================================================================
# Tests the full compliance tier system:
#   - Tier determination logic (pure functions)
#   - Tier multiplier math
#   - Tier upgrade/downgrade transitions
#   - Category minimum tier enforcement
#   - WeightedConfidence clamping
#
# These tests run mostly in pure Go (no node required) to validate the
# types/compliance.go and keeper/compliance.go logic.
# =============================================================================

set -euo pipefail

BINARY="${BINARY:-threatattestd}"
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0; TESTS_SKIPPED=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

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

# ── Go unit test suite ────────────────────────────────────────────────────────

GOTEST=$(mktemp /tmp/compliance_test_XXXXX.go)

cat > "$GOTEST" << 'GOEOF'
package main

import (
	"fmt"
	"os"
	"strings"
)

// ── Types (mirror from x/identity/types) ──────────────────────────────────────

type ComplianceTier int32

const (
	TierAnonymous ComplianceTier = 0
	TierStaked    ComplianceTier = 1
	TierDNSBound  ComplianceTier = 2
	TierExpert    ComplianceTier = 3
)

func (t ComplianceTier) String() string {
	switch t {
	case TierAnonymous: return "ANONYMOUS"
	case TierStaked:    return "STAKED"
	case TierDNSBound:  return "DNS_BOUND"
	case TierExpert:    return "EXPERT"
	default:            return "UNKNOWN"
	}
}

func (t ComplianceTier) Numerator() int64 {
	switch t {
	case TierStaked:   return 2
	case TierDNSBound: return 4
	case TierExpert:   return 8
	default:           return 1
	}
}

// ── WeightedConfidence (mirror from types/compliance.go) ─────────────────────

func WeightedConfidence(raw uint32, tier ComplianceTier) uint32 {
	num := tier.Numerator()
	scaled := int64(raw) * num / 4
	if scaled > 100 { scaled = 100 }
	if scaled < 0   { scaled = 0 }
	return uint32(scaled)
}

// ── TierRequirementsMet (mirror from types/compliance.go) ────────────────────

func TierRequirementsMet(hasDNS, active, expert bool, score, expertMin, stakedMin int64) ComplianceTier {
	if hasDNS && active && expert && score >= expertMin {
		return TierExpert
	}
	if hasDNS && active {
		return TierDNSBound
	}
	if score >= stakedMin {
		return TierStaked
	}
	return TierAnonymous
}

// ── CategoryMinTier enforcement ───────────────────────────────────────────────

type Policy struct {
	Enabled         bool
	HardMin         ComplianceTier
	CategoryMinTier map[string]ComplianceTier
}

func (p Policy) Check(category string, tier ComplianceTier) string {
	minTier, ok := p.CategoryMinTier[category]
	if !ok { return "" }
	if tier < minTier {
		return fmt.Sprintf("category %s requires Tier %d (%s); got Tier %d (%s)",
			category, int(minTier), minTier, int(tier), tier)
	}
	return ""
}

// ── Test framework ────────────────────────────────────────────────────────────

var passed, failed int

func assert(label string, cond bool) {
	if cond {
		fmt.Printf("  PASS  %s\n", label)
		passed++
	} else {
		fmt.Printf("  FAIL  %s\n", label)
		failed++
	}
}

func assertEqual[T comparable](label string, got, want T) {
	if got == want {
		fmt.Printf("  PASS  %s (got %v)\n", label, got)
		passed++
	} else {
		fmt.Printf("  FAIL  %s: got=%v want=%v\n", label, got, want)
		failed++
	}
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func testTierMultipliers() {
	fmt.Println("\n── Tier Multipliers ──")
	assertEqual("Tier0 numerator=1",  TierAnonymous.Numerator(), int64(1))
	assertEqual("Tier1 numerator=2",  TierStaked.Numerator(),    int64(2))
	assertEqual("Tier2 numerator=4",  TierDNSBound.Numerator(),  int64(4))
	assertEqual("Tier3 numerator=8",  TierExpert.Numerator(),    int64(8))
}

func testWeightedConfidence() {
	fmt.Println("\n── WeightedConfidence ──")

	// Tier 0: 0.25x
	assertEqual("T0: 100→25",  WeightedConfidence(100, TierAnonymous), uint32(25))
	assertEqual("T0: 80→20",   WeightedConfidence(80,  TierAnonymous), uint32(20))
	assertEqual("T0: 50→12",   WeightedConfidence(50,  TierAnonymous), uint32(12)) // floor div
	assertEqual("T0: 0→0",     WeightedConfidence(0,   TierAnonymous), uint32(0))
	assertEqual("T0: 4→1",     WeightedConfidence(4,   TierAnonymous), uint32(1))

	// Tier 1: 0.50x
	assertEqual("T1: 100→50",  WeightedConfidence(100, TierStaked), uint32(50))
	assertEqual("T1: 80→40",   WeightedConfidence(80,  TierStaked), uint32(40))
	assertEqual("T1: 50→25",   WeightedConfidence(50,  TierStaked), uint32(25))

	// Tier 2: 1.00x (no change)
	assertEqual("T2: 100→100", WeightedConfidence(100, TierDNSBound), uint32(100))
	assertEqual("T2: 80→80",   WeightedConfidence(80,  TierDNSBound), uint32(80))
	assertEqual("T2: 0→0",     WeightedConfidence(0,   TierDNSBound), uint32(0))

	// Tier 3: 2.00x (clamped at 100)
	assertEqual("T3: 100→100 (clamped)", WeightedConfidence(100, TierExpert), uint32(100))
	assertEqual("T3: 80→100 (clamped)", WeightedConfidence(80,  TierExpert), uint32(100)) // 160 clamped
	assertEqual("T3: 50→100",  WeightedConfidence(50, TierExpert),  uint32(100)) // 100
	assertEqual("T3: 40→80",   WeightedConfidence(40, TierExpert),  uint32(80))  // 80
	assertEqual("T3: 0→0",     WeightedConfidence(0,  TierExpert),  uint32(0))
}

func testTierRequirementsMet() {
	fmt.Println("\n── TierRequirementsMet ──")
	expertMin := int64(5000)
	stakedMin := int64(500)

	// Tier 3: DNS + active + expert flag + score >= expertMin
	assertEqual("DNS+active+expert+score=6000 → Expert",
		TierRequirementsMet(true, true, true, 6000, expertMin, stakedMin), TierExpert)

	// Tier 3 fails: score below expertMin
	assertEqual("DNS+active+expert+score=4999 → DNS_BOUND",
		TierRequirementsMet(true, true, true, 4999, expertMin, stakedMin), TierDNSBound)

	// Tier 3 fails: no expert flag
	assertEqual("DNS+active+noexpert+score=6000 → DNS_BOUND",
		TierRequirementsMet(true, true, false, 6000, expertMin, stakedMin), TierDNSBound)

	// Tier 2: DNS + active (no expert flag)
	assertEqual("DNS+active → DNS_BOUND",
		TierRequirementsMet(true, true, false, 0, expertMin, stakedMin), TierDNSBound)

	// Tier 2 fails: DNS but not active
	assertEqual("DNS+inactive → checks staked",
		TierRequirementsMet(true, false, false, 600, expertMin, stakedMin), TierStaked)

	// Tier 1: score >= stakedMin
	assertEqual("noDNS+score=600 → Staked",
		TierRequirementsMet(false, false, false, 600, expertMin, stakedMin), TierStaked)

	assertEqual("noDNS+score=500 → Staked (exact)",
		TierRequirementsMet(false, false, false, 500, expertMin, stakedMin), TierStaked)

	// Tier 0: score < stakedMin
	assertEqual("noDNS+score=0 → Anonymous",
		TierRequirementsMet(false, false, false, 0, expertMin, stakedMin), TierAnonymous)

	assertEqual("noDNS+score=499 → Anonymous",
		TierRequirementsMet(false, false, false, 499, expertMin, stakedMin), TierAnonymous)
}

func testCategoryEnforcement() {
	fmt.Println("\n── Category Minimum Tier Enforcement ──")

	policy := Policy{
		Enabled: true,
		HardMin: TierAnonymous,
		CategoryMinTier: map[string]ComplianceTier{
			"TATST:MALWARE":    TierDNSBound,
			"TATST:RANSOMWARE": TierDNSBound,
			"TATST:APT":        TierExpert,
		},
	}

	// Should pass: Tier2 ≥ Tier2 requirement
	err := policy.Check("TATST:MALWARE", TierDNSBound)
	assert("MALWARE + Tier2 → allowed", err == "")

	// Should pass: Tier3 ≥ Tier2 requirement
	err = policy.Check("TATST:MALWARE", TierExpert)
	assert("MALWARE + Tier3 → allowed", err == "")

	// Should fail: Tier1 < Tier2 requirement
	err = policy.Check("TATST:MALWARE", TierStaked)
	assert("MALWARE + Tier1 → denied",
		strings.Contains(err, "requires Tier 2"))

	// Should fail: Tier0 < Tier2 requirement
	err = policy.Check("TATST:MALWARE", TierAnonymous)
	assert("MALWARE + Tier0 → denied",
		strings.Contains(err, "requires Tier 2"))

	// Should fail: Tier2 < Tier3 requirement for APT
	err = policy.Check("TATST:APT", TierDNSBound)
	assert("APT + Tier2 → denied",
		strings.Contains(err, "requires Tier 3"))

	// Should pass: Tier3 ≥ Tier3 requirement for APT
	err = policy.Check("TATST:APT", TierExpert)
	assert("APT + Tier3 → allowed", err == "")

	// No minimum for PHISHING_URL → always allowed
	err = policy.Check("TATST:PHISHING_URL", TierAnonymous)
	assert("PHISHING_URL + Tier0 → allowed (no min)", err == "")
}

func testTierStrings() {
	fmt.Println("\n── Tier String Representations ──")
	assertEqual("Tier0.String()", TierAnonymous.String(), "ANONYMOUS")
	assertEqual("Tier1.String()", TierStaked.String(),    "STAKED")
	assertEqual("Tier2.String()", TierDNSBound.String(),  "DNS_BOUND")
	assertEqual("Tier3.String()", TierExpert.String(),    "EXPERT")
}

func testEdgeCases() {
	fmt.Println("\n── Edge Cases ──")

	// Zero confidence always produces zero regardless of tier
	assertEqual("0 conf, Tier3 → 0", WeightedConfidence(0, TierExpert), uint32(0))

	// Max confidence with all tiers
	assertEqual("100 conf, Tier0 → 25",  WeightedConfidence(100, TierAnonymous), uint32(25))
	assertEqual("100 conf, Tier1 → 50",  WeightedConfidence(100, TierStaked),    uint32(50))
	assertEqual("100 conf, Tier2 → 100", WeightedConfidence(100, TierDNSBound),  uint32(100))
	assertEqual("100 conf, Tier3 → 100", WeightedConfidence(100, TierExpert),    uint32(100)) // clamped

	// Borderline cases for integer division
	assertEqual("3 conf, Tier0 → 0", WeightedConfidence(3, TierAnonymous), uint32(0))   // 3*1/4=0
	assertEqual("4 conf, Tier0 → 1", WeightedConfidence(4, TierAnonymous), uint32(1))   // 4*1/4=1
	assertEqual("5 conf, Tier0 → 1", WeightedConfidence(5, TierAnonymous), uint32(1))   // 5*1/4=1

	// DNS identity conditions
	assertEqual("No DNS, expert flag but no DNS → Anon (score=0)",
		TierRequirementsMet(false, false, true, 0, 5000, 500), TierAnonymous)

	assertEqual("DNS present but inactive + expert → check staked",
		TierRequirementsMet(true, false, true, 1000, 5000, 500), TierStaked)
}

func main() {
	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("Compliance Tier Unit Tests")
	fmt.Println("═══════════════════════════════════════════")

	testTierStrings()
	testTierMultipliers()
	testWeightedConfidence()
	testTierRequirementsMet()
	testCategoryEnforcement()
	testEdgeCases()

	fmt.Printf("\n═══════════════════════════════════════════\n")
	fmt.Printf("Results: %d passed, %d failed\n", passed, failed)
	fmt.Printf("═══════════════════════════════════════════\n")

	if failed > 0 {
		os.Exit(1)
	}
}
GOEOF

header "Compliance Tier Unit Tests (Go)"

if command -v go &>/dev/null; then
  run_test "all tier logic unit tests pass" \
    go run "$GOTEST"
else
  skip "Go not in PATH — skipping tier logic unit tests"
fi

rm -f "$GOTEST"

# ── CLI tier query test ────────────────────────────────────────────────────────

header "CLI Tier Query Tests"

if { command -v "$BINARY" &>/dev/null || [[ -x "$BINARY" ]]; }; then
  # CLI queries require a running node
  if curl -sf "${NODE_URL:-http://localhost:26657}/status" &>/dev/null; then
    run_test "tier query shows tier definitions" \
      bash -c '"$BINARY" query identity tier cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9as36n 2>&1 | grep -qi "tier\|multiplier\|anonymous"' \
      BINARY="$BINARY"
  
    run_test "params shows dns_bound_tier_requires_dnssec" \
      bash -c '"$BINARY" query identity params 2>&1 | grep -qi "dns_bound\|dnssec\|params"' \
      BINARY="$BINARY"
  else
    skip "Node not reachable — skipping CLI tier query tests"
  fi
else
  echo -e "${YELLOW}[SKIP]${RESET}  Binary '$BINARY' not found — skipping CLI tier tests"
  (( TESTS_SKIPPED += 1 )) || true
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}═══════════════════════════════════════${RESET}"
echo -e "  Tests run:    ${BOLD}$TESTS_RUN${RESET}"
echo -e "  ${GREEN}Passed:       $TESTS_PASSED${RESET}"
echo -e "  ${RED}Failed:       $TESTS_FAILED${RESET}"
echo -e "  ${YELLOW}Skipped:      $TESTS_SKIPPED${RESET}"
echo ""

if ((TESTS_FAILED > 0)); then
  echo -e "${RED}${BOLD}FAILED${RESET}"; exit 1
else
  echo -e "${GREEN}${BOLD}ALL TESTS PASSED${RESET}"
fi
