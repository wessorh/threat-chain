// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import "fmt"

// ============================================================
// Compliance Tier Reference Tables
// ============================================================
// These types and tables are the authoritative source of truth for tier
// definitions, requirements, and weight multipliers used across both
// x/identity and x/attestation.
// ============================================================

// TierDefinition holds the human-readable metadata for one compliance tier.
type TierDefinition struct {
	Tier              ComplianceTier
	Name              string
	Icon              string
	MultiplierDisplay string // human-readable, e.g. "1.00×"
	Numerator         int64  // weight numerator (denominator = 4)
	MaxScaledConfidence int64 // max confidence after scaling (0-100)
	Requirements      string
}

// TierDefinitions is the authoritative ordered list of all compliance tiers.
var TierDefinitions = []TierDefinition{
	{
		Tier:                ComplianceTier_ANONYMOUS,
		Name:                "Anonymous",
		Icon:                "👤",
		MultiplierDisplay:   "0.25×",
		Numerator:           1,
		MaxScaledConfidence: 25,
		Requirements:        "No requirements — default tier for all addresses",
	},
	{
		Tier:                ComplianceTier_STAKED,
		Name:                "Staked",
		Icon:                "🔒",
		MultiplierDisplay:   "0.50×",
		Numerator:           2,
		MaxScaledConfidence: 50,
		Requirements:        "Minimum token delegation (params.staked_tier_min_delegation)",
	},
	{
		Tier:                ComplianceTier_DNS_BOUND,
		Name:                "DNS Bound",
		Icon:                "🌐",
		MultiplierDisplay:   "1.00×",
		Numerator:           4,
		MaxScaledConfidence: 100,
		Requirements:        "Active DNSSEC-anchored identity (MsgRegisterIdentity + DNS TXT records)",
	},
	{
		Tier:                ComplianceTier_EXPERT,
		Name:                "Expert",
		Icon:                "⭐",
		MultiplierDisplay:   "2.00×",
		Numerator:           8,
		MaxScaledConfidence: 100, // clamped to 100
		Requirements:        "Active DNS identity + IdentityFlag_EXPERT + reputation >= expert_tier_min_reputation_score",
	},
}

// GetTierDefinition returns the TierDefinition for tier t.
// Panics if the tier is not in TierDefinitions (programming error).
func GetTierDefinition(t ComplianceTier) TierDefinition {
	for _, td := range TierDefinitions {
		if td.Tier == t {
			return td
		}
	}
	panic(fmt.Sprintf("x/identity: unknown compliance tier %d", int(t)))
}

// ============================================================
// Tier weight application
// ============================================================

// WeightedScore applies the tier multiplier to a raw score and returns the
// scaled result, clamped to [0, maxValue].
//
// The multiplier fractions are: Tier0=1/4, Tier1=2/4, Tier2=4/4, Tier3=8/4.
func WeightedScore(rawScore, maxValue int64, tier ComplianceTier) int64 {
	td := GetTierDefinition(tier)
	scaled := rawScore * td.Numerator / 4
	if scaled > maxValue {
		scaled = maxValue
	}
	if scaled < 0 {
		scaled = 0
	}
	return scaled
}

// WeightedConfidence applies the tier multiplier to a raw confidence (0–100)
// and clamps the result to [0, 100].
func WeightedConfidence(rawConfidence uint32, tier ComplianceTier) uint32 {
	scaled := WeightedScore(int64(rawConfidence), 100, tier)
	return uint32(scaled)
}

// ============================================================
// Tier requirement checks
// ============================================================

// TierRequirementsMet returns the highest tier the attester qualifies for,
// given their current trust score, DNS identity status, and flags.
//
// This is the pure-function version used in tests and documentation.
// The keeper's GetTier() is the authoritative on-chain implementation.
func TierRequirementsMet(
	hasDNSIdentity bool,
	identityActive bool,
	expertFlag bool,
	trustScore int64,
	expertMinScore int64,
	stakedMinScore int64,
) ComplianceTier {
	// Tier 3: DNS identity + EXPERT flag + score threshold
	if hasDNSIdentity && identityActive && expertFlag && trustScore >= expertMinScore {
		return ComplianceTier_EXPERT
	}
	// Tier 2: active DNS identity
	if hasDNSIdentity && identityActive {
		return ComplianceTier_DNS_BOUND
	}
	// Tier 1: staked (using trust score as a proxy)
	if trustScore >= stakedMinScore {
		return ComplianceTier_STAKED
	}
	// Tier 0: default
	return ComplianceTier_ANONYMOUS
}

// ============================================================
// Tier upgrade / downgrade event descriptions
// ============================================================

// TierTransitionDesc returns a human-readable description of a tier transition.
func TierTransitionDesc(from, to ComplianceTier) string {
	if from == to {
		return fmt.Sprintf("no change (Tier %d %s)", int(from), from.String())
	}
	if to > from {
		return fmt.Sprintf("upgrade: Tier %d (%s) → Tier %d (%s)",
			int(from), from.String(), int(to), to.String())
	}
	return fmt.Sprintf("downgrade: Tier %d (%s) → Tier %d (%s)",
		int(from), from.String(), int(to), to.String())
}

// ============================================================
// TierEnforcement — attestation weight enforcement config
// ============================================================

// TierEnforcementPolicy controls how tier weights are applied to attestation
// confidence values.
type TierEnforcementPolicy struct {
	// Enabled controls whether tier-based confidence scaling is applied.
	// When false, raw confidence values are used unchanged.
	Enabled bool

	// HardMinimumTier is the minimum tier required to publish attestations.
	// Addresses below this tier will have their PublishAttestation rejected.
	// Default: ComplianceTier_ANONYMOUS (no minimum — any address can publish).
	HardMinimumTier ComplianceTier

	// CategoryMinimumTiers maps threat category codes to minimum tier requirements.
	// Example: require Tier 2 (DNS_BOUND) to publish TATST:MALWARE attestations.
	CategoryMinimumTiers map[string]ComplianceTier
}

// DefaultTierEnforcementPolicy returns the default (permissive) enforcement policy.
func DefaultTierEnforcementPolicy() TierEnforcementPolicy {
	return TierEnforcementPolicy{
		Enabled:              true,
		HardMinimumTier:      ComplianceTier_ANONYMOUS,
		CategoryMinimumTiers: map[string]ComplianceTier{
			// No minimum tiers by default — governance can tighten these.
		},
	}
}

// CheckCategoryTierRequirement returns an error message if the tier is below
// the minimum required for the given category, or "" if allowed.
func (p TierEnforcementPolicy) CheckCategoryTierRequirement(
	category string,
	tier ComplianceTier,
) string {
	minTier, ok := p.CategoryMinimumTiers[category]
	if !ok {
		return ""
	}
	if tier < minTier {
		return fmt.Sprintf("category %s requires minimum Tier %d (%s); attester is Tier %d (%s)",
			category, int(minTier), minTier.String(), int(tier), tier.String())
	}
	return ""
}