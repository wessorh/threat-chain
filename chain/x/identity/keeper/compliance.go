// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/types"
)

// ============================================================
// Compliance Tier Enforcement
// ============================================================
// This file provides the public API surface used by x/attestation to apply
// per-tier weight multipliers to attestation records at publish time.
//
// Usage from x/attestation/keeper/msg_server.go:
//
//   tier := identityKeeper.GetTier(ctx, attesterAddr)
//   weightedConfidence := identityKeeper.ScaleConfidence(rawConfidence, tier)
// ============================================================

// TierInfo bundles a tier with its human-readable label for event/log output.
type TierInfo struct {
	Tier        types.ComplianceTier
	Label       string
	Multiplier  string // e.g. "1.00x"
	ScoreBonus  int64  // score awarded on this tier transition
}

// GetTierInfo returns a TierInfo struct for cosmosAddr.
func (k Keeper) GetTierInfo(ctx sdk.Context, cosmosAddr string) TierInfo {
	tier := k.GetTier(ctx, cosmosAddr)
	num := tier.TierMultiplierNumerator()
	mult := fmt.Sprintf("%.2fx", float64(num)/4.0)
	return TierInfo{
		Tier:       tier,
		Label:      tier.String(),
		Multiplier: mult,
	}
}

// ScaleConfidence scales a raw confidence value (0–100) by the tier multiplier.
//
// The scaled value is clamped to [0, 100]:
//
//	Tier 0 (ANONYMOUS):  confidence * 0.25  → max 25
//	Tier 1 (STAKED):     confidence * 0.50  → max 50
//	Tier 2 (DNS_BOUND):  confidence * 1.00  → max 100
//	Tier 3 (EXPERT):     confidence * 2.00  → clamped to 100
func (k Keeper) ScaleConfidence(ctx sdk.Context, rawConfidence int64, cosmosAddr string) int64 {
	tier := k.GetTier(ctx, cosmosAddr)
	return ScaleConfidenceByTier(rawConfidence, tier)
}

// ScaleConfidenceByTier is the pure-function version of ScaleConfidence that
// accepts an already-resolved tier.  Useful in tests.
func ScaleConfidenceByTier(rawConfidence int64, tier types.ComplianceTier) int64 {
	scaled := ApplyTierMultiplier(rawConfidence, tier)
	if scaled > 100 {
		scaled = 100
	}
	if scaled < 0 {
		scaled = 0
	}
	return scaled
}

// EnforceMinTier returns an error if the attester's current tier is below
// minTier.  Used to gate certain privileged attestation categories.
func (k Keeper) EnforceMinTier(ctx sdk.Context, cosmosAddr string, minTier types.ComplianceTier) error {
	tier := k.GetTier(ctx, cosmosAddr)
	if tier < minTier {
		return fmt.Errorf("attester %s is Tier %d (%s); minimum required is Tier %d (%s)",
			cosmosAddr, int(tier), tier.String(), int(minTier), minTier.String())
	}
	return nil
}

// TierBreakdown returns a formatted multi-line breakdown of how the tier was
// determined for cosmosAddr.  Useful for CLI query output and debugging.
func (k Keeper) TierBreakdown(ctx sdk.Context, cosmosAddr string) string {
	params := k.GetParams(ctx)
	tier := k.GetTier(ctx, cosmosAddr)
	score := k.GetTrustScore(ctx, cosmosAddr)
	rec, hasRec := k.GetRecord(ctx, cosmosAddr)

	out := fmt.Sprintf("Address:         %s\n", cosmosAddr)
	out += fmt.Sprintf("Trust Score:     %d RS\n", score)
	out += fmt.Sprintf("Current Tier:    Tier %d (%s) → %.2fx weight\n",
		int(tier), tier.String(), float64(tier.TierMultiplierNumerator())/4.0)
	out += fmt.Sprintf("Expert Min RS:   %d\n", params.ExpertTierMinReputationScore)
	out += fmt.Sprintf("Staked Min Del:  %d utat\n", params.StakedTierMinDelegation)
	if hasRec {
		out += fmt.Sprintf("DNS Identity:    %s (status=%s, domain=%s)\n",
			rec.IdentityID[:12]+"…", rec.Status, rec.Domain)
	} else {
		out += "DNS Identity:    none\n"
	}
	return out
}

// AllTierThresholds returns a slice of TierInfo for all four tiers, useful for
// documentation and CLI help output.
func AllTierThresholds() []TierInfo {
	tiers := []types.ComplianceTier{
		types.ComplianceTier_ANONYMOUS,
		types.ComplianceTier_STAKED,
		types.ComplianceTier_DNS_BOUND,
		types.ComplianceTier_EXPERT,
	}
	result := make([]TierInfo, len(tiers))
	for i, t := range tiers {
		num := t.TierMultiplierNumerator()
		result[i] = TierInfo{
			Tier:       t,
			Label:      t.String(),
			Multiplier: fmt.Sprintf("%.2fx", float64(num)/4.0),
		}
	}
	return result
}