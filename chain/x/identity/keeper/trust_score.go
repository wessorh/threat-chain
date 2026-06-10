// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"encoding/json"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/types"
)

// ============================================================
// Trust Score & Compliance Tier
// ============================================================
// The identity module maintains a simple reputation score (RS) per Cosmos
// address.  These scores feed into the compliance tier calculation and are
// emitted as events so external indexers can aggregate them.
//
// The attestation module reads compliance tiers via the GetTier() call to
// apply per-tier attestation weight multipliers.
// ============================================================

const (
	// TrustScoreKeyPrefix is the KV prefix for trust score entries.
	// Layout: 0x10 + cosmosAddr → int64 JSON
	TrustScoreKeyPrefix = byte(0x10)
)

// trustScoreKey builds the KV key for a trust score entry.
func trustScoreKey(cosmosAddr string) []byte {
	return append([]byte{TrustScoreKeyPrefix}, []byte(cosmosAddr)...)
}

// ── Score CRUD ────────────────────────────────────────────────────────────────

// GetTrustScore returns the current reputation score for cosmosAddr.
// Returns 0 if no score has been recorded.
func (k Keeper) GetTrustScore(ctx sdk.Context, cosmosAddr string) int64 {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(trustScoreKey(cosmosAddr))
	if bz == nil {
		return 0
	}
	var score int64
	_ = json.Unmarshal(bz, &score)
	return score
}

// SetTrustScore stores an absolute trust score for cosmosAddr.
func (k Keeper) SetTrustScore(ctx sdk.Context, cosmosAddr string, score int64) {
	store := ctx.KVStore(k.storeKey)
	bz, _ := json.Marshal(score)
	store.Set(trustScoreKey(cosmosAddr), bz)
}

// AddTrustScore atomically adds delta to the current trust score.
// The score is clamped to [0, MaxInt64] (cannot go below zero).
func (k Keeper) AddTrustScore(ctx sdk.Context, cosmosAddr string, delta int64) int64 {
	current := k.GetTrustScore(ctx, cosmosAddr)
	next := current + delta
	if next < 0 {
		next = 0
	}
	k.SetTrustScore(ctx, cosmosAddr, next)
	k.emitTrustScoreEvent(ctx, cosmosAddr, delta, next)
	return next
}

// ── Lifecycle score adjustments ───────────────────────────────────────────────

// OnRegistration awards TrustScoreRegistration (+200 RS) when an identity is
// promoted from PENDING to ACTIVE.
func (k Keeper) OnRegistration(ctx sdk.Context, cosmosAddr string) int64 {
	return k.AddTrustScore(ctx, cosmosAddr, types.TrustScoreRegistration)
}

// OnMilestone30d awards TrustScoreMilestone30d (+50 RS) once an identity has
// been active for 30 days.  This is called by the EndBlocker epoch logic.
func (k Keeper) OnMilestone30d(ctx sdk.Context, cosmosAddr string) int64 {
	return k.AddTrustScore(ctx, cosmosAddr, types.TrustScoreMilestone30d)
}

// OnRenewal awards TrustScoreRenewal (+10 RS) when an identity is successfully
// renewed via MsgRenewIdentity.
func (k Keeper) OnRenewal(ctx sdk.Context, cosmosAddr string) int64 {
	return k.AddTrustScore(ctx, cosmosAddr, types.TrustScoreRenewal)
}

// OnDNSRemoved penalises TrustScoreDNSRemoved (-200 RS) when the DNS TXT
// record can no longer be resolved during a verification epoch.
func (k Keeper) OnDNSRemoved(ctx sdk.Context, cosmosAddr string) int64 {
	return k.AddTrustScore(ctx, cosmosAddr, types.TrustScoreDNSRemoved)
}

// OnRevocation penalises TrustScoreRevoked (-100 RS) when an identity is
// voluntarily or governance-revoked.
func (k Keeper) OnRevocation(ctx sdk.Context, cosmosAddr string) int64 {
	return k.AddTrustScore(ctx, cosmosAddr, types.TrustScoreRevoked)
}

// ── Compliance Tier ───────────────────────────────────────────────────────────

// GetTier returns the ComplianceTier for cosmosAddr based on:
//   Tier 3 (EXPERT):    active DNS-bound identity + flags&EXPERT + score >= expertMin
//   Tier 2 (DNS_BOUND): active DNS-bound identity
//   Tier 1 (STAKED):    meets staked_tier_min_delegation (stub: always qualifies if staked)
//   Tier 0 (ANONYMOUS): default
func (k Keeper) GetTier(ctx sdk.Context, cosmosAddr string) types.ComplianceTier {
	params := k.GetParams(ctx)

	// Tier 2 / 3 — requires an ACTIVE DNS identity record
	rec, found := k.GetRecord(ctx, cosmosAddr)
	if found && rec.Status == types.DNSIDStatus_ACTIVE {
		score := k.GetTrustScore(ctx, cosmosAddr)
		if (rec.Flags&types.IdentityFlag_EXPERT) != 0 &&
			score >= params.ExpertTierMinReputationScore {
			return types.ComplianceTier_EXPERT
		}
		return types.ComplianceTier_DNS_BOUND
	}

	// Tier 1 — requires minimum delegation (simplified: check trust score proxy)
	// In production: query staking keeper for total delegated tokens.
	score := k.GetTrustScore(ctx, cosmosAddr)
	if score >= params.StakedTierMinDelegation/1000 { // proxy: 500 RS → tier 1
		return types.ComplianceTier_STAKED
	}

	return types.ComplianceTier_ANONYMOUS
}

// ApplyTierMultiplier scales a raw attestation weight by the tier multiplier.
// The multiplier is expressed as a fraction with denominator 4:
//
//	Tier 0 → weight * 1/4
//	Tier 1 → weight * 2/4 = weight / 2
//	Tier 2 → weight * 4/4 = weight
//	Tier 3 → weight * 8/4 = weight * 2
//
// Returns the scaled weight (always >= 0).
func ApplyTierMultiplier(rawWeight int64, tier types.ComplianceTier) int64 {
	num := tier.TierMultiplierNumerator()
	scaled := rawWeight * num / 4
	if scaled < 0 {
		return 0
	}
	return scaled
}

// TierSummary returns a human-readable summary of a tier for logging/events.
func TierSummary(tier types.ComplianceTier) string {
	return fmt.Sprintf("Tier%d(%s, %.2fx)",
		int(tier), tier.String(), float64(tier.TierMultiplierNumerator())/4.0)
}

// ── Events ────────────────────────────────────────────────────────────────────

func (k Keeper) emitTrustScoreEvent(ctx sdk.Context, cosmosAddr string, delta, newScore int64) {
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"identity_trust_score_update",
		sdk.NewAttribute("cosmos_addr", cosmosAddr),
		sdk.NewAttribute("delta", fmt.Sprintf("%+d", delta)),
		sdk.NewAttribute("new_score", fmt.Sprintf("%d", newScore)),
	))
}