// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"fmt"
)

const (
	ModuleName = "reputation"
	StoreKey   = ModuleName
	RouterKey  = ModuleName

	// KVStore key prefixes
	ReputationKeyPrefix = 0x00
	ParamsKeyByte       = 0x01
	DecayQueuePrefix    = 0x02

	// Tier thresholds
	Tier3MinScore uint32 = 500
	Tier2MinScore uint32 = 100
	Tier1MinScore uint32 = 0

	// Score bounds
	MaxReputationScore uint32 = 10_000
	InitialScore       uint32 = 0

	// Blocks per day at 2 s block time
	BlocksPerDay = int64(43_200)
)

// ============================================================
// Struct: ReputationRecord
// ============================================================

// ReputationRecord holds a single attester's on-chain reputation state.
type ReputationRecord struct {
	Attester       string `json:"attester"`
	Score          uint32 `json:"score"`
	Tier           uint32 `json:"tier"` // 1, 2, or 3
	LastDecayBlock int64  `json:"last_decay_block"`
	TotalPublished uint64 `json:"total_published"`
	TotalEndorsed  uint64 `json:"total_endorsed"`
	TotalDisputed  uint64 `json:"total_disputed"`
	TotalRevoked   uint64 `json:"total_revoked"`
	Blacklisted    bool   `json:"blacklisted"`
}

// ComputeTier returns the tier for a given score.
func ComputeTier(score uint32) uint32 {
	switch {
	case score >= Tier3MinScore:
		return 3
	case score >= Tier2MinScore:
		return 2
	default:
		return 1
	}
}

// ============================================================
// Struct: Params
// ============================================================

// Params holds x/reputation module parameters.
type Params struct {
	// DecayRatePerDay is the fraction (in basis points, 1 bp = 0.01%) by which
	// reputation decays per day of inactivity. Default: 10 bp = 0.10%/day.
	DecayRateBPS        uint32 `json:"decay_rate_bps"`
	// MaxScorePerEpoch caps reputation gains in a single epoch.
	MaxGainPerEpoch     uint32 `json:"max_gain_per_epoch"`
	// InactivityDaysBeforeDecay is the number of days with no attestation
	// activity before decay kicks in.
	InactivityDaysBeforeDecay uint32 `json:"inactivity_days_before_decay"`
}

// DefaultParams returns sensible default reputation parameters.
func DefaultParams() Params {
	return Params{
		DecayRateBPS:              10,  // 0.10% per day
		MaxGainPerEpoch:           50,
		InactivityDaysBeforeDecay: 30,
	}
}

// Validate checks that all parameters are within acceptable bounds.
func (p Params) Validate() error {
	if p.DecayRateBPS > 10_000 {
		return fmt.Errorf("decay_rate_bps must be <= 10000 (100%%)")
	}
	if p.MaxGainPerEpoch == 0 {
		return fmt.Errorf("max_gain_per_epoch must be > 0")
	}
	return nil
}

// ============================================================
// Struct: GenesisState
// ============================================================

// GenesisState defines the genesis state for x/reputation.
type GenesisState struct {
	Params      Params             `json:"params"`
	Reputations []ReputationRecord `json:"reputations"`
}

// DefaultGenesisState returns an empty genesis with default params.
func DefaultGenesisState() GenesisState {
	return GenesisState{
		Params:      DefaultParams(),
		Reputations: []ReputationRecord{},
	}
}

// ValidateGenesis performs stateless validation of the genesis state.
func ValidateGenesis(gs GenesisState) error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid reputation params: %w", err)
	}
	seen := make(map[string]bool, len(gs.Reputations))
	for _, r := range gs.Reputations {
		if r.Attester == "" {
			return fmt.Errorf("reputation record has empty attester")
		}
		if seen[r.Attester] {
			return fmt.Errorf("duplicate reputation record for attester: %s", r.Attester)
		}
		seen[r.Attester] = true
		if r.Score > MaxReputationScore {
			return fmt.Errorf("attester %s score %d exceeds max %d",
				r.Attester, r.Score, MaxReputationScore)
		}
	}
	return nil
}