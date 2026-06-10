// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"fmt"
)

const (
	ModuleName   = "tatmint"
	StoreKey     = ModuleName
	RouterKey    = ModuleName
	MintDenom    = "utatst"

	// Key prefixes
	ParamsKeyByte   = 0x00
	MintStateKeyByte = 0x01

	// ============================================================
	// Emission schedule
	// ============================================================
	//
	// Total supply cap: 1,000,000,000 TATST = 1e15 utatst
	// Initial block reward: 10 TATST = 10,000,000 utatst
	// Halving period: every 2,102,400 blocks (~4 years at 2 s/block)
	//
	// Approximate emission per halving epoch:
	//   Epoch 0: 10 TATST/block × 2,102,400 blocks = 21,024,000 TATST
	//   Epoch 1:  5 TATST/block × 2,102,400 blocks = 10,512,000 TATST
	//   ... converges to ~42,048,000 TATST total (well under 1B cap)
	// The remainder of the 1B cap is reserved for the community pool and
	// genesis allocation.

	TotalSupplyCap     = int64(1_000_000_000_000_000) // 1e9 TATST in utatst
	InitialBlockReward = int64(10_000_000)            // 10 TATST in utatst
	HalvingInterval    = int64(2_102_400)             // blocks per epoch (~4 years)
	MaxHalvings        = 30                           // after 30 halvings reward = 0
)

// ============================================================
// Struct: MintState
// ============================================================

// MintState tracks cumulative minting progress.
type MintState struct {
	// CurrentBlockReward is the reward per block in utatst for the current epoch.
	CurrentBlockReward int64  `json:"current_block_reward"`
	// HalvingEpoch is the number of halvings that have occurred so far.
	HalvingEpoch       uint32 `json:"halving_epoch"`
	// TotalMinted is the total utatst minted so far (excluding genesis allocation).
	TotalMinted        int64  `json:"total_minted"`
	// NextHalvingBlock is the block height at which the next halving occurs.
	NextHalvingBlock   int64  `json:"next_halving_block"`
}

// ============================================================
// Struct: Params
// ============================================================

// Params holds x/tatmint module parameters.
type Params struct {
	// MintDenom is the denomination of the minted coin.
	MintDenom           string `json:"mint_denom"`
	// BlocksPerYear is used for APR calculations (informational only).
	BlocksPerYear       int64  `json:"blocks_per_year"`
	// ValidatorRewardBPS is the fraction (basis points) of each block reward
	// distributed to the proposer validator.
	ValidatorRewardBPS  uint32 `json:"validator_reward_bps"`
	// CommunityPoolBPS is the fraction directed to the community pool.
	CommunityPoolBPS    uint32 `json:"community_pool_bps"`
	// AttesterRewardBPS is the fraction reserved for attester incentives.
	AttesterRewardBPS   uint32 `json:"attester_reward_bps"`
}

// DefaultParams returns sensible default minting parameters.
func DefaultParams() Params {
	return Params{
		MintDenom:          MintDenom,
		BlocksPerYear:      15_768_000, // ~2 s block time
		ValidatorRewardBPS: 5000,       // 50% to validators
		CommunityPoolBPS:   2000,       // 20% to community pool
		AttesterRewardBPS:  3000,       // 30% to attesters
	}
}

// Validate checks that the split fractions sum to 10000 bp (100%).
func (p Params) Validate() error {
	if p.MintDenom == "" {
		return fmt.Errorf("mint_denom cannot be empty")
	}
	total := p.ValidatorRewardBPS + p.CommunityPoolBPS + p.AttesterRewardBPS
	if total != 10_000 {
		return fmt.Errorf("reward fractions must sum to 10000 bp, got %d", total)
	}
	return nil
}

// ============================================================
// Struct: GenesisState
// ============================================================

// GenesisState defines the genesis state for x/tatmint.
type GenesisState struct {
	Params    Params    `json:"params"`
	MintState MintState `json:"mint_state"`
}

// DefaultGenesisState returns the default genesis with initial block reward set.
func DefaultGenesisState() GenesisState {
	return GenesisState{
		Params: DefaultParams(),
		MintState: MintState{
			CurrentBlockReward: InitialBlockReward,
			HalvingEpoch:       0,
			TotalMinted:        0,
			NextHalvingBlock:   HalvingInterval,
		},
	}
}

// ValidateGenesis performs stateless validation of the genesis state.
func ValidateGenesis(gs GenesisState) error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid tatmint params: %w", err)
	}
	if gs.MintState.CurrentBlockReward < 0 {
		return fmt.Errorf("current_block_reward cannot be negative")
	}
	if gs.MintState.TotalMinted < 0 {
		return fmt.Errorf("total_minted cannot be negative")
	}
	if gs.MintState.TotalMinted > TotalSupplyCap {
		return fmt.Errorf("total_minted exceeds supply cap")
	}
	return nil
}

// ============================================================
// Helpers
// ============================================================

// BlockRewardAtEpoch returns the block reward for a given halving epoch.
func BlockRewardAtEpoch(epoch uint32) int64 {
	if epoch >= MaxHalvings {
		return 0
	}
	reward := InitialBlockReward
	for i := uint32(0); i < epoch; i++ {
		reward /= 2
		if reward == 0 {
			return 0
		}
	}
	return reward
}

// EpochForHeight returns the halving epoch number for a given block height.
func EpochForHeight(height int64) uint32 {
	if height <= 0 {
		return 0
	}
	e := uint32(height / HalvingInterval)
	if e >= MaxHalvings {
		return MaxHalvings
	}
	return e
}