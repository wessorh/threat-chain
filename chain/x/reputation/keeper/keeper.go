// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log/v2"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/reputation/types"
)

// Keeper provides state access for the reputation module.
type Keeper struct {
	cdc          codec.BinaryCodec
	storeService store.KVStoreService
	logger       log.Logger
	authority    string
}

// NewKeeper constructs a new reputation Keeper.
func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	authority string,
) Keeper {
	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		logger:       logger.With("module", types.ModuleName),
		authority:    authority,
	}
}

// Logger returns the module logger.
func (k Keeper) Logger() log.Logger { return k.logger }

// ============================================================
// Params
// ============================================================

func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	bz, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal reputation params: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set([]byte{types.ParamsKeyByte}, bz)
}

func (k Keeper) GetParams(ctx sdk.Context) (types.Params, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get([]byte{types.ParamsKeyByte})
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var p types.Params
	if err := json.Unmarshal(bz, &p); err != nil {
		return types.Params{}, fmt.Errorf("unmarshal reputation params: %w", err)
	}
	return p, nil
}

// ============================================================
// Reputation CRUD
// ============================================================

func reputationKey(attester string) []byte {
	return append([]byte{types.ReputationKeyPrefix}, []byte(attester)...)
}

// SetReputation persists a ReputationRecord.
func (k Keeper) SetReputation(ctx sdk.Context, rec types.ReputationRecord) error {
	bz, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal reputation: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set(reputationKey(rec.Attester), bz)
}

// GetReputation retrieves a ReputationRecord for an attester.
// Returns a zero-score default if the attester has no record yet.
func (k Keeper) GetReputation(ctx sdk.Context, attester string) (types.ReputationRecord, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(reputationKey(attester))
	if err != nil {
		return types.ReputationRecord{}, err
	}
	if bz == nil {
		return types.ReputationRecord{
			Attester:       attester,
			Score:          types.InitialScore,
			Tier:           1,
			LastDecayBlock: ctx.BlockHeight(),
		}, nil
	}
	var rec types.ReputationRecord
	if err := json.Unmarshal(bz, &rec); err != nil {
		return types.ReputationRecord{}, fmt.Errorf("unmarshal reputation: %w", err)
	}
	return rec, nil
}

// IterateReputations iterates all stored reputation records.
func (k Keeper) IterateReputations(ctx sdk.Context, cb func(types.ReputationRecord) bool) error {
	prefix := []byte{types.ReputationKeyPrefix}
	iter, err := k.storeService.OpenKVStore(ctx).Iterator(prefix, prefixEnd(prefix))
	if err != nil {
		return err
	}
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var rec types.ReputationRecord
		if err := json.Unmarshal(iter.Value(), &rec); err != nil {
			return fmt.Errorf("unmarshal reputation: %w", err)
		}
		if cb(rec) {
			break
		}
	}
	return nil
}

// ============================================================
// Score mutations
// ============================================================

// GetReputationScore returns just the score for an attester (satisfies ReputationKeeper interface).
func (k Keeper) GetReputationScore(ctx sdk.Context, attester string) (uint32, error) {
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return 0, err
	}
	return rec.Score, nil
}

// AddReputation increases an attester's reputation score by delta.
// The score is capped at MaxReputationScore.
func (k Keeper) AddReputation(ctx sdk.Context, attester string, delta int32) error {
	if delta <= 0 {
		return nil
	}
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return err
	}
	newScore := rec.Score + uint32(delta)
	if newScore > types.MaxReputationScore {
		newScore = types.MaxReputationScore
	}
	rec.Score = newScore
	rec.Tier = types.ComputeTier(newScore)
	rec.LastDecayBlock = ctx.BlockHeight()
	rec.TotalPublished++
	return k.SetReputation(ctx, rec)
}

// SubReputation decreases an attester's reputation score by delta (floor 0).
func (k Keeper) SubReputation(ctx sdk.Context, attester string, delta uint32) error {
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return err
	}
	if delta >= rec.Score {
		rec.Score = 0
	} else {
		rec.Score -= delta
	}
	rec.Tier = types.ComputeTier(rec.Score)
	return k.SetReputation(ctx, rec)
}

// IsBlacklisted returns true if the attester is blacklisted in x/reputation.
func (k Keeper) IsBlacklisted(ctx sdk.Context, attester string) bool {
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return false
	}
	return rec.Blacklisted
}

// SetBlacklisted marks an attester as blacklisted (or clears the flag).
func (k Keeper) SetBlacklisted(ctx sdk.Context, attester string, blacklisted bool) error {
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return err
	}
	rec.Blacklisted = blacklisted
	if blacklisted {
		rec.Score = 0
		rec.Tier = 1
	}
	return k.SetReputation(ctx, rec)
}

// ============================================================
// Lazy decay
// ============================================================

// ApplyDecay applies reputation decay to an attester based on elapsed blocks
// since their last active block. Called lazily on read/write.
func (k Keeper) ApplyDecay(ctx sdk.Context, attester string) error {
	params, err := k.GetParams(ctx)
	if err != nil {
		return err
	}
	rec, err := k.GetReputation(ctx, attester)
	if err != nil {
		return err
	}

	currentBlock := ctx.BlockHeight()
	elapsedBlocks := currentBlock - rec.LastDecayBlock
	if elapsedBlocks <= 0 || rec.Score == 0 {
		return nil
	}

	// Only start decaying after inactivity threshold
	inactivityThreshold := int64(params.InactivityDaysBeforeDecay) * types.BlocksPerDay
	if elapsedBlocks < inactivityThreshold {
		return nil
	}

	// Decay days = elapsed_blocks / blocks_per_day
	decayDays := elapsedBlocks / types.BlocksPerDay
	if decayDays == 0 {
		return nil
	}

	// Apply compound decay: score * (1 - rate)^days
	// Using integer arithmetic: newScore = score * (10000 - decayRateBPS)^days / 10000^days
	// For simplicity and to avoid floating point, apply per-day decay iteratively
	// with a cap of 365 iterations.
	rate := params.DecayRateBPS
	score := rec.Score
	maxIter := int64(365)
	if decayDays < maxIter {
		maxIter = decayDays
	}
	for i := int64(0); i < maxIter; i++ {
		reduction := score * rate / 10_000
		if reduction == 0 {
			break
		}
		score -= reduction
	}

	rec.Score = score
	rec.Tier = types.ComputeTier(score)
	rec.LastDecayBlock = currentBlock
	return k.SetReputation(ctx, rec)
}

// ============================================================
// Epoch decay scan (EndBlocker — runs once per epoch)
// ============================================================

// DecayAllInactive scans all reputation records and applies lazy decay to
// any attester whose last_decay_block is older than the inactivity threshold.
// Called from EndBlocker once per epoch rather than every block.
func (k Keeper) DecayAllInactive(ctx sdk.Context) error {
	return k.IterateReputations(ctx, func(rec types.ReputationRecord) bool {
		_ = k.ApplyDecay(ctx, rec.Attester)
		return false
	})
}

// ============================================================
// Helpers
// ============================================================

func prefixEnd(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}

// encodeUint64 encodes a uint64 as big-endian 8 bytes (used for decay queue keys).
func encodeUint64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
