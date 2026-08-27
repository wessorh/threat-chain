// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package abci

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/types"
)

// BeginBlocker is called at the start of every block.
// It handles epoch transitions and prunes stale epoch counters.
func BeginBlocker(ctx sdk.Context, k keeper.Keeper) error {
	height := ctx.BlockHeight()

	// Compute current epoch
	currentEpoch := types.CurrentEpoch(height)

	// Load stored epoch
	storedEpoch, err := k.GetCurrentEpoch(ctx)
	if err != nil {
		return err
	}

	if currentEpoch > storedEpoch {
		// Distribute the previous epoch's replenishment pro-rata to its
		// participants, then prune its rate-limit counters.
		if err := k.DistributeEpochRewards(ctx, storedEpoch); err != nil {
			k.Logger().Error("failed to distribute epoch rewards",
				"epoch", storedEpoch, "error", err)
		}
		// Epoch has advanced — prune the previous epoch's rate-limit counters
		if err := k.PruneEpochCounts(ctx, storedEpoch); err != nil {
			k.Logger().Error("failed to prune epoch counts",
				"epoch", storedEpoch, "error", err)
			// Non-fatal: log and continue
		}
		if err := k.SetCurrentEpoch(ctx, currentEpoch); err != nil {
			return err
		}
		k.Logger().Info("epoch advanced",
			"from", storedEpoch, "to", currentEpoch, "height", height)
	}

	return nil
}

// EndBlocker is called at the end of every block.
// It scans the expiry queue and expires all attestations whose TTL has elapsed.
func EndBlocker(ctx sdk.Context, k keeper.Keeper) error {
	blockTime := ctx.BlockTime().Unix()

	var expiredIDs []string

	// Collect all expired IDs (iterate before modifying state)
	err := k.IterateExpiredAttestations(ctx, blockTime, func(id string) bool {
		expiredIDs = append(expiredIDs, id)
		return false // keep iterating
	})
	if err != nil {
		return err
	}

	for _, id := range expiredIDs {
		if err := k.ExpireAttestation(ctx, id); err != nil {
			// Log but don't halt the chain — a missing record is non-fatal
			k.Logger().Error("failed to expire attestation",
				"id", id, "error", err)
		}
	}

	if len(expiredIDs) > 0 {
		k.Logger().Info("expired attestations",
			"count", len(expiredIDs),
			"block_height", ctx.BlockHeight(),
		)
	}

	return nil
}
