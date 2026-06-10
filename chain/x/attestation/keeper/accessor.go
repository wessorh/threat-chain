// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// GetAttesterRS returns the reputation score for an attester address.
// This is a thin accessor that exposes repKeeper to QueryServer.
func (k Keeper) GetAttesterRS(ctx sdk.Context, attester string) (uint32, error) {
	return k.repKeeper.GetReputationScore(ctx, attester)
}