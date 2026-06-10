// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package identity

import (
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/keeper"
	"github.com/threatattest/chain/x/identity/types"
)

// InitGenesis initialises the x/identity module from a GenesisState.
// It stores all provided identity records and sets the module parameters.
func InitGenesis(ctx sdk.Context, k keeper.Keeper, gs types.GenesisState) {
	k.SetParams(ctx, gs.Params)

	for _, rec := range gs.Records {
		if err := k.SetRecord(ctx, rec); err != nil {
			panic("identity InitGenesis: failed to set record for " + rec.CosmosAddr + ": " + err.Error())
		}
		// Re-enqueue expiry for each active record
		if rec.Status == types.DNSIDStatus_ACTIVE || rec.Status == types.DNSIDStatus_PENDING {
			k.EnqueueExpiry(ctx, rec.ExpiresAt, rec.CosmosAddr)
		}
	}
}

// ExportGenesis exports the current x/identity module state as a GenesisState.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) *types.GenesisState {
	var records []types.DNSIdentityRecord
	k.IterateRecords(ctx, func(rec types.DNSIdentityRecord) bool {
		records = append(records, rec)
		return false
	})
	return &types.GenesisState{
		Params:  k.GetParams(ctx),
		Records: records,
	}
}