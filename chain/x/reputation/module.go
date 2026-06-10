// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package reputation

import (
	"context"
	"encoding/json"

	"cosmossdk.io/core/appmodule"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"

	"github.com/threatattest/chain/x/reputation/keeper"
	"github.com/threatattest/chain/x/reputation/types"
)

var (
	_ module.AppModule       = AppModule{}
	_ module.AppModuleBasic  = AppModuleBasic{}
	_ appmodule.AppModule    = AppModule{}
	_ appmodule.HasEndBlocker = AppModule{}
)

const ConsensusVersion = 1

// ============================================================
// AppModuleBasic
// ============================================================

type AppModuleBasic struct{}

func (AppModuleBasic) Name() string                { return types.ModuleName }
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}
func (AppModuleBasic) RegisterInterfaces(_ codectypes.InterfaceRegistry) {}

func (AppModuleBasic) DefaultGenesis(_ codec.JSONCodec) json.RawMessage {
	bz, _ := json.Marshal(types.DefaultGenesisState())
	return bz
}

func (AppModuleBasic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		return err
	}
	return types.ValidateGenesis(gs)
}

func (AppModuleBasic) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}

// ============================================================
// AppModule
// ============================================================

type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{keeper: k}
}

func (am AppModule) Name() string             { return types.ModuleName }
func (am AppModule) ConsensusVersion() uint64 { return ConsensusVersion }
func (am AppModule) IsOnePerModuleType()      {}
func (am AppModule) IsAppModule()             {}

func (am AppModule) RegisterServices(_ module.Configurator) {}

func (am AppModule) InitGenesis(ctx sdk.Context, _ codec.JSONCodec, data json.RawMessage) {
	var gs types.GenesisState
	if err := json.Unmarshal(data, &gs); err != nil {
		panic("failed to unmarshal reputation genesis: " + err.Error())
	}
	if err := am.keeper.SetParams(ctx, gs.Params); err != nil {
		panic("failed to set reputation params: " + err.Error())
	}
	for _, rec := range gs.Reputations {
		if err := am.keeper.SetReputation(ctx, rec); err != nil {
			panic("failed to set reputation record: " + err.Error())
		}
	}
}

func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	params, err := am.keeper.GetParams(ctx)
	if err != nil {
		panic("failed to get reputation params: " + err.Error())
	}
	var recs []types.ReputationRecord
	_ = am.keeper.IterateReputations(ctx, func(r types.ReputationRecord) bool {
		recs = append(recs, r)
		return false
	})
	gs := types.GenesisState{Params: params, Reputations: recs}
	bz, _ := json.Marshal(gs)
	return bz
}

// EndBlock applies lazy decay to inactive attesters once per day-epoch.
func (am AppModule) EndBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	if sdkCtx.BlockHeight()%types.BlocksPerDay != 0 {
		return nil
	}
	return am.keeper.DecayAllInactive(sdkCtx)
}

func (am AppModule) QuerierRoute() string     { return types.ModuleName }
func (am AppModule) GetQueryCmd() interface{} { return nil }
func (am AppModule) GetTxCmd() interface{}    { return nil }