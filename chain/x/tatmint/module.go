// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package tatmint

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

	"github.com/threatattest/chain/x/tatmint/keeper"
	"github.com/threatattest/chain/x/tatmint/types"
)

var (
	_ module.AppModule          = AppModule{}
	_ module.AppModuleBasic     = AppModuleBasic{}
	_ appmodule.AppModule       = AppModule{}
	_ appmodule.HasBeginBlocker = AppModule{}
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
		panic("failed to unmarshal tatmint genesis: " + err.Error())
	}
	if err := am.keeper.SetParams(ctx, gs.Params); err != nil {
		panic("failed to set tatmint params: " + err.Error())
	}
	if err := am.keeper.SetMintState(ctx, gs.MintState); err != nil {
		panic("failed to set mint state: " + err.Error())
	}
}

func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	params, err := am.keeper.GetParams(ctx)
	if err != nil {
		panic("failed to get tatmint params: " + err.Error())
	}
	ms, err := am.keeper.GetMintState(ctx)
	if err != nil {
		panic("failed to get mint state: " + err.Error())
	}
	gs := types.GenesisState{Params: params, MintState: ms}
	bz, _ := json.Marshal(gs)
	return bz
}

// BeginBlock mints the block reward for the current block.
func (am AppModule) BeginBlock(ctx context.Context) error {
	return am.keeper.MintBlockReward(sdk.UnwrapSDKContext(ctx))
}

func (am AppModule) QuerierRoute() string     { return types.ModuleName }
func (am AppModule) GetQueryCmd() interface{} { return nil }
func (am AppModule) GetTxCmd() interface{}    { return nil }