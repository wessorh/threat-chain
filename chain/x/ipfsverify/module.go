// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package ipfsverify

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

	"github.com/threatattest/chain/x/ipfsverify/keeper"
	"github.com/threatattest/chain/x/ipfsverify/types"
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
		panic("failed to unmarshal ipfsverify genesis: " + err.Error())
	}
	if err := am.keeper.SetParams(ctx, gs.Params); err != nil {
		panic("failed to set ipfsverify params: " + err.Error())
	}
	for _, job := range gs.Jobs {
		if err := am.keeper.SetJob(ctx, job); err != nil {
			panic("failed to restore verification job: " + err.Error())
		}
	}
	for _, report := range gs.Reports {
		if err := am.keeper.SetReport(ctx, report); err != nil {
			panic("failed to restore verification report: " + err.Error())
		}
	}
}

func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	params, err := am.keeper.GetParams(ctx)
	if err != nil {
		panic("failed to get ipfsverify params: " + err.Error())
	}
	var jobs []types.VerificationJob
	_ = am.keeper.IterateJobs(ctx, func(j types.VerificationJob) bool {
		jobs = append(jobs, j)
		return false
	})
	gs := types.GenesisState{Params: params, Jobs: jobs}
	bz, _ := json.Marshal(gs)
	return bz
}

// EndBlock checks for stale IPFS verification jobs and marks them timed out.
func (am AppModule) EndBlock(ctx context.Context) error {
	return am.keeper.TimeoutStaleJobs(sdk.UnwrapSDKContext(ctx))
}

func (am AppModule) QuerierRoute() string     { return types.ModuleName }
func (am AppModule) GetQueryCmd() interface{} { return nil }
func (am AppModule) GetTxCmd() interface{}    { return nil }