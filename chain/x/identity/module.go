// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package identity

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

	identitycli "github.com/threatattest/chain/x/identity/cli"
	"github.com/threatattest/chain/x/identity/keeper"
	"github.com/threatattest/chain/x/identity/types"
)

// Ensure AppModule implements all required interfaces.
var (
	_ module.AppModule        = AppModule{}
	_ module.AppModuleBasic   = AppModuleBasic{}
	_ appmodule.AppModule     = AppModule{}
	_ appmodule.HasEndBlocker = AppModule{}
)

// ConsensusVersion defines the current x/identity module consensus version.
const ConsensusVersion = 1

// ============================================================
// AppModuleBasic
// ============================================================

// AppModuleBasic implements module.AppModuleBasic for x/identity.
type AppModuleBasic struct{}

// Name returns the module's name.
func (AppModuleBasic) Name() string { return types.ModuleName }

// RegisterLegacyAminoCodec is a no-op (no legacy amino types needed).
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}

// RegisterInterfaces is a no-op (proto codec registration done at app level).
func (AppModuleBasic) RegisterInterfaces(_ codectypes.InterfaceRegistry) {}

// DefaultGenesis returns the default genesis state as raw JSON.
func (AppModuleBasic) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	gs := types.DefaultGenesisState()
	bz, _ := json.Marshal(gs)
	return bz
}

// ValidateGenesis validates the genesis state.
func (AppModuleBasic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		return err
	}
	return gs.Validate()
}

// RegisterGRPCGatewayRoutes registers gRPC gateway routes (no-op for now).
func (AppModuleBasic) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}

// GetTxCmd returns the root tx command for x/identity.
func (AppModuleBasic) GetTxCmd() *identitycli.RootTxCmd { return identitycli.NewTxCmd() }

// ============================================================
// AppModule
// ============================================================

// AppModule implements module.AppModule for x/identity.
type AppModule struct {
	AppModuleBasic
	keeper keeper.Keeper
}

// NewAppModule creates a new AppModule.
func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{keeper: k}
}

// Name returns the module name.
func (am AppModule) Name() string { return types.ModuleName }

// IsAppModule implements appmodule.AppModule.
func (am AppModule) IsAppModule() {}

// IsOnePerModuleType implements appmodule.AppModule.
func (am AppModule) IsOnePerModuleType() {}

// ConsensusVersion returns the module's consensus version.
func (am AppModule) ConsensusVersion() uint64 { return ConsensusVersion }

// RegisterServices registers the module's message and query servers (no-op for now).
func (am AppModule) RegisterServices(_ module.Configurator) {}

// RegisterGRPCGatewayRoutes is a no-op.
func (am AppModule) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}

// RegisterInterfaces is a no-op.
func (am AppModule) RegisterInterfaces(_ codectypes.InterfaceRegistry) {}

// RegisterLegacyAminoCodec is a no-op.
func (am AppModule) RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}

// DefaultGenesis returns the raw JSON default genesis state.
func (am AppModule) DefaultGenesis(cdc codec.JSONCodec) json.RawMessage {
	return am.AppModuleBasic.DefaultGenesis(cdc)
}

// ValidateGenesis validates the provided genesis state.
func (am AppModule) ValidateGenesis(cdc codec.JSONCodec, cfg client.TxEncodingConfig, bz json.RawMessage) error {
	return am.AppModuleBasic.ValidateGenesis(cdc, cfg, bz)
}

// InitGenesis initialises module state from genesis.
func (am AppModule) InitGenesis(ctx sdk.Context, _ codec.JSONCodec, bz json.RawMessage) {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		panic(err)
	}
	InitGenesis(ctx, am.keeper, gs)
}

// ExportGenesis exports the module's state as genesis JSON.
func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	gs := ExportGenesis(ctx, am.keeper)
	bz, _ := json.Marshal(gs)
	return bz
}

// EndBlock runs end-block logic: processes expired identities.
func (am AppModule) EndBlock(ctx context.Context) error {
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	am.keeper.ProcessExpiredIdentities(sdkCtx)
	return nil
}

// RegisterInvariants is a no-op for now.
func (am AppModule) RegisterInvariants(_ sdk.InvariantRegistry) {}

// RegisterGRPCGatewayRoutesV2 is a no-op (no grpc-gateway routes yet).
func (am AppModule) RegisterGRPCGatewayRoutesV2(_ client.Context, _ *runtime.ServeMux) {}
