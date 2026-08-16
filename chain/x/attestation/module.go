// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package attestation

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

	attestabci "github.com/threatattest/chain/x/attestation/abci"
	attestgenesis "github.com/threatattest/chain/x/attestation/genesis"
	"github.com/threatattest/chain/x/attestation/keeper"
	attestquery "github.com/threatattest/chain/x/attestation/query"
	"github.com/threatattest/chain/x/attestation/types"
	pb "github.com/threatattest/chain/x/attestation/types/pb"
)

// Ensure AppModule implements all required interfaces.
var (
	_ module.AppModule          = AppModule{}
	_ module.AppModuleBasic     = AppModuleBasic{}
	_ appmodule.AppModule       = AppModule{}
	_ appmodule.HasBeginBlocker = AppModule{}
	_ appmodule.HasEndBlocker   = AppModule{}
)

// ConsensusVersion defines the current x/attestation module consensus version.
const ConsensusVersion = 1

// ============================================================
// AppModuleBasic
// ============================================================

// AppModuleBasic implements module.AppModuleBasic for x/attestation.
type AppModuleBasic struct{}

// Name returns the module's name.
func (AppModuleBasic) Name() string { return types.ModuleName }

// RegisterCodec registers legacy amino codec types.
func (AppModuleBasic) RegisterLegacyAminoCodec(_ *codec.LegacyAmino) {}

// RegisterInterfaces registers the module's sdk.Msg types with the codec so
// they can be decoded from tx Any values and routed by the MsgServiceRouter.
func (AppModuleBasic) RegisterInterfaces(registry codectypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&pb.MsgPublishAttestation{},
		&pb.MsgEndorseAttestation{},
		&pb.MsgRevokeAttestation{},
		&pb.MsgDisputeAttestation{},
		&pb.MsgUpdateParams{},
		&pb.MsgClaimReward{},
		&pb.MsgSubscribe{},
		&pb.MsgUnsubscribe{},
	)
	pb.RegisterMsgServiceDesc(registry)
}

// DefaultGenesis returns the default genesis state JSON.
func (AppModuleBasic) DefaultGenesis(_ codec.JSONCodec) json.RawMessage {
	gs := types.DefaultGenesisState()
	bz, _ := json.Marshal(gs)
	return bz
}

// ValidateGenesis validates the genesis JSON.
func (AppModuleBasic) ValidateGenesis(_ codec.JSONCodec, _ client.TxEncodingConfig, bz json.RawMessage) error {
	var gs types.GenesisState
	if err := json.Unmarshal(bz, &gs); err != nil {
		return err
	}
	return attestgenesis.ValidateGenesis(gs)
}

// RegisterGRPCGatewayRoutes registers gRPC-Gateway routes (no-op without proto-gen).
func (AppModuleBasic) RegisterGRPCGatewayRoutes(_ client.Context, _ *runtime.ServeMux) {}

// ============================================================
// AppModule
// ============================================================

// AppModule implements the full module interface for x/attestation.
type AppModule struct {
	AppModuleBasic
	keeper    keeper.Keeper
	msgServer *keeper.MsgServer
	qServer   *attestquery.QueryServer
}

// NewAppModule constructs an AppModule.
func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{
		keeper:    k,
		msgServer: keeper.NewMsgServer(k),
		qServer:   attestquery.NewQueryServer(k),
	}
}

// SetIdentityKeeper injects the identity keeper for tier-based confidence
// scaling. Call during app wiring; when not called the module defaults to
// Tier 0 (ANONYMOUS) for every attester.
func (am *AppModule) SetIdentityKeeper(k keeper.IdentityTierKeeper) {
	am.msgServer.SetIdentityKeeper(k)
}

// SetIPFSVerifyKeeper injects the ipfsverify keeper for detection-rule job
// creation. Call during app wiring; when not called no jobs are enqueued.
func (am *AppModule) SetIPFSVerifyKeeper(k keeper.IPFSVerifyKeeper) {
	am.msgServer.SetIPFSVerifyKeeper(k)
}

// Name returns the module name.
func (am AppModule) Name() string { return types.ModuleName }

// ConsensusVersion returns the module's consensus version.
func (am AppModule) ConsensusVersion() uint64 { return ConsensusVersion }

// RegisterServices registers gRPC handlers (MsgServer + QueryServer).
func (am AppModule) RegisterServices(cfg module.Configurator) {
	pb.RegisterMsgServer(cfg.MsgServer(), &wireMsgServer{inner: am.msgServer})
	pb.RegisterQueryServer(cfg.QueryServer(), &wireQueryServer{inner: am.qServer})
}

// InitGenesis initialises module state from genesis JSON.
func (am AppModule) InitGenesis(ctx sdk.Context, _ codec.JSONCodec, data json.RawMessage) {
	var gs types.GenesisState
	if err := json.Unmarshal(data, &gs); err != nil {
		panic("failed to unmarshal attestation genesis state: " + err.Error())
	}
	if err := attestgenesis.InitGenesis(ctx, am.keeper, gs); err != nil {
		panic("failed to init attestation genesis: " + err.Error())
	}
}

// ExportGenesis exports the current state as genesis JSON.
func (am AppModule) ExportGenesis(ctx sdk.Context, _ codec.JSONCodec) json.RawMessage {
	gs, err := attestgenesis.ExportGenesis(ctx, am.keeper)
	if err != nil {
		panic("failed to export attestation genesis: " + err.Error())
	}
	bz, err := json.Marshal(gs)
	if err != nil {
		panic("failed to marshal attestation genesis: " + err.Error())
	}
	return bz
}

// BeginBlock is called at the beginning of each block.
func (am AppModule) BeginBlock(ctx context.Context) error {
	return attestabci.BeginBlocker(sdk.UnwrapSDKContext(ctx), am.keeper)
}

// EndBlock is called at the end of each block.
func (am AppModule) EndBlock(ctx context.Context) error {
	return attestabci.EndBlocker(sdk.UnwrapSDKContext(ctx), am.keeper)
}

// IsOnePerModuleType implements appmodule.AppModule.
func (am AppModule) IsOnePerModuleType() {}

// IsAppModule implements appmodule.AppModule.
func (am AppModule) IsAppModule() {}
