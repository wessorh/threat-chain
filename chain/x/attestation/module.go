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
	"google.golang.org/grpc"

	attestabci "github.com/threatattest/chain/x/attestation/abci"
	attestgenesis "github.com/threatattest/chain/x/attestation/genesis"
	"github.com/threatattest/chain/x/attestation/keeper"
	attestmsgs "github.com/threatattest/chain/x/attestation/msgs"
	attestquery "github.com/threatattest/chain/x/attestation/query"
	"github.com/threatattest/chain/x/attestation/types"
	_ "github.com/threatattest/chain/x/attestation/types/pb"
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
		&attestmsgs.MsgPublishAttestation{},
		&attestmsgs.MsgEndorseAttestation{},
		&attestmsgs.MsgRevokeAttestation{},
		&attestmsgs.MsgDisputeAttestation{},
		&attestmsgs.MsgUpdateParams{},
		&attestmsgs.MsgClaimReward{},
		&attestmsgs.MsgSubscribe{},
		&attestmsgs.MsgUnsubscribe{},
	)
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

// Name returns the module name.
func (am AppModule) Name() string { return types.ModuleName }

// ConsensusVersion returns the module's consensus version.
func (am AppModule) ConsensusVersion() uint64 { return ConsensusVersion }

// RegisterServices registers gRPC handlers (MsgServer + QueryServer).
func (am AppModule) RegisterServices(cfg module.Configurator) {
	registerMsgRoutes(cfg.MsgServer(), am.msgServer)
	registerQueryRoutes(cfg.QueryServer(), am.qServer)
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

// ============================================================
// gRPC route registration helpers
// ============================================================

// grpcMethodHandler matches grpc's unexported methodHandler type (v1.64.1 has
// no exported grpc.MethodHandler). As a type alias it stays assignable to the
// grpc.MethodDesc.Handler field.
type grpcMethodHandler = func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error)

// newUnaryHandler adapts a typed handler method into a grpc method handler.
func newUnaryHandler[Srv, Req, Res any](fn func(*Srv, context.Context, *Req) (*Res, error)) grpcMethodHandler {
	return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
		in := new(Req)
		if err := dec(in); err != nil {
			return nil, err
		}
		// NOTE: during service registration the SDK invokes the handler with a
		// nil srv to extract the request type URL, so cast srv lazily (inside the
		// branches that only run for real requests).
		if interceptor == nil {
			return fn(srv.(*Srv), ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return fn(srv.(*Srv), ctx, req.(*Req))
		}
		return interceptor(ctx, in, info, handler)
	}
}

var _Msg_serviceDesc = grpc.ServiceDesc{
	ServiceName: "threatattest.attestation.Msg",
	HandlerType: (*keeper.MsgServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "PublishAttestation", Handler: newUnaryHandler((*keeper.MsgServer).PublishAttestation)},
		{MethodName: "EndorseAttestation", Handler: newUnaryHandler((*keeper.MsgServer).EndorseAttestation)},
		{MethodName: "RevokeAttestation", Handler: newUnaryHandler((*keeper.MsgServer).RevokeAttestation)},
		{MethodName: "DisputeAttestation", Handler: newUnaryHandler((*keeper.MsgServer).DisputeAttestation)},
		{MethodName: "UpdateParams", Handler: newUnaryHandler((*keeper.MsgServer).UpdateParams)},
		{MethodName: "ClaimReward", Handler: newUnaryHandler((*keeper.MsgServer).ClaimReward)},
		{MethodName: "Subscribe", Handler: newUnaryHandler((*keeper.MsgServer).Subscribe)},
		{MethodName: "Unsubscribe", Handler: newUnaryHandler((*keeper.MsgServer).Unsubscribe)},
	},
}

var _Query_serviceDesc = grpc.ServiceDesc{
	ServiceName: "threatattest.attestation.Query",
	HandlerType: (*attestquery.QueryServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "IsMalicious", Handler: newUnaryHandler((*attestquery.QueryServer).IsMalicious)},
		{MethodName: "IsMaliciousURL", Handler: newUnaryHandler((*attestquery.QueryServer).IsMaliciousURL)},
		{MethodName: "IsMaliciousIPv4", Handler: newUnaryHandler((*attestquery.QueryServer).IsMaliciousIPv4)},
		{MethodName: "IsMaliciousHolloman", Handler: newUnaryHandler((*attestquery.QueryServer).IsMaliciousHolloman)},
		{MethodName: "GetAttestation", Handler: newUnaryHandler((*attestquery.QueryServer).GetAttestation)},
		{MethodName: "ListArtifactAttestations", Handler: newUnaryHandler((*attestquery.QueryServer).ListArtifactAttestations)},
		{MethodName: "ListAttesterAttestations", Handler: newUnaryHandler((*attestquery.QueryServer).ListAttesterAttestations)},
		{MethodName: "GetDispute", Handler: newUnaryHandler((*attestquery.QueryServer).GetDispute)},
		{MethodName: "IsBlacklisted", Handler: newUnaryHandler((*attestquery.QueryServer).IsBlacklisted)},
		{MethodName: "Params", Handler: newUnaryHandler((*attestquery.QueryServer).Params)},
	},
}

func registerMsgRoutes(srv grpc.ServiceRegistrar, ms *keeper.MsgServer) {
	srv.RegisterService(&_Msg_serviceDesc, ms)
}

func registerQueryRoutes(srv grpc.ServiceRegistrar, qs *attestquery.QueryServer) {
	srv.RegisterService(&_Query_serviceDesc, qs)
}

// ============================================================
// Msg handler map for app-level router wiring
// ============================================================

// MsgHandlers returns the message handlers map for manual router wiring.
func (am AppModule) MsgHandlers() map[string]func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
	return map[string]func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error){
		sdk.MsgTypeURL(&attestmsgs.MsgPublishAttestation{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.PublishAttestation(ctx, msg.(*attestmsgs.MsgPublishAttestation))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgEndorseAttestation{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.EndorseAttestation(ctx, msg.(*attestmsgs.MsgEndorseAttestation))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgRevokeAttestation{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.RevokeAttestation(ctx, msg.(*attestmsgs.MsgRevokeAttestation))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgDisputeAttestation{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.DisputeAttestation(ctx, msg.(*attestmsgs.MsgDisputeAttestation))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgUpdateParams{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.UpdateParams(ctx, msg.(*attestmsgs.MsgUpdateParams))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgClaimReward{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.ClaimReward(ctx, msg.(*attestmsgs.MsgClaimReward))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgSubscribe{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.Subscribe(ctx, msg.(*attestmsgs.MsgSubscribe))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
		sdk.MsgTypeURL(&attestmsgs.MsgUnsubscribe{}): func(ctx sdk.Context, msg sdk.Msg) (sdk.Result, error) {
			resp, err := am.msgServer.Unsubscribe(ctx, msg.(*attestmsgs.MsgUnsubscribe))
			if err != nil {
				return sdk.Result{}, err
			}
			bz, _ := json.Marshal(resp)
			return sdk.Result{Data: bz}, nil
		},
	}
}
