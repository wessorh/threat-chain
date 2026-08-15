// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package app

import (
	evidencemodule "cosmossdk.io/x/evidence"
	feegrantmodule "cosmossdk.io/x/feegrant/module"
	"cosmossdk.io/x/tx/signing"
	upgrademodule "cosmossdk.io/x/upgrade"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/std"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	"github.com/cosmos/cosmos-sdk/x/auth/vesting"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	"github.com/cosmos/cosmos-sdk/x/bank"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	"github.com/cosmos/cosmos-sdk/x/distribution"
	"github.com/cosmos/cosmos-sdk/x/gov"
	"github.com/cosmos/cosmos-sdk/x/params"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	"github.com/cosmos/cosmos-sdk/x/staking"
	"github.com/cosmos/gogoproto/proto"

	attestation "github.com/threatattest/chain/x/attestation"
	ipfsverify "github.com/threatattest/chain/x/ipfsverify"
	reputation "github.com/threatattest/chain/x/reputation"
	tatmint "github.com/threatattest/chain/x/tatmint"
)

// EncodingConfig specifies the concrete encoding types for the app and CLI.
type EncodingConfig struct {
	InterfaceRegistry codectypes.InterfaceRegistry
	Codec             *codec.ProtoCodec
	TxConfig          client.TxConfig
	Amino             *codec.LegacyAmino
}

// ModuleBasics is the basic module manager used for interface registration,
// legacy amino codec registration, and genesis handling. It must include every
// module wired into the full app (standard + custom).
var ModuleBasics = module.NewBasicManager(
	auth.AppModuleBasic{},
	vesting.AppModuleBasic{},
	bank.AppModuleBasic{},
	staking.AppModuleBasic{},
	distribution.AppModuleBasic{},
	slashing.AppModuleBasic{},
	gov.AppModuleBasic{},
	crisis.AppModuleBasic{},
	upgrademodule.AppModuleBasic{},
	evidencemodule.AppModuleBasic{},
	feegrantmodule.AppModuleBasic{},
	authzmodule.AppModuleBasic{},
	params.AppModuleBasic{},
	consensus.AppModuleBasic{},
	tatmint.AppModuleBasic{},
	reputation.AppModuleBasic{},
	attestation.AppModuleBasic{},
	ipfsverify.AppModuleBasic{},
)

// MakeEncodingConfig builds an encoding config with all module interfaces
// registered. It is shared by the node (NewThreatAttestApp) and the CLI
// (NewRootCmd) so that genesis/transaction encoding is consistent.
func MakeEncodingConfig() EncodingConfig {
	interfaceRegistry, err := codectypes.NewInterfaceRegistryWithOptions(codectypes.InterfaceRegistryOptions{
		ProtoFiles: proto.HybridResolver,
		SigningOptions: signing.Options{
			AddressCodec:          addresscodec.NewBech32Codec(Bech32Prefix),
			ValidatorAddressCodec: addresscodec.NewBech32Codec(Bech32Prefix + "valoper"),
		},
	})
	if err != nil {
		panic(err)
	}
	cdc := codec.NewProtoCodec(interfaceRegistry)
	legacyAmino := codec.NewLegacyAmino()

	std.RegisterLegacyAminoCodec(legacyAmino)
	std.RegisterInterfaces(interfaceRegistry)

	ModuleBasics.RegisterLegacyAminoCodec(legacyAmino)
	ModuleBasics.RegisterInterfaces(interfaceRegistry)

	txConfig := authtx.NewTxConfig(cdc, authtx.DefaultSignModes)

	return EncodingConfig{
		InterfaceRegistry: interfaceRegistry,
		Codec:             cdc,
		TxConfig:          txConfig,
		Amino:             legacyAmino,
	}
}
