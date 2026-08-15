// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Package app wires together all Cosmos SDK modules and custom ThreatAttest
// modules into a single application.
package app

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"

	"cosmossdk.io/log"
	storetypes "cosmossdk.io/store/types"
	evidencemodule "cosmossdk.io/x/evidence"
	evidencekeeper "cosmossdk.io/x/evidence/keeper"
	evidencetypes "cosmossdk.io/x/evidence/types"
	feegranttypes "cosmossdk.io/x/feegrant"
	feegrantkeeper "cosmossdk.io/x/feegrant/keeper"
	feegrantmodule "cosmossdk.io/x/feegrant/module"
	upgrademodule "cosmossdk.io/x/upgrade"
	upgradekeeper "cosmossdk.io/x/upgrade/keeper"
	upgradetypes "cosmossdk.io/x/upgrade/types"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/cosmos-sdk/server/api"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/version"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authkeeper "github.com/cosmos/cosmos-sdk/x/auth/keeper"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/auth/vesting"
	"github.com/cosmos/cosmos-sdk/x/authz"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	authzmodule "github.com/cosmos/cosmos-sdk/x/authz/module"
	"github.com/cosmos/cosmos-sdk/x/bank"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/cosmos/cosmos-sdk/x/consensus"
	consensuskeeper "github.com/cosmos/cosmos-sdk/x/consensus/keeper"
	consensustypes "github.com/cosmos/cosmos-sdk/x/consensus/types"
	"github.com/cosmos/cosmos-sdk/x/crisis"
	crisiskeeper "github.com/cosmos/cosmos-sdk/x/crisis/keeper"
	crisistypes "github.com/cosmos/cosmos-sdk/x/crisis/types"
	"github.com/cosmos/cosmos-sdk/x/distribution"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"github.com/cosmos/cosmos-sdk/x/params"
	paramskeeper "github.com/cosmos/cosmos-sdk/x/params/keeper"
	paramstypes "github.com/cosmos/cosmos-sdk/x/params/types"
	"github.com/cosmos/cosmos-sdk/x/slashing"
	slashingkeeper "github.com/cosmos/cosmos-sdk/x/slashing/keeper"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"
	"github.com/cosmos/cosmos-sdk/x/staking"
	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	cmtservice "github.com/cosmos/cosmos-sdk/client/grpc/cmtservice"
	nodeservice "github.com/cosmos/cosmos-sdk/client/grpc/node"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"

	tatante "github.com/threatattest/chain/ante"
	attestation "github.com/threatattest/chain/x/attestation"
	attestkeeper "github.com/threatattest/chain/x/attestation/keeper"
	attesttypes "github.com/threatattest/chain/x/attestation/types"
	ipfsverify "github.com/threatattest/chain/x/ipfsverify"
	ipfskeeper "github.com/threatattest/chain/x/ipfsverify/keeper"
	reputation "github.com/threatattest/chain/x/reputation"
	repkeeper "github.com/threatattest/chain/x/reputation/keeper"
	reptypes "github.com/threatattest/chain/x/reputation/types"
	tatmint "github.com/threatattest/chain/x/tatmint"
	mintkeeper "github.com/threatattest/chain/x/tatmint/keeper"
	minttypes "github.com/threatattest/chain/x/tatmint/types"
)

const (
	AppName      = "threatattestd"
	Bech32Prefix = "tatst"
	BondDenom    = "utatst"
)

// DefaultNodeHome is the default home directory for the node daemon.
var DefaultNodeHome = filepath.Join(func() string {
	home, _ := os.UserHomeDir()
	return home
}(), ".threatattestd")

// maccPerms defines module account permissions for x/bank blocking.
var maccPerms = map[string][]string{
	authtypes.FeeCollectorName:     nil,
	distrtypes.ModuleName:          nil,
	stakingtypes.BondedPoolName:    {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName: {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:            {authtypes.Burner},
	attesttypes.ModuleName:         {authtypes.Minter, authtypes.Burner},
	reptypes.ModuleName:            nil,
	minttypes.ModuleName:           {authtypes.Minter},
}

// GenesisState is the genesis state map for all modules.
type GenesisState map[string]json.RawMessage

// ThreatAttestApp is the main application struct.
type ThreatAttestApp struct {
	*baseapp.BaseApp

	cdc               *codec.ProtoCodec
	interfaceRegistry codectypes.InterfaceRegistry
	mm                *module.Manager
	configurator      module.Configurator

	// Standard keepers
	AccountKeeper   authkeeper.AccountKeeper
	BankKeeper      bankkeeper.BaseKeeper
	StakingKeeper   *stakingkeeper.Keeper
	SlashingKeeper  slashingkeeper.Keeper
	DistrKeeper     distrkeeper.Keeper
	GovKeeper       *govkeeper.Keeper
	CrisisKeeper    *crisiskeeper.Keeper
	UpgradeKeeper   *upgradekeeper.Keeper
	ParamsKeeper    paramskeeper.Keeper
	AuthzKeeper     authzkeeper.Keeper
	FeeGrantKeeper  feegrantkeeper.Keeper
	EvidenceKeeper  evidencekeeper.Keeper
	ConsensusKeeper consensuskeeper.Keeper

	// Custom keepers
	AttestKeeper attestkeeper.Keeper
	RepKeeper    repkeeper.Keeper
	IPFSKeeper   ipfskeeper.Keeper
	MintKeeper   mintkeeper.Keeper
}

// NewThreatAttestApp creates and fully wires the ThreatAttest application.
func NewThreatAttestApp(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	loadLatest bool,
	appOpts servertypes.AppOptions,
	baseAppOptions ...func(*baseapp.BaseApp),
) *ThreatAttestApp {
	// Note: bech32 prefixes are set and sealed in NewRootCmd (before the app is
	// constructed), so we must not call SetBech32Prefix* here again.
	sdk.DefaultBondDenom = BondDenom

	encodingConfig := MakeEncodingConfig()
	interfaceRegistry := encodingConfig.InterfaceRegistry
	cdc := encodingConfig.Codec
	legacyAmino := encodingConfig.Amino

	bApp := baseapp.NewBaseApp(AppName, logger, db, nil, baseAppOptions...)
	bApp.SetCommitMultiStoreTracer(traceStore)
	bApp.SetVersion(version.Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)

	app := &ThreatAttestApp{
		BaseApp:           bApp,
		cdc:               cdc,
		interfaceRegistry: interfaceRegistry,
	}

	// Address codecs
	addrCodec := addresscodec.NewBech32Codec(Bech32Prefix)
	validatorAddrCodec := addresscodec.NewBech32Codec(Bech32Prefix + "valoper")
	consensusAddrCodec := addresscodec.NewBech32Codec(Bech32Prefix + "valcons")

	// KV store keys
	keys := storetypes.NewKVStoreKeys(
		authtypes.StoreKey,
		banktypes.StoreKey,
		stakingtypes.StoreKey,
		crisistypes.StoreKey,
		slashingtypes.StoreKey,
		distrtypes.StoreKey,
		govtypes.StoreKey,
		upgradetypes.StoreKey,
		paramstypes.StoreKey,
		authz.ModuleName,
		feegranttypes.ModuleName,
		evidencetypes.StoreKey,
		consensustypes.StoreKey,
		attesttypes.StoreKey,
		reptypes.StoreKey,
		"ipfsverify",
		minttypes.StoreKey,
	)
	tkeys := storetypes.NewTransientStoreKeys(paramstypes.TStoreKey)

	app.MountKVStores(keys)
	app.MountTransientStores(tkeys)

	app.ParamsKeeper = initParamsKeeper(cdc, legacyAmino,
		keys[paramstypes.StoreKey], tkeys[paramstypes.TStoreKey])

	govAuthority := authtypes.NewModuleAddress(govtypes.ModuleName).String()

	// ── Standard keepers ────────────────────────────────────────────────────────

	app.AccountKeeper = authkeeper.NewAccountKeeper(
		cdc,
		runtime.NewKVStoreService(keys[authtypes.StoreKey]),
		authtypes.ProtoBaseAccount,
		maccPerms,
		addrCodec,
		Bech32Prefix,
		govAuthority,
	)

	app.BankKeeper = bankkeeper.NewBaseKeeper(
		cdc,
		runtime.NewKVStoreService(keys[banktypes.StoreKey]),
		app.AccountKeeper,
		BlockedModuleAddresses(),
		govAuthority,
		logger,
	)

	app.StakingKeeper = stakingkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[stakingtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		govAuthority,
		validatorAddrCodec,
		consensusAddrCodec,
	)

	app.DistrKeeper = distrkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[distrtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		authtypes.FeeCollectorName,
		govAuthority,
	)

	app.SlashingKeeper = slashingkeeper.NewKeeper(
		cdc,
		legacyAmino,
		runtime.NewKVStoreService(keys[slashingtypes.StoreKey]),
		app.StakingKeeper,
		govAuthority,
	)

	app.CrisisKeeper = crisiskeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[crisistypes.StoreKey]),
		5,
		app.BankKeeper,
		authtypes.FeeCollectorName,
		govAuthority,
		app.AccountKeeper.AddressCodec(),
	)

	app.UpgradeKeeper = upgradekeeper.NewKeeper(
		map[int64]bool{},
		runtime.NewKVStoreService(keys[upgradetypes.StoreKey]),
		cdc,
		DefaultNodeHome,
		app.BaseApp,
		govAuthority,
	)

	app.AuthzKeeper = authzkeeper.NewKeeper(
		runtime.NewKVStoreService(keys[authz.ModuleName]),
		cdc,
		app.BaseApp.MsgServiceRouter(),
		app.AccountKeeper,
	)

	app.FeeGrantKeeper = feegrantkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[feegranttypes.ModuleName]),
		app.AccountKeeper,
	)

	evidenceK := evidencekeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[evidencetypes.StoreKey]),
		app.StakingKeeper,
		app.SlashingKeeper,
		app.AccountKeeper.AddressCodec(),
		runtime.ProvideCometInfoService(),
	)
	app.EvidenceKeeper = *evidenceK

	app.ConsensusKeeper = consensuskeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[consensustypes.StoreKey]),
		govAuthority,
		runtime.ProvideEventService(),
	)
	bApp.SetParamStore(app.ConsensusKeeper.ParamsStore)

	app.GovKeeper = govkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[govtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.StakingKeeper,
		app.DistrKeeper,
		app.BaseApp.MsgServiceRouter(),
		govtypes.DefaultConfig(),
		govAuthority,
	)

	// ── Custom keepers ───────────────────────────────────────────────────────────

	app.RepKeeper = repkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[reptypes.StoreKey]),
		logger,
		govAuthority,
	)

	app.AttestKeeper = attestkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[attesttypes.StoreKey]),
		logger,
		app.RepKeeper,
		nil,
		app.BankKeeper,
		govAuthority,
	)

	app.IPFSKeeper = ipfskeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys["ipfsverify"]),
		logger,
		&app.AttestKeeper,
		govAuthority,
	)

	app.MintKeeper = mintkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[minttypes.StoreKey]),
		logger,
		app.BankKeeper,
		app.DistrKeeper,
		authtypes.FeeCollectorName,
	)

	// ── Module manager ──────────────────────────────────────────────────────────

	app.mm = module.NewManager(
		auth.NewAppModule(cdc, app.AccountKeeper, nil, nil),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(cdc, app.BankKeeper, app.AccountKeeper, nil),
		staking.NewAppModule(cdc, app.StakingKeeper, app.AccountKeeper, app.BankKeeper, nil),
		distribution.NewAppModule(cdc, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, nil),
		slashing.NewAppModule(cdc, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, nil, cdc.InterfaceRegistry()),
		gov.NewAppModule(cdc, app.GovKeeper, app.AccountKeeper, app.BankKeeper, nil),
		crisis.NewAppModule(app.CrisisKeeper, false, nil),
		upgrademodule.NewAppModule(app.UpgradeKeeper, addrCodec),
		evidencemodule.NewAppModule(app.EvidenceKeeper),
		feegrantmodule.NewAppModule(cdc, app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, cdc.InterfaceRegistry()),
		authzmodule.NewAppModule(cdc, app.AuthzKeeper, app.AccountKeeper, app.BankKeeper, cdc.InterfaceRegistry()),
		params.NewAppModule(app.ParamsKeeper),
		consensus.NewAppModule(cdc, app.ConsensusKeeper),
		tatmint.NewAppModule(app.MintKeeper),
		reputation.NewAppModule(app.RepKeeper),
		attestation.NewAppModule(app.AttestKeeper),
		ipfsverify.NewAppModule(app.IPFSKeeper),
	)

	app.mm.SetOrderBeginBlockers(
		upgradetypes.ModuleName,
		minttypes.ModuleName,
		distrtypes.ModuleName,
		slashingtypes.ModuleName,
		evidencetypes.ModuleName,
		stakingtypes.ModuleName,
		attesttypes.ModuleName,
		authz.ModuleName,
	)

	app.mm.SetOrderEndBlockers(
		crisistypes.ModuleName,
		govtypes.ModuleName,
		stakingtypes.ModuleName,
		attesttypes.ModuleName,
		reptypes.ModuleName,
		"ipfsverify",
		feegranttypes.ModuleName,
		authz.ModuleName,
	)

	genesisOrder := []string{
		authtypes.ModuleName,
		banktypes.ModuleName,
		distrtypes.ModuleName,
		stakingtypes.ModuleName,
		slashingtypes.ModuleName,
		govtypes.ModuleName,
		crisistypes.ModuleName,
		upgradetypes.ModuleName,
		evidencetypes.ModuleName,
		feegranttypes.ModuleName,
		authz.ModuleName,
		paramstypes.ModuleName,
		consensustypes.ModuleName,
		"vesting",
		minttypes.ModuleName,
		reptypes.ModuleName,
		attesttypes.ModuleName,
		"ipfsverify",
	}
	app.mm.SetOrderInitGenesis(genesisOrder...)
	app.mm.SetOrderExportGenesis(genesisOrder...)

	app.configurator = module.NewConfigurator(cdc, app.MsgServiceRouter(), app.GRPCQueryRouter())
	if err := app.mm.RegisterServices(app.configurator); err != nil {
		panic(err)
	}

	// ── AnteHandler ─────────────────────────────────────────────────────────────

	anteHandler, err := tatante.NewAnteHandler(tatante.HandlerOptions{
		HandlerOptions: authante.HandlerOptions{
			AccountKeeper:   app.AccountKeeper,
			BankKeeper:      app.BankKeeper,
			FeegrantKeeper:  app.FeeGrantKeeper,
			SignModeHandler: encodingConfig.TxConfig.SignModeHandler(),
		},
		AttestKeeper: app.AttestKeeper,
	})
	if err != nil {
		panic(err)
	}
	app.SetAnteHandler(anteHandler)

	// ── Chain lifecycle hooks ────────────────────────────────────────────────────

	app.SetInitChainer(func(ctx sdk.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
		var gs GenesisState
		if err := json.Unmarshal(req.AppStateBytes, &gs); err != nil {
			return nil, err
		}
		app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
		return app.mm.InitGenesis(ctx, cdc, gs)
	})
	app.SetBeginBlocker(func(ctx sdk.Context) (sdk.BeginBlock, error) {
		return app.mm.BeginBlock(ctx)
	})
	app.SetEndBlocker(func(ctx sdk.Context) (sdk.EndBlock, error) {
		return app.mm.EndBlock(ctx)
	})

	if loadLatest {
		if err := app.LoadLatestVersion(); err != nil {
			panic(err)
		}
	}

	return app
}

// DefaultGenesis returns the default genesis state map.
func (app *ThreatAttestApp) DefaultGenesis() GenesisState {
	bm := module.NewBasicManagerFromManager(app.mm, nil)
	return bm.DefaultGenesis(app.cdc)
}

// RegisterAPIRoutes registers REST/gRPC-Gateway routes.
func (app *ThreatAttestApp) RegisterAPIRoutes(_ *api.Server, _ serverconfig.APIConfig) {}

// RegisterTxService registers the gRPC tx service.
func (app *ThreatAttestApp) RegisterTxService(clientCtx client.Context) {
	authtx.RegisterTxService(app.GRPCQueryRouter(), clientCtx, app.Simulate, app.interfaceRegistry)
}

// RegisterTendermintService registers the gRPC CometBFT service.
func (app *ThreatAttestApp) RegisterTendermintService(clientCtx client.Context) {
	cmtApp := server.NewCometABCIWrapper(app)
	cmtservice.RegisterTendermintService(
		clientCtx,
		app.GRPCQueryRouter(),
		app.interfaceRegistry,
		cmtApp.Query,
	)
}

// RegisterNodeService registers the node gRPC service.
func (app *ThreatAttestApp) RegisterNodeService(clientCtx client.Context, cfg serverconfig.Config) {
	nodeservice.RegisterNodeService(clientCtx, app.GRPCQueryRouter(), cfg)
}

// ExportAppStateAndValidators exports the genesis state for snapshots.
func (app *ThreatAttestApp) ExportAppStateAndValidators(
	forZeroHeight bool,
	_ []string,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	ctx := app.NewContextLegacy(true, cmtproto.Header{Height: app.LastBlockHeight()})
	height := app.LastBlockHeight() + 1
	if forZeroHeight {
		height = 0
	}
	genState, err := app.mm.ExportGenesisForModules(ctx, app.cdc, modulesToExport)
	if err != nil {
		return servertypes.ExportedApp{}, err
	}
	appState, err := json.MarshalIndent(genState, "", "  ")
	if err != nil {
		return servertypes.ExportedApp{}, err
	}
	validators, err := staking.WriteValidators(ctx, app.StakingKeeper)
	return servertypes.ExportedApp{
		AppState:        appState,
		Validators:      validators,
		Height:          height,
		ConsensusParams: app.BaseApp.GetConsensusParams(ctx),
	}, err
}

// SimulationManager returns nil (simulation not implemented).
func (app *ThreatAttestApp) SimulationManager() interface{} { return nil }

func initParamsKeeper(
	cdc codec.BinaryCodec,
	legacyAmino *codec.LegacyAmino,
	key, tkey storetypes.StoreKey,
) paramskeeper.Keeper {
	k := paramskeeper.NewKeeper(cdc, legacyAmino, key, tkey)
	k.Subspace(authtypes.ModuleName)
	k.Subspace(banktypes.ModuleName)
	k.Subspace(stakingtypes.ModuleName)
	k.Subspace(distrtypes.ModuleName)
	k.Subspace(slashingtypes.ModuleName)
	k.Subspace(govtypes.ModuleName) //nolint:staticcheck
	k.Subspace(crisistypes.ModuleName)
	return k
}

// BlockedModuleAddresses returns addresses blocked from receiving bank sends.
func BlockedModuleAddresses() map[string]bool {
	blocked := make(map[string]bool, len(maccPerms))
	for acc := range maccPerms {
		blocked[authtypes.NewModuleAddress(acc).String()] = true
	}
	return blocked
}
