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

	"cosmossdk.io/log/v2"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	evidencemodule "github.com/cosmos/cosmos-sdk/x/evidence"
	evidencekeeper "github.com/cosmos/cosmos-sdk/x/evidence/keeper"
	evidencetypes "github.com/cosmos/cosmos-sdk/x/evidence/types"
	feegranttypes "github.com/cosmos/cosmos-sdk/x/feegrant"
	feegrantkeeper "github.com/cosmos/cosmos-sdk/x/feegrant/keeper"
	feegrantmodule "github.com/cosmos/cosmos-sdk/x/feegrant/module"
	upgrademodule "github.com/cosmos/cosmos-sdk/x/upgrade"
	upgradekeeper "github.com/cosmos/cosmos-sdk/x/upgrade/keeper"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

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
	"github.com/cosmos/cosmos-sdk/x/distribution"
	distrkeeper "github.com/cosmos/cosmos-sdk/x/distribution/keeper"
	distrtypes "github.com/cosmos/cosmos-sdk/x/distribution/types"
	genutil "github.com/cosmos/cosmos-sdk/x/genutil"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/cosmos/cosmos-sdk/x/gov"
	govkeeper "github.com/cosmos/cosmos-sdk/x/gov/keeper"
	govtypes "github.com/cosmos/cosmos-sdk/x/gov/types"
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
	identity "github.com/threatattest/chain/x/identity"
	identitykeeper "github.com/threatattest/chain/x/identity/keeper"
	identitytypes "github.com/threatattest/chain/x/identity/types"
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
	authtypes.FeeCollectorName:          nil,
	distrtypes.ModuleName:               nil,
	stakingtypes.BondedPoolName:         {authtypes.Burner, authtypes.Staking},
	stakingtypes.NotBondedPoolName:      {authtypes.Burner, authtypes.Staking},
	govtypes.ModuleName:                 {authtypes.Burner},
	attesttypes.ModuleName:              {authtypes.Minter, authtypes.Burner},
	reptypes.ModuleName:                 nil,
	minttypes.ModuleName:                {authtypes.Minter},
	stakingtypes.KeyRotationFeePoolName: {authtypes.Burner},
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
	UpgradeKeeper   *upgradekeeper.Keeper
	AuthzKeeper     authzkeeper.Keeper
	FeeGrantKeeper  feegrantkeeper.Keeper
	EvidenceKeeper  evidencekeeper.Keeper
	ConsensusKeeper consensuskeeper.Keeper

	// Custom keepers
	AttestKeeper    attestkeeper.Keeper
	RepKeeper       repkeeper.Keeper
	IPFSKeeper      ipfskeeper.Keeper
	MintKeeper      mintkeeper.Keeper
	IdentityKeeper  identitykeeper.Keeper
}

// identityTierAdapter adapts the x/identity keeper to the x/attestation
// keeper.IdentityTierKeeper interface, bridging the sdk.Context parameter and
// the ComplianceTier -> int32 return type.
type identityTierAdapter struct {
	keeper identitykeeper.Keeper
}

// GetTier returns the compliance tier (0-3) for an attester address.
func (a identityTierAdapter) GetTier(ctx interface{}, cosmosAddr string) int32 {
	sdkCtx, ok := ctx.(sdk.Context)
	if !ok {
		return 0
	}
	return int32(a.keeper.GetTier(sdkCtx, cosmosAddr))
}

// ipfsVerifyAdapter adapts the x/ipfsverify keeper to the x/attestation
// keeper.IPFSVerifyKeeper interface (dropping the job return value).
type ipfsVerifyAdapter struct {
	keeper ipfskeeper.Keeper
}

func (a ipfsVerifyAdapter) SubmitVerificationJob(ctx sdk.Context, attestationID, ruleID, cid, expectedSHA256, submittedBy string) error {
	_, err := a.keeper.SubmitVerificationJob(ctx, attestationID, ruleID, cid, expectedSHA256, submittedBy)
	return err
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
	bApp.SetVersion(version.Version)
	bApp.SetInterfaceRegistry(interfaceRegistry)
	bApp.SetTxDecoder(encodingConfig.TxConfig.TxDecoder())
	bApp.SetTxEncoder(encodingConfig.TxConfig.TxEncoder())

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
		slashingtypes.StoreKey,
		distrtypes.StoreKey,
		govtypes.StoreKey,
		upgradetypes.StoreKey,
		authz.ModuleName,
		feegranttypes.ModuleName,
		evidencetypes.StoreKey,
		consensustypes.StoreKey,
		attesttypes.StoreKey,
		reptypes.StoreKey,
		"ipfsverify",
		minttypes.StoreKey,
		identitytypes.StoreKey,
	)

	app.MountKVStores(keys)

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

	// Wire staking hooks so distribution (fee allocation) and slashing (validator
	// signing-info initialisation) react to validator lifecycle events. Without
	// this, slashing has no signing info for the genesis validator and panics on
	// the first block it signs.
	app.StakingKeeper.SetHooks(
		stakingtypes.NewMultiStakingHooks(
			app.DistrKeeper.Hooks(),
			app.SlashingKeeper.Hooks(),
		),
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
		runtime.EventService{},
	)
	bApp.SetParamStore(app.ConsensusKeeper.ParamsStore)

	app.GovKeeper = govkeeper.NewKeeper(
		cdc,
		runtime.NewKVStoreService(keys[govtypes.StoreKey]),
		app.AccountKeeper,
		app.BankKeeper,
		app.DistrKeeper,
		app.BaseApp.MsgServiceRouter(),
		govtypes.DefaultConfig(),
		govAuthority,
		govkeeper.NewDefaultCalculateVoteResultsAndVotingPower(app.StakingKeeper),
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
		app.StakingKeeper,
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

	app.IdentityKeeper = identitykeeper.NewKeeper(
		keys[identitytypes.StoreKey],
		cdc,
	)

	// ── Module manager ──────────────────────────────────────────────────────────

	attestModule := attestation.NewAppModule(app.AttestKeeper)
	attestModule.SetIdentityKeeper(identityTierAdapter{app.IdentityKeeper})
	attestModule.SetIPFSVerifyKeeper(ipfsVerifyAdapter{app.IPFSKeeper})

	app.mm = module.NewManager(
		genutil.NewAppModule(app.AccountKeeper, app.StakingKeeper, app.BaseApp, encodingConfig.TxConfig),
		auth.NewAppModule(cdc, app.AccountKeeper, nil),
		vesting.NewAppModule(app.AccountKeeper, app.BankKeeper),
		bank.NewAppModule(cdc, app.BankKeeper, app.AccountKeeper),
		staking.NewAppModule(cdc, app.StakingKeeper, app.AccountKeeper, app.BankKeeper),
		distribution.NewAppModule(cdc, app.DistrKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper),
		slashing.NewAppModule(cdc, app.SlashingKeeper, app.AccountKeeper, app.BankKeeper, app.StakingKeeper, cdc.InterfaceRegistry()),
		gov.NewAppModule(cdc, app.GovKeeper, app.AccountKeeper, app.BankKeeper),
		upgrademodule.NewAppModule(app.UpgradeKeeper, addrCodec),
		evidencemodule.NewAppModule(app.EvidenceKeeper),
		feegrantmodule.NewAppModule(cdc, app.AccountKeeper, app.BankKeeper, app.FeeGrantKeeper, cdc.InterfaceRegistry()),
		authzmodule.NewAppModule(cdc, app.AuthzKeeper, app.AccountKeeper, app.BankKeeper, cdc.InterfaceRegistry()),
		consensus.NewAppModule(cdc, app.ConsensusKeeper),
		tatmint.NewAppModule(app.MintKeeper),
		reputation.NewAppModule(app.RepKeeper),
		attestModule,
		ipfsverify.NewAppModule(app.IPFSKeeper),
		identity.NewAppModule(app.IdentityKeeper),
	)

	app.mm.SetOrderPreBlockers(
		upgradetypes.ModuleName,
		authtypes.ModuleName,
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
		govtypes.ModuleName,
		stakingtypes.ModuleName,
		banktypes.ModuleName,
		attesttypes.ModuleName,
		reptypes.ModuleName,
		"ipfsverify",
		identitytypes.ModuleName,
		feegranttypes.ModuleName,
		authz.ModuleName,
	)

	genesisOrder := []string{
		authtypes.ModuleName,
		banktypes.ModuleName,
		distrtypes.ModuleName,
		stakingtypes.ModuleName,
		genutiltypes.ModuleName,
		slashingtypes.ModuleName,
		govtypes.ModuleName,
		upgradetypes.ModuleName,
		evidencetypes.ModuleName,
		feegranttypes.ModuleName,
		authz.ModuleName,
		consensustypes.ModuleName,
		"vesting",
		minttypes.ModuleName,
		reptypes.ModuleName,
		attesttypes.ModuleName,
		"ipfsverify",
		identitytypes.ModuleName,
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

	app.SetPreBlocker(app.PreBlocker)
	app.SetInitChainer(func(ctx sdk.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
		var gs GenesisState
		if err := json.Unmarshal(req.AppStateBytes, &gs); err != nil {
			return nil, err
		}
		app.UpgradeKeeper.SetModuleVersionMap(ctx, app.mm.GetVersionMap())
		res, err := app.mm.InitGenesis(ctx, cdc, gs)
		if err != nil {
			return res, err
		}

		// Ensure no IAVL store is ever empty. Modules with empty genesis state
		// (authz, feegrant, evidence) leave an empty tree, whose SaveEmptyRoot path
		// does not persist a root key in the store/v2 fast-storage layout, causing
		// "version does not exist" on every query. Writing a non-empty sentinel to
		// every store keeps each tree non-empty so the normal SaveRoot/SaveNode path
		// is used.
		for _, key := range keys {
			ctx.KVStore(key).Set([]byte("__tatst_sentinel__"), []byte{0x01})
		}

		return res, nil
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

// PreBlocker runs the module pre-block hooks (e.g. upgrade, auth fee handling).
func (app *ThreatAttestApp) PreBlocker(ctx sdk.Context, _ *abci.RequestFinalizeBlock) (*sdk.ResponsePreBlock, error) {
	return app.mm.PreBlock(ctx)
}

// DefaultGenesis returns the default genesis state map.
func (app *ThreatAttestApp) DefaultGenesis() GenesisState {
	bm := module.NewBasicManagerFromManager(app.mm, nil)
	return bm.DefaultGenesis(app.cdc)
}

// RegisterAPIRoutes registers REST/gRPC-Gateway routes.
func (app *ThreatAttestApp) RegisterAPIRoutes(apiSvr *api.Server, _ serverconfig.APIConfig) {
	clientCtx := apiSvr.ClientCtx
	authtx.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
	cmtservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
	nodeservice.RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
	module.NewBasicManagerFromManager(app.mm, nil).RegisterGRPCGatewayRoutes(clientCtx, apiSvr.GRPCGatewayRouter)
}

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
	nodeservice.RegisterNodeService(clientCtx, app.GRPCQueryRouter(), cfg, func() int64 {
		return app.CommitMultiStore().EarliestVersion()
	})
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

// BlockedModuleAddresses returns addresses blocked from receiving bank sends.
func BlockedModuleAddresses() map[string]bool {
	blocked := make(map[string]bool, len(maccPerms))
	for acc := range maccPerms {
		blocked[authtypes.NewModuleAddress(acc).String()] = true
	}
	return blocked
}
