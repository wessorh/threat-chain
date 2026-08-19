// Package testutil provides shared mock keepers and a keeper constructor for
// x/attestation tests.
package testutil

import (
	"context"
	"testing"

	"cosmossdk.io/log/v2"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/types"
)

// Authority is the governance authority address the test keeper is configured
// with. It must be a valid tatst bech32 address (MsgUpdateParams validates it).
const Authority = "tatst1zl4e00uzhj3vrhsg26lvv0ukmjsnle5g3h470s"

// MockReputationKeeper implements keeper.ReputationKeeper.
type MockReputationKeeper struct {
	Score       uint32
	Blacklisted map[string]bool
}

func (m MockReputationKeeper) GetReputationScore(_ sdk.Context, _ string) (uint32, error) {
	return m.Score, nil
}
func (MockReputationKeeper) AddReputation(sdk.Context, string, int32) error  { return nil }
func (MockReputationKeeper) SubReputation(sdk.Context, string, uint32) error { return nil }
func (m MockReputationKeeper) IsBlacklisted(_ sdk.Context, addr string) bool {
	return m.Blacklisted[addr]
}

// MockBankKeeper implements keeper.BankKeeper with configurable balances.
type MockBankKeeper struct {
	Balances map[string]sdk.Coins
}

func (m *MockBankKeeper) SpendableCoins(_ context.Context, addr sdk.AccAddress) sdk.Coins {
	if m == nil || m.Balances == nil {
		return sdk.Coins{}
	}
	return m.Balances[addr.String()]
}
func (*MockBankKeeper) SendCoinsFromAccountToModule(context.Context, sdk.AccAddress, string, sdk.Coins) error {
	return nil
}
func (*MockBankKeeper) SendCoinsFromModuleToAccount(context.Context, string, sdk.AccAddress, sdk.Coins) error {
	return nil
}
func (*MockBankKeeper) BurnCoins(context.Context, string, sdk.Coins) error { return nil }

// MockStakingKeeper implements keeper.StakingKeeper.
type MockStakingKeeper struct{}

func (MockStakingKeeper) GetDelegatorDelegations(context.Context, sdk.AccAddress, uint16) ([]stakingtypes.Delegation, error) {
	return nil, nil
}

// NewKeeper builds a keeper over an in-memory IAVL store wired with the mock
// reputation/bank/staking keepers. bank may be nil for handlers that do not
// touch the bank keeper.
func NewKeeper(t *testing.T, repScore uint32, bank *MockBankKeeper) (keeper.Keeper, sdk.Context) {
	t.Helper()
	db := dbm.NewMemDB()
	cms := rootmulti.NewStore(db, log.NewNopLogger())
	key := storetypes.NewKVStoreKey(types.StoreKey)
	cms.MountStoreWithDB(key, storetypes.StoreTypeIAVL, db)
	if err := cms.LoadLatestVersion(); err != nil {
		t.Fatalf("load store: %v", err)
	}
	ctx := sdk.NewContext(cms, cmtproto.Header{}, false, log.NewNopLogger())
	k := keeper.NewKeeper(
		codec.NewProtoCodec(codectypes.NewInterfaceRegistry()),
		runtime.NewKVStoreService(key),
		log.NewNopLogger(),
		MockReputationKeeper{Score: repScore},
		MockStakingKeeper{},
		bank,
		Authority,
	)
	return k, ctx
}
