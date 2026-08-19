// Package keeper_test exercises the x/attestation msg server (dispute path)
// against an in-memory store.
package keeper_test

import (
	"os"
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

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/msgs"
	"github.com/threatattest/chain/x/attestation/types"
)

const (
	validAttester = "tatst1zl4e00uzhj3vrhsg26lvv0ukmjsnle5g3h470s"
	validDisputer = "tatst1klkraa5qpmga69xsm9quh5ke3t6x9n0t5gcy8j"
)

func TestMain(m *testing.M) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount("tatst", "tatstpub")
	cfg.SetBech32PrefixForValidator("tatstvaloper", "tatstvaloperpub")
	cfg.SetBech32PrefixForConsensusNode("tatstvalcons", "tatstvalconspub")
	cfg.Seal()
	os.Exit(m.Run())
}

// mockRep is a minimal keeper.ReputationKeeper returning a fixed score.
type mockRep struct{ score uint32 }

func (m mockRep) GetReputationScore(_ sdk.Context, _ string) (uint32, error) { return m.score, nil }
func (mockRep) AddReputation(sdk.Context, string, int32) error               { return nil }
func (mockRep) SubReputation(sdk.Context, string, uint32) error              { return nil }
func (mockRep) IsBlacklisted(sdk.Context, string) bool                       { return false }

func newTestKeeper(t *testing.T) (keeper.Keeper, sdk.Context) {
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
		mockRep{score: 100},
		nil, // stakingKeeper
		nil, // bankKeeper
		"tatst1authority",
	)
	return k, ctx
}

// TestDisputeIncrementsCount verifies the dispute handler bumps DisputeCount and
// flips the attestation status to DISPUTED.
func TestDisputeIncrementsCount(t *testing.T) {
	k, ctx := newTestKeeper(t)

	rec := types.AttestationRecord{
		ID:             "att-1",
		SchemaVersion:  1,
		ArtifactType:   types.ArtifactType_FILE,
		ArtifactSHA256: "abcd",
		Severity:       types.SeverityLevel_HIGH,
		Attester:       validAttester,
		Status:         types.AttestationStatus_ACTIVE,
	}
	if err := k.SetAttestation(ctx, rec); err != nil {
		t.Fatalf("set attestation: %v", err)
	}

	ms := keeper.NewMsgServer(k)
	_, err := ms.DisputeAttestation(ctx, &msgs.MsgDisputeAttestation{
		Disputer:      validDisputer,
		AttestationID: "att-1",
		Ground:        types.DisputeGround_FALSE_POSITIVE,
		Evidence:      "benign per vendor",
	})
	if err != nil {
		t.Fatalf("dispute: %v", err)
	}

	got, err := k.GetAttestation(ctx, "att-1")
	if err != nil {
		t.Fatalf("get attestation: %v", err)
	}
	if got.DisputeCount != 1 {
		t.Fatalf("expected DisputeCount=1, got %d", got.DisputeCount)
	}
	if got.Status != types.AttestationStatus_DISPUTED {
		t.Fatalf("expected DISPUTED status, got %v", got.Status)
	}
}
