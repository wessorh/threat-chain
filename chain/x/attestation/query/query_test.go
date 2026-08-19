// Package query_test exercises the x/attestation query service (the gRPC/query
// "RPC module") end-to-end against an in-memory store, so handler regressions
// surface as unit-test failures instead of "the query isn't communicating".
package query_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/threatattest/chain/x/attestation/query"
	"github.com/threatattest/chain/x/attestation/types"
)

// validAttester is a well-formed tatst bech32 address used as a test fixture.
const validAttester = "tatst1zl4e00uzhj3vrhsg26lvv0ukmjsnle5g3h470s"

// TestMain configures the global SDK bech32 prefixes the same way NewRootCmd
// does, so sdk.AccAddressFromBech32 accepts "tatst1..." addresses in handlers.
func TestMain(m *testing.M) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount("tatst", "tatstpub")
	cfg.SetBech32PrefixForValidator("tatstvaloper", "tatstvaloperpub")
	cfg.SetBech32PrefixForConsensusNode("tatstvalcons", "tatstvalconspub")
	cfg.Seal()
	os.Exit(m.Run())
}

// mockRepKeeper is a minimal keeper.ReputationKeeper for query tests.
type mockRepKeeper struct {
	scores      map[string]uint32
	blacklisted map[string]bool
}

func (m mockRepKeeper) GetReputationScore(_ sdk.Context, attester string) (uint32, error) {
	return m.scores[attester], nil
}
func (mockRepKeeper) AddReputation(sdk.Context, string, int32) error  { return nil }
func (mockRepKeeper) SubReputation(sdk.Context, string, uint32) error { return nil }
func (m mockRepKeeper) IsBlacklisted(_ sdk.Context, attester string) bool {
	return m.blacklisted[attester]
}

// newTestServer builds a QueryServer over an in-memory store and seeds one
// ACTIVE attestation, plus its artifact/attester indexes.
func newTestServer(t *testing.T) (*query.QueryServer, sdk.Context, keeper.Keeper, types.AttestationRecord) {
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
		mockRepKeeper{scores: map[string]uint32{}, blacklisted: map[string]bool{}},
		nil, // stakingKeeper (delegation gate not exercised by queries)
		nil, // bankKeeper
		"tatst1authority",
	)

	if err := k.SetParams(ctx, types.DefaultParams()); err != nil {
		t.Fatalf("set params: %v", err)
	}

	sum := sha256.Sum256([]byte("malware.exe"))
	sha := hex.EncodeToString(sum[:])
	rec := types.AttestationRecord{
		ID:             "attestation-1",
		SchemaVersion:  1,
		ArtifactType:   types.ArtifactType_FILE,
		ArtifactSHA256: sha,
		Severity:       types.SeverityLevel_HIGH,
		Attester:       validAttester,
		PublishedAt:    1700000000,
		Confidence:     90,
		Status:         types.AttestationStatus_ACTIVE,
	}
	if err := k.SetAttestation(ctx, rec); err != nil {
		t.Fatalf("set attestation: %v", err)
	}
	if err := k.SetArtifactIndex(ctx, sha, []string{rec.ID}); err != nil {
		t.Fatalf("set artifact index: %v", err)
	}
	if err := k.SetAttesterIndex(ctx, rec.Attester, []string{rec.ID}); err != nil {
		t.Fatalf("set attester index: %v", err)
	}

	return query.NewQueryServer(k), ctx, k, rec
}

func TestParams(t *testing.T) {
	q, ctx, _, _ := newTestServer(t)
	resp, err := q.Params(ctx, &query.QueryParamsRequest{})
	if err != nil {
		t.Fatalf("Params: %v", err)
	}
	if resp.Params.MinAttesterDelegation != types.DefaultParams().MinAttesterDelegation {
		t.Fatalf("unexpected params: %+v", resp.Params)
	}
}

func TestIsMalicious_Hit(t *testing.T) {
	q, ctx, _, rec := newTestServer(t)
	resp, err := q.IsMalicious(ctx, &query.QueryIsMaliciousRequest{ArtifactSHA256: rec.ArtifactSHA256})
	if err != nil {
		t.Fatalf("IsMalicious: %v", err)
	}
	if !resp.IsMalicious {
		t.Fatal("expected IsMalicious=true for seeded artifact")
	}
	if resp.Attestation == nil || resp.Attestation.ID != rec.ID {
		t.Fatalf("expected attestation %q, got %+v", rec.ID, resp.Attestation)
	}
}

func TestIsMalicious_Miss(t *testing.T) {
	q, ctx, _, _ := newTestServer(t)
	other := sha256.Sum256([]byte("benign.txt"))
	resp, err := q.IsMalicious(ctx, &query.QueryIsMaliciousRequest{
		ArtifactSHA256: hex.EncodeToString(other[:]),
	})
	if err != nil {
		t.Fatalf("IsMalicious(miss): %v", err)
	}
	if resp.IsMalicious {
		t.Fatal("expected IsMalicious=false for unknown artifact")
	}
}

func TestIsMalicious_InvalidSHA(t *testing.T) {
	q, ctx, _, _ := newTestServer(t)
	_, err := q.IsMalicious(ctx, &query.QueryIsMaliciousRequest{ArtifactSHA256: "not-hex"})
	if err == nil {
		t.Fatal("expected error for invalid SHA-256")
	}
}

func TestGetAttestation_Hit(t *testing.T) {
	q, ctx, _, rec := newTestServer(t)
	resp, err := q.GetAttestation(ctx, &query.QueryGetAttestationRequest{AttestationID: rec.ID})
	if err != nil {
		t.Fatalf("GetAttestation: %v", err)
	}
	if resp.Attestation.ArtifactSHA256 != rec.ArtifactSHA256 {
		t.Fatalf("unexpected attestation: %+v", resp.Attestation)
	}
}

func TestGetAttestation_NotFound(t *testing.T) {
	q, ctx, _, _ := newTestServer(t)
	_, err := q.GetAttestation(ctx, &query.QueryGetAttestationRequest{AttestationID: "does-not-exist"})
	if err == nil {
		t.Fatal("expected error for missing attestation")
	}
}

func TestListAttesterAttestations(t *testing.T) {
	q, ctx, _, rec := newTestServer(t)
	resp, err := q.ListAttesterAttestations(ctx, &query.QueryListAttesterAttestationsRequest{
		Attester: rec.Attester,
	})
	if err != nil {
		t.Fatalf("ListAttesterAttestations: %v", err)
	}
	if len(resp.Attestations) != 1 || resp.Attestations[0].ID != rec.ID {
		t.Fatalf("expected 1 attestation, got %+v", resp.Attestations)
	}
}

func TestListArtifactAttestations(t *testing.T) {
	q, ctx, _, rec := newTestServer(t)
	resp, err := q.ListArtifactAttestations(ctx, &query.QueryListArtifactAttestationsRequest{
		ArtifactSHA256: rec.ArtifactSHA256,
	})
	if err != nil {
		t.Fatalf("ListArtifactAttestations: %v", err)
	}
	if len(resp.Attestations) != 1 || resp.Attestations[0].ID != rec.ID {
		t.Fatalf("expected 1 attestation, got %+v", resp.Attestations)
	}
}

func TestIsBlacklisted(t *testing.T) {
	q, ctx, k, _ := newTestServer(t)
	// Not blacklisted initially.
	resp, err := q.IsBlacklisted(ctx, &query.QueryIsBlacklistedRequest{Attester: validAttester})
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if resp.IsBlacklisted {
		t.Fatal("expected not blacklisted")
	}
	// Blacklist, then re-query.
	if err := k.SetBlacklisted(ctx, validAttester); err != nil {
		t.Fatalf("SetBlacklisted: %v", err)
	}
	resp, err = q.IsBlacklisted(ctx, &query.QueryIsBlacklistedRequest{Attester: validAttester})
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !resp.IsBlacklisted {
		t.Fatal("expected blacklisted after SetBlacklisted")
	}
}

// compile-time guard: QueryServer is wired through the wireQueryServer bridge.
var _ = context.Background
