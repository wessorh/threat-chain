// Package keeper_test exercises the x/attestation msg server handlers against
// an in-memory store.
package keeper_test

import (
	"os"
	"strings"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/msgs"
	"github.com/threatattest/chain/x/attestation/testutil"
	"github.com/threatattest/chain/x/attestation/types"
)

const (
	validAttester = "tatst1zl4e00uzhj3vrhsg26lvv0ukmjsnle5g3h470s"
	validOther    = "tatst1klkraa5qpmga69xsm9quh5ke3t6x9n0t5gcy8j"
)

func TestMain(m *testing.M) {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount("tatst", "tatstpub")
	cfg.SetBech32PrefixForValidator("tatstvaloper", "tatstvaloperpub")
	cfg.SetBech32PrefixForConsensusNode("tatstvalcons", "tatstvalconspub")
	cfg.Seal()
	os.Exit(m.Run())
}

// seedActive stores one ACTIVE attestation with its artifact + attester indexes.
func seedActive(t *testing.T, k keeper.Keeper, ctx sdk.Context, id, attester, sha string) {
	t.Helper()
	rec := types.AttestationRecord{
		ID:             id,
		SchemaVersion:  1,
		ArtifactType:   types.ArtifactType_FILE,
		ArtifactSHA256: sha,
		Severity:       types.SeverityLevel_HIGH,
		Attester:       attester,
		Status:         types.AttestationStatus_ACTIVE,
	}
	if err := k.SetAttestation(ctx, rec); err != nil {
		t.Fatalf("set attestation: %v", err)
	}
	if err := k.SetArtifactIndex(ctx, sha, []string{id}); err != nil {
		t.Fatalf("set artifact index: %v", err)
	}
	if err := k.SetAttesterIndex(ctx, attester, []string{id}); err != nil {
		t.Fatalf("set attester index: %v", err)
	}
}

// ── Revoke (easiest) ────────────────────────────────────────────────────────

func TestRevokeAttestation(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	sha := strings.Repeat("a", 64)
	seedActive(t, k, ctx, "att-1", validAttester, sha)

	ms := keeper.NewMsgServer(k)
	_, err := ms.RevokeAttestation(ctx, &msgs.MsgRevokeAttestation{
		Attester:      validAttester,
		AttestationID: "att-1",
		Reason:        "false positive confirmed",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := k.GetAttestation(ctx, "att-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != types.AttestationStatus_REVOKED {
		t.Fatalf("expected REVOKED, got %v", got.Status)
	}
	if got.RevokeReason != "false positive confirmed" {
		t.Fatalf("reason mismatch: %q", got.RevokeReason)
	}
	ids, _ := k.GetArtifactIndex(ctx, sha)
	if len(ids) != 0 {
		t.Fatalf("expected artifact index removed, got %v", ids)
	}
}

func TestRevokeAttestation_WrongAttester(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	seedActive(t, k, ctx, "att-1", validAttester, strings.Repeat("a", 64))

	ms := keeper.NewMsgServer(k)
	_, err := ms.RevokeAttestation(ctx, &msgs.MsgRevokeAttestation{
		Attester:      validOther, // not the attester
		AttestationID: "att-1",
	})
	if err == nil {
		t.Fatal("expected unauthorized-revoke error")
	}
}

// ── Endorse ─────────────────────────────────────────────────────────────────

func TestEndorseAttestation(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	seedActive(t, k, ctx, "att-1", validAttester, strings.Repeat("a", 64))

	ms := keeper.NewMsgServer(k)
	resp, err := ms.EndorseAttestation(ctx, &msgs.MsgEndorseAttestation{
		Endorser:      validOther,
		AttestationID: "att-1",
	})
	if err != nil {
		t.Fatalf("endorse: %v", err)
	}
	if resp.EndorsementCount != 1 {
		t.Fatalf("expected response count 1, got %d", resp.EndorsementCount)
	}

	got, _ := k.GetAttestation(ctx, "att-1")
	if got.EndorsementCount != 1 {
		t.Fatalf("expected EndorsementCount=1, got %d", got.EndorsementCount)
	}
}

func TestEndorseAttestation_SelfEndorse(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	seedActive(t, k, ctx, "att-1", validAttester, strings.Repeat("a", 64))

	ms := keeper.NewMsgServer(k)
	_, err := ms.EndorseAttestation(ctx, &msgs.MsgEndorseAttestation{
		Endorser:      validAttester, // self
		AttestationID: "att-1",
	})
	if err == nil {
		t.Fatal("expected self-endorse error")
	}
}

// ── UpdateParams ────────────────────────────────────────────────────────────

func TestUpdateParams(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	ms := keeper.NewMsgServer(k)

	if _, err := ms.UpdateParams(ctx, &msgs.MsgUpdateParams{
		Authority: "tatst1wrong", Params: types.DefaultParams(),
	}); err == nil {
		t.Fatal("expected unauthorized error")
	}

	if _, err := ms.UpdateParams(ctx, &msgs.MsgUpdateParams{
		Authority: testutil.Authority, Params: types.DefaultParams(),
	}); err != nil {
		t.Fatalf("update params: %v", err)
	}
}

// ── Publish ─────────────────────────────────────────────────────────────────

func TestPublishAttestation(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	ms := keeper.NewMsgServer(k)
	sha := strings.Repeat("b", 64)
	sig := strings.Repeat("ab", 64) // 64-byte secp256k1 compact = 128 hex

	resp, err := ms.PublishAttestation(ctx, &msgs.MsgPublishAttestation{
		Attester:       validAttester,
		ArtifactType:   types.ArtifactType_FILE,
		ArtifactSHA256: sha,
		Severity:       types.SeverityLevel_HIGH,
		TTLSeconds:     86400,
		Confidence:     90,
		AttesterSig:    sig,
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if resp.AttestationID == "" {
		t.Fatal("expected attestation id")
	}

	got, err := k.GetAttestation(ctx, resp.AttestationID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != types.AttestationStatus_ACTIVE {
		t.Fatalf("expected ACTIVE, got %v", got.Status)
	}
	if got.ArtifactSHA256 != sha || got.Attester != validAttester {
		t.Fatalf("record mismatch: %+v", got)
	}
	ids, _ := k.GetArtifactIndex(ctx, sha)
	if len(ids) != 1 {
		t.Fatalf("expected artifact index, got %v", ids)
	}
}

// ── Dispute ─────────────────────────────────────────────────────────────────

func TestDisputeIncrementsCount(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, nil)
	seedActive(t, k, ctx, "att-1", validAttester, strings.Repeat("a", 64))

	ms := keeper.NewMsgServer(k)
	resp, err := ms.DisputeAttestation(ctx, &msgs.MsgDisputeAttestation{
		Disputer:      validOther,
		AttestationID: "att-1",
		Ground:        types.DisputeGround_FALSE_POSITIVE,
		Evidence:      "benign per vendor",
	})
	if err != nil {
		t.Fatalf("dispute: %v", err)
	}
	if resp.DisputeCount != 1 {
		t.Fatalf("expected response DisputeCount=1, got %d", resp.DisputeCount)
	}

	got, _ := k.GetAttestation(ctx, "att-1")
	if got.DisputeCount != 1 {
		t.Fatalf("expected DisputeCount=1, got %d", got.DisputeCount)
	}
	if got.Status != types.AttestationStatus_DISPUTED {
		t.Fatalf("expected DISPUTED, got %v", got.Status)
	}
}

// ── Subscribe / Unsubscribe ─────────────────────────────────────────────────

func TestSubscribe(t *testing.T) {
	bank := &testutil.MockBankKeeper{Balances: map[string]sdk.Coins{
		validOther: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 2_000_000_000)),
	}}
	k, ctx := testutil.NewKeeper(t, 100, bank)
	ms := keeper.NewMsgServer(k)

	resp, err := ms.Subscribe(ctx, &msgs.MsgSubscribe{
		Subscriber: validOther,
		Tier:       int32(types.SubscriptionTier_PROFESSIONAL),
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if resp.Tier != "PROFESSIONAL" {
		t.Fatalf("tier: %q", resp.Tier)
	}

	rec, found := k.GetSubscription(ctx, validOther)
	if !found {
		t.Fatal("expected subscription record")
	}
	if rec.Tier != types.SubscriptionTier_PROFESSIONAL {
		t.Fatalf("record tier: %v", rec.Tier)
	}
}

func TestUnsubscribe(t *testing.T) {
	k, ctx := testutil.NewKeeper(t, 100, &testutil.MockBankKeeper{})
	k.SetSubscription(ctx, types.SubscriptionRecord{
		Subscriber:  validOther,
		Tier:        types.SubscriptionTier_PROFESSIONAL,
		StakeAmount: 1_000_000_000,
		StartedAt:   1,
		ExpiresAt:   1000,
	})

	ms := keeper.NewMsgServer(k)
	if _, err := ms.Unsubscribe(ctx, &msgs.MsgUnsubscribe{Subscriber: validOther}); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}
	if _, found := k.GetSubscription(ctx, validOther); found {
		t.Fatal("expected subscription removed")
	}
}

// ── ClaimReward ─────────────────────────────────────────────────────────────

func TestClaimReward(t *testing.T) {
	modAddr := authtypes.NewModuleAddress(types.ModuleName).String()
	bank := &testutil.MockBankKeeper{Balances: map[string]sdk.Coins{
		modAddr: sdk.NewCoins(sdk.NewInt64Coin(sdk.DefaultBondDenom, 1_000_000)),
	}}
	k, ctx := testutil.NewKeeper(t, 100, bank)
	ms := keeper.NewMsgServer(k)

	resp, err := ms.ClaimReward(ctx, &msgs.MsgClaimReward{Attester: validOther})
	if err != nil {
		t.Fatalf("claim reward: %v", err)
	}
	if resp.ClaimedAmount == "" {
		t.Fatal("expected claimed amount")
	}
}
