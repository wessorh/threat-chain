// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"context"
	"time"

	"cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	"github.com/threatattest/chain/x/attestation/msgs"
	"github.com/threatattest/chain/x/attestation/types"
)

// MsgServer implements the attestation message handlers.
type MsgServer struct {
	Keeper
	identityKeeper IdentityTierKeeper
}

// NewMsgServer returns a new MsgServer backed by the given Keeper.
func NewMsgServer(k Keeper) *MsgServer {
	return &MsgServer{Keeper: k}
}

// SetIdentityKeeper injects the identity keeper for tier-based confidence
// scaling. Call during app wiring. If not called, defaults to Tier 0.
func (s *MsgServer) SetIdentityKeeper(k IdentityTierKeeper) {
	s.identityKeeper = k
}

// ============================================================
// PublishAttestation
// ============================================================

// PublishAttestation processes MsgPublishAttestation.
func (s *MsgServer) PublishAttestation(goCtx context.Context, msg *msgs.MsgPublishAttestation) (*msgs.MsgPublishAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	params, err := s.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Reputation gate: minimum RS to publish
	rs, err := s.repKeeper.GetReputationScore(ctx, msg.Attester)
	if err != nil {
		return nil, errors.Wrap(types.ErrReputation, err.Error())
	}
	if rs < params.MinReputationToAttest {
		return nil, errors.Wrapf(types.ErrInsufficientReputation,
			"score=%d required=%d", rs, params.MinReputationToAttest)
	}

	// Verify attester_sig covers the attestation payload.
	// The signed message is SHA-256(artifact_sha256 || attester || ttl_seconds_big_endian_8bytes).
	if err := types.VerifyAttesterSig(msg.Attester, msg.ArtifactSHA256, msg.TTLSeconds, msg.AttesterSig); err != nil {
		return nil, errors.Wrap(types.ErrInvalidSignature, err.Error())
	}

	// Timestamp & TTL
	publishedAt := ctx.BlockTime().Unix()
	expiresAt := publishedAt + msg.TTLSeconds

	// Compute deterministic attestation ID
	attestationID := types.ComputeAttestationID(
		msg.ArtifactSHA256,
		msg.Attester,
		publishedAt,
	)

	// Determine compliance tier and apply weight multiplier to confidence.
	// Tier 0 (anon) = 0.25x, Tier 1 (staked) = 0.50x, Tier 2 (DNS) = 1.0x, Tier 3 (expert) = 2.0x capped at 100.
	attesterTier := s.identityTier(ctx, msg.Attester)
	scaledConfidence := applyTierToConfidence(msg.Confidence, attesterTier)

	// Build the record
	rec := types.AttestationRecord{
		ID:                attestationID,
		SchemaVersion:     types.SchemaVersion,
		ArtifactType:      msg.ArtifactType,
		ArtifactSHA256:    msg.ArtifactSHA256,
		HollomanSignature: msg.HollomanSignature,
		HammingMask:       msg.HammingMask,
		RawValue:          msg.RawValue,
		Severity:          msg.Severity,
		TLP:               msg.TLP,
		Attester:          msg.Attester,
		PublishedAt:       publishedAt,
		TTLSeconds:        msg.TTLSeconds,
		ExpiresAt:         expiresAt,
		Confidence:        uint32(scaledConfidence),
		Description:       msg.Description,
		Tags:              msg.Tags,
		ThreatCategories:  msg.ThreatCategories,
		DetectionRules:    msg.DetectionRules,
		RelatedTo:         msg.RelatedTo,
		MitreAttackIDs:    msg.MitreAttackIDs,
		AttesterSig:       msg.AttesterSig,
		Status:            types.AttestationStatus_ACTIVE,
		EndorsementCount:  0,
		BlockHeight:       ctx.BlockHeight(),
		PUAInfo:           msg.PUAInfo,
		AttesterDomain:    msg.AttesterDomain,
		AttesterSelector:  msg.AttesterSelector,
		AttesterTier:      int32(attesterTier),
	}

	if err := s.PublishAttestationRecord(ctx, rec); err != nil {
		return nil, err
	}

	// Reputation reward for first-time contributors
	_ = s.repKeeper.AddReputation(ctx, msg.Attester, 5)

	return &msgs.MsgPublishAttestationResponse{
		AttestationID: attestationID,
		ExpiresAt:     time.Unix(expiresAt, 0).UTC(),
	}, nil
}

// ============================================================
// EndorseAttestation
// ============================================================

// EndorseAttestation processes MsgEndorseAttestation.
func (s *MsgServer) EndorseAttestation(goCtx context.Context, msg *msgs.MsgEndorseAttestation) (*msgs.MsgEndorseAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	params, err := s.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Reputation gate for endorsers
	rs, err := s.repKeeper.GetReputationScore(ctx, msg.Endorser)
	if err != nil {
		return nil, errors.Wrap(types.ErrReputation, err.Error())
	}
	if rs < params.MinReputationToEndorse {
		return nil, errors.Wrapf(types.ErrInsufficientReputation,
			"score=%d required=%d", rs, params.MinReputationToEndorse)
	}

	if err := s.EndorseAttestationRecord(ctx, msg.AttestationID, msg.Endorser); err != nil {
		return nil, err
	}

	count, err := s.CountEndorsements(ctx, msg.AttestationID)
	if err != nil {
		return nil, err
	}

	return &msgs.MsgEndorseAttestationResponse{EndorsementCount: count}, nil
}

// ============================================================
// RevokeAttestation
// ============================================================

// RevokeAttestation processes MsgRevokeAttestation.
func (s *MsgServer) RevokeAttestation(goCtx context.Context, msg *msgs.MsgRevokeAttestation) (*msgs.MsgRevokeAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	if err := s.RevokeAttestationRecord(ctx, msg.AttestationID, msg.Attester, msg.Reason); err != nil {
		return nil, err
	}

	return &msgs.MsgRevokeAttestationResponse{}, nil
}

// ============================================================
// DisputeAttestation
// ============================================================

// DisputeAttestation processes MsgDisputeAttestation.
func (s *MsgServer) DisputeAttestation(goCtx context.Context, msg *msgs.MsgDisputeAttestation) (*msgs.MsgDisputeAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	params, err := s.GetParams(ctx)
	if err != nil {
		return nil, err
	}

	// Disputer must have minimum reputation
	rs, err := s.repKeeper.GetReputationScore(ctx, msg.Disputer)
	if err != nil {
		return nil, errors.Wrap(types.ErrReputation, err.Error())
	}
	if rs < params.MinReputationToDispute {
		return nil, errors.Wrapf(types.ErrInsufficientReputation,
			"score=%d required=%d", rs, params.MinReputationToDispute)
	}

	// Fetch the target attestation
	rec, err := s.GetAttestation(ctx, msg.AttestationID)
	if err != nil {
		return nil, err
	}
	if rec.Status != types.AttestationStatus_ACTIVE {
		return nil, errors.Wrapf(types.ErrNotActive, "cannot dispute status=%s", rec.Status.String())
	}

	// Prevent self-dispute
	if rec.Attester == msg.Disputer {
		return nil, types.ErrSelfDispute
	}

	// Compute dispute ID
	disputeID := types.ComputeDisputeID(msg.AttestationID, msg.Disputer, ctx.BlockTime().Unix())

	dispute := types.DisputeRecord{
		ID:            disputeID,
		AttestationID: msg.AttestationID,
		Disputer:      msg.Disputer,
		Ground:        msg.Ground,
		Evidence:      msg.Evidence,
		EvidenceCID:   msg.EvidenceCID,
		CreatedAt:     ctx.BlockTime().Unix(),
		Status:        types.DisputeStatus_OPEN,
	}

	if err := s.SetDispute(ctx, dispute); err != nil {
		return nil, err
	}

	// Mark attestation as DISPUTED (keeps it in the active index but flags it)
	rec.Status = types.AttestationStatus_DISPUTED
	if err := s.SetAttestation(ctx, rec); err != nil {
		return nil, err
	}

	// Reputation penalty for the attester (pending resolution)
	_ = s.repKeeper.SubReputation(ctx, rec.Attester, 5)

	// Sybil-attack ground triggers immediate blacklist review
	if msg.Ground == types.DisputeGround_SYBIL_ATTACK {
		// Flag for governance review; actual blacklist requires governance vote
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			types.EventTypeSybilFlag,
			sdk.NewAttribute(types.AttributeKeyAttester, rec.Attester),
			sdk.NewAttribute(types.AttributeKeyDisputeID, disputeID),
		))
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeDisputeAttestation,
		sdk.NewAttribute(types.AttributeKeyDisputeID, disputeID),
		sdk.NewAttribute(types.AttributeKeyAttestationID, msg.AttestationID),
		sdk.NewAttribute(types.AttributeKeyDisputer, msg.Disputer),
		sdk.NewAttribute(types.AttributeKeyDisputeGround, msg.Ground.String()),
	))

	return &msgs.MsgDisputeAttestationResponse{DisputeID: disputeID}, nil
}

// ============================================================
// UpdateParams (governance)
// ============================================================

// UpdateParams processes MsgUpdateParams, gated to the governance authority.
func (s *MsgServer) UpdateParams(goCtx context.Context, msg *msgs.MsgUpdateParams) (*msgs.MsgUpdateParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if msg.Authority != s.Keeper.authority {
		return nil, errors.Wrapf(types.ErrUnauthorized,
			"expected authority=%s got=%s", s.Keeper.authority, msg.Authority)
	}
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := s.SetParams(ctx, msg.Params); err != nil {
		return nil, err
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeUpdateParams,
		sdk.NewAttribute(types.AttributeKeyAuthority, msg.Authority),
	))
	return &msgs.MsgUpdateParamsResponse{}, nil
}

// ============================================================
// Compliance tier helpers
// ============================================================

// IdentityTierKeeper is the interface the attestation keeper uses to look up
// the compliance tier for an attester address.  This avoids a hard import of
// the x/identity package (prevents circular dependencies).
type IdentityTierKeeper interface {
	GetTier(ctx interface{}, cosmosAddr string) int32
}

// identityTier returns the compliance tier (0-3) for the given attester.
// Delegates to the wired IdentityTierKeeper. If not wired, defaults to
// Tier 0 (ANONYMOUS) so the module compiles and runs without identity.
func (s *MsgServer) identityTier(ctx interface{ BlockHeight() int64 }, attester string) int32 {
	if s.identityKeeper != nil {
		return s.identityKeeper.GetTier(ctx, attester)
	}
	return 0
}

// applyTierToConfidence scales a raw confidence value (0-100) by the tier
// multiplier and clamps the result to [0, 100].
//
//	Tier 0 (ANONYMOUS): confidence * 1/4
//	Tier 1 (STAKED):    confidence * 2/4
//	Tier 2 (DNS_BOUND): confidence * 4/4  (unchanged)
//	Tier 3 (EXPERT):    confidence * 8/4  (clamped to 100)
func applyTierToConfidence(rawConfidence uint32, tier int32) uint32 {
	var numerator uint32
	switch tier {
	case 1:
		numerator = 2
	case 2:
		numerator = 4
	case 3:
		numerator = 8
	default: // 0 = ANONYMOUS
		numerator = 1
	}
	scaled := rawConfidence * numerator / 4
	if scaled > 100 {
		scaled = 100
	}
	return scaled
}

// ============================================================
// ClaimReward — attestation incentive pool distribution
// ============================================================

// ClaimReward allows an attester to claim their share of the attestation
// module account's incentive pool. Each claim withdraws 1% of the pool
// balance to prevent draining. A minimum of 1 utatst is always claimable.
func (s *MsgServer) ClaimReward(goCtx context.Context, msg *msgs.MsgClaimReward) (*msgs.MsgClaimRewardResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	attester, err := sdk.AccAddressFromBech32(msg.Attester)
	if err != nil {
		return nil, err
	}

	// Rate-limit claims to one per attester per epoch.
	epoch := types.CurrentEpoch(ctx.BlockHeight())
	lastClaim, err := s.Keeper.GetClaimEpoch(ctx, msg.Attester)
	if err != nil {
		return nil, err
	}
	if lastClaim == epoch {
		return nil, errors.Wrap(types.ErrRateLimitExceeded, "already claimed this epoch")
	}

	// Get attestation module account balance
	modAddr := authtypes.NewModuleAddress(types.ModuleName)
	poolBal := s.Keeper.bankKeeper.SpendableCoins(ctx, modAddr)

	if poolBal.IsZero() {
		return nil, errors.Wrap(types.ErrIncentivePoolEmpty, "incentive pool is empty")
	}

	// Calculate reward: 1% of pool per claim, clamped to the available balance.
	denom := sdk.DefaultBondDenom
	available := poolBal.AmountOf(denom)
	reward := available.QuoRaw(100)
	if reward.IsZero() {
		reward = math.NewInt(1) // minimum 1 utatst
	}
	if reward.GT(available) {
		reward = available
	}
	rewardCoins := sdk.NewCoins(sdk.NewCoin(denom, reward))

	// Send reward from attestation module to attester
	if err := s.Keeper.bankKeeper.SendCoinsFromModuleToAccount(
		ctx,
		types.ModuleName,
		attester,
		rewardCoins,
	); err != nil {
		return nil, errors.Wrapf(err, "failed to send reward to %s", msg.Attester)
	}

	if err := s.Keeper.SetClaimEpoch(ctx, msg.Attester, epoch); err != nil {
		return nil, err
	}

	// Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeClaimReward,
		sdk.NewAttribute(types.AttributeKeyAttester, msg.Attester),
		sdk.NewAttribute("reward_amount", rewardCoins.String()),
	))

	remaining := s.Keeper.bankKeeper.SpendableCoins(ctx, modAddr)
	return &msgs.MsgClaimRewardResponse{
		ClaimedAmount: rewardCoins.String(),
		PoolRemaining: remaining.String(),
	}, nil
}

// ============================================================
// Subscribe — API tier subscription
// ============================================================

// Subscribe locks tokens from the subscriber and activates a paid API tier.
func (s *MsgServer) Subscribe(goCtx context.Context, msg *msgs.MsgSubscribe) (*msgs.MsgSubscribeResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	tier := types.SubscriptionTier(msg.Tier)
	cfg, ok := types.TierConfigs[tier]
	if !ok {
		return nil, errors.Wrap(types.ErrInvalidTier, "unknown tier")
	}
	if tier == types.SubscriptionTier_FREE {
		return nil, errors.Wrap(types.ErrInvalidTier, "use MsgUnsubscribe to return to free tier")
	}

	subscriber, err := sdk.AccAddressFromBech32(msg.Subscriber)
	if err != nil {
		return nil, err
	}

	// Refund any stake locked by a prior subscription before overwriting it.
	if prior, found := s.Keeper.GetSubscription(ctx, msg.Subscriber); found && prior.StakeAmount > 0 {
		refund := sdk.NewInt64Coin(sdk.DefaultBondDenom, prior.StakeAmount)
		if err := s.Keeper.bankKeeper.SendCoinsFromModuleToAccount(
			ctx, types.ModuleName, subscriber, sdk.NewCoins(refund),
		); err != nil {
			return nil, errors.Wrap(err, "failed to refund prior stake")
		}
	}

	// Check subscriber has enough spendable coins
	coins := s.Keeper.bankKeeper.SpendableCoins(ctx, subscriber)
	stakeNeeded := sdk.NewInt64Coin(sdk.DefaultBondDenom, cfg.StakeRequired)
	if coins.AmountOf(sdk.DefaultBondDenom).LT(stakeNeeded.Amount) {
		return nil, errors.Wrap(types.ErrInsufficientReputation,
			"insufficient balance for stake")
	}

	// Lock tokens: subscriber → attestation module
	if err := s.Keeper.bankKeeper.SendCoinsFromAccountToModule(
		ctx, subscriber, types.ModuleName, sdk.NewCoins(stakeNeeded),
	); err != nil {
		return nil, errors.Wrap(err, "failed to lock stake")
	}

	// Store subscription record
	now := ctx.BlockTime().Unix()
	expiresAt := now + int64(cfg.LockDays)*86400

	rec := types.SubscriptionRecord{
		Subscriber:  msg.Subscriber,
		Tier:        tier,
		StakeAmount: cfg.StakeRequired,
		StartedAt:   now,
		ExpiresAt:   expiresAt,
	}
	s.Keeper.SetSubscription(ctx, rec)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"subscribe",
		sdk.NewAttribute(types.AttributeKeyAttester, msg.Subscriber),
		sdk.NewAttribute("tier", tier.String()),
		sdk.NewAttribute("stake", stakeNeeded.String()),
	))

	return &msgs.MsgSubscribeResponse{
		Tier:        tier.String(),
		ExpiresAt:   expiresAt,
		StakeLocked: stakeNeeded.String(),
	}, nil
}

// ============================================================
// Unsubscribe — cancel API subscription
// ============================================================

// Unsubscribe returns locked tokens and resets to the FREE tier.
func (s *MsgServer) Unsubscribe(goCtx context.Context, msg *msgs.MsgUnsubscribe) (*msgs.MsgUnsubscribeResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}

	rec, found := s.Keeper.GetSubscription(ctx, msg.Subscriber)
	if !found {
		return nil, errors.Wrap(types.ErrSubscriptionNotFound, "no active subscription")
	}

	if rec.Tier == types.SubscriptionTier_FREE {
		return nil, errors.Wrap(types.ErrSubscriptionNotFound, "already on free tier")
	}

	subscriber, err := sdk.AccAddressFromBech32(msg.Subscriber)
	if err != nil {
		return nil, err
	}

	// Return locked tokens
	refund := sdk.NewInt64Coin(sdk.DefaultBondDenom, rec.StakeAmount)
	if err := s.Keeper.bankKeeper.SendCoinsFromModuleToAccount(
		ctx, types.ModuleName, subscriber, sdk.NewCoins(refund),
	); err != nil {
		return nil, errors.Wrap(err, "failed to return stake")
	}

	s.Keeper.DeleteSubscription(ctx, msg.Subscriber)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		"unsubscribe",
		sdk.NewAttribute(types.AttributeKeyAttester, msg.Subscriber),
		sdk.NewAttribute("refund", refund.String()),
	))

	return &msgs.MsgUnsubscribeResponse{
		UnlockedAmount: refund.String(),
	}, nil
}
