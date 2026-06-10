// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"context"
	"time"

	"cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/attestation/msgs"
	"github.com/threatattest/chain/x/attestation/types"
)

// MsgServer implements the attestation message handlers.
type MsgServer struct {
	Keeper
}

// NewMsgServer returns a new MsgServer backed by the given Keeper.
func NewMsgServer(k Keeper) *MsgServer {
	return &MsgServer{Keeper: k}
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
		ID:               attestationID,
		SchemaVersion:    types.SchemaVersion,
		ArtifactType:     msg.ArtifactType,
		ArtifactSHA256:   msg.ArtifactSHA256,
		RawValue:         msg.RawValue,
		Severity:         msg.Severity,
		TLP:              msg.TLP,
		Attester:         msg.Attester,
		PublishedAt:      publishedAt,
		TTLSeconds:       msg.TTLSeconds,
		ExpiresAt:        expiresAt,
		Confidence:       uint32(scaledConfidence),
		Description:      msg.Description,
		Tags:             msg.Tags,
		ThreatCategories: msg.ThreatCategories,
		DetectionRules:   msg.DetectionRules,
		RelatedTo:        msg.RelatedTo,
		MitreAttackIDs:   msg.MitreAttackIDs,
		AttesterSig:      msg.AttesterSig,
		Status:           types.AttestationStatus_ACTIVE,
		EndorsementCount: 0,
		BlockHeight:      ctx.BlockHeight(),
		PUAInfo:          msg.PUAInfo,
		AttesterDomain:   msg.AttesterDomain,
		AttesterSelector: msg.AttesterSelector,
		AttesterTier:     int32(attesterTier),
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
// If no identity keeper is wired up (nil), defaults to Tier 0 (ANONYMOUS).
func (s MsgServer) identityTier(ctx interface{ BlockHeight() int64 }, attester string) int32 {
	// In production: inject IdentityTierKeeper into MsgServer and call it here.
	// For now return ANONYMOUS (0) as a safe default so the module compiles.
	// Wire-up example in app.go:
	//   attestationMsgServer.SetIdentityKeeper(identityKeeper)
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
