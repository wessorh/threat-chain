// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package attestation

import (
	"context"

	"github.com/threatattest/chain/x/attestation/keeper"
	attestmsgs "github.com/threatattest/chain/x/attestation/msgs"
	"github.com/threatattest/chain/x/attestation/types"
	pb "github.com/threatattest/chain/x/attestation/types/pb"
)

// This file bridges the generated protobuf wire messages (package pb) to the
// handwritten internal message types (package msgs) used by the keeper. The
// generated types are protobuf-serialisable and therefore work with the tx
// codec, while the handwritten types carry ValidateBasic and the keeper's
// business logic unchanged.

func pbRulesToTypes(in []*pb.DetectionRuleRef) []types.DetectionRuleRef {
	if in == nil {
		return nil
	}
	out := make([]types.DetectionRuleRef, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, types.DetectionRuleRef{
			RuleID:         r.RuleId,
			RuleType:       types.RuleType(r.RuleType),
			RuleName:       r.RuleName,
			CID:            r.Cid,
			ContentSHA256:  r.ContentSha256,
			RuleVersion:    r.RuleVersion,
			RuleAuthor:     r.RuleAuthor,
			AppliesTo:      types.RuleAppliesTo(r.AppliesTo),
			MinYaraVersion: r.MinYaraVersion,
			Verified:       r.Verified,
		})
	}
	return out
}

func pbPUAToTypes(in *pb.PUAMetadata) *types.PUAMetadata {
	if in == nil {
		return nil
	}
	return &types.PUAMetadata{
		SoftwareName:    in.SoftwareName,
		Vendor:          in.Vendor,
		Version:         in.Version,
		InstallerSHA256: in.InstallerSha256,
		Behaviors:       types.PUABehavior(in.Behaviors),
		BehaviorNotes:   in.BehaviorNotes,
		DetectionNames:  in.DetectionNames,
	}
}

func pbParamsToTypes(in *pb.Params) types.Params {
	return types.Params{
		MinAttesterDelegation:     in.MinAttesterDelegation,
		MinTTLSeconds:             in.MinTtlSeconds,
		MaxTTLSeconds:             in.MaxTtlSeconds,
		MaxTTLIPv4Seconds:         in.MaxTtlIpv4Seconds,
		MaxDetectionRules:         in.MaxDetectionRules,
		MaxAttestationsPerEpoch:   in.MaxAttestationsPerEpoch,
		DisputeBondAmount:         in.DisputeBondAmount,
		IPv4MinConfidence:         in.Ipv4MinConfidence,
		TimestampToleranceSeconds: in.TimestampToleranceSeconds,
		MinReputationToAttest:     in.MinReputationToAttest,
		MinReputationToEndorse:    in.MinReputationToEndorse,
		MinReputationToDispute:    in.MinReputationToDispute,
	}
}

func pbToMsgsPublish(m *pb.MsgPublishAttestation) *attestmsgs.MsgPublishAttestation {
	return &attestmsgs.MsgPublishAttestation{
		Attester:          m.Attester,
		ArtifactType:      types.ArtifactType(m.ArtifactType),
		ArtifactSHA256:    m.ArtifactSha256,
		HollomanSignature: m.HollomanSignature,
		HammingMask:       m.HammingMask,
		RawValue:          m.RawValue,
		Severity:          types.SeverityLevel(m.Severity),
		TLP:               types.TLPLevel(m.Tlp),
		TTLSeconds:        m.TtlSeconds,
		Confidence:        m.Confidence,
		Description:       m.Description,
		Tags:              m.Tags,
		ThreatCategories:  m.ThreatCategories,
		DetectionRules:    pbRulesToTypes(m.DetectionRules),
		RelatedTo:         m.RelatedTo,
		MitreAttackIDs:    m.MitreAttackIds,
		AttesterSig:       m.AttesterSig,
		PUAInfo:           pbPUAToTypes(m.PuaInfo),
		AttesterDomain:    m.AttesterDomain,
		AttesterSelector:  m.AttesterSelector,
	}
}

func pbToMsgsEndorse(m *pb.MsgEndorseAttestation) *attestmsgs.MsgEndorseAttestation {
	return &attestmsgs.MsgEndorseAttestation{
		Endorser:      m.Endorser,
		AttestationID: m.AttestationId,
		Comment:       m.Comment,
	}
}

func pbToMsgsRevoke(m *pb.MsgRevokeAttestation) *attestmsgs.MsgRevokeAttestation {
	return &attestmsgs.MsgRevokeAttestation{
		Attester:      m.Attester,
		AttestationID: m.AttestationId,
		Reason:        m.Reason,
	}
}

func pbToMsgsDispute(m *pb.MsgDisputeAttestation) *attestmsgs.MsgDisputeAttestation {
	return &attestmsgs.MsgDisputeAttestation{
		Disputer:      m.Disputer,
		AttestationID: m.AttestationId,
		Ground:        types.DisputeGround(m.Ground),
		Evidence:      m.Evidence,
		EvidenceCID:   m.EvidenceCid,
	}
}

func pbToMsgsUpdateParams(m *pb.MsgUpdateParams) *attestmsgs.MsgUpdateParams {
	return &attestmsgs.MsgUpdateParams{
		Authority: m.Authority,
		Params:    pbParamsToTypes(m.Params),
	}
}

func pbToMsgsClaimReward(m *pb.MsgClaimReward) *attestmsgs.MsgClaimReward {
	return &attestmsgs.MsgClaimReward{Attester: m.Attester}
}

func pbToMsgsSubscribe(m *pb.MsgSubscribe) *attestmsgs.MsgSubscribe {
	return &attestmsgs.MsgSubscribe{Subscriber: m.Subscriber, Tier: m.Tier}
}

func pbToMsgsUnsubscribe(m *pb.MsgUnsubscribe) *attestmsgs.MsgUnsubscribe {
	return &attestmsgs.MsgUnsubscribe{Subscriber: m.Subscriber}
}

func msgsToPbPublishResp(r *attestmsgs.MsgPublishAttestationResponse) *pb.MsgPublishAttestationResponse {
	return &pb.MsgPublishAttestationResponse{AttestationId: r.AttestationID, ExpiresAt: r.ExpiresAt.Unix()}
}

func msgsToPbEndorseResp(r *attestmsgs.MsgEndorseAttestationResponse) *pb.MsgEndorseAttestationResponse {
	return &pb.MsgEndorseAttestationResponse{EndorsementCount: r.EndorsementCount}
}

func msgsToPbRevokeResp(_ *attestmsgs.MsgRevokeAttestationResponse) *pb.MsgRevokeAttestationResponse {
	return &pb.MsgRevokeAttestationResponse{}
}

func msgsToPbDisputeResp(r *attestmsgs.MsgDisputeAttestationResponse) *pb.MsgDisputeAttestationResponse {
	return &pb.MsgDisputeAttestationResponse{DisputeId: r.DisputeID}
}

func msgsToPbUpdateParamsResp(_ *attestmsgs.MsgUpdateParamsResponse) *pb.MsgUpdateParamsResponse {
	return &pb.MsgUpdateParamsResponse{}
}

func msgsToPbClaimRewardResp(r *attestmsgs.MsgClaimRewardResponse) *pb.MsgClaimRewardResponse {
	return &pb.MsgClaimRewardResponse{ClaimedAmount: r.ClaimedAmount, PoolRemaining: r.PoolRemaining}
}

func msgsToPbSubscribeResp(r *attestmsgs.MsgSubscribeResponse) *pb.MsgSubscribeResponse {
	return &pb.MsgSubscribeResponse{Tier: r.Tier, ExpiresAt: r.ExpiresAt, StakeLocked: r.StakeLocked}
}

func msgsToPbUnsubscribeResp(r *attestmsgs.MsgUnsubscribeResponse) *pb.MsgUnsubscribeResponse {
	return &pb.MsgUnsubscribeResponse{UnlockedAmount: r.UnlockedAmount}
}

// wireMsgServer adapts the handwritten keeper.MsgServer (package msgs) to the
// generated pb.MsgServer interface so it can be registered with the SDK's
// MsgServiceRouter via the generated RegisterMsgServer.
type wireMsgServer struct {
	inner *keeper.MsgServer
}

func (w *wireMsgServer) PublishAttestation(ctx context.Context, m *pb.MsgPublishAttestation) (*pb.MsgPublishAttestationResponse, error) {
	resp, err := w.inner.PublishAttestation(ctx, pbToMsgsPublish(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbPublishResp(resp), nil
}

func (w *wireMsgServer) EndorseAttestation(ctx context.Context, m *pb.MsgEndorseAttestation) (*pb.MsgEndorseAttestationResponse, error) {
	resp, err := w.inner.EndorseAttestation(ctx, pbToMsgsEndorse(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbEndorseResp(resp), nil
}

func (w *wireMsgServer) RevokeAttestation(ctx context.Context, m *pb.MsgRevokeAttestation) (*pb.MsgRevokeAttestationResponse, error) {
	resp, err := w.inner.RevokeAttestation(ctx, pbToMsgsRevoke(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbRevokeResp(resp), nil
}

func (w *wireMsgServer) DisputeAttestation(ctx context.Context, m *pb.MsgDisputeAttestation) (*pb.MsgDisputeAttestationResponse, error) {
	resp, err := w.inner.DisputeAttestation(ctx, pbToMsgsDispute(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbDisputeResp(resp), nil
}

func (w *wireMsgServer) UpdateParams(ctx context.Context, m *pb.MsgUpdateParams) (*pb.MsgUpdateParamsResponse, error) {
	resp, err := w.inner.UpdateParams(ctx, pbToMsgsUpdateParams(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbUpdateParamsResp(resp), nil
}

func (w *wireMsgServer) ClaimReward(ctx context.Context, m *pb.MsgClaimReward) (*pb.MsgClaimRewardResponse, error) {
	resp, err := w.inner.ClaimReward(ctx, pbToMsgsClaimReward(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbClaimRewardResp(resp), nil
}

func (w *wireMsgServer) Subscribe(ctx context.Context, m *pb.MsgSubscribe) (*pb.MsgSubscribeResponse, error) {
	resp, err := w.inner.Subscribe(ctx, pbToMsgsSubscribe(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbSubscribeResp(resp), nil
}

func (w *wireMsgServer) Unsubscribe(ctx context.Context, m *pb.MsgUnsubscribe) (*pb.MsgUnsubscribeResponse, error) {
	resp, err := w.inner.Unsubscribe(ctx, pbToMsgsUnsubscribe(m))
	if err != nil {
		return nil, err
	}
	return msgsToPbUnsubscribeResp(resp), nil
}
