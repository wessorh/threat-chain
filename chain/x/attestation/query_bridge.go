// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package attestation

import (
	"context"

	attestquery "github.com/threatattest/chain/x/attestation/query"
	"github.com/threatattest/chain/x/attestation/types"
	pb "github.com/threatattest/chain/x/attestation/types/pb"
)

// This file bridges the generated protobuf query wire types (package pb) to the
// handwritten query types (package query) used by the QueryServer. The generated
// types are protobuf-serialisable and therefore work with the gRPC query
// service, while the handwritten types carry the keeper's business logic.

// ── Data model: handwritten types → protobuf ─────────────────────────────────

func typesRulesToPb(in []types.DetectionRuleRef) []*pb.DetectionRuleRef {
	if in == nil {
		return nil
	}
	out := make([]*pb.DetectionRuleRef, 0, len(in))
	for _, r := range in {
		out = append(out, &pb.DetectionRuleRef{
			RuleId:         r.RuleID,
			RuleType:       int32(r.RuleType),
			RuleName:       r.RuleName,
			Cid:            r.CID,
			ContentSha256:  r.ContentSHA256,
			RuleVersion:    r.RuleVersion,
			RuleAuthor:     r.RuleAuthor,
			AppliesTo:      int32(r.AppliesTo),
			MinYaraVersion: r.MinYaraVersion,
			Verified:       r.Verified,
		})
	}
	return out
}

func typesPUAToPb(in *types.PUAMetadata) *pb.PUAMetadata {
	if in == nil {
		return nil
	}
	return &pb.PUAMetadata{
		SoftwareName:    in.SoftwareName,
		Vendor:          in.Vendor,
		Version:         in.Version,
		InstallerSha256: in.InstallerSHA256,
		Behaviors:       uint32(in.Behaviors),
		BehaviorNotes:   in.BehaviorNotes,
		DetectionNames:  in.DetectionNames,
	}
}

func typesParamsToPb(in types.Params) *pb.Params {
	return &pb.Params{
		MinAttesterDelegation:     in.MinAttesterDelegation,
		MinTtlSeconds:             in.MinTTLSeconds,
		MaxTtlSeconds:             in.MaxTTLSeconds,
		MaxTtlIpv4Seconds:         in.MaxTTLIPv4Seconds,
		MaxDetectionRules:         in.MaxDetectionRules,
		MaxAttestationsPerEpoch:   in.MaxAttestationsPerEpoch,
		DisputeBondAmount:         in.DisputeBondAmount,
		Ipv4MinConfidence:         in.IPv4MinConfidence,
		TimestampToleranceSeconds: in.TimestampToleranceSeconds,
		MinReputationToAttest:     in.MinReputationToAttest,
		MinReputationToEndorse:    in.MinReputationToEndorse,
		MinReputationToDispute:    in.MinReputationToDispute,
	}
}

func typesToPbRecord(r *types.AttestationRecord) *pb.AttestationRecord {
	if r == nil {
		return nil
	}
	return &pb.AttestationRecord{
		Id:                r.ID,
		SchemaVersion:     r.SchemaVersion,
		ArtifactType:      int32(r.ArtifactType),
		ArtifactSha256:    r.ArtifactSHA256,
		HollomanSignature: r.HollomanSignature,
		HammingMask:       r.HammingMask,
		RawValue:          r.RawValue,
		Severity:          int32(r.Severity),
		Tlp:               int32(r.TLP),
		Attester:          r.Attester,
		PublishedAt:       r.PublishedAt,
		TtlSeconds:        r.TTLSeconds,
		ExpiresAt:         r.ExpiresAt,
		Confidence:        r.Confidence,
		Description:       r.Description,
		Tags:              r.Tags,
		ThreatCategories:  r.ThreatCategories,
		DetectionRules:    typesRulesToPb(r.DetectionRules),
		RelatedTo:         r.RelatedTo,
		MitreAttackIds:    r.MitreAttackIDs,
		AttesterSig:       r.AttesterSig,
		Status:            int32(r.Status),
		EndorsementCount:  r.EndorsementCount,
		DisputeCount:      r.DisputeCount,
		RevokeReason:      r.RevokeReason,
		BlockHeight:       r.BlockHeight,
		TxHash:            r.TxHash,
		PuaInfo:           typesPUAToPb(r.PUAInfo),
		AttesterDomain:    r.AttesterDomain,
		AttesterSelector:  r.AttesterSelector,
		AttesterTier:      r.AttesterTier,
	}
}

func typesToPbDispute(d *types.DisputeRecord) *pb.DisputeRecord {
	if d == nil {
		return nil
	}
	return &pb.DisputeRecord{
		Id:            d.ID,
		AttestationId: d.AttestationID,
		Disputer:      d.Disputer,
		Ground:        int32(d.Ground),
		Evidence:      d.Evidence,
		EvidenceCid:   d.EvidenceCID,
		CreatedAt:     d.CreatedAt,
		Status:        int32(d.Status),
		RebuttalCid:   d.RebuttalCID,
		ResolvedAt:    d.ResolvedAt,
	}
}

// ── Query requests: protobuf → handwritten ───────────────────────────────────

func pbToQueryIsMaliciousReq(m *pb.QueryIsMaliciousRequest) *attestquery.QueryIsMaliciousRequest {
	return &attestquery.QueryIsMaliciousRequest{ArtifactSHA256: m.ArtifactSha256}
}

func pbToQueryIsMaliciousURLReq(m *pb.QueryIsMaliciousURLRequest) *attestquery.QueryIsMaliciousURLRequest {
	return &attestquery.QueryIsMaliciousURLRequest{URL: m.Url}
}

func pbToQueryIsMaliciousIPv4Req(m *pb.QueryIsMaliciousIPv4Request) *attestquery.QueryIsMaliciousIPv4Request {
	return &attestquery.QueryIsMaliciousIPv4Request{IPv4: m.Ipv4}
}

func pbToQueryIsMaliciousHollomanReq(m *pb.QueryIsMaliciousHollomanRequest) *attestquery.QueryIsMaliciousHollomanRequest {
	return &attestquery.QueryIsMaliciousHollomanRequest{HollomanSignature: m.HollomanSignature, HammingMask: m.HammingMask}
}

func pbToQueryGetAttestationReq(m *pb.QueryGetAttestationRequest) *attestquery.QueryGetAttestationRequest {
	return &attestquery.QueryGetAttestationRequest{AttestationID: m.AttestationId}
}

func pbToQueryListArtifactReq(m *pb.QueryListArtifactAttestationsRequest) *attestquery.QueryListArtifactAttestationsRequest {
	return &attestquery.QueryListArtifactAttestationsRequest{ArtifactSHA256: m.ArtifactSha256, Pagination: m.Pagination}
}

func pbToQueryListAttesterReq(m *pb.QueryListAttesterAttestationsRequest) *attestquery.QueryListAttesterAttestationsRequest {
	return &attestquery.QueryListAttesterAttestationsRequest{Attester: m.Attester, Pagination: m.Pagination}
}

func pbToQueryGetDisputeReq(m *pb.QueryGetDisputeRequest) *attestquery.QueryGetDisputeRequest {
	return &attestquery.QueryGetDisputeRequest{DisputeID: m.DisputeId}
}

func pbToQueryIsBlacklistedReq(m *pb.QueryIsBlacklistedRequest) *attestquery.QueryIsBlacklistedRequest {
	return &attestquery.QueryIsBlacklistedRequest{Attester: m.Attester}
}

// ── Query responses: handwritten → protobuf ──────────────────────────────────

func queryToPbIsMaliciousResp(r *attestquery.QueryIsMaliciousResponse) *pb.QueryIsMaliciousResponse {
	return &pb.QueryIsMaliciousResponse{
		IsMalicious: r.IsMalicious,
		Attestation: typesToPbRecord(r.Attestation),
		TrustScore:  r.TrustScore,
	}
}

func queryToPbGetAttestationResp(r *attestquery.QueryGetAttestationResponse) *pb.QueryGetAttestationResponse {
	return &pb.QueryGetAttestationResponse{Attestation: typesToPbRecord(&r.Attestation)}
}

func queryToPbListArtifactResp(r *attestquery.QueryListArtifactAttestationsResponse) *pb.QueryListArtifactAttestationsResponse {
	return &pb.QueryListArtifactAttestationsResponse{
		Attestations: typesRecordsToPb(r.Attestations),
		Pagination:   r.Pagination,
	}
}

func queryToPbListAttesterResp(r *attestquery.QueryListAttesterAttestationsResponse) *pb.QueryListAttesterAttestationsResponse {
	return &pb.QueryListAttesterAttestationsResponse{
		Attestations: typesRecordsToPb(r.Attestations),
		Pagination:   r.Pagination,
	}
}

func queryToPbGetDisputeResp(r *attestquery.QueryGetDisputeResponse) *pb.QueryGetDisputeResponse {
	return &pb.QueryGetDisputeResponse{Dispute: typesToPbDispute(&r.Dispute)}
}

func queryToPbIsBlacklistedResp(r *attestquery.QueryIsBlacklistedResponse) *pb.QueryIsBlacklistedResponse {
	return &pb.QueryIsBlacklistedResponse{IsBlacklisted: r.IsBlacklisted}
}

func queryToPbParamsResp(r *attestquery.QueryParamsResponse) *pb.QueryParamsResponse {
	return &pb.QueryParamsResponse{Params: typesParamsToPb(r.Params)}
}

func typesRecordsToPb(in []types.AttestationRecord) []*pb.AttestationRecord {
	out := make([]*pb.AttestationRecord, 0, len(in))
	for i := range in {
		out = append(out, typesToPbRecord(&in[i]))
	}
	return out
}

// ── wireQueryServer adapts the handwritten QueryServer to the generated pb ──

type wireQueryServer struct {
	inner *attestquery.QueryServer
}

func (w *wireQueryServer) IsMalicious(ctx context.Context, m *pb.QueryIsMaliciousRequest) (*pb.QueryIsMaliciousResponse, error) {
	resp, err := w.inner.IsMalicious(ctx, pbToQueryIsMaliciousReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbIsMaliciousResp(resp), nil
}

func (w *wireQueryServer) IsMaliciousURL(ctx context.Context, m *pb.QueryIsMaliciousURLRequest) (*pb.QueryIsMaliciousResponse, error) {
	resp, err := w.inner.IsMaliciousURL(ctx, pbToQueryIsMaliciousURLReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbIsMaliciousResp(resp), nil
}

func (w *wireQueryServer) IsMaliciousIPv4(ctx context.Context, m *pb.QueryIsMaliciousIPv4Request) (*pb.QueryIsMaliciousResponse, error) {
	resp, err := w.inner.IsMaliciousIPv4(ctx, pbToQueryIsMaliciousIPv4Req(m))
	if err != nil {
		return nil, err
	}
	return queryToPbIsMaliciousResp(resp), nil
}

func (w *wireQueryServer) IsMaliciousHolloman(ctx context.Context, m *pb.QueryIsMaliciousHollomanRequest) (*pb.QueryIsMaliciousResponse, error) {
	resp, err := w.inner.IsMaliciousHolloman(ctx, pbToQueryIsMaliciousHollomanReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbIsMaliciousResp(resp), nil
}

func (w *wireQueryServer) GetAttestation(ctx context.Context, m *pb.QueryGetAttestationRequest) (*pb.QueryGetAttestationResponse, error) {
	resp, err := w.inner.GetAttestation(ctx, pbToQueryGetAttestationReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbGetAttestationResp(resp), nil
}

func (w *wireQueryServer) ListArtifactAttestations(ctx context.Context, m *pb.QueryListArtifactAttestationsRequest) (*pb.QueryListArtifactAttestationsResponse, error) {
	resp, err := w.inner.ListArtifactAttestations(ctx, pbToQueryListArtifactReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbListArtifactResp(resp), nil
}

func (w *wireQueryServer) ListAttesterAttestations(ctx context.Context, m *pb.QueryListAttesterAttestationsRequest) (*pb.QueryListAttesterAttestationsResponse, error) {
	resp, err := w.inner.ListAttesterAttestations(ctx, pbToQueryListAttesterReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbListAttesterResp(resp), nil
}

func (w *wireQueryServer) GetDispute(ctx context.Context, m *pb.QueryGetDisputeRequest) (*pb.QueryGetDisputeResponse, error) {
	resp, err := w.inner.GetDispute(ctx, pbToQueryGetDisputeReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbGetDisputeResp(resp), nil
}

func (w *wireQueryServer) IsBlacklisted(ctx context.Context, m *pb.QueryIsBlacklistedRequest) (*pb.QueryIsBlacklistedResponse, error) {
	resp, err := w.inner.IsBlacklisted(ctx, pbToQueryIsBlacklistedReq(m))
	if err != nil {
		return nil, err
	}
	return queryToPbIsBlacklistedResp(resp), nil
}

func (w *wireQueryServer) Params(ctx context.Context, m *pb.QueryParamsRequest) (*pb.QueryParamsResponse, error) {
	resp, err := w.inner.Params(ctx, &attestquery.QueryParamsRequest{})
	if err != nil {
		return nil, err
	}
	return queryToPbParamsResp(resp), nil
}

func (w *wireQueryServer) Subscription(ctx context.Context, m *pb.QuerySubscriptionRequest) (*pb.QuerySubscriptionResponse, error) {
	resp, err := w.inner.Subscription(ctx, &attestquery.QuerySubscriptionRequest{Subscriber: m.GetSubscriber()})
	if err != nil {
		return nil, err
	}
	return &pb.QuerySubscriptionResponse{
		Subscriber: resp.Subscriber,
		Tier:       resp.Tier,
		RateLimit:  resp.RateLimit,
		Features:   resp.Features,
		Active:     resp.Active,
	}, nil
}
