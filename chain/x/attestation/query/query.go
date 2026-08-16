// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package query

import (
	"context"

	"cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/query"

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/types"
)

// ============================================================
// Request / Response types
// ============================================================

// QueryIsMaliciousRequest asks whether an artifact is currently attested malicious.
type QueryIsMaliciousRequest struct {
	// SHA-256 hex of the artifact (canonical form).
	ArtifactSHA256 string `json:"artifact_sha256"`
}

type QueryIsMaliciousResponse struct {
	IsMalicious bool                     `json:"is_malicious"`
	Attestation *types.AttestationRecord `json:"attestation,omitempty"`
	// TrustScore combines severity, confidence, endorsement count, and RS.
	TrustScore uint32 `json:"trust_score"`
}

// QueryGetAttestationRequest fetches a single attestation by ID.
type QueryGetAttestationRequest struct {
	AttestationID string `json:"attestation_id"`
}

type QueryGetAttestationResponse struct {
	Attestation types.AttestationRecord `json:"attestation"`
}

// QueryListArtifactAttestationsRequest lists all attestations for an artifact SHA-256.
type QueryListArtifactAttestationsRequest struct {
	ArtifactSHA256 string             `json:"artifact_sha256"`
	Pagination     *query.PageRequest `json:"pagination,omitempty"`
}

type QueryListArtifactAttestationsResponse struct {
	Attestations []types.AttestationRecord `json:"attestations"`
	Pagination   *query.PageResponse       `json:"pagination,omitempty"`
}

// QueryListAttesterAttestationsRequest lists all attestations by an attester.
type QueryListAttesterAttestationsRequest struct {
	Attester   string             `json:"attester"`
	Pagination *query.PageRequest `json:"pagination,omitempty"`
}

type QueryListAttesterAttestationsResponse struct {
	Attestations []types.AttestationRecord `json:"attestations"`
	Pagination   *query.PageResponse       `json:"pagination,omitempty"`
}

// QueryGetDisputeRequest fetches a dispute by ID.
type QueryGetDisputeRequest struct {
	DisputeID string `json:"dispute_id"`
}

type QueryGetDisputeResponse struct {
	Dispute types.DisputeRecord `json:"dispute"`
}

// QueryIsBlacklistedRequest checks if an attester is blacklisted.
type QueryIsBlacklistedRequest struct {
	Attester string `json:"attester"`
}

type QueryIsBlacklistedResponse struct {
	IsBlacklisted bool `json:"is_blacklisted"`
}

// QueryParamsRequest fetches the module parameters.
type QueryParamsRequest struct{}

type QueryParamsResponse struct {
	Params types.Params `json:"params"`
}

// QuerySubscriptionRequest returns the API subscription tier for a subscriber.
type QuerySubscriptionRequest struct {
	Subscriber string `json:"subscriber"`
}

// QuerySubscriptionResponse carries the tier, rate limit, and feature bitmask.
type QuerySubscriptionResponse struct {
	Subscriber string `json:"subscriber"`
	Tier       int32  `json:"tier"`
	RateLimit  int32  `json:"rate_limit"`
	Features   int32  `json:"features"`
	Active     bool   `json:"active"`
}

// QueryIsMaliciousURLRequest looks up by raw URL string.
type QueryIsMaliciousURLRequest struct {
	URL string `json:"url"`
}

// QueryIsMaliciousIPv4Request looks up by raw IPv4 address string.
type QueryIsMaliciousIPv4Request struct {
	IPv4 string `json:"ipv4"`
}

// QueryIsMaliciousHollomanRequest looks up by holloman perceptual signature
// with an optional query-side hamming mask (tolerance radius).
type QueryIsMaliciousHollomanRequest struct {
	// HollomanSignature is the 128-bit holloman fingerprint (32 lowercase hex).
	HollomanSignature string `json:"holloman_signature"`
	// HammingMask is the query-side tolerance (0-128). A stored attestation
	// matches when its fingerprint is within (this mask + its own stored mask)
	// Hamming distance of HollomanSignature.
	HammingMask int32 `json:"hamming_mask,omitempty"`
}

// ============================================================
// QueryServer
// ============================================================

// QueryServer provides read-only access to attestation state.
type QueryServer struct {
	keeper keeper.Keeper
}

// NewQueryServer creates a new QueryServer.
func NewQueryServer(k keeper.Keeper) *QueryServer {
	return &QueryServer{keeper: k}
}

// IsMalicious checks whether an artifact SHA-256 is currently attested malicious.
func (q *QueryServer) IsMalicious(goCtx context.Context, req *QueryIsMaliciousRequest) (*QueryIsMaliciousResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if !types.IsValidSHA256Hex(req.ArtifactSHA256) {
		return nil, errors.Wrap(types.ErrInvalidSHA256, req.ArtifactSHA256)
	}

	malicious, rec, err := q.keeper.IsMaliciousBySHA256(ctx, req.ArtifactSHA256)
	if err != nil {
		return nil, err
	}

	var trustScore uint32
	if rec != nil {
		attesterRS, _ := q.fetchAttesterRS(ctx, rec.Attester)
		trustScore = types.TrustScore(rec.Severity, rec.Confidence, rec.EndorsementCount, attesterRS)
	}

	return &QueryIsMaliciousResponse{
		IsMalicious: malicious,
		Attestation: rec,
		TrustScore:  trustScore,
	}, nil
}

// IsMaliciousURL checks a raw URL string by normalizing and computing its SHA-256.
func (q *QueryServer) IsMaliciousURL(goCtx context.Context, req *QueryIsMaliciousURLRequest) (*QueryIsMaliciousResponse, error) {
	normalized, err := types.NormalizeURL(req.URL)
	if err != nil {
		return nil, errors.Wrap(types.ErrInvalidURL, err.Error())
	}
	sha256 := types.ArtifactSHA256ForURL(normalized)
	return q.IsMalicious(goCtx, &QueryIsMaliciousRequest{ArtifactSHA256: sha256})
}

// IsMaliciousIPv4 checks a raw IPv4 address string.
func (q *QueryServer) IsMaliciousIPv4(goCtx context.Context, req *QueryIsMaliciousIPv4Request) (*QueryIsMaliciousResponse, error) {
	if types.IsReservedIPv4(req.IPv4) {
		return nil, errors.Wrap(types.ErrReservedIPv4, req.IPv4)
	}
	sha256 := types.ArtifactSHA256ForIPv4(req.IPv4)
	return q.IsMalicious(goCtx, &QueryIsMaliciousRequest{ArtifactSHA256: sha256})
}

// IsMaliciousHolloman checks whether an artifact is attested malicious by its
// holloman perceptual signature, using hamming-mask matching.
func (q *QueryServer) IsMaliciousHolloman(goCtx context.Context, req *QueryIsMaliciousHollomanRequest) (*QueryIsMaliciousResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if !types.IsValidHollomanSignature(req.HollomanSignature) {
		return nil, errors.Wrap(types.ErrInvalidHollomanSignature, req.HollomanSignature)
	}
	if !types.IsValidHammingMask(req.HammingMask) {
		return nil, errors.Wrap(types.ErrInvalidHammingMask, "query hamming mask out of range")
	}

	malicious, rec, err := q.keeper.IsMaliciousByHolloman(ctx, req.HollomanSignature, req.HammingMask)
	if err != nil {
		return nil, err
	}

	var trustScore uint32
	if rec != nil {
		attesterRS, _ := q.fetchAttesterRS(ctx, rec.Attester)
		trustScore = types.TrustScore(rec.Severity, rec.Confidence, rec.EndorsementCount, attesterRS)
	}

	return &QueryIsMaliciousResponse{
		IsMalicious: malicious,
		Attestation: rec,
		TrustScore:  trustScore,
	}, nil
}

// GetAttestation fetches a single attestation record by ID.
func (q *QueryServer) GetAttestation(goCtx context.Context, req *QueryGetAttestationRequest) (*QueryGetAttestationResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	rec, err := q.keeper.GetAttestation(ctx, req.AttestationID)
	if err != nil {
		return nil, err
	}
	return &QueryGetAttestationResponse{Attestation: rec}, nil
}

// ListArtifactAttestations returns all attestations for a given artifact SHA-256.
func (q *QueryServer) ListArtifactAttestations(goCtx context.Context, req *QueryListArtifactAttestationsRequest) (*QueryListArtifactAttestationsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if !types.IsValidSHA256Hex(req.ArtifactSHA256) {
		return nil, errors.Wrap(types.ErrInvalidSHA256, req.ArtifactSHA256)
	}

	ids, err := q.keeper.GetArtifactIndex(ctx, req.ArtifactSHA256)
	if err != nil {
		return nil, err
	}

	// Apply pagination
	start, end := paginate(len(ids), req.Pagination)
	paged := ids[start:end]

	var recs []types.AttestationRecord
	for _, id := range paged {
		rec, err := q.keeper.GetAttestation(ctx, id)
		if err != nil {
			continue // skip deleted/corrupted
		}
		recs = append(recs, rec)
	}

	return &QueryListArtifactAttestationsResponse{
		Attestations: recs,
		Pagination:   buildPageResponse(len(ids), end),
	}, nil
}

// ListAttesterAttestations returns all attestations by an attester address.
func (q *QueryServer) ListAttesterAttestations(goCtx context.Context, req *QueryListAttesterAttestationsRequest) (*QueryListAttesterAttestationsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	if _, err := sdk.AccAddressFromBech32(req.Attester); err != nil {
		return nil, errors.Wrap(types.ErrInvalidAttesterAddress, req.Attester)
	}

	ids, err := q.keeper.GetAttesterIndex(ctx, req.Attester)
	if err != nil {
		return nil, err
	}

	start, end := paginate(len(ids), req.Pagination)
	paged := ids[start:end]

	var recs []types.AttestationRecord
	for _, id := range paged {
		rec, err := q.keeper.GetAttestation(ctx, id)
		if err != nil {
			continue
		}
		recs = append(recs, rec)
	}

	return &QueryListAttesterAttestationsResponse{
		Attestations: recs,
		Pagination:   buildPageResponse(len(ids), end),
	}, nil
}

// GetDispute fetches a dispute record by ID.
func (q *QueryServer) GetDispute(goCtx context.Context, req *QueryGetDisputeRequest) (*QueryGetDisputeResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	d, err := q.keeper.GetDispute(ctx, req.DisputeID)
	if err != nil {
		return nil, err
	}
	return &QueryGetDisputeResponse{Dispute: d}, nil
}

// IsBlacklisted checks whether an attester is blacklisted.
func (q *QueryServer) IsBlacklisted(goCtx context.Context, req *QueryIsBlacklistedRequest) (*QueryIsBlacklistedResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	bl, err := q.keeper.IsBlacklisted(ctx, req.Attester)
	if err != nil {
		return nil, err
	}
	return &QueryIsBlacklistedResponse{IsBlacklisted: bl}, nil
}

// Params returns the current module parameters.
func (q *QueryServer) Params(goCtx context.Context, _ *QueryParamsRequest) (*QueryParamsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	p, err := q.keeper.GetParams(ctx)
	if err != nil {
		return nil, err
	}
	return &QueryParamsResponse{Params: p}, nil
}

// Subscription returns the API subscription tier, rate limit, and feature
// bitmask for a subscriber address. An off-chain gateway uses this to enforce
// per-tier rate limiting.
func (q *QueryServer) Subscription(goCtx context.Context, req *QuerySubscriptionRequest) (*QuerySubscriptionResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	subscriber := req.Subscriber
	tier := q.keeper.GetSubscriptionTier(ctx, subscriber)
	cfg := types.TierConfigs[tier]

	active := false
	if rec, found := q.keeper.GetSubscription(ctx, subscriber); found {
		active = rec.IsActive(ctx.BlockTime().Unix())
	}

	return &QuerySubscriptionResponse{
		Subscriber: subscriber,
		Tier:       int32(tier),
		RateLimit:  cfg.RateLimit,
		Features:   cfg.Features,
		Active:     active,
	}, nil
}

// ============================================================
// Helpers
// ============================================================

// fetchAttesterRS is a thin wrapper to get RS from the reputation keeper via
// the embedded Keeper field.  We use a concrete *keeper.Keeper here since
// QueryServer holds the value type.
func (q *QueryServer) fetchAttesterRS(ctx sdk.Context, attester string) (uint32, error) {
	// The reputation keeper is accessible through the embedded Keeper.
	// We cast to access repKeeper via an unexported accessor method.
	return q.keeper.GetAttesterRS(ctx, attester)
}

func paginate(total int, req *query.PageRequest) (start, end int) {
	if req == nil {
		return 0, minInt(total, 100)
	}
	offset := int(req.Offset)
	limit := int(req.Limit)
	if limit == 0 {
		limit = 100
	}
	start = offset
	if start > total {
		start = total
	}
	end = start + limit
	if end > total {
		end = total
	}
	return
}

func buildPageResponse(total, end int) *query.PageResponse {
	var nextKey []byte
	if end < total {
		// encode next offset as 8-byte big-endian
		nextKey = make([]byte, 8)
		nextKey[7] = byte(end)
	}
	return &query.PageResponse{
		NextKey: nextKey,
		Total:   uint64(total),
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================
// gogoproto proto.Message implementations
// (required so the GRPCQueryRouter can register the Query service)
// ============================================================

func (*QueryIsMaliciousRequest) Reset()                        {}
func (*QueryIsMaliciousRequest) ProtoMessage()                 {}
func (m *QueryIsMaliciousRequest) String() string              { return m.ArtifactSHA256 }
func (*QueryIsMaliciousResponse) Reset()                       {}
func (*QueryIsMaliciousResponse) ProtoMessage()                {}
func (m *QueryIsMaliciousResponse) String() string             { return "QueryIsMaliciousResponse" }
func (*QueryGetAttestationRequest) Reset()                     {}
func (*QueryGetAttestationRequest) ProtoMessage()              {}
func (m *QueryGetAttestationRequest) String() string           { return m.AttestationID }
func (*QueryGetAttestationResponse) Reset()                    {}
func (*QueryGetAttestationResponse) ProtoMessage()             {}
func (m *QueryGetAttestationResponse) String() string          { return "QueryGetAttestationResponse" }
func (*QueryListArtifactAttestationsRequest) Reset()           {}
func (*QueryListArtifactAttestationsRequest) ProtoMessage()    {}
func (m *QueryListArtifactAttestationsRequest) String() string { return m.ArtifactSHA256 }
func (*QueryListArtifactAttestationsResponse) Reset()          {}
func (*QueryListArtifactAttestationsResponse) ProtoMessage()   {}
func (m *QueryListArtifactAttestationsResponse) String() string {
	return "QueryListArtifactAttestationsResponse"
}
func (*QueryListAttesterAttestationsRequest) Reset()           {}
func (*QueryListAttesterAttestationsRequest) ProtoMessage()    {}
func (m *QueryListAttesterAttestationsRequest) String() string { return m.Attester }
func (*QueryListAttesterAttestationsResponse) Reset()          {}
func (*QueryListAttesterAttestationsResponse) ProtoMessage()   {}
func (m *QueryListAttesterAttestationsResponse) String() string {
	return "QueryListAttesterAttestationsResponse"
}
func (*QueryGetDisputeRequest) Reset()                    {}
func (*QueryGetDisputeRequest) ProtoMessage()             {}
func (m *QueryGetDisputeRequest) String() string          { return m.DisputeID }
func (*QueryGetDisputeResponse) Reset()                   {}
func (*QueryGetDisputeResponse) ProtoMessage()            {}
func (m *QueryGetDisputeResponse) String() string         { return "QueryGetDisputeResponse" }
func (*QueryIsBlacklistedRequest) Reset()                 {}
func (*QueryIsBlacklistedRequest) ProtoMessage()          {}
func (m *QueryIsBlacklistedRequest) String() string       { return m.Attester }
func (*QueryIsBlacklistedResponse) Reset()                {}
func (*QueryIsBlacklistedResponse) ProtoMessage()         {}
func (m *QueryIsBlacklistedResponse) String() string      { return "QueryIsBlacklistedResponse" }
func (*QueryParamsRequest) Reset()                        {}
func (*QueryParamsRequest) ProtoMessage()                 {}
func (*QueryParamsRequest) String() string                { return "QueryParamsRequest" }
func (*QueryParamsResponse) Reset()                       {}
func (*QueryParamsResponse) ProtoMessage()                {}
func (*QueryParamsResponse) String() string               { return "QueryParamsResponse" }
func (*QueryIsMaliciousURLRequest) Reset()                {}
func (*QueryIsMaliciousURLRequest) ProtoMessage()         {}
func (m *QueryIsMaliciousURLRequest) String() string      { return m.URL }
func (*QueryIsMaliciousIPv4Request) Reset()               {}
func (*QueryIsMaliciousIPv4Request) ProtoMessage()        {}
func (m *QueryIsMaliciousIPv4Request) String() string     { return m.IPv4 }
func (*QueryIsMaliciousHollomanRequest) Reset()           {}
func (*QueryIsMaliciousHollomanRequest) ProtoMessage()    {}
func (m *QueryIsMaliciousHollomanRequest) String() string { return m.HollomanSignature }
