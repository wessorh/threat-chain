// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package identity

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/keeper"
	"github.com/threatattest/chain/x/identity/types"
	pb "github.com/threatattest/chain/x/identity/types/pb"
)

// This file bridges the generated protobuf wire messages (package pb) to the
// handwritten internal message types (package types) used by the keeper. The
// generated types are protobuf-serialisable and therefore work with the tx
// codec, while the handwritten types carry ValidateBasic and the keeper's
// business logic unchanged.

// ── DNSSEC evidence helpers ──────────────────────────────────────────────────

func pbRRSIGsToTypes(in []*pb.RRSIGRecord) []types.RRSIGRecord {
	if in == nil {
		return nil
	}
	out := make([]types.RRSIGRecord, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, types.RRSIGRecord{
			TypeCovered: r.TypeCovered,
			Algorithm:   int(r.Algorithm),
			Labels:      int(r.Labels),
			OriginalTTL: r.OriginalTtl,
			Expiration:  r.Expiration,
			Inception:   r.Inception,
			KeyTag:      int(r.KeyTag),
			SignerName:  r.SignerName,
			Signature:   r.Signature,
		})
	}
	return out
}

func pbDNSKEYsToTypes(in []*pb.DNSKEYRecord) []types.DNSKEYRecord {
	if in == nil {
		return nil
	}
	out := make([]types.DNSKEYRecord, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, types.DNSKEYRecord{
			Flags:     int(r.Flags),
			Protocol:  int(r.Protocol),
			Algorithm: int(r.Algorithm),
			PublicKey: r.PublicKey,
			KeyTag:    int(r.KeyTag),
		})
	}
	return out
}

func pbDSToTypes(in []*pb.DSRecord) []types.DSRecord {
	if in == nil {
		return nil
	}
	out := make([]types.DSRecord, 0, len(in))
	for _, r := range in {
		if r == nil {
			continue
		}
		out = append(out, types.DSRecord{
			KeyTag:     int(r.KeyTag),
			Algorithm:  int(r.Algorithm),
			DigestType: int(r.DigestType),
			Digest:     r.Digest,
		})
	}
	return out
}

func pbEvidenceToTypes(in *pb.DNSEvidenceBundle) *types.DNSEvidenceBundle {
	if in == nil {
		return nil
	}
	return &types.DNSEvidenceBundle{
		TXTRecords:    in.TxtRecords,
		TXTRRSIGs:     pbRRSIGsToTypes(in.TxtRrsigs),
		ZoneDNSKEYs:   pbDNSKEYsToTypes(in.ZoneDnskeys),
		DNSKEYRRSIGs:  pbRRSIGsToTypes(in.DnskeyRrsigs),
		ParentDS:      pbDSToTypes(in.ParentDs),
		CollectedAt:   in.CollectedAt,
		Resolver:      in.Resolver,
	}
}

// ── Message converters (pb → types) ─────────────────────────────────────────

func pbRegisterToTypes(m *pb.MsgRegisterIdentity) *types.MsgRegisterIdentity {
	return &types.MsgRegisterIdentity{
		CosmosAddr:     m.CosmosAddr,
		Domain:         m.Domain,
		Selector:       m.Selector,
		PublicKeyHex:   m.PublicKeyHex,
		Name:           m.Name,
		URI:            m.Uri,
		Flags:          types.IdentityFlag(m.Flags),
		DomainProofSig: m.DomainProofSig,
		PublishedAt:    m.PublishedAt,
		Evidence:       pbEvidenceToTypes(m.Evidence),
		TTLSeconds:     m.TtlSeconds,
	}
}

func pbRotateToTypes(m *pb.MsgRotateIdentityKey) *types.MsgRotateIdentityKey {
	return &types.MsgRotateIdentityKey{
		CosmosAddr:           m.CosmosAddr,
		NewSelector:          m.NewSelector,
		NewPublicKeyHex:      m.NewPublicKeyHex,
		RotationAuthSig:      m.RotationAuthSig,
		NewKeyDomainProofSig: m.NewKeyDomainProofSig,
		RotatedAt:            m.RotatedAt,
		Evidence:             pbEvidenceToTypes(m.Evidence),
		Notes:                m.Notes,
	}
}

func pbRevokeToTypes(m *pb.MsgRevokeIdentity) *types.MsgRevokeIdentity {
	return &types.MsgRevokeIdentity{
		CosmosAddr: m.CosmosAddr,
		Reason:     m.Reason,
	}
}

func pbRenewToTypes(m *pb.MsgRenewIdentity) *types.MsgRenewIdentity {
	ev := pbEvidenceToTypes(m.Evidence)
	if ev == nil {
		ev = &types.DNSEvidenceBundle{}
	}
	return &types.MsgRenewIdentity{
		CosmosAddr: m.CosmosAddr,
		Evidence:   *ev,
		TTLSeconds: m.TtlSeconds,
	}
}

// ── wireMsgServer ───────────────────────────────────────────────────────────

// wireMsgServer adapts the handwritten keeper handlers to the generated
// pb.MsgServer interface so the module can be registered with the SDK's
// MsgServiceRouter via the generated RegisterMsgServer.
type wireMsgServer struct {
	k keeper.Keeper
}

func (w *wireMsgServer) RegisterIdentity(ctx context.Context, m *pb.MsgRegisterIdentity) (*pb.MsgRegisterIdentityResponse, error) {
	msg := pbRegisterToTypes(m)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	rec, err := w.k.RegisterIdentity(sdk.UnwrapSDKContext(ctx), msg)
	if err != nil {
		return nil, err
	}
	return &pb.MsgRegisterIdentityResponse{
		IdentityId: rec.IdentityID,
		Domain:     rec.Domain,
		Selector:   rec.Selector,
		Status:     rec.Status.String(),
		ExpiresAt:  rec.ExpiresAt,
	}, nil
}

func (w *wireMsgServer) RotateIdentityKey(ctx context.Context, m *pb.MsgRotateIdentityKey) (*pb.MsgRotateIdentityKeyResponse, error) {
	msg := pbRotateToTypes(m)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	rec, err := w.k.RotateIdentityKey(sdk.UnwrapSDKContext(ctx), msg)
	if err != nil {
		return nil, err
	}
	return &pb.MsgRotateIdentityKeyResponse{IdentityId: rec.IdentityID}, nil
}

func (w *wireMsgServer) RevokeIdentity(ctx context.Context, m *pb.MsgRevokeIdentity) (*pb.MsgRevokeIdentityResponse, error) {
	msg := pbRevokeToTypes(m)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	if err := w.k.RevokeIdentity(sdk.UnwrapSDKContext(ctx), msg); err != nil {
		return nil, err
	}
	return &pb.MsgRevokeIdentityResponse{}, nil
}

func (w *wireMsgServer) RenewIdentity(ctx context.Context, m *pb.MsgRenewIdentity) (*pb.MsgRenewIdentityResponse, error) {
	msg := pbRenewToTypes(m)
	if err := msg.ValidateBasic(); err != nil {
		return nil, err
	}
	rec, err := w.k.RenewIdentity(sdk.UnwrapSDKContext(ctx), msg)
	if err != nil {
		return nil, err
	}
	return &pb.MsgRenewIdentityResponse{ExpiresAt: rec.ExpiresAt}, nil
}
