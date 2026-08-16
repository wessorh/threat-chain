// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package ipfsverify

import (
	"context"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/ipfsverify/keeper"
	"github.com/threatattest/chain/x/ipfsverify/types"
	pb "github.com/threatattest/chain/x/ipfsverify/types/pb"
)

// This file bridges the generated protobuf wire messages (package pb) to the
// handwritten store-facing types (package types) used by the keeper.

// wireMsgServer adapts the keeper to the generated pb.MsgServer interface.
type wireMsgServer struct {
	k keeper.Keeper
}

// SubmitVerificationReport processes a report from the off-chain verifier
// daemon. The signer (relayer) is recorded as the report's VerifiedBy.
func (w *wireMsgServer) SubmitVerificationReport(ctx context.Context, m *pb.MsgSubmitVerificationReport) (*pb.MsgSubmitVerificationReportResponse, error) {
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	// Enforce the relayer whitelist (empty whitelist = allow all).
	params, err := w.k.GetParams(sdkCtx)
	if err != nil {
		return nil, err
	}
	if !params.IsRelayerAllowed(m.Sender) {
		return nil, fmt.Errorf("sender %s is not a whitelisted relayer", m.Sender)
	}

	report := types.VerificationReport{
		JobID:          m.Report.JobId,
		AttestationID:  m.Report.AttestationId,
		RuleID:         m.Report.RuleId,
		CID:            m.Report.Cid,
		ExpectedSHA256: m.Report.ExpectedSha256,
		ActualSHA256:   m.Report.ActualSha256,
		Matched:        m.Report.Matched,
		VerifiedAt:     m.Report.VerifiedAt,
		VerifiedBy:     m.Sender,
		ErrorMsg:       m.Report.ErrorMsg,
	}
	if err := w.k.SubmitVerificationReport(sdkCtx, report); err != nil {
		return nil, err
	}
	return &pb.MsgSubmitVerificationReportResponse{}, nil
}
