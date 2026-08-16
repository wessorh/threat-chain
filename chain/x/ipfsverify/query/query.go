// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package query

import (
	"context"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/ipfsverify/keeper"
	pb "github.com/threatattest/chain/x/ipfsverify/types/pb"
)

// QueryServer implements the ipfsverify gRPC query service.
type QueryServer struct {
	keeper keeper.Keeper
}

// NewQueryServer returns a new QueryServer backed by the given Keeper.
func NewQueryServer(k keeper.Keeper) *QueryServer {
	return &QueryServer{keeper: k}
}

// PendingJobs returns up to maxCount pending verification jobs.
func (q *QueryServer) PendingJobs(goCtx context.Context, req *pb.QueryPendingJobsRequest) (*pb.QueryPendingJobsResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	maxCount := int(req.GetMaxCount())
	if maxCount <= 0 || maxCount > 100 {
		maxCount = 50
	}
	jobs, err := q.keeper.DequeuePendingJobs(ctx, maxCount)
	if err != nil {
		return nil, err
	}
	out := make([]*pb.VerificationJob, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, &pb.VerificationJob{
			JobId:          j.JobID,
			AttestationId:  j.AttestationID,
			RuleId:         j.RuleID,
			Cid:            j.CID,
			ExpectedSha256: j.ExpectedSHA256,
			SubmittedBy:    j.SubmittedBy,
			Status:         int32(j.Status),
			Attempts:       j.Attempts,
		})
	}
	return &pb.QueryPendingJobsResponse{Jobs: out}, nil
}
