// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cli

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	pb "github.com/threatattest/chain/x/ipfsverify/types/pb"
)

// NewQueryCmd returns the root query command for x/ipfsverify.
func NewQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "ipfsverify",
		Short:                      "IPFS verification query commands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(CmdPendingJobs())
	return cmd
}

// CmdPendingJobs lists pending IPFS verification jobs.
func CmdPendingJobs() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pending-jobs",
		Short: "List pending IPFS verification jobs",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			maxCount, _ := cmd.Flags().GetUint32("max-count")
			qc := pb.NewQueryClient(clientCtx)
			res, err := qc.PendingJobs(cmd.Context(), &pb.QueryPendingJobsRequest{MaxCount: maxCount})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().Uint32("max-count", 50, "Maximum number of jobs to return")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}
