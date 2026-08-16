// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cli

import (
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	pb "github.com/threatattest/chain/x/ipfsverify/types/pb"
)

// NewTxCmd returns the root tx command for x/ipfsverify.
func NewTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "ipfsverify",
		Short:                      "IPFS detection-rule verification transaction commands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(CmdSubmitVerificationReport())
	return cmd
}

// CmdSubmitVerificationReport builds and broadcasts a MsgSubmitVerificationReport.
func CmdSubmitVerificationReport() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "submit-report",
		Short: "Submit an IPFS verification report (off-chain verifier daemon)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			jobID, _ := cmd.Flags().GetString("job-id")
			attestationID, _ := cmd.Flags().GetString("attestation-id")
			ruleID, _ := cmd.Flags().GetString("rule-id")
			cid, _ := cmd.Flags().GetString("cid")
			expectedSHA256, _ := cmd.Flags().GetString("expected-sha256")
			actualSHA256, _ := cmd.Flags().GetString("actual-sha256")
			matched, _ := cmd.Flags().GetBool("matched")
			verifiedAt, _ := cmd.Flags().GetInt64("verified-at")
			errorMsg, _ := cmd.Flags().GetString("error-msg")

			msg := &pb.MsgSubmitVerificationReport{
				Sender: clientCtx.GetFromAddress().String(),
				Report: &pb.VerificationReport{
					JobId:          jobID,
					AttestationId:  attestationID,
					RuleId:         ruleID,
					Cid:            cid,
					ExpectedSha256: expectedSHA256,
					ActualSha256:   actualSHA256,
					Matched:        matched,
					VerifiedAt:     verifiedAt,
					ErrorMsg:       errorMsg,
				},
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String("job-id", "", "Verification job ID (required)")
	cmd.Flags().String("attestation-id", "", "Attestation ID (required)")
	cmd.Flags().String("rule-id", "", "Detection rule ID (required)")
	cmd.Flags().String("cid", "", "IPFS CID (required)")
	cmd.Flags().String("expected-sha256", "", "Expected SHA-256 of the CID content (required)")
	cmd.Flags().String("actual-sha256", "", "Actual SHA-256 computed by the verifier")
	cmd.Flags().Bool("matched", false, "Whether actual SHA-256 matches the expected value")
	cmd.Flags().Int64("verified-at", 0, "Verification Unix timestamp (default: now)")
	cmd.Flags().String("error-msg", "", "Error message if the content could not be fetched")

	_ = cmd.MarkFlagRequired("job-id")
	_ = cmd.MarkFlagRequired("cid")
	_ = cmd.MarkFlagRequired("expected-sha256")

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}
