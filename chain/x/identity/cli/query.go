// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cli

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/spf13/cobra"

	"github.com/threatattest/chain/x/identity/types"
)

// NewQueryCmd returns the root query command for x/identity.
func NewQueryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "identity",
		Short:                      "ThreatAttest DNS identity query commands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(
		CmdVerifyDomainProof(),
	)
	return cmd
}

// ============================================================
// verify-domain-proof
// ============================================================

// CmdVerifyDomainProof is a local (off-chain) utility that verifies a domain
// proof payload and signature without submitting a transaction.
func CmdVerifyDomainProof() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-domain-proof",
		Short: "Locally verify a domain proof payload and signature (off-chain utility)",
		Long: `Compute and display the domain proof payload for the given parameters.
This is a local utility — it does not contact the chain.

Use this to verify that your domain proof signature is correct before
submitting a register-identity transaction.

Example:
  threatattestd query identity verify-domain-proof \
    --domain example.com \
    --selector tat2025a \
    --cosmos-addr cosmos1abc... \
    --registered-at 1700000000`,
		RunE: runVerifyDomainProof,
	}

	cmd.Flags().String("domain", "", "Domain name (required)")
	cmd.Flags().String("selector", "", "DNS selector (required)")
	cmd.Flags().String("cosmos-addr", "", "Cosmos bech32 address (required)")
	cmd.Flags().Int64("registered-at", 0, "Unix timestamp (required)")
	cmd.Flags().String("sig", "", "Signature hex to verify (optional)")

	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("selector")
	_ = cmd.MarkFlagRequired("cosmos-addr")
	_ = cmd.MarkFlagRequired("registered-at")

	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func runVerifyDomainProof(cmd *cobra.Command, _ []string) error {
	domain, _ := cmd.Flags().GetString("domain")
	selector, _ := cmd.Flags().GetString("selector")
	cosmosAddr, _ := cmd.Flags().GetString("cosmos-addr")
	registeredAt, _ := cmd.Flags().GetInt64("registered-at")

	normDomain, err := types.NormalizeDomain(domain)
	if err != nil {
		return fmt.Errorf("invalid domain: %w", err)
	}

	payload := types.DomainProofPayload(normDomain, selector, cosmosAddr, registeredAt)

	fmt.Printf("Domain Proof Verification\n")
	fmt.Printf("=========================\n")
	fmt.Printf("Domain (normalized): %s\n", normDomain)
	fmt.Printf("Selector:            %s\n", selector)
	fmt.Printf("Cosmos Address:      %s\n", cosmosAddr)
	fmt.Printf("Registered At:       %d\n", registeredAt)
	fmt.Printf("TAT Key FQDN:        %s\n", types.TATKeyFQDN(selector, normDomain))
	fmt.Printf("Proof FQDN:          %s\n", types.TATProofFQDN(normDomain))
	fmt.Printf("Active Selector:     %s\n", types.TATActiveSelectorFQDN(normDomain))
	fmt.Printf("\nPayload (SHA-256 pre-image):\n")
	fmt.Printf("  tatkey-domain-proof|%s|%s|%s|%d\n",
		normDomain, selector, cosmosAddr, registeredAt)
	fmt.Printf("\nPayload digest (hex):\n")
	fmt.Printf("  %x\n", payload)
	fmt.Printf("\nIdentity ID:\n")
	fmt.Printf("  %s\n", types.ComputeIdentityID(cosmosAddr, normDomain, registeredAt))

	sig, _ := cmd.Flags().GetString("sig")
	if sig != "" {
		fmt.Printf("\nSignature provided: %s\n", sig)
		fmt.Printf("Note: full secp256k1 signature verification requires --pubkey flag\n")
		fmt.Printf("      (not yet implemented in CLI; use the Go SDK or test script)\n")
	} else {
		fmt.Printf("\nTip: provide --sig <hex> to verify a signature against this payload\n")
	}

	return nil
}
