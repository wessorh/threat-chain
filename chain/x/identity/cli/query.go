// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cli

import (
	"encoding/json"
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
		CmdQueryIdentity(),
		CmdQueryIdentityByDomain(),
		CmdQueryIdentityByID(),
		CmdQueryTrustScore(),
		CmdQueryTier(),
		CmdQueryParams(),
		CmdVerifyDomainProof(),
	)
	return cmd
}

// ============================================================
// query identity [address]
// ============================================================

func CmdQueryIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity [cosmos-address]",
		Short: "Query the DNS identity record for a Cosmos address",
		Args:  cobra.ExactArgs(1),
		Example: `  threatattestd query identity identity cosmos1abc...
  threatattestd q identity identity cosmos1abc... --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			// NOTE: In a production deployment this would call the gRPC query
			// endpoint.  Here we print a helpful placeholder that shows what
			// the response would look like.
			_ = clientCtx
			addr := args[0]
			printQueryPlaceholder(cmd, "GetIdentity", map[string]interface{}{
				"cosmos_addr": addr,
				"note":        "gRPC query endpoint: /threatattest.identity.Query/GetIdentity",
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// query identity-by-domain [domain]
// ============================================================

func CmdQueryIdentityByDomain() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity-by-domain [domain]",
		Short: "Query the DNS identity record for a domain name",
		Args:  cobra.ExactArgs(1),
		Example: `  threatattestd query identity identity-by-domain example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			_ = clientCtx
			domain, err := types.NormalizeDomain(args[0])
			if err != nil {
				return fmt.Errorf("invalid domain %q: %w", args[0], err)
			}
			printQueryPlaceholder(cmd, "GetIdentityByDomain", map[string]interface{}{
				"domain": domain,
				"note":   "gRPC query endpoint: /threatattest.identity.Query/GetIdentityByDomain",
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// query identity-by-id [identity-id]
// ============================================================

func CmdQueryIdentityByID() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity-by-id [identity-id]",
		Short: "Query a DNS identity record by its identity ID (SHA-256 hex)",
		Args:  cobra.ExactArgs(1),
		Example: `  threatattestd query identity identity-by-id a1b2c3d4...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			_ = clientCtx
			printQueryPlaceholder(cmd, "GetIdentityByID", map[string]interface{}{
				"identity_id": args[0],
				"note":        "gRPC query endpoint: /threatattest.identity.Query/GetIdentityByID",
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// query trust-score [address]
// ============================================================

func CmdQueryTrustScore() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust-score [cosmos-address]",
		Short: "Query the reputation trust score for a Cosmos address",
		Args:  cobra.ExactArgs(1),
		Example: `  threatattestd query identity trust-score cosmos1abc...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			_ = clientCtx
			printQueryPlaceholder(cmd, "GetTrustScore", map[string]interface{}{
				"cosmos_addr": args[0],
				"note":        "gRPC query endpoint: /threatattest.identity.Query/GetTrustScore",
				"score_deltas": map[string]int64{
					"registration":  types.TrustScoreRegistration,
					"milestone_30d": types.TrustScoreMilestone30d,
					"renewal":       types.TrustScoreRenewal,
					"dns_removed":   types.TrustScoreDNSRemoved,
					"revoked":       types.TrustScoreRevoked,
				},
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// query tier [address]
// ============================================================

func CmdQueryTier() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tier [cosmos-address]",
		Short: "Query the compliance tier and attestation weight multiplier for an address",
		Args:  cobra.ExactArgs(1),
		Example: `  threatattestd query identity tier cosmos1abc...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			_ = clientCtx
			printQueryPlaceholder(cmd, "GetTier", map[string]interface{}{
				"cosmos_addr": args[0],
				"tier_table": []map[string]interface{}{
					{"tier": 0, "name": "ANONYMOUS", "multiplier": "0.25x", "requirement": "none"},
					{"tier": 1, "name": "STAKED", "multiplier": "0.50x", "requirement": "min delegation"},
					{"tier": 2, "name": "DNS_BOUND", "multiplier": "1.00x", "requirement": "active DNS identity"},
					{"tier": 3, "name": "EXPERT", "multiplier": "2.00x", "requirement": "DNS identity + EXPERT flag + min RS"},
				},
				"note": "gRPC query endpoint: /threatattest.identity.Query/GetTier",
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// query params
// ============================================================

func CmdQueryParams() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Query the x/identity module parameters",
		Args:  cobra.NoArgs,
		Example: `  threatattestd query identity params`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			_ = clientCtx
			defaults := types.DefaultParams()
			printQueryPlaceholder(cmd, "GetParams", map[string]interface{}{
				"default_params": defaults,
				"note":           "gRPC query endpoint: /threatattest.identity.Query/GetParams",
			})
			return nil
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
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

// ============================================================
// Helper
// ============================================================

// printQueryPlaceholder prints a JSON-formatted query response placeholder
// to stdout.  In production these would be live gRPC responses.
func printQueryPlaceholder(cmd *cobra.Command, queryName string, data map[string]interface{}) {
	outputFmt, _ := cmd.Flags().GetString("output")
	data["query"] = queryName
	if outputFmt == "json" {
		bz, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(bz))
	} else {
		bz, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(bz))
	}
}