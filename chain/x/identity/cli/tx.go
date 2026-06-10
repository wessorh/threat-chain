// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/spf13/cobra"

	"github.com/threatattest/chain/x/identity/types"
)

// RootTxCmd is the type alias used by module.go GetTxCmd().
type RootTxCmd = cobra.Command

// NewTxCmd returns the root transaction command for x/identity.
func NewTxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        types.ModuleName,
		Short:                      "ThreatAttest DNS identity transaction commands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(
		CmdRegisterIdentity(),
		CmdRotateIdentityKey(),
		CmdRevokeIdentity(),
		CmdRenewIdentity(),
	)
	return cmd
}

// ============================================================
// register-identity
// ============================================================

// CmdRegisterIdentity returns the CLI command for MsgRegisterIdentity.
func CmdRegisterIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register-identity",
		Short: "Register a new DNSSEC-anchored signing identity",
		Long: `Register a DNS-bound signing identity on the ThreatAttest chain.

The transaction binds your Cosmos address to a domain name that you control.
You must have already published the required DNS TXT records before submitting
this transaction.

Required DNS records:
  {selector}._tatkey.{domain}  IN TXT  "v=TAT1 k=secp256k1 p={pubkey} a={addr} ..."
  _tatproof.{domain}           IN TXT  "v=TAT1 sel={selector} proof={sig} t={unix}"
  _tatkey.{domain}             IN TXT  "sel={selector}"

Example:
  threatattestd tx identity register-identity \
    --domain example.com \
    --selector tat2025a \
    --pubkey 02a1b2c3... \
    --domain-proof-sig aabbcc... \
    --published-at 1700000000 \
    --evidence-file evidence.json \
    --name "Example Corp Security" \
    --uri https://security.example.com \
    --from mykey --chain-id threatattest-1`,
		RunE: runRegisterIdentity,
	}

	cmd.Flags().String("domain", "", "Domain name to bind (required)")
	cmd.Flags().String("selector", "", "DNS selector for the TAT key record (required)")
	cmd.Flags().String("pubkey", "", "Compressed secp256k1 public key hex, 66 chars (required)")
	cmd.Flags().String("domain-proof-sig", "", "Domain proof signature hex, 128 chars (required)")
	cmd.Flags().Int64("published-at", 0, "Unix timestamp for proof anchor (default: now)")
	cmd.Flags().String("evidence-file", "", "Path to JSON file containing DNSEvidenceBundle")
	cmd.Flags().String("name", "", "Human-readable identity name (optional, max 128 chars)")
	cmd.Flags().String("uri", "", "Identity URI (optional, must be https://)")
	cmd.Flags().Int64("ttl", 0, "Identity TTL in seconds (0 = use chain default)")
	cmd.Flags().Uint32("flags", 0, "IdentityFlag bitmask (e.g. 1=EXPERT, 2=ORGANIZATION)")

	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("selector")
	_ = cmd.MarkFlagRequired("pubkey")
	_ = cmd.MarkFlagRequired("domain-proof-sig")

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func runRegisterIdentity(cmd *cobra.Command, _ []string) error {
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}

	domain, _ := cmd.Flags().GetString("domain")
	selector, _ := cmd.Flags().GetString("selector")
	pubkey, _ := cmd.Flags().GetString("pubkey")
	proofSig, _ := cmd.Flags().GetString("domain-proof-sig")
	publishedAt, _ := cmd.Flags().GetInt64("published-at")
	name, _ := cmd.Flags().GetString("name")
	uri, _ := cmd.Flags().GetString("uri")
	ttl, _ := cmd.Flags().GetInt64("ttl")
	flagBits, _ := cmd.Flags().GetUint32("flags")
	evidenceFile, _ := cmd.Flags().GetString("evidence-file")

	if publishedAt == 0 {
		publishedAt = time.Now().Unix()
	}

	msg := &types.MsgRegisterIdentity{
		CosmosAddr:     clientCtx.GetFromAddress().String(),
		Domain:         domain,
		Selector:       selector,
		PublicKeyHex:   pubkey,
		DomainProofSig: proofSig,
		PublishedAt:    publishedAt,
		Name:           name,
		URI:            uri,
		TTLSeconds:     ttl,
		Flags:          types.IdentityFlag(flagBits),
	}

	// Load evidence bundle from file if provided
	if evidenceFile != "" {
		bz, err := os.ReadFile(evidenceFile)
		if err != nil {
			return fmt.Errorf("cannot read evidence file %q: %w", evidenceFile, err)
		}
		var bundle types.DNSEvidenceBundle
		if err := json.Unmarshal(bz, &bundle); err != nil {
			return fmt.Errorf("cannot parse evidence file %q: %w", evidenceFile, err)
		}
		msg.Evidence = &bundle
	}

	if err := msg.ValidateBasic(); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
}

// ============================================================
// rotate-identity-key
// ============================================================

// CmdRotateIdentityKey returns the CLI command for MsgRotateIdentityKey.
func CmdRotateIdentityKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-identity-key",
		Short: "Rotate the signing key for an existing DNS identity",
		Long: `Rotate the signing key for an existing DNS identity using DKIM-style
dual-selector key handoff.

Before submitting this transaction you must:
  1. Generate a new secp256k1 key pair.
  2. Publish the new selector's TAT key record in DNS.
  3. Produce a rotation authorization signature with the CURRENT active key.
  4. Produce a domain proof signature with the NEW key.

The old key record can be removed from DNS after the rotation is confirmed.

Example:
  threatattestd tx identity rotate-identity-key \
    --new-selector tat2025b \
    --new-pubkey 03d4e5f6... \
    --rotation-auth-sig aabbcc... \
    --new-key-proof-sig ddeeff... \
    --rotated-at 1700086400 \
    --evidence-file new_evidence.json \
    --from mykey --chain-id threatattest-1`,
		RunE: runRotateIdentityKey,
	}

	cmd.Flags().String("new-selector", "", "New DNS selector (required)")
	cmd.Flags().String("new-pubkey", "", "New compressed secp256k1 public key hex (required)")
	cmd.Flags().String("rotation-auth-sig", "", "Rotation auth signature by current key (required)")
	cmd.Flags().String("new-key-proof-sig", "", "Domain proof signature by new key (required)")
	cmd.Flags().Int64("rotated-at", 0, "Unix timestamp for rotation anchor (default: now)")
	cmd.Flags().String("evidence-file", "", "Path to JSON file containing new DNSEvidenceBundle")
	cmd.Flags().String("notes", "", "Optional rotation reason notes")

	_ = cmd.MarkFlagRequired("new-selector")
	_ = cmd.MarkFlagRequired("new-pubkey")
	_ = cmd.MarkFlagRequired("rotation-auth-sig")
	_ = cmd.MarkFlagRequired("new-key-proof-sig")

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func runRotateIdentityKey(cmd *cobra.Command, _ []string) error {
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}

	newSelector, _ := cmd.Flags().GetString("new-selector")
	newPubkey, _ := cmd.Flags().GetString("new-pubkey")
	rotAuthSig, _ := cmd.Flags().GetString("rotation-auth-sig")
	newKeyProofSig, _ := cmd.Flags().GetString("new-key-proof-sig")
	rotatedAt, _ := cmd.Flags().GetInt64("rotated-at")
	notes, _ := cmd.Flags().GetString("notes")
	evidenceFile, _ := cmd.Flags().GetString("evidence-file")

	if rotatedAt == 0 {
		rotatedAt = time.Now().Unix()
	}

	msg := &types.MsgRotateIdentityKey{
		CosmosAddr:           clientCtx.GetFromAddress().String(),
		NewSelector:          newSelector,
		NewPublicKeyHex:      newPubkey,
		RotationAuthSig:      rotAuthSig,
		NewKeyDomainProofSig: newKeyProofSig,
		RotatedAt:            rotatedAt,
		Notes:                notes,
	}

	if evidenceFile != "" {
		bz, err := os.ReadFile(evidenceFile)
		if err != nil {
			return fmt.Errorf("cannot read evidence file %q: %w", evidenceFile, err)
		}
		var bundle types.DNSEvidenceBundle
		if err := json.Unmarshal(bz, &bundle); err != nil {
			return fmt.Errorf("cannot parse evidence file %q: %w", evidenceFile, err)
		}
		msg.Evidence = &bundle
	}

	if err := msg.ValidateBasic(); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
}

// ============================================================
// revoke-identity
// ============================================================

// CmdRevokeIdentity returns the CLI command for MsgRevokeIdentity.
func CmdRevokeIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-identity",
		Short: "Voluntarily revoke your DNS identity record",
		Long: `Voluntarily revoke your DNS-bound identity record.

WARNING: Revocation is permanent.  A revoked identity cannot be reinstated.
You will need to register a new identity if you wish to re-establish DNS binding.

The revocation incurs a trust score penalty of -100 RS.

Example:
  threatattestd tx identity revoke-identity \
    --reason "Key compromise - rotating to new identity" \
    --from mykey --chain-id threatattest-1`,
		RunE: runRevokeIdentity,
	}

	cmd.Flags().String("reason", "", "Revocation reason (optional, max 512 chars)")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func runRevokeIdentity(cmd *cobra.Command, _ []string) error {
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}

	reason, _ := cmd.Flags().GetString("reason")

	msg := &types.MsgRevokeIdentity{
		CosmosAddr: clientCtx.GetFromAddress().String(),
		Reason:     reason,
	}

	if err := msg.ValidateBasic(); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
}

// ============================================================
// renew-identity
// ============================================================

// CmdRenewIdentity returns the CLI command for MsgRenewIdentity.
func CmdRenewIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "renew-identity",
		Short: "Renew an existing DNS identity with fresh DNSSEC evidence",
		Long: `Renew your DNS-bound identity record with a fresh DNSSEC evidence bundle.

Renewal extends the expiry by the configured TTL (default: 365 days) and
awards +10 RS to your trust score.  You must provide a fresh evidence bundle
collected within the last hour.

Use the 'collect-evidence' helper script to generate the evidence bundle:
  ./scripts/collect_evidence.sh example.com tat2025a > evidence.json

Example:
  threatattestd tx identity renew-identity \
    --evidence-file evidence.json \
    --ttl 31536000 \
    --from mykey --chain-id threatattest-1`,
		RunE: runRenewIdentity,
	}

	cmd.Flags().String("evidence-file", "", "Path to fresh DNSEvidenceBundle JSON file (required)")
	cmd.Flags().Int64("ttl", 0, "TTL extension in seconds (0 = use chain default)")

	_ = cmd.MarkFlagRequired("evidence-file")

	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func runRenewIdentity(cmd *cobra.Command, _ []string) error {
	clientCtx, err := client.GetClientTxContext(cmd)
	if err != nil {
		return err
	}

	evidenceFile, _ := cmd.Flags().GetString("evidence-file")
	ttl, _ := cmd.Flags().GetInt64("ttl")

	bz, err := os.ReadFile(evidenceFile)
	if err != nil {
		return fmt.Errorf("cannot read evidence file %q: %w", evidenceFile, err)
	}
	var bundle types.DNSEvidenceBundle
	if err := json.Unmarshal(bz, &bundle); err != nil {
		return fmt.Errorf("cannot parse evidence file %q: %w", evidenceFile, err)
	}

	msg := &types.MsgRenewIdentity{
		CosmosAddr: clientCtx.GetFromAddress().String(),
		Evidence:   bundle,
		TTLSeconds: ttl,
	}

	if err := msg.ValidateBasic(); err != nil {
		return fmt.Errorf("message validation failed: %w", err)
	}

	return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
}

// ============================================================
// Helpers
// ============================================================

// parseUint32 is a helper for parsing flag values.
func parseUint32(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}