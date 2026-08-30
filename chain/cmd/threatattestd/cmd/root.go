// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

// Package cmd provides the root CLI command tree for threatattestd.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	cmtcfg "github.com/cometbft/cometbft/config"

	"cosmossdk.io/log/v2"
	confixcmd "cosmossdk.io/tools/confix/cmd"
	"github.com/cosmos/cosmos-sdk/store/v2/snapshots"
	snapshottypes "github.com/cosmos/cosmos-sdk/store/v2/snapshots/types"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/baseapp"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/config"
	"github.com/cosmos/cosmos-sdk/client/debug"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/keys"
	"github.com/cosmos/cosmos-sdk/client/pruning"
	"github.com/cosmos/cosmos-sdk/client/rpc"
	"github.com/cosmos/cosmos-sdk/client/snapshot"
	"github.com/cosmos/cosmos-sdk/client/tx"
	addresscodec "github.com/cosmos/cosmos-sdk/codec/address"
	"github.com/cosmos/cosmos-sdk/server"
	serverconfig "github.com/cosmos/cosmos-sdk/server/config"
	servertypes "github.com/cosmos/cosmos-sdk/server/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"
	bankcli "github.com/cosmos/cosmos-sdk/x/bank/client/cli"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	genutilcli "github.com/cosmos/cosmos-sdk/x/genutil/client/cli"
	genutiltypes "github.com/cosmos/cosmos-sdk/x/genutil/types"
	"github.com/spf13/cobra"

	tatapp "github.com/threatattest/chain/app"
	attesttypes "github.com/threatattest/chain/x/attestation/types"
	pb "github.com/threatattest/chain/x/attestation/types/pb"
	identitycli "github.com/threatattest/chain/x/identity/cli"
	ipfsverifycli "github.com/threatattest/chain/x/ipfsverify/cli"
)

// DefaultNodeHome is the default home directory for the node.
const DefaultNodeHome = ".threatattestd"

// NewRootCmd builds the root cobra command for threatattestd.
func NewRootCmd() *cobra.Command {
	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(tatapp.Bech32Prefix, tatapp.Bech32Prefix+"pub")
	cfg.SetBech32PrefixForValidator(tatapp.Bech32Prefix+"valoper", tatapp.Bech32Prefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(tatapp.Bech32Prefix+"valcons", tatapp.Bech32Prefix+"valconspub")
	cfg.Seal()

	encodingConfig := tatapp.MakeEncodingConfig()

	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Codec).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithLegacyAmino(encodingConfig.Amino).
		WithTxConfig(encodingConfig.TxConfig).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithHomeDir(DefaultNodeHome).
		WithViper("TATST")

	rootCmd := &cobra.Command{
		Use:   "threatattestd",
		Short: "ThreatAttest — Decentralised Threat Intelligence Blockchain",
		Long: `threatattestd is the node binary for the ThreatAttest blockchain.
It provides:
  - Full node operation with CometBFT consensus
  - Publishing and querying threat attestations (file SHA-256, URL, IPv4)
  - IPFS-linked detection rules (YARA, Sigma, Snort)
  - Reputation-gated attestation publishing
  - IBC-enabled cross-chain threat feed subscriptions`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			initClientCtx, err := client.ReadPersistentCommandFlags(initClientCtx, cmd.Flags())
			if err != nil {
				return err
			}
			initClientCtx, err = config.ReadFromClientConfig(initClientCtx)
			if err != nil {
				return err
			}
			if err := client.SetCmdClientContextHandler(initClientCtx, cmd); err != nil {
				return err
			}
			customAppTemplate, customAppConfig := initAppConfig()
			return server.InterceptConfigsPreRunHandler(
				cmd, customAppTemplate, customAppConfig, initCometBFTConfig(),
			)
		},
	}

	initRootCmd(rootCmd, initClientCtx)
	return rootCmd
}

func initRootCmd(rootCmd *cobra.Command, clientCtx client.Context) {
	valAddrCodec := addresscodec.NewBech32Codec(tatapp.Bech32Prefix + "valoper")

	rootCmd.AddCommand(
		genutilcli.InitCmd(newBasicManager(), DefaultNodeHome),
		genutilcli.CollectGenTxsCmd(
			banktypes.GenesisBalancesIterator{},
			DefaultNodeHome,
			genutiltypes.DefaultMessageValidator,
			valAddrCodec,
		),
		genutilcli.GenTxCmd(
			newBasicManager(),
			clientCtx.TxConfig,
			banktypes.GenesisBalancesIterator{},
			DefaultNodeHome,
			valAddrCodec,
		),
		genutilcli.ValidateGenesisCmd(newBasicManager()),
		addGenesisAccountCmd(DefaultNodeHome, tatapp.Bech32Prefix),
		debug.Cmd(),
		confixcmd.ConfigCommand(),
		pruning.Cmd(newApp, DefaultNodeHome),
		snapshot.Cmd(newApp),
		attestFileCmd(),
		attestURLCmd(),
		attestDomainCmd(),
	)

	server.AddCommands(rootCmd, DefaultNodeHome, newApp, appExport, addModuleInitFlags)

	rootCmd.AddCommand(
		server.StatusCommand(),
		queryCommand(),
		txCommand(),
		keys.Commands(),
		rpc.WaitTxCmd(),
	)
}

func addModuleInitFlags(_ *cobra.Command) {}

// ============================================================
// attest-file — the key demo command
// ============================================================

// AttestationSpec is the JSON structure written to the output file.
type AttestationSpec struct {
	SchemaVersion     string   `json:"schema_version"`
	ArtifactType      string   `json:"artifact_type"`
	ArtifactSHA256    string   `json:"artifact_sha256"`
	HollomanSignature string   `json:"holloman_signature,omitempty"`
	HammingMask       int32    `json:"hamming_mask,omitempty"`
	RawValue          string   `json:"raw_value,omitempty"`
	Severity          string   `json:"severity"`
	Confidence        int      `json:"confidence"`
	TTLSeconds        int64    `json:"ttl_seconds"`
	Description       string   `json:"description"`
	Tags              []string `json:"tags,omitempty"`
	ThreatCategory    []string `json:"threat_category,omitempty"`
	Attester          string   `json:"attester,omitempty"`
	PublishedAt       int64    `json:"published_at"`
	ExpiresAt         int64    `json:"expires_at"`
	ChainID           string   `json:"chain_id,omitempty"`
	// Computed fields displayed to the user
	FileSizeBytes int64  `json:"file_size_bytes,omitempty"`
	FileName      string `json:"file_name,omitempty"`
}

// attestFileCmd returns the attest-file command which computes a file's SHA-256,
// validates the attestation parameters, and writes a ready-to-broadcast JSON spec
// to an output file.  This is the primary demo entry point.
func attestFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest-file [file]",
		Short: "Compute SHA-256 of a file and produce a signed attestation spec",
		Long: `attest-file hashes a local file with SHA-256, validates the attestation
parameters you supply, and writes a complete MsgPublishAttestation JSON document
to an output file.  That file can then be broadcast to a running ThreatAttest
node with:

    threatattestd tx attestation publish \
      --spec attestation.json \
      --from <key> \
      --chain-id <chain-id>

Parameters are validated locally before the spec is written so you get
immediate feedback on any invalid values (e.g. confidence out of range,
TTL too long, description containing HTML tags).

Examples:
  # Attest a suspicious binary
  threatattestd attest-file /path/to/malware.exe \
    --severity HIGH \
    --confidence 90 \
    --ttl 86400 \
    --description "Suspected ransomware dropper" \
    --tags "ransomware,dropper" \
    --category "RANSOMWARE" \
    --output attestation.json

  # Attest with a specific attester address
  threatattestd attest-file /path/to/sample.pdf \
    --severity MEDIUM \
    --confidence 75 \
    --ttl 604800 \
    --description "PDF with embedded JavaScript" \
    --attester tatst1abc123... \
    --output attestation.json`,
		Args: cobra.ExactArgs(1),
		RunE: runAttestFile,
	}

	cmd.Flags().String("severity", "MEDIUM",
		"Severity level: UNSPECIFIED|LOW|MEDIUM|HIGH|CRITICAL")
	cmd.Flags().Int("confidence", 80,
		"Confidence score 0-100 (analyst certainty that the artifact is malicious)")
	cmd.Flags().Int64("ttl", 86400,
		"Time-to-live in seconds (how long the attestation remains ACTIVE, max 2592000 = 30 days)")
	cmd.Flags().String("description", "",
		"Human-readable description of the threat (max 1024 bytes, no HTML)")
	cmd.Flags().StringSlice("tags", nil,
		"Comma-separated list of tags, e.g. ransomware,dropper (max 16, each max 32 bytes)")
	cmd.Flags().StringSlice("category", nil,
		"Comma-separated threat categories, e.g. RANSOMWARE,TROJAN (max 8)")
	cmd.Flags().String("attester", "",
		"Bech32 attester address (tatst1...). If omitted, a placeholder is used.")
	cmd.Flags().String("output", "attestation.json",
		"Path to write the attestation JSON spec")
	cmd.Flags().String("chain-id", "threatattest-1",
		"Chain ID to embed in the spec")
	cmd.Flags().Bool("dry-run", false,
		"Validate and print the spec without writing to disk")
	cmd.Flags().String("artifact-type", "FILE",
		"Artifact type: FILE or EMAIL_BODY")
	cmd.Flags().String("holloman-signature", "",
		"128-bit holloman perceptual fingerprint (32 lowercase hex chars) for near-duplicate matching")
	cmd.Flags().Int32("hamming-mask", 0,
		"Holloman hamming-mask radius (0-128); the attestation matches fingerprints within this Hamming distance")

	return cmd
}

func runAttestFile(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	// ── Open and hash the file ────────────────────────────────────────────────
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file %q: %w", filePath, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat file %q: %w", filePath, err)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("error reading file %q: %w", filePath, err)
	}
	artifactSHA256 := hex.EncodeToString(h.Sum(nil))

	// Holloman / artifact-type flags (parsed here, validated below).
	artifactType, _ := cmd.Flags().GetString("artifact-type")
	hollomanSig, _ := cmd.Flags().GetString("holloman-signature")
	hammingMask, _ := cmd.Flags().GetInt32("hamming-mask")

	// ── Read flags ────────────────────────────────────────────────────────────
	severity, _ := cmd.Flags().GetString("severity")
	confidence, _ := cmd.Flags().GetInt("confidence")
	ttl, _ := cmd.Flags().GetInt64("ttl")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	categories, _ := cmd.Flags().GetStringSlice("category")
	attester, _ := cmd.Flags().GetString("attester")
	outputPath, _ := cmd.Flags().GetString("output")
	chainID, _ := cmd.Flags().GetString("chain-id")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// ── Validate parameters ───────────────────────────────────────────────────
	validSeverities := map[string]bool{
		"UNSPECIFIED": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}
	if !validSeverities[severity] {
		return fmt.Errorf("invalid --severity %q: must be one of UNSPECIFIED, LOW, MEDIUM, HIGH, CRITICAL", severity)
	}
	if confidence < 0 || confidence > 100 {
		return fmt.Errorf("invalid --confidence %d: must be 0-100", confidence)
	}
	if ttl < 300 {
		return fmt.Errorf("invalid --ttl %d: minimum is 300 seconds (5 minutes)", ttl)
	}
	if ttl > 2592000 {
		return fmt.Errorf("invalid --ttl %d: maximum is 2592000 seconds (30 days)", ttl)
	}
	if len(description) > 1024 {
		return fmt.Errorf("--description exceeds 1024 bytes (%d bytes)", len(description))
	}
	if len(tags) > 16 {
		return fmt.Errorf("too many --tags: maximum is 16, got %d", len(tags))
	}
	for _, tag := range tags {
		if len(tag) > 32 {
			return fmt.Errorf("tag %q exceeds 32 bytes", tag)
		}
	}
	if len(categories) > 8 {
		return fmt.Errorf("too many --category entries: maximum is 8, got %d", len(categories))
	}
	if artifactType != "FILE" && artifactType != "EMAIL_BODY" {
		return fmt.Errorf("invalid --artifact-type %q: must be FILE or EMAIL_BODY", artifactType)
	}
	if hammingMask < 0 || hammingMask > 128 {
		return fmt.Errorf("invalid --hamming-mask %d: must be 0-128", hammingMask)
	}
	if hollomanSig != "" {
		valid := len(hollomanSig) == 32
		for _, c := range hollomanSig {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				valid = false
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid --holloman-signature: must be 32 lowercase hex chars")
		}
	}
	if artifactType == "EMAIL_BODY" && hollomanSig == "" {
		return fmt.Errorf("--holloman-signature is required for EMAIL_BODY artifacts")
	}
	if attester == "" {
		attester = "<set --attester tatst1... or use 'tx attestation publish --from key'>"
	}

	// ── Build spec ────────────────────────────────────────────────────────────
	now := time.Now().Unix()
	spec := AttestationSpec{
		SchemaVersion:     "1.0",
		ArtifactType:      artifactType,
		ArtifactSHA256:    artifactSHA256,
		HollomanSignature: hollomanSig,
		HammingMask:       hammingMask,
		Severity:          severity,
		Confidence:        confidence,
		TTLSeconds:        ttl,
		Description:       description,
		Tags:              tags,
		ThreatCategory:    categories,
		Attester:          attester,
		PublishedAt:       now,
		ExpiresAt:         now + ttl,
		ChainID:           chainID,
		FileSizeBytes:     fi.Size(),
		FileName:          fi.Name(),
	}

	specJSON, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}

	// ── Print summary ─────────────────────────────────────────────────────────
	cmd.Println()
	cmd.Println("╔══════════════════════════════════════════════════════════════╗")
	cmd.Println("║           ThreatAttest — File Attestation                   ║")
	cmd.Println("╚══════════════════════════════════════════════════════════════╝")
	cmd.Println()
	cmd.Printf("  File        : %s\n", filePath)
	cmd.Printf("  Size        : %d bytes\n", fi.Size())
	cmd.Printf("  SHA-256     : %s\n", artifactSHA256)
	cmd.Printf("  Severity    : %s\n", severity)
	cmd.Printf("  Confidence  : %d%%\n", confidence)
	cmd.Printf("  TTL         : %d seconds (%s)\n", ttl, formatDuration(ttl))
	cmd.Printf("  Expires At  : %s\n", time.Unix(now+ttl, 0).UTC().Format(time.RFC3339))
	if description != "" {
		cmd.Printf("  Description : %s\n", description)
	}
	if len(tags) > 0 {
		cmd.Printf("  Tags        : %v\n", tags)
	}
	if len(categories) > 0 {
		cmd.Printf("  Categories  : %v\n", categories)
	}
	cmd.Printf("  Attester    : %s\n", attester)
	cmd.Printf("  Chain ID    : %s\n", chainID)
	cmd.Println()

	if dryRun {
		cmd.Println("── Dry-run mode: attestation spec (not written to disk) ─────────")
		cmd.Println(string(specJSON))
		return nil
	}

	// ── Write output file ─────────────────────────────────────────────────────
	if err := os.WriteFile(outputPath, specJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file %q: %w", outputPath, err)
	}

	cmd.Printf("✓ Attestation spec written to: %s\n", outputPath)
	cmd.Println()
	cmd.Println("── Next steps ──────────────────────────────────────────────────")
	cmd.Println()
	cmd.Println("  1. Start a ThreatAttest node (see demo/run_demo.sh):")
	cmd.Println("       threatattestd start --home ~/.threatattestd")
	cmd.Println()
	cmd.Println("  2. Broadcast the attestation transaction:")
	cmd.Printf("       threatattestd tx attestation publish \\\\\n")
	cmd.Printf("         --artifact-sha256 %s \\\\\n", artifactSHA256)
	cmd.Printf("         --artifact-type FILE \\\\\n")
	cmd.Printf("         --severity %s \\\\\n", severity)
	cmd.Printf("         --confidence %d \\\\\n", confidence)
	cmd.Printf("         --ttl %d \\\\\n", ttl)
	if description != "" {
		cmd.Printf("         --description &quot;%s&quot; \\\\\n", description)
	}
	cmd.Printf("         --from <your-key> \\\\\n")
	cmd.Printf("         --chain-id %s \\\\\n", chainID)
	cmd.Printf("         --fees 500utatst\n")
	cmd.Println()
	cmd.Println("  3. Query whether the file is marked malicious:")
	cmd.Printf("       threatattestd query attestation is-malicious \\\\\n")
	cmd.Printf("         --sha256 %s\n", artifactSHA256)
	cmd.Println()

	return nil
}

// ============================================================
// attest-url — convenience command for URL / phishing attestations
// ============================================================

// attestURLCmd returns the attest-url command which normalizes a URL, computes
// its SHA-256, and produces a ready-to-broadcast JSON attestation spec.
// Supports TATST:PHISHING, TATST:PHISHING_URL, TATST:PHISHING_SITE,
// TATST:MALVERTISING, TATST:ADWARE, TATST:C2, and all other categories
// valid for URL artifacts.
func attestURLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest-url [url]",
		Short: "Normalize a URL, compute its SHA-256, and produce an attestation spec",
		Long: `attest-url accepts a raw URL, normalises it (lowercased scheme/host,
default ports stripped, query params sorted, fragment removed), computes the
canonical SHA-256, and writes a ready-to-broadcast MsgPublishAttestation JSON
document.

Supported categories for URL artifacts:
  TATST:PHISHING       — generic phishing page
  TATST:PHISHING_URL   — specific URL serving phishing content
  TATST:PHISHING_SITE  — the whole site is a phishing operation
  TATST:ADWARE         — URL delivering intrusive / deceptive advertising
  TATST:MALVERTISING   — URL used for malvertising / exploit-kit delivery
  TATST:C2             — command-and-control endpoint
  TATST:MALWARE        — malware download endpoint
  (all other unconstrained TATST categories are also accepted)

Examples:
  # Attest a phishing URL
  threatattestd attest-url "https://secure-login.evil.example/verify" \
    --severity HIGH \
    --confidence 92 \
    --ttl 604800 \
    --description "PayPal phishing page collecting credentials" \
    --category "TATST:PHISHING_URL" \
    --output phishing-url-attest.json

  # Attest a malvertising landing domain/URL
  threatattestd attest-url "https://ads.malicious-cdn.example/serve?id=1234" \
    --severity MEDIUM \
    --confidence 80 \
    --ttl 86400 \
    --category "TATST:MALVERTISING" \
    --output malvertising-attest.json`,
		Args: cobra.ExactArgs(1),
		RunE: runAttestURL,
	}

	cmd.Flags().String("severity", "MEDIUM", "Severity level: UNSPECIFIED|LOW|MEDIUM|HIGH|CRITICAL")
	cmd.Flags().Int("confidence", 85, "Confidence score 0-100")
	cmd.Flags().Int64("ttl", 604800, "Time-to-live in seconds (default 7 days)")
	cmd.Flags().String("description", "", "Human-readable description (max 1024 bytes, no HTML)")
	cmd.Flags().StringSlice("tags", nil, "Comma-separated tags (max 16)")
	cmd.Flags().StringSlice("category", []string{"TATST:PHISHING_URL"}, "Comma-separated threat categories (max 8)")
	cmd.Flags().String("attester", "", "Bech32 attester address (tatst1...)")
	cmd.Flags().String("output", "url-attestation.json", "Path to write the attestation JSON spec")
	cmd.Flags().String("chain-id", "threatattest-1", "Chain ID to embed in the spec")
	cmd.Flags().Bool("dry-run", false, "Validate and print the spec without writing to disk")
	cmd.Flags().String("holloman-signature", "",
		"128-bit holloman perceptual fingerprint (32 lowercase hex chars) for near-duplicate matching")
	cmd.Flags().Int32("hamming-mask", 0,
		"Holloman hamming-mask radius (0-128)")
	return cmd
}

func runAttestURL(cmd *cobra.Command, args []string) error {
	rawURL := args[0]

	// Normalise & hash
	normURL, normErr := normalizeURLCLI(rawURL)
	if normErr != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, normErr)
	}
	h := sha256.Sum256([]byte(normURL))
	artifactSHA256 := hex.EncodeToString(h[:])

	// Holloman flags
	hollomanSig, _ := cmd.Flags().GetString("holloman-signature")
	hammingMask, _ := cmd.Flags().GetInt32("hamming-mask")
	if hammingMask < 0 || hammingMask > 128 {
		return fmt.Errorf("invalid --hamming-mask %d: must be 0-128", hammingMask)
	}
	if hollomanSig != "" {
		valid := len(hollomanSig) == 32
		for _, c := range hollomanSig {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				valid = false
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid --holloman-signature: must be 32 lowercase hex chars")
		}
	}

	// Read flags
	severity, _ := cmd.Flags().GetString("severity")
	confidence, _ := cmd.Flags().GetInt("confidence")
	ttl, _ := cmd.Flags().GetInt64("ttl")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	categories, _ := cmd.Flags().GetStringSlice("category")
	attester, _ := cmd.Flags().GetString("attester")
	outputPath, _ := cmd.Flags().GetString("output")
	chainID, _ := cmd.Flags().GetString("chain-id")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	validSeverities := map[string]bool{
		"UNSPECIFIED": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}
	if !validSeverities[severity] {
		return fmt.Errorf("invalid --severity %q", severity)
	}
	if confidence < 0 || confidence > 100 {
		return fmt.Errorf("--confidence must be 0-100, got %d", confidence)
	}
	if ttl < 300 || ttl > 31536000 {
		return fmt.Errorf("--ttl must be 300-31536000, got %d", ttl)
	}
	if attester == "" {
		attester = "<set --attester tatst1... or use 'tx attestation publish --from key'>"
	}

	now := time.Now().Unix()
	spec := AttestationSpec{
		SchemaVersion:     "1.0",
		ArtifactType:      "URL",
		ArtifactSHA256:    artifactSHA256,
		HollomanSignature: hollomanSig,
		HammingMask:       hammingMask,
		RawValue:          normURL,
		Severity:          severity,
		Confidence:        confidence,
		TTLSeconds:        ttl,
		Description:       description,
		Tags:              tags,
		ThreatCategory:    categories,
		Attester:          attester,
		PublishedAt:       now,
		ExpiresAt:         now + ttl,
		ChainID:           chainID,
	}

	specJSON, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}

	cmd.Println()
	cmd.Println("╔══════════════════════════════════════════════════════════════╗")
	cmd.Println("║          ThreatAttest — URL Attestation                      ║")
	cmd.Println("╚══════════════════════════════════════════════════════════════╝")
	cmd.Println()
	cmd.Printf("  Raw URL     : %s\n", rawURL)
	cmd.Printf("  Normalized  : %s\n", normURL)
	cmd.Printf("  SHA-256     : %s\n", artifactSHA256)
	cmd.Printf("  Severity    : %s\n", severity)
	cmd.Printf("  Confidence  : %d%%\n", confidence)
	cmd.Printf("  TTL         : %d seconds (%s)\n", ttl, formatDuration(ttl))
	cmd.Printf("  Categories  : %v\n", categories)
	cmd.Println()

	if dryRun {
		cmd.Println("── Dry-run mode: attestation spec (not written to disk) ──────────")
		cmd.Println(string(specJSON))
		return nil
	}

	if err := os.WriteFile(outputPath, specJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file %q: %w", outputPath, err)
	}
	cmd.Printf("✓ Attestation spec written to: %s\n", outputPath)
	return nil
}

// normalizeURLCLI mirrors types.NormalizeURL for use in the CLI layer without
// importing the full types package (avoids circular deps if types is moved).
func normalizeURLCLI(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	// Minimal normalization for CLI display. Full normalization (sort query params,
	// strip default ports, etc.) is enforced by the keeper / types.NormalizeURL.
	d := strings.TrimSpace(rawURL)
	if !strings.Contains(d, "://") {
		return "", fmt.Errorf("URL must include a scheme (http:// or https://)")
	}
	return d, nil
}

// ============================================================
// attest-domain — convenience command for domain/adware/malvertising attestations
// ============================================================

// attestDomainCmd returns the attest-domain command which normalizes a bare
// domain name, computes its SHA-256, and produces a ready-to-broadcast JSON
// attestation spec.  Supports TATST:ADWARE, TATST:MALVERTISING,
// TATST:PHISHING_SITE, and any other categories valid for DOMAIN artifacts.
func attestDomainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest-domain [domain]",
		Short: "Normalize a domain name and produce an adware/phishing domain attestation spec",
		Long: `attest-domain accepts a bare domain name (e.g. "evil-ads.example.com"),
normalises it (lowercase, strip www., validate labels), computes its canonical
SHA-256, and writes a ready-to-broadcast MsgPublishAttestation JSON document
with artifact_type = DOMAIN.

DOMAIN artifacts are used when you want to attest an entire domain rather than
a specific URL.  Common use-cases:

  TATST:ADWARE         — domain distributes adware / browser-hijacking software
  TATST:MALVERTISING   — ad-serving domain used for malvertising campaigns
  TATST:PHISHING_SITE  — entire domain is a phishing operation
  TATST:C2             — domain used as C2 infrastructure

The browser extension and other consumers can query domains directly against
the chain and act on the result without needing a full URL.

Examples:
  # Attest an adware distribution domain
  threatattestd attest-domain "downloads.shady-toolbar.example" \
    --severity MEDIUM \
    --confidence 88 \
    --ttl 2592000 \
    --description "Downloads bundled adware installers" \
    --category "TATST:ADWARE" \
    --output adware-domain-attest.json

  # Attest a malvertising CDN domain
  threatattestd attest-domain "malicious-ads.cdn.example" \
    --severity HIGH \
    --confidence 90 \
    --ttl 604800 \
    --description "Serves malvertising creatives redirecting to exploit kits" \
    --category "TATST:MALVERTISING" \
    --output malvertising-domain-attest.json

  # Attest a phishing site domain
  threatattestd attest-domain "paypal-secure-login.phishing.example" \
    --severity HIGH \
    --confidence 95 \
    --ttl 2592000 \
    --description "Entire domain used for PayPal credential phishing" \
    --category "TATST:PHISHING_SITE" \
    --output phishing-site-attest.json`,
		Args: cobra.ExactArgs(1),
		RunE: runAttestDomain,
	}

	cmd.Flags().String("severity", "MEDIUM", "Severity level: UNSPECIFIED|LOW|MEDIUM|HIGH|CRITICAL")
	cmd.Flags().Int("confidence", 80, "Confidence score 0-100")
	cmd.Flags().Int64("ttl", 2592000, "Time-to-live in seconds (default 30 days)")
	cmd.Flags().String("description", "", "Human-readable description (max 1024 bytes, no HTML)")
	cmd.Flags().StringSlice("tags", nil, "Comma-separated tags (max 16)")
	cmd.Flags().StringSlice("category", []string{"TATST:ADWARE"}, "Comma-separated threat categories (max 8)")
	cmd.Flags().String("attester", "", "Bech32 attester address (tatst1...)")
	cmd.Flags().String("output", "domain-attestation.json", "Path to write the attestation JSON spec")
	cmd.Flags().String("chain-id", "threatattest-1", "Chain ID to embed in the spec")
	cmd.Flags().Bool("dry-run", false, "Validate and print the spec without writing to disk")
	return cmd
}

func runAttestDomain(cmd *cobra.Command, args []string) error {
	rawDomain := args[0]

	// Normalize domain
	normDomain, err := normalizeDomainCLI(rawDomain)
	if err != nil {
		return fmt.Errorf("invalid domain %q: %w", rawDomain, err)
	}
	h := sha256.Sum256([]byte(normDomain))
	artifactSHA256 := hex.EncodeToString(h[:])

	// Read flags
	severity, _ := cmd.Flags().GetString("severity")
	confidence, _ := cmd.Flags().GetInt("confidence")
	ttl, _ := cmd.Flags().GetInt64("ttl")
	description, _ := cmd.Flags().GetString("description")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	categories, _ := cmd.Flags().GetStringSlice("category")
	attester, _ := cmd.Flags().GetString("attester")
	outputPath, _ := cmd.Flags().GetString("output")
	chainID, _ := cmd.Flags().GetString("chain-id")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	validSeverities := map[string]bool{
		"UNSPECIFIED": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}
	if !validSeverities[severity] {
		return fmt.Errorf("invalid --severity %q", severity)
	}
	if confidence < 0 || confidence > 100 {
		return fmt.Errorf("--confidence must be 0-100, got %d", confidence)
	}
	if ttl < 300 || ttl > 31536000 {
		return fmt.Errorf("--ttl must be 300-31536000, got %d", ttl)
	}
	if attester == "" {
		attester = "<set --attester tatst1... or use 'tx attestation publish --from key'>"
	}

	now := time.Now().Unix()
	spec := AttestationSpec{
		SchemaVersion:  "1.0",
		ArtifactType:   "DOMAIN",
		ArtifactSHA256: artifactSHA256,
		RawValue:       normDomain,
		Severity:       severity,
		Confidence:     confidence,
		TTLSeconds:     ttl,
		Description:    description,
		Tags:           tags,
		ThreatCategory: categories,
		Attester:       attester,
		PublishedAt:    now,
		ExpiresAt:      now + ttl,
		ChainID:        chainID,
	}

	specJSON, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal spec: %w", err)
	}

	cmd.Println()
	cmd.Println("╔══════════════════════════════════════════════════════════════╗")
	cmd.Println("║         ThreatAttest — Domain Attestation                    ║")
	cmd.Println("╚══════════════════════════════════════════════════════════════╝")
	cmd.Println()
	cmd.Printf("  Raw Domain  : %s\n", rawDomain)
	cmd.Printf("  Normalized  : %s\n", normDomain)
	cmd.Printf("  SHA-256     : %s\n", artifactSHA256)
	cmd.Printf("  Severity    : %s\n", severity)
	cmd.Printf("  Confidence  : %d%%\n", confidence)
	cmd.Printf("  TTL         : %d seconds (%s)\n", ttl, formatDuration(ttl))
	cmd.Printf("  Categories  : %v\n", categories)
	cmd.Println()
	cmd.Println("  This creates a DOMAIN artifact attesting that the bare domain")
	cmd.Println("  is associated with the specified threat category.")
	cmd.Printf("  Consumers can query: sha256('%s') = %s\n", normDomain, artifactSHA256)
	cmd.Println()

	if dryRun {
		cmd.Println("── Dry-run mode: attestation spec (not written to disk) ──────────")
		cmd.Println(string(specJSON))
		return nil
	}

	if err := os.WriteFile(outputPath, specJSON, 0644); err != nil {
		return fmt.Errorf("failed to write output file %q: %w", outputPath, err)
	}
	cmd.Printf("✓ Domain attestation spec written to: %s\n", outputPath)
	cmd.Println()
	cmd.Println("── Next steps ─────────────────────────────────────────────────────")
	cmd.Println()
	cmd.Println("  1. Broadcast the attestation transaction:")
	cmd.Printf("       threatattestd tx attestation publish \\\n")
	cmd.Printf("         --artifact-sha256 %s \\\n", artifactSHA256)
	cmd.Printf("         --artifact-type DOMAIN \\\n")
	cmd.Printf("         --raw-value %s \\\n", normDomain)
	cmd.Printf("         --severity %s \\\n", severity)
	cmd.Printf("         --from <your-key> \\\n")
	cmd.Printf("         --chain-id %s \\\n", chainID)
	cmd.Printf("         --fees 500utatst\n")
	cmd.Println()
	cmd.Println("  2. Query whether the domain is attested:")
	cmd.Printf("       threatattestd query attestation is-malicious \\\n")
	cmd.Printf("         --sha256 %s\n", artifactSHA256)
	return nil
}

// normalizeDomainCLI performs CLI-side domain normalization (lowercase, strip www.).
func normalizeDomainCLI(domain string) (string, error) {
	// Simple normalization matching types.NormalizeDomain logic
	d := strings.ToLower(strings.TrimSpace(domain))
	// strip scheme
	if idx := strings.Index(d, "://"); idx != -1 {
		d = d[idx+3:]
	}
	// strip path
	if idx := strings.IndexAny(d, "/?#"); idx != -1 {
		d = d[:idx]
	}
	// strip port
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}
	// strip www.
	d = strings.TrimPrefix(d, "www.")
	if d == "" {
		return "", fmt.Errorf("empty domain after normalization")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must have at least two labels: %s", d)
	}
	return d, nil
}

func formatDuration(seconds int64) string {
	switch {
	case seconds < 3600:
		return fmt.Sprintf("%d minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%d hours", seconds/3600)
	default:
		return fmt.Sprintf("%d days", seconds/86400)
	}
}

// ============================================================
// query / tx command trees
// ============================================================

func queryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "query",
		Aliases:                    []string{"q"},
		Short:                      "Querying subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(
		rpc.ValidatorCommand(),
		authcmd.QueryTxsByEventsCmd(),
		authcmd.QueryTxCmd(),
		bankQueryCmds(),
		attestationQueryCmds(),
		identitycli.NewQueryCmd(),
		ipfsverifycli.NewQueryCmd(),
	)
	return cmd
}

func txCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                        "tx",
		Short:                      "Transactions subcommands",
		DisableFlagParsing:         false,
		SuggestionsMinimumDistance: 2,
		RunE:                       client.ValidateCmd,
	}
	cmd.AddCommand(
		authcmd.GetSignCommand(),
		authcmd.GetSignBatchCommand(),
		authcmd.GetMultiSignCommand(),
		authcmd.GetValidateSignaturesCommand(),
		flags.LineBreak,
		authcmd.GetBroadcastCommand(),
		authcmd.GetEncodeCommand(),
		authcmd.GetDecodeCommand(),
		bankcli.NewTxCmd(addresscodec.NewBech32Codec(tatapp.Bech32Prefix)),
		attestationTxCmds(),
		identitycli.NewTxCmd(),
		ipfsverifycli.NewTxCmd(),
	)
	return cmd
}

// ============================================================
// Attestation query commands
// ============================================================

func attestationQueryCmds() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Querying commands for x/attestation",
	}
	cmd.AddCommand(
		isMaliciousCmd(),
		isMaliciousURLCmd(),
		isMaliciousIPv4Cmd(),
		isMaliciousHollomanCmd(),
		getAttestationCmd(),
		listByArtifactCmd(),
		listByAttesterCmd(),
		getDisputeCmd(),
		isBlacklistedCmd(),
		paramsCmd(),
	)
	return cmd
}

func isMaliciousCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-malicious",
		Short: "Check if an artifact SHA-256 is marked malicious on-chain",
		Long: `Query the ThreatAttest chain to determine whether a given SHA-256 hash
is currently attested as malicious.  Returns the trust score and the best
active attestation record if one exists.

Examples:
  threatattestd query attestation is-malicious \
    --sha256 0fd5115915d3d3a05ba5efc2fbeae0fc8dcd26b04947050a986020ecea43de45

  # Hash a file locally first
  SHA=$(sha256sum /path/to/file | awk '{print $1}')
  threatattestd query attestation is-malicious --sha256 $SHA`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			sha256val, _ := cmd.Flags().GetString("sha256")
			if sha256val == "" {
				return errors.New("--sha256 is required")
			}
			if len(sha256val) != 64 {
				return fmt.Errorf("--sha256 must be 64 hex characters, got %d", len(sha256val))
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.IsMalicious(cmd.Context(), &pb.QueryIsMaliciousRequest{ArtifactSha256: sha256val})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("sha256", "", "Artifact SHA-256 hex string (64 characters, required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func getAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [attestation_id]",
		Short: "Fetch a single attestation record by its ID",
		Long: `Retrieve the full attestation record for a given attestation ID.
The attestation ID is a deterministic hash of (artifact_sha256 + attester + published_at).

Example:
  threatattestd query attestation get attest_abc123...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.GetAttestation(cmd.Context(), &pb.QueryGetAttestationRequest{AttestationId: args[0]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func listByArtifactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-by-artifact",
		Short: "List all attestations for a given artifact SHA-256",
		Long: `Return all attestation records (active, expired, revoked) that reference
a given artifact SHA-256.  Useful for seeing the full history of how a
particular file, URL, or IP has been attested over time.

Example:
  threatattestd query attestation list-by-artifact \
    --sha256 0fd5115915d3d3a05ba5efc2fbeae0fc8dcd26b04947050a986020ecea43de45`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			sha256val, _ := cmd.Flags().GetString("sha256")
			if sha256val == "" {
				return errors.New("--sha256 is required")
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.ListArtifactAttestations(cmd.Context(), &pb.QueryListArtifactAttestationsRequest{ArtifactSha256: sha256val})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("sha256", "", "Artifact SHA-256 hex string (64 characters, required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func isMaliciousURLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-malicious-url",
		Short: "Check if a raw URL is marked malicious on-chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			url, _ := cmd.Flags().GetString("url")
			if url == "" {
				return errors.New("--url is required")
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.IsMaliciousURL(cmd.Context(), &pb.QueryIsMaliciousURLRequest{Url: url})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("url", "", "Raw URL string (required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func isMaliciousIPv4Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-malicious-ipv4",
		Short: "Check if a raw IPv4 address is marked malicious on-chain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			ipv4, _ := cmd.Flags().GetString("ipv4")
			if ipv4 == "" {
				return errors.New("--ipv4 is required")
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.IsMaliciousIPv4(cmd.Context(), &pb.QueryIsMaliciousIPv4Request{Ipv4: ipv4})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("ipv4", "", "Raw IPv4 address string (required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func isMaliciousHollomanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-malicious-holloman",
		Short: "Check if a holloman perceptual signature is marked malicious",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			sig, _ := cmd.Flags().GetString("holloman-signature")
			if sig == "" {
				return errors.New("--holloman-signature is required")
			}
			mask, _ := cmd.Flags().GetInt32("hamming-mask")
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.IsMaliciousHolloman(cmd.Context(), &pb.QueryIsMaliciousHollomanRequest{HollomanSignature: sig, HammingMask: mask})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("holloman-signature", "", "128-bit holloman fingerprint (32 hex chars, required)")
	cmd.Flags().Int32("hamming-mask", 0, "Hamming tolerance radius (0-128)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func listByAttesterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-by-attester",
		Short: "List all attestations published by an attester address",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			attester, _ := cmd.Flags().GetString("attester")
			if attester == "" {
				return errors.New("--attester is required")
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.ListAttesterAttestations(cmd.Context(), &pb.QueryListAttesterAttestationsRequest{Attester: attester})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("attester", "", "Attester bech32 address (required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func getDisputeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get-dispute [dispute_id]",
		Short: "Fetch a dispute record by its ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.GetDispute(cmd.Context(), &pb.QueryGetDisputeRequest{DisputeId: args[0]})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func isBlacklistedCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "is-blacklisted",
		Short: "Check if an attester is blacklisted",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			attester, _ := cmd.Flags().GetString("attester")
			if attester == "" {
				return errors.New("--attester is required")
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.IsBlacklisted(cmd.Context(), &pb.QueryIsBlacklistedRequest{Attester: attester})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	cmd.Flags().String("attester", "", "Attester bech32 address (required)")
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

func paramsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "params",
		Short: "Fetch the x/attestation module parameters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return err
			}
			queryClient := pb.NewQueryClient(clientCtx)
			res, err := queryClient.Params(cmd.Context(), &pb.QueryParamsRequest{})
			if err != nil {
				return err
			}
			return clientCtx.PrintProto(res)
		},
	}
	flags.AddQueryFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// Attestation tx commands
// ============================================================

func attestationTxCmds() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Transaction commands for x/attestation",
	}
	cmd.AddCommand(
		publishAttestationCmd(),
		endorseAttestationCmd(),
		revokeAttestationCmd(),
		disputeAttestationCmd(),
		updateParamsCmd(),
		claimRewardCmd(),
		subscribeCmd(),
		unsubscribeCmd(),
	)
	return cmd
}

func publishAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish a new threat attestation to the chain",
		Long: `Construct and broadcast a MsgPublishAttestation transaction.

The attester must have a reputation score of at least Tier 1 (≥100 RS).
A TTL between 300 and 2592000 seconds must be specified.
The artifact_sha256 must be the lowercase hex SHA-256 of the artifact.

For FILE artifacts:   provide --artifact-sha256 (pre-computed hash).
For URL artifacts:    provide --raw-value with the full URL; the chain
                      verifies sha256(url) == artifact_sha256.
For IPv4 artifacts:   provide --raw-value with the IP address; reserved
                      ranges (RFC-1918, loopback) are rejected.
For EMAIL_BODY:       provide --holloman-signature (required) and either
                      --artifact-sha256 or --raw-value (the body text).

Examples:
  # Attest a malicious file
  threatattestd tx attestation publish \
    --artifact-type FILE \
    --artifact-sha256 0fd5115915d3d3a05ba5efc2fbeae0fc8dcd26b04947050a986020ecea43de45 \
    --severity HIGH \
    --confidence 90 \
    --ttl 86400 \
    --description "Ransomware dropper" \
    --category RANSOMWARE \
    --tags "dropper,pe32" \
    --from alice \
    --chain-id threatattest-1 \
    --fees 500utatst

  # Attest a malicious URL
  threatattestd tx attestation publish \
    --artifact-type URL \
    --raw-value "https://evil.example.com/payload.exe" \
    --severity CRITICAL \
    --confidence 95 \
    --ttl 604800 \
    --description "Malware delivery endpoint" \
    --from alice \
    --chain-id threatattest-1 \
    --fees 500utatst`,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}

			artifactType, _ := cmd.Flags().GetString("artifact-type")
			artifactSHA256, _ := cmd.Flags().GetString("artifact-sha256")
			rawValue, _ := cmd.Flags().GetString("raw-value")
			severity, _ := cmd.Flags().GetString("severity")
			confidence, _ := cmd.Flags().GetInt("confidence")
			ttl, _ := cmd.Flags().GetInt64("ttl")
			description, _ := cmd.Flags().GetString("description")
			tags, _ := cmd.Flags().GetStringSlice("tags")
			categories, _ := cmd.Flags().GetStringSlice("category")
			attesterDomain, _ := cmd.Flags().GetString("attester-domain")
			attesterSelector, _ := cmd.Flags().GetString("attester-selector")
			hollomanSig, _ := cmd.Flags().GetString("holloman-signature")
			hammingMask, _ := cmd.Flags().GetInt32("hamming-mask")

			// Validation
			if artifactSHA256 == "" && rawValue == "" {
				return errors.New("either --artifact-sha256 or --raw-value is required")
			}
			validTypes := map[string]int32{"FILE": 1, "URL": 2, "IPV4": 3, "DOMAIN": 4, "EMAIL_BODY": 5}
			artifactTypeInt, ok := validTypes[artifactType]
			if !ok {
				return fmt.Errorf("invalid --artifact-type %q: must be FILE, URL, IPV4, DOMAIN, or EMAIL_BODY", artifactType)
			}
			validSeverities := map[string]int32{"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
			severityInt, ok := validSeverities[severity]
			if !ok {
				return fmt.Errorf("invalid --severity %q: must be LOW, MEDIUM, HIGH, or CRITICAL", severity)
			}
			if confidence < 0 || confidence > 100 {
				return fmt.Errorf("--confidence must be 0-100, got %d", confidence)
			}
			if ttl < 300 || ttl > 2592000 {
				return fmt.Errorf("--ttl must be 300-2592000, got %d", ttl)
			}

			// Cross-field validation: domain and selector must be used together
			if attesterDomain != "" && attesterSelector == "" {
				return errors.New("--attester-selector is required when --attester-domain is set")
			}
			if attesterSelector != "" && attesterDomain == "" {
				return errors.New("--attester-domain is required when --attester-selector is set")
			}

			// Holloman perceptual-fingerprint validation
			if hammingMask < 0 || hammingMask > 128 {
				return fmt.Errorf("invalid --hamming-mask %d: must be 0-128", hammingMask)
			}
			if hollomanSig != "" && !attesttypes.IsValidHollomanSignature(hollomanSig) {
				return errors.New("invalid --holloman-signature: must be 32 lowercase hex chars")
			}
			if artifactType == "EMAIL_BODY" && hollomanSig == "" {
				return errors.New("--holloman-signature is required for EMAIL_BODY artifacts")
			}

			// If raw-value provided but no sha256, compute it based on artifact type
			if artifactSHA256 == "" && rawValue != "" {
				h := sha256.Sum256([]byte(rawValue))
				artifactSHA256 = hex.EncodeToString(h[:])
				cmd.Printf("Computed artifact_sha256 from --raw-value: %s\n", artifactSHA256)
			}

			// Sign the attestation payload with the attester's key. This binds the
			// attester's identity to the specific threat data and prevents a tx relay
			// from substituting a different artifact.
			attester := clientCtx.GetFromAddress().String()
			attesterSig, err := signAttesterSig(clientCtx, artifactSHA256, attester, ttl)
			if err != nil {
				return err
			}

			msg := &pb.MsgPublishAttestation{
				Attester:          attester,
				ArtifactType:      artifactTypeInt,
				ArtifactSha256:    artifactSHA256,
				HollomanSignature: hollomanSig,
				HammingMask:       hammingMask,
				RawValue:          rawValue,
				Severity:          severityInt,
				TtlSeconds:        ttl,
				Confidence:        uint32(confidence),
				Description:       description,
				Tags:              tags,
				ThreatCategories:  categories,
				AttesterSig:       attesterSig,
				AttesterDomain:    attesterDomain,
				AttesterSelector:  attesterSelector,
				PuaInfo:           buildPUAInfo(cmd),
			}

			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}

	cmd.Flags().String("artifact-type", "FILE",
		"Artifact type: FILE|URL|IPV4|DOMAIN|EMAIL_BODY")
	// PUA-specific flags (only used when --artifact-type FILE and --category includes TATST:PUA)
	cmd.Flags().String("pua-software-name", "",
		"(PUA) Display name of the software (e.g. 'SpeedBooster Pro')")
	cmd.Flags().String("pua-vendor", "",
		"(PUA) Publisher or code-signing entity (e.g. 'OptimiseSoft LLC')")
	cmd.Flags().String("pua-version", "",
		"(PUA) Software version where PUA behaviour was observed")
	cmd.Flags().String("pua-behavior-notes", "",
		"(PUA) Free-text description of observed PUA behaviours (max 512 bytes)")
	cmd.Flags().StringSlice("pua-detection-names", nil,
		"(PUA) Comma-separated list of AV detection names (e.g. 'PUA.Win32.Adware.Generic')")
	cmd.Flags().String("artifact-sha256", "",
		"Lowercase hex SHA-256 of the artifact (required for FILE type)")
	cmd.Flags().String("raw-value", "",
		"Raw value for URL/IPV4/DOMAIN artifacts (sha256 will be computed automatically); for EMAIL_BODY it is the body text")
	cmd.Flags().String("holloman-signature", "",
		"128-bit holloman perceptual fingerprint (32 lowercase hex chars; required for EMAIL_BODY)")
	cmd.Flags().Int32("hamming-mask", 0,
		"Holloman hamming-mask radius (0-128); the attestation matches fingerprints within this Hamming distance")
	cmd.Flags().String("severity", "MEDIUM",
		"Severity level: UNSPECIFIED|LOW|MEDIUM|HIGH|CRITICAL")
	cmd.Flags().Int("confidence", 80,
		"Confidence score 0-100")
	cmd.Flags().Int64("ttl", 86400,
		"Time-to-live in seconds (300-2592000)")
	cmd.Flags().String("description", "",
		"Human-readable description (max 1024 bytes, no HTML)")
	cmd.Flags().StringSlice("tags", nil,
		"Comma-separated tags (max 16, each max 32 bytes)")
	cmd.Flags().StringSlice("category", nil,
		"Comma-separated threat categories (max 8)")
	cmd.Flags().String("attester-domain", "",
		"(Optional) Normalized domain name of attester's DNS identity (e.g. example.com)")
	cmd.Flags().String("attester-selector", "",
		"(Optional) DNS selector for the attester's active TAT key record (e.g. tat2025a)")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// buildPUAInfo assembles PUA metadata from the (optional) PUA flags. Returns
// nil when no PUA flags are supplied.
func buildPUAInfo(cmd *cobra.Command) *pb.PUAMetadata {
	softwareName, _ := cmd.Flags().GetString("pua-software-name")
	vendor, _ := cmd.Flags().GetString("pua-vendor")
	version, _ := cmd.Flags().GetString("pua-version")
	notes, _ := cmd.Flags().GetString("pua-behavior-notes")
	names, _ := cmd.Flags().GetStringSlice("pua-detection-names")

	if softwareName == "" && vendor == "" && version == "" && notes == "" && len(names) == 0 {
		return nil
	}
	return &pb.PUAMetadata{
		SoftwareName:   softwareName,
		Vendor:         vendor,
		Version:        version,
		BehaviorNotes:  notes,
		DetectionNames: names,
	}
}

// signAttesterSig signs the canonical attestation payload with the attester's
// key, producing the 128-hex-char secp256k1 signature stored in the
// MsgPublishAttestation.attester_sig field.
func signAttesterSig(clientCtx client.Context, artifactSHA256, attester string, ttl int64) (string, error) {
	from := clientCtx.FromName
	if from == "" {
		return "", errors.New("--from is required")
	}
	payload := attesttypes.BuildAttesterSigPayload(artifactSHA256, attester, ttl)
	sig, _, err := clientCtx.Keyring.Sign(from, payload, signing.SignMode_SIGN_MODE_DIRECT)
	if err != nil {
		return "", fmt.Errorf("failed to sign attestation payload: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

func endorseAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endorse [attestation_id]",
		Short: "Endorse an existing attestation to increase its trust score",
		Long: `Submit a MsgEndorseAttestation to increase the endorsement count and
therefore the trust score of an existing ACTIVE attestation.

The endorser must:
  - Have a reputation score of at least Tier 1 (≥100 RS)
  - Not be the original attester
  - Not have already endorsed this attestation

Example:
  threatattestd tx attestation endorse attest_abc123 \
    --from bob \
    --chain-id threatattest-1 \
    --fees 250utatst`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			msg := &pb.MsgEndorseAttestation{
				Endorser:      clientCtx.GetFromAddress().String(),
				AttestationId: args[0],
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func revokeAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke [attestation_id]",
		Short: "Revoke an attestation you originally published",
		Long: `Submit a MsgRevokeAttestation.  Only the original attester may revoke.
A revoked attestation is removed from all malicious-lookup indexes immediately.

Example:
  threatattestd tx attestation revoke attest_abc123 \
    --reason "False positive confirmed by vendor" \
    --from alice \
    --chain-id threatattest-1 \
    --fees 250utatst`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			reason, _ := cmd.Flags().GetString("reason")
			msg := &pb.MsgRevokeAttestation{
				Attester:      clientCtx.GetFromAddress().String(),
				AttestationId: args[0],
				Reason:        reason,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	cmd.Flags().String("reason", "", "Human-readable revocation reason")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func disputeAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dispute [attestation_id]",
		Short: "File a dispute against an attestation",
		Long: `Submit a MsgDisputeAttestation.  Disputes are used to challenge
attestations believed to be incorrect.  The disputer must provide a ground
code and evidence.  Supported grounds:

  FALSE_POSITIVE        — file/URL/IP is not actually malicious
  INCORRECT_SEVERITY    — severity rating is wrong
  FABRICATED_EVIDENCE   — attester fabricated evidence
  STALE_REUSE           — hash recycled from an old unrelated sample
  SYBIL_ATTACK          — attester is conducting a sybil attack

Example:
  threatattestd tx attestation dispute attest_abc123 \
    --ground FALSE_POSITIVE \
    --evidence "Confirmed benign by VirusTotal (0/72 detections)" \
    --from charlie \
    --chain-id threatattest-1 \
    --fees 1000utatst`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			ground, _ := cmd.Flags().GetString("ground")
			evidence, _ := cmd.Flags().GetString("evidence")
			validGrounds := map[string]int32{
				"FALSE_POSITIVE": 1, "INCORRECT_SEVERITY": 2,
				"FABRICATED_EVIDENCE": 3, "STALE_REUSE": 4, "SYBIL_ATTACK": 5,
			}
			groundInt, ok := validGrounds[ground]
			if !ok {
				return fmt.Errorf("invalid --ground %q", ground)
			}
			msg := &pb.MsgDisputeAttestation{
				Disputer:      clientCtx.GetFromAddress().String(),
				AttestationId: args[0],
				Ground:        groundInt,
				Evidence:      evidence,
			}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	cmd.Flags().String("ground", "FALSE_POSITIVE",
		"Dispute ground: FALSE_POSITIVE|INCORRECT_SEVERITY|FABRICATED_EVIDENCE|STALE_REUSE|SYBIL_ATTACK")
	cmd.Flags().String("evidence", "",
		"Evidence supporting the dispute (max 1024 bytes)")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func updateParamsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-params",
		Short: "Update x/attestation module parameters (governance-gated)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			authority, _ := cmd.Flags().GetString("authority")
			if authority == "" {
				return errors.New("--authority is required")
			}
			paramsJSON, _ := cmd.Flags().GetString("params-json")
			if paramsJSON == "" {
				return errors.New("--params-json is required")
			}
			var params pb.Params
			if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
				return fmt.Errorf("invalid --params-json: %w", err)
			}
			msg := &pb.MsgUpdateParams{Authority: authority, Params: &params}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	cmd.Flags().String("authority", "", "Governance authority address (required)")
	cmd.Flags().String("params-json", "", "Full Params object as JSON (required)")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func claimRewardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claim-reward",
		Short: "Claim the attester's share of the attestation incentive pool",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			msg := &pb.MsgClaimReward{Attester: clientCtx.GetFromAddress().String()}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func subscribeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subscribe",
		Short: "Lock tokens to activate a paid API tier",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			tier, _ := cmd.Flags().GetInt32("tier")
			if tier < 1 || tier > 2 {
				return fmt.Errorf("invalid --tier %d: must be 1 (PROFESSIONAL) or 2 (ENTERPRISE)", tier)
			}
			msg := &pb.MsgSubscribe{Subscriber: clientCtx.GetFromAddress().String(), Tier: tier}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	cmd.Flags().Int32("tier", 1, "Subscription tier: 1=PROFESSIONAL, 2=ENTERPRISE")
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

func unsubscribeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unsubscribe",
		Short: "Unlock tokens and return to the FREE tier",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			clientCtx, err := client.GetClientTxContext(cmd)
			if err != nil {
				return err
			}
			msg := &pb.MsgUnsubscribe{Subscriber: clientCtx.GetFromAddress().String()}
			return tx.GenerateOrBroadcastTxCLI(clientCtx, cmd.Flags(), msg)
		},
	}
	flags.AddTxFlagsToCmd(cmd)
	return cmd
}

// ============================================================
// App factory functions
// ============================================================

func newApp(
	logger log.Logger,
	db dbm.DB,
	appOpts servertypes.AppOptions,
) servertypes.Application {
	baseappOptions := server.DefaultBaseappOptions(appOpts)
	return tatapp.NewThreatAttestApp(logger, db, nil, true, appOpts, baseappOptions...)
}

func appExport(
	logger log.Logger,
	db dbm.DB,
	height int64,
	forZeroHeight bool,
	jailAllowedAddrs []string,
	appOpts servertypes.AppOptions,
	modulesToExport []string,
) (servertypes.ExportedApp, error) {
	app := tatapp.NewThreatAttestApp(logger, db, nil, height == -1, appOpts)
	if height != -1 {
		if err := app.LoadVersion(height); err != nil {
			return servertypes.ExportedApp{}, err
		}
	}
	return app.ExportAppStateAndValidators(forZeroHeight, jailAllowedAddrs, modulesToExport)
}

// addGenesisAccountCmd returns the genesis account command using the
// standard Cosmos SDK genutil.AddGenesisAccount implementation. It accepts
// a bech32 address prefix so that address decoding works correctly for
// the chain's native prefix (tatst).
func addGenesisAccountCmd(defaultNodeHome, bech32Prefix string) *cobra.Command {
	return genutilcli.AddGenesisAccountCmd(
		defaultNodeHome,
		addresscodec.NewBech32Codec(bech32Prefix),
	)
}

// ============================================================
// Helpers
// ============================================================

func newBasicManager() module.BasicManager {
	return tatapp.ModuleBasics
}

func initAppConfig() (string, interface{}) {
	type CustomAppConfig struct {
		serverconfig.Config
		IPFSGatewayURL string `mapstructure:"ipfs-gateway-url"`
	}
	srvCfg := serverconfig.DefaultConfig()
	srvCfg.MinGasPrices = "0.025utatst"
	customCfg := CustomAppConfig{
		Config:         *srvCfg,
		IPFSGatewayURL: "https://ipfs.io/ipfs/",
	}
	template := serverconfig.DefaultConfigTemplate + `
###############################################################################
###                         ThreatAttest Config                             ###
###############################################################################

# IPFS gateway URL for rule content fetching
ipfs-gateway-url = "{{ .IPFSGatewayURL }}"
`
	return template, customCfg
}

func initCometBFTConfig() *cmtcfg.Config {
	cfg := cmtcfg.DefaultConfig()
	cfg.Consensus.TimeoutCommit = 2000000000 // 2 seconds
	return cfg
}

func addGenesisAttestation(_ string) *cobra.Command {
	return &cobra.Command{
		Use:   "add-genesis-attestation",
		Short: "Add a pre-seeded attestation to genesis.json",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("Not yet implemented — edit genesis.json directly for genesis attestations.")
			return nil
		},
	}
}

func init() {
	_, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
}

// ============================================================
// Snapshot store helpers
// ============================================================

func newSnapshotStore(appOpts servertypes.AppOptions) (*snapshots.Store, error) {
	homeDir := cast(appOpts.Get("home"))
	snapshotDir := homeDir + "/data/snapshots"
	snapshotDB, err := dbm.NewDB("metadata", dbm.GoLevelDBBackend, snapshotDir)
	if err != nil {
		return nil, err
	}
	return snapshots.NewStore(snapshotDB, snapshotDir)
}

func cast(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return DefaultNodeHome
}

func newAppWithOptions(
	logger log.Logger,
	db dbm.DB,
	traceStore io.Writer,
	appOpts servertypes.AppOptions,
) *tatapp.ThreatAttestApp {
	snapshotStore, err := newSnapshotStore(appOpts)
	if err != nil {
		panic(err)
	}
	snapshotOptions := snapshottypes.NewSnapshotOptions(
		uint64(cast64(appOpts.Get(server.FlagStateSyncSnapshotInterval))),
		uint32(cast64(appOpts.Get(server.FlagStateSyncSnapshotKeepRecent))),
	)
	baseappOptions := []func(*baseapp.BaseApp){
		baseapp.SetSnapshot(snapshotStore, snapshotOptions),
		baseapp.SetChainID(castString(appOpts.Get(flags.FlagChainID))),
	}
	return tatapp.NewThreatAttestApp(logger, db, traceStore, true, appOpts, baseappOptions...)
}

func cast64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case uint64:
		return int64(t)
	case int:
		return int64(t)
	}
	return 0
}

func castString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Ensure storetypes is used.
var _ storetypes.StoreType = storetypes.StoreTypeIAVL
