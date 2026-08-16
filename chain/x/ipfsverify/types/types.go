// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	ModuleName = "ipfsverify"
	StoreKey   = ModuleName
	RouterKey  = ModuleName

	// KVStore key prefixes
	JobKeyPrefix    = 0x00
	ReportKeyPrefix = 0x01
	ParamsKeyByte   = 0x02
	PendingQueuePrefix = 0x03

	// Job result TTL: how long to retain completed reports (seconds)
	ReportRetentionSeconds = int64(7 * 24 * 3600) // 7 days

	// Maximum CID length for safety
	MaxCIDLength = 128

	// Maximum number of pending jobs at once
	MaxPendingJobs = 1000
)

// ============================================================
// Enum: VerificationJobStatus
// ============================================================

type VerificationJobStatus int32

const (
	JobStatus_PENDING   VerificationJobStatus = 0
	JobStatus_RUNNING   VerificationJobStatus = 1
	JobStatus_COMPLETED VerificationJobStatus = 2
	JobStatus_FAILED    VerificationJobStatus = 3
	JobStatus_TIMEOUT   VerificationJobStatus = 4
)

func (s VerificationJobStatus) String() string {
	switch s {
	case JobStatus_RUNNING:
		return "RUNNING"
	case JobStatus_COMPLETED:
		return "COMPLETED"
	case JobStatus_FAILED:
		return "FAILED"
	case JobStatus_TIMEOUT:
		return "TIMEOUT"
	default:
		return "PENDING"
	}
}

// ============================================================
// Struct: VerificationJob
// ============================================================

// VerificationJob is queued when a new DetectionRuleRef is published.
// The off-chain IPFS verifier daemon picks these up, fetches the CID,
// verifies the SHA-256 matches, and submits a VerificationReport.
type VerificationJob struct {
	// JobID is SHA-256(cid || "|" || expected_sha256 || "|" || attestation_id).
	JobID         string                `json:"job_id"`
	AttestationID string                `json:"attestation_id"`
	RuleID        string                `json:"rule_id"`
	CID           string                `json:"cid"`
	ExpectedSHA256 string               `json:"expected_sha256"`
	SubmittedAt   int64                 `json:"submitted_at"`
	SubmittedBy   string                `json:"submitted_by"`
	Status        VerificationJobStatus `json:"status"`
	// Attempts counts how many times the verifier has tried this job.
	Attempts      uint32                `json:"attempts"`
	// DeadlineHeight is the block height after which the job is marked TIMEOUT.
	DeadlineHeight int64                `json:"deadline_height"`
}

// ============================================================
// Struct: VerificationReport
// ============================================================

// VerificationReport is the result of an IPFS verification job.
type VerificationReport struct {
	JobID          string `json:"job_id"`
	AttestationID  string `json:"attestation_id"`
	RuleID         string `json:"rule_id"`
	CID            string `json:"cid"`
	ExpectedSHA256 string `json:"expected_sha256"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
	Matched        bool   `json:"matched"`
	VerifiedAt     int64  `json:"verified_at"`
	VerifiedBy     string `json:"verified_by"`
	ErrorMsg       string `json:"error_msg,omitempty"`
}

// ============================================================
// Struct: Params
// ============================================================

// Params holds x/ipfsverify module parameters.
type Params struct {
	// VerificationTimeoutBlocks is the number of blocks after which a pending
	// verification job is considered timed out.
	VerificationTimeoutBlocks int64  `json:"verification_timeout_blocks"`
	// MaxRetries is the maximum number of retry attempts per job.
	MaxRetries                uint32 `json:"max_retries"`
	// IPFSGatewayURL is the HTTP gateway for fetching CID content.
	// In a production deployment this is configured per-validator.
	IPFSGatewayURL            string `json:"ipfs_gateway_url"`
	// RelayerWhitelist is the set of addresses allowed to submit verification
	// reports. An empty whitelist allows all relayers.
	RelayerWhitelist          []string `json:"relayer_whitelist"`
}

// DefaultParams returns sensible defaults.
func DefaultParams() Params {
	return Params{
		VerificationTimeoutBlocks: 300,   // ~10 minutes at 2 s blocks
		MaxRetries:                3,
		IPFSGatewayURL:            "https://ipfs.io/ipfs/",
		RelayerWhitelist:          []string{},
	}
}

// IsRelayerAllowed reports whether the given relayer address may submit
// verification reports. An empty whitelist allows all relayers.
func (p Params) IsRelayerAllowed(addr string) bool {
	if len(p.RelayerWhitelist) == 0 {
		return true
	}
	for _, w := range p.RelayerWhitelist {
		if w == addr {
			return true
		}
	}
	return false
}

// Validate checks that all parameters are within acceptable bounds.
func (p Params) Validate() error {
	if p.VerificationTimeoutBlocks <= 0 {
		return fmt.Errorf("verification_timeout_blocks must be > 0")
	}
	if p.MaxRetries == 0 {
		return fmt.Errorf("max_retries must be > 0")
	}
	for i, addr := range p.RelayerWhitelist {
		if _, err := sdk.AccAddressFromBech32(addr); err != nil {
			return fmt.Errorf("relayer_whitelist[%d] is not a valid bech32 address: %w", i, err)
		}
	}
	return nil
}

// ============================================================
// Struct: GenesisState
// ============================================================

// GenesisState defines the genesis state for x/ipfsverify.
type GenesisState struct {
	Params  Params               `json:"params"`
	Jobs    []VerificationJob    `json:"jobs"`
	Reports []VerificationReport `json:"reports"`
}

// DefaultGenesisState returns an empty genesis with default params.
func DefaultGenesisState() GenesisState {
	return GenesisState{
		Params:  DefaultParams(),
		Jobs:    []VerificationJob{},
		Reports: []VerificationReport{},
	}
}

// ValidateGenesis performs stateless validation of the genesis state.
func ValidateGenesis(gs GenesisState) error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid ipfsverify params: %w", err)
	}
	seenJobs := make(map[string]bool, len(gs.Jobs))
	for _, j := range gs.Jobs {
		if j.JobID == "" {
			return fmt.Errorf("verification job has empty job_id")
		}
		if seenJobs[j.JobID] {
			return fmt.Errorf("duplicate verification job_id: %s", j.JobID)
		}
		seenJobs[j.JobID] = true
	}
	return nil
}