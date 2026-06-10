// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/log"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	attestkeeper "github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/ipfsverify/types"
)

// Keeper provides state access for the ipfsverify module.
type Keeper struct {
	cdc          codec.BinaryCodec
	storeService store.KVStoreService
	logger       log.Logger
	attestKeeper *attestkeeper.Keeper
	authority    string
}

// NewKeeper constructs a new ipfsverify Keeper.
func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	attestKeeper *attestkeeper.Keeper,
	authority string,
) Keeper {
	return Keeper{
		cdc:          cdc,
		storeService: storeService,
		logger:       logger.With("module", types.ModuleName),
		attestKeeper: attestKeeper,
		authority:    authority,
	}
}

// Logger returns the module logger.
func (k Keeper) Logger() log.Logger { return k.logger }

// ============================================================
// Params
// ============================================================

func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	bz, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal ipfsverify params: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set([]byte{types.ParamsKeyByte}, bz)
}

func (k Keeper) GetParams(ctx sdk.Context) (types.Params, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get([]byte{types.ParamsKeyByte})
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var p types.Params
	if err := json.Unmarshal(bz, &p); err != nil {
		return types.Params{}, fmt.Errorf("unmarshal ipfsverify params: %w", err)
	}
	return p, nil
}

// ============================================================
// Job CRUD
// ============================================================

func jobKey(jobID string) []byte {
	return append([]byte{types.JobKeyPrefix}, []byte(jobID)...)
}

// SetJob persists a VerificationJob.
func (k Keeper) SetJob(ctx sdk.Context, job types.VerificationJob) error {
	bz, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal verification job: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set(jobKey(job.JobID), bz)
}

// GetJob retrieves a VerificationJob by ID.
func (k Keeper) GetJob(ctx sdk.Context, jobID string) (types.VerificationJob, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(jobKey(jobID))
	if err != nil {
		return types.VerificationJob{}, err
	}
	if bz == nil {
		return types.VerificationJob{}, fmt.Errorf("verification job not found: %s", jobID)
	}
	var job types.VerificationJob
	if err := json.Unmarshal(bz, &job); err != nil {
		return types.VerificationJob{}, fmt.Errorf("unmarshal verification job: %w", err)
	}
	return job, nil
}

// IterateJobs iterates all verification jobs.
func (k Keeper) IterateJobs(ctx sdk.Context, cb func(types.VerificationJob) bool) error {
	prefix := []byte{types.JobKeyPrefix}
	iter, err := k.storeService.OpenKVStore(ctx).Iterator(prefix, prefixEnd(prefix))
	if err != nil {
		return err
	}
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var job types.VerificationJob
		if err := json.Unmarshal(iter.Value(), &job); err != nil {
			return fmt.Errorf("unmarshal verification job: %w", err)
		}
		if cb(job) {
			break
		}
	}
	return iter.Error()
}

// ============================================================
// Report CRUD
// ============================================================

func reportKey(jobID string) []byte {
	return append([]byte{types.ReportKeyPrefix}, []byte(jobID)...)
}

// SetReport persists a VerificationReport.
func (k Keeper) SetReport(ctx sdk.Context, report types.VerificationReport) error {
	bz, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal verification report: %w", err)
	}
	return k.storeService.OpenKVStore(ctx).Set(reportKey(report.JobID), bz)
}

// GetReport retrieves a VerificationReport by job ID.
func (k Keeper) GetReport(ctx sdk.Context, jobID string) (types.VerificationReport, error) {
	bz, err := k.storeService.OpenKVStore(ctx).Get(reportKey(jobID))
	if err != nil {
		return types.VerificationReport{}, err
	}
	if bz == nil {
		return types.VerificationReport{}, fmt.Errorf("verification report not found: %s", jobID)
	}
	var report types.VerificationReport
	if err := json.Unmarshal(bz, &report); err != nil {
		return types.VerificationReport{}, fmt.Errorf("unmarshal verification report: %w", err)
	}
	return report, nil
}

// ============================================================
// Pending queue
// ============================================================

// pendingQueueKey = 0x03 | submitted_at_big_endian_8bytes | job_id
func pendingQueueKey(submittedAt int64, jobID string) []byte {
	key := []byte{types.PendingQueuePrefix}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(submittedAt))
	key = append(key, b...)
	key = append(key, []byte(jobID)...)
	return key
}

// EnqueueJob adds a job to the pending queue and persists its record.
func (k Keeper) EnqueueJob(ctx sdk.Context, job types.VerificationJob) error {
	if err := k.SetJob(ctx, job); err != nil {
		return err
	}
	return k.storeService.OpenKVStore(ctx).Set(
		pendingQueueKey(job.SubmittedAt, job.JobID),
		[]byte(job.JobID),
	)
}

// DequeuePendingJobs returns up to maxCount pending jobs (oldest first).
func (k Keeper) DequeuePendingJobs(ctx sdk.Context, maxCount int) ([]types.VerificationJob, error) {
	prefix := []byte{types.PendingQueuePrefix}
	iter, err := k.storeService.OpenKVStore(ctx).Iterator(prefix, prefixEnd(prefix))
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var jobs []types.VerificationJob
	for ; iter.Valid() && len(jobs) < maxCount; iter.Next() {
		jobID := string(iter.Value())
		job, err := k.GetJob(ctx, jobID)
		if err != nil {
			continue
		}
		if job.Status == types.JobStatus_PENDING {
			jobs = append(jobs, job)
		}
	}
	return jobs, iter.Error()
}

// RemoveFromQueue removes a job from the pending queue.
func (k Keeper) RemoveFromQueue(ctx sdk.Context, submittedAt int64, jobID string) error {
	return k.storeService.OpenKVStore(ctx).Delete(pendingQueueKey(submittedAt, jobID))
}

// ============================================================
// Business logic
// ============================================================

// SubmitVerificationJob creates and enqueues a new IPFS verification job.
func (k Keeper) SubmitVerificationJob(
	ctx sdk.Context,
	attestationID, ruleID, cid, expectedSHA256, submittedBy string,
) (types.VerificationJob, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return types.VerificationJob{}, err
	}

	jobID := computeJobID(cid, expectedSHA256, attestationID)
	now := ctx.BlockTime().Unix()
	deadline := ctx.BlockHeight() + params.VerificationTimeoutBlocks

	job := types.VerificationJob{
		JobID:          jobID,
		AttestationID:  attestationID,
		RuleID:         ruleID,
		CID:            cid,
		ExpectedSHA256: expectedSHA256,
		SubmittedAt:    now,
		SubmittedBy:    submittedBy,
		Status:         types.JobStatus_PENDING,
		Attempts:       0,
		DeadlineHeight: deadline,
	}

	if err := k.EnqueueJob(ctx, job); err != nil {
		return types.VerificationJob{}, err
	}

	k.logger.Info("IPFS verification job queued",
		"job_id", jobID,
		"cid", cid,
		"attestation_id", attestationID,
	)
	return job, nil
}

// SubmitVerificationReport processes a report from the off-chain verifier.
// If the SHA-256 matches, the DetectionRuleRef in the attestation is marked verified.
// If it does not match, the rule is flagged invalid.
func (k Keeper) SubmitVerificationReport(ctx sdk.Context, report types.VerificationReport) error {
	// Fetch the job to confirm it exists
	job, err := k.GetJob(ctx, report.JobID)
	if err != nil {
		return fmt.Errorf("job not found for report %s: %w", report.JobID, err)
	}
	if job.Status == types.JobStatus_COMPLETED || job.Status == types.JobStatus_FAILED {
		return fmt.Errorf("job %s already finalised", report.JobID)
	}

	// Store the report
	if err := k.SetReport(ctx, report); err != nil {
		return err
	}

	// Update job status
	if report.Matched {
		job.Status = types.JobStatus_COMPLETED
	} else {
		job.Status = types.JobStatus_FAILED
	}
	if err := k.SetJob(ctx, job); err != nil {
		return err
	}

	// Remove from pending queue
	_ = k.RemoveFromQueue(ctx, job.SubmittedAt, job.JobID)

	// Update the attestation record's rule verified flag
	if k.attestKeeper != nil {
		rec, err := k.attestKeeper.GetAttestation(ctx, job.AttestationID)
		if err == nil {
			for i, rule := range rec.DetectionRules {
				if rule.RuleID == job.RuleID {
					rec.DetectionRules[i].Verified = report.Matched
					break
				}
			}
			_ = k.attestKeeper.SetAttestation(ctx, rec)
		}
	}

	k.logger.Info("IPFS verification report processed",
		"job_id", report.JobID,
		"cid", job.CID,
		"matched", report.Matched,
	)
	return nil
}

// TimeoutStaleJobs scans all running/pending jobs that have exceeded their
// deadline height and marks them TIMEOUT.
// Called from EndBlocker.
func (k Keeper) TimeoutStaleJobs(ctx sdk.Context) error {
	currentHeight := ctx.BlockHeight()
	return k.IterateJobs(ctx, func(job types.VerificationJob) bool {
		if job.Status != types.JobStatus_PENDING && job.Status != types.JobStatus_RUNNING {
			return false
		}
		if currentHeight <= job.DeadlineHeight {
			return false
		}
		job.Status = types.JobStatus_TIMEOUT
		if err := k.SetJob(ctx, job); err != nil {
			k.logger.Error("failed to timeout job", "job_id", job.JobID, "error", err)
			return false
		}
		_ = k.RemoveFromQueue(ctx, job.SubmittedAt, job.JobID)
		k.logger.Info("IPFS verification job timed out",
			"job_id", job.JobID,
			"deadline_height", job.DeadlineHeight,
		)
		return false
	})
}

// ============================================================
// Helpers
// ============================================================

// computeJobID derives a deterministic job ID from the CID, expected SHA-256,
// and attestation ID.
func computeJobID(cid, expectedSHA256, attestationID string) string {
	data := fmt.Sprintf("%s|%s|%s", cid, expectedSHA256, attestationID)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func prefixEnd(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}
	end := make([]byte, len(prefix))
	copy(end, prefix)
	for i := len(end) - 1; i >= 0; i-- {
		end[i]++
		if end[i] != 0 {
			return end[:i+1]
		}
	}
	return nil
}