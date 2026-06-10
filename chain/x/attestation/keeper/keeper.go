// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"cosmossdk.io/core/store"
	"cosmossdk.io/errors"
	"cosmossdk.io/log"
	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/attestation/types"
)

// ReputationKeeper is the subset of x/reputation keeper needed by x/attestation.
type ReputationKeeper interface {
	GetReputationScore(ctx sdk.Context, attester string) (uint32, error)
	AddReputation(ctx sdk.Context, attester string, delta int32) error
	SubReputation(ctx sdk.Context, attester string, delta uint32) error
	IsBlacklisted(ctx sdk.Context, attester string) bool
	SetMinimumTier(ctx sdk.Context, attester string, tier uint32) error
}

// StakingKeeper is the subset of x/staking keeper needed by x/attestation.
type StakingKeeper interface {
	GetDelegatorDelegations(ctx sdk.Context, delegator sdk.AccAddress, maxRetrieve uint16) ([]interface{}, error)
	TotalBondedTokens(ctx sdk.Context) (math.Int, error)
}

// BankKeeper is the subset of x/bank keeper needed by x/attestation.
type BankKeeper interface {
	SpendableCoins(ctx context.Context, addr sdk.AccAddress) sdk.Coins
	SendCoinsFromAccountToModule(ctx context.Context, sender sdk.AccAddress, module string, coins sdk.Coins) error
	BurnCoins(ctx context.Context, module string, coins sdk.Coins) error
}

// Keeper provides state access for the attestation module.
type Keeper struct {
	cdc            codec.BinaryCodec
	storeService   store.KVStoreService
	logger         log.Logger
	repKeeper      ReputationKeeper
	stakingKeeper  StakingKeeper
	bankKeeper     BankKeeper
	authority      string // gov module account address
}

// NewKeeper constructs a new attestation Keeper.
func NewKeeper(
	cdc codec.BinaryCodec,
	storeService store.KVStoreService,
	logger log.Logger,
	repKeeper ReputationKeeper,
	stakingKeeper StakingKeeper,
	bankKeeper BankKeeper,
	authority string,
) Keeper {
	return Keeper{
		cdc:           cdc,
		storeService:  storeService,
		logger:        logger.With("module", types.ModuleName),
		repKeeper:     repKeeper,
		stakingKeeper: stakingKeeper,
		bankKeeper:    bankKeeper,
		authority:     authority,
	}
}

// Logger returns the module logger.
func (k Keeper) Logger() log.Logger { return k.logger }

// Authority returns the governance authority address string.
func (k Keeper) Authority() string { return k.authority }

// ============================================================
// Params
// ============================================================

// SetParams stores the module parameters.
func (k Keeper) SetParams(ctx sdk.Context, params types.Params) error {
	bz, err := json.Marshal(params)
	if err != nil {
		return errors.Wrap(types.ErrInvalidParams, err.Error())
	}
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set([]byte{types.ParamsKey}, bz)
}

// GetParams retrieves the module parameters.
func (k Keeper) GetParams(ctx sdk.Context) (types.Params, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get([]byte{types.ParamsKey})
	if err != nil {
		return types.Params{}, err
	}
	if bz == nil {
		return types.DefaultParams(), nil
	}
	var p types.Params
	if err := json.Unmarshal(bz, &p); err != nil {
		return types.Params{}, errors.Wrap(types.ErrInvalidParams, err.Error())
	}
	return p, nil
}

// ============================================================
// Attestation CRUD
// ============================================================

// SetAttestation persists an AttestationRecord.
func (k Keeper) SetAttestation(ctx sdk.Context, rec types.AttestationRecord) error {
	bz, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal attestation: %w", err)
	}
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.AttestationKey(rec.ID), bz)
}

// GetAttestation retrieves an AttestationRecord by ID.
// Returns (zero, ErrAttestationNotFound) if absent.
func (k Keeper) GetAttestation(ctx sdk.Context, id string) (types.AttestationRecord, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.AttestationKey(id))
	if err != nil {
		return types.AttestationRecord{}, err
	}
	if bz == nil {
		return types.AttestationRecord{}, errors.Wrapf(types.ErrAttestationNotFound, "id=%s", id)
	}
	var rec types.AttestationRecord
	if err := json.Unmarshal(bz, &rec); err != nil {
		return types.AttestationRecord{}, fmt.Errorf("unmarshal attestation %s: %w", id, err)
	}
	return rec, nil
}

// DeleteAttestation removes an AttestationRecord by ID.
func (k Keeper) DeleteAttestation(ctx sdk.Context, id string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Delete(types.AttestationKey(id))
}

// HasAttestation returns true if an attestation with the given ID exists.
func (k Keeper) HasAttestation(ctx sdk.Context, id string) (bool, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Has(types.AttestationKey(id))
}

// IterateAttestations iterates all stored attestations in lexicographic key order.
// The callback receives each record; returning true stops iteration.
func (k Keeper) IterateAttestations(ctx sdk.Context, cb func(types.AttestationRecord) bool) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	prefix := []byte{types.AttestationKeyPrefix}
	iter, err := kvStore.Iterator(prefix, prefixEndBytes(prefix))
	if err != nil {
		return err
	}
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var rec types.AttestationRecord
		if err := json.Unmarshal(iter.Value(), &rec); err != nil {
			return fmt.Errorf("unmarshal attestation: %w", err)
		}
		if cb(rec) {
			break
		}
	}
	return iter.Error()
}

// ============================================================
// Artifact Index  (sha256 → []attestation_id)
// ============================================================

// SetArtifactIndex stores the list of attestation IDs for a given artifact SHA-256.
func (k Keeper) SetArtifactIndex(ctx sdk.Context, artifactSHA256 string, ids []string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("marshal artifact index: %w", err)
	}
	return kvStore.Set(types.ArtifactIndexKey(artifactSHA256), bz)
}

// GetArtifactIndex returns all attestation IDs associated with an artifact SHA-256.
func (k Keeper) GetArtifactIndex(ctx sdk.Context, artifactSHA256 string) ([]string, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.ArtifactIndexKey(artifactSHA256))
	if err != nil {
		return nil, err
	}
	if bz == nil {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(bz, &ids); err != nil {
		return nil, fmt.Errorf("unmarshal artifact index: %w", err)
	}
	return ids, nil
}

// AddArtifactIndexEntry appends an attestation ID to the artifact index.
func (k Keeper) AddArtifactIndexEntry(ctx sdk.Context, artifactSHA256, attestationID string) error {
	ids, err := k.GetArtifactIndex(ctx, artifactSHA256)
	if err != nil {
		return err
	}
	ids = append(ids, attestationID)
	return k.SetArtifactIndex(ctx, artifactSHA256, ids)
}

// RemoveArtifactIndexEntry removes a specific attestation ID from the artifact index.
func (k Keeper) RemoveArtifactIndexEntry(ctx sdk.Context, artifactSHA256, attestationID string) error {
	ids, err := k.GetArtifactIndex(ctx, artifactSHA256)
	if err != nil {
		return err
	}
	filtered := ids[:0]
	for _, id := range ids {
		if id != attestationID {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		kvStore := k.storeService.OpenKVStore(ctx)
		return kvStore.Delete(types.ArtifactIndexKey(artifactSHA256))
	}
	return k.SetArtifactIndex(ctx, artifactSHA256, filtered)
}

// ============================================================
// Attester Index  (attester_address → []attestation_id)
// ============================================================

// SetAttesterIndex stores the list of attestation IDs published by an attester.
func (k Keeper) SetAttesterIndex(ctx sdk.Context, attester string, ids []string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := json.Marshal(ids)
	if err != nil {
		return fmt.Errorf("marshal attester index: %w", err)
	}
	return kvStore.Set(types.AttesterIndexKey(attester), bz)
}

// GetAttesterIndex returns all attestation IDs published by an attester.
func (k Keeper) GetAttesterIndex(ctx sdk.Context, attester string) ([]string, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.AttesterIndexKey(attester))
	if err != nil {
		return nil, err
	}
	if bz == nil {
		return nil, nil
	}
	var ids []string
	if err := json.Unmarshal(bz, &ids); err != nil {
		return nil, fmt.Errorf("unmarshal attester index: %w", err)
	}
	return ids, nil
}

// AddAttesterIndexEntry appends an attestation ID to the attester index.
func (k Keeper) AddAttesterIndexEntry(ctx sdk.Context, attester, attestationID string) error {
	ids, err := k.GetAttesterIndex(ctx, attester)
	if err != nil {
		return err
	}
	ids = append(ids, attestationID)
	return k.SetAttesterIndex(ctx, attester, ids)
}

// RemoveAttesterIndexEntry removes a specific attestation ID from the attester index.
func (k Keeper) RemoveAttesterIndexEntry(ctx sdk.Context, attester, attestationID string) error {
	ids, err := k.GetAttesterIndex(ctx, attester)
	if err != nil {
		return err
	}
	filtered := ids[:0]
	for _, id := range ids {
		if id != attestationID {
			filtered = append(filtered, id)
		}
	}
	return k.SetAttesterIndex(ctx, attester, filtered)
}

// ============================================================
// Expiry Queue
// ============================================================

// EnqueueExpiry inserts an entry into the expiry queue.
func (k Keeper) EnqueueExpiry(ctx sdk.Context, expiresAt int64, attestationID string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.ExpiryQueueKey(expiresAt, attestationID), []byte(attestationID))
}

// DequeueExpiry removes an entry from the expiry queue.
func (k Keeper) DequeueExpiry(ctx sdk.Context, expiresAt int64, attestationID string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Delete(types.ExpiryQueueKey(expiresAt, attestationID))
}

// IterateExpiredAttestations iterates all attestations whose TTL has passed
// (expiresAt <= currentBlockTime) and calls cb for each, stopping if cb returns true.
func (k Keeper) IterateExpiredAttestations(ctx sdk.Context, currentTime int64, cb func(attestationID string) bool) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	prefix := []byte{types.ExpiryQueuePrefix}

	// The expiry queue is sorted by big-endian timestamp, so we iterate from the
	// start of the prefix up to (but not including) the first key whose timestamp
	// exceeds currentTime.
	end := expiryQueueEndKey(currentTime)

	iter, err := kvStore.Iterator(prefix, end)
	if err != nil {
		return err
	}
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		id := string(iter.Value())
		if cb(id) {
			break
		}
	}
	return iter.Error()
}

// expiryQueueEndKey builds the exclusive upper bound for expiry iteration:
// prefix byte + big-endian (currentTime+1) — this gives all keys with
// timestamp ≤ currentTime.
func expiryQueueEndKey(currentTime int64) []byte {
	key := []byte{types.ExpiryQueuePrefix}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(currentTime)+1)
	return append(key, b...)
}

// ============================================================
// Epoch rate-limiting
// ============================================================

// GetEpochCount returns how many attestations an address published in the given epoch.
func (k Keeper) GetEpochCount(ctx sdk.Context, epoch uint64, attester string) (uint32, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.EpochCountKey(epoch, attester))
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint32(bz), nil
}

// IncrementEpochCount bumps the per-epoch attestation counter for an attester.
func (k Keeper) IncrementEpochCount(ctx sdk.Context, epoch uint64, attester string) error {
	count, err := k.GetEpochCount(ctx, epoch, attester)
	if err != nil {
		return err
	}
	count++
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, count)
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.EpochCountKey(epoch, attester), b)
}

// PruneEpochCounts removes all epoch-count entries for a given epoch.
// Called from EndBlocker when the epoch rolls over.
func (k Keeper) PruneEpochCounts(ctx sdk.Context, epoch uint64) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	// Build prefix = 0x04 | epoch(8 bytes)
	prefix := make([]byte, 9)
	prefix[0] = types.EpochCountPrefix
	binary.BigEndian.PutUint64(prefix[1:], epoch)

	iter, err := kvStore.Iterator(prefix, prefixEndBytes(prefix))
	if err != nil {
		return err
	}
	defer iter.Close()

	var keys [][]byte
	for ; iter.Valid(); iter.Next() {
		k2 := make([]byte, len(iter.Key()))
		copy(k2, iter.Key())
		keys = append(keys, k2)
	}
	if err := iter.Error(); err != nil {
		return err
	}

	for _, key := range keys {
		if err := kvStore.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================
// Epoch number
// ============================================================

// GetCurrentEpoch returns the stored epoch number.
func (k Keeper) GetCurrentEpoch(ctx sdk.Context) (uint64, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get([]byte{types.EpochNumberKey})
	if err != nil {
		return 0, err
	}
	if bz == nil {
		return 0, nil
	}
	return binary.BigEndian.Uint64(bz), nil
}

// SetCurrentEpoch stores the current epoch number.
func (k Keeper) SetCurrentEpoch(ctx sdk.Context, epoch uint64) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, epoch)
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set([]byte{types.EpochNumberKey}, b)
}

// ============================================================
// Dispute Records
// ============================================================

// SetDispute persists a DisputeRecord.
func (k Keeper) SetDispute(ctx sdk.Context, d types.DisputeRecord) error {
	bz, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal dispute: %w", err)
	}
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.DisputeKey(d.ID), bz)
}

// GetDispute retrieves a DisputeRecord by ID.
func (k Keeper) GetDispute(ctx sdk.Context, id string) (types.DisputeRecord, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.DisputeKey(id))
	if err != nil {
		return types.DisputeRecord{}, err
	}
	if bz == nil {
		return types.DisputeRecord{}, errors.Wrapf(types.ErrDisputeNotFound, "id=%s", id)
	}
	var d types.DisputeRecord
	if err := json.Unmarshal(bz, &d); err != nil {
		return types.DisputeRecord{}, fmt.Errorf("unmarshal dispute %s: %w", id, err)
	}
	return d, nil
}

// IterateDisputes iterates all dispute records.
func (k Keeper) IterateDisputes(ctx sdk.Context, cb func(types.DisputeRecord) bool) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	prefix := []byte{types.DisputeKeyPrefix}
	iter, err := kvStore.Iterator(prefix, prefixEndBytes(prefix))
	if err != nil {
		return err
	}
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var d types.DisputeRecord
		if err := json.Unmarshal(iter.Value(), &d); err != nil {
			return fmt.Errorf("unmarshal dispute: %w", err)
		}
		if cb(d) {
			break
		}
	}
	return iter.Error()
}

// ============================================================
// Blacklist
// ============================================================

// SetBlacklisted marks an attester address as blacklisted.
func (k Keeper) SetBlacklisted(ctx sdk.Context, attester string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.BlacklistKey(attester), []byte{0x01})
}

// IsBlacklisted returns true if the attester is in the on-chain blacklist.
func (k Keeper) IsBlacklisted(ctx sdk.Context, attester string) (bool, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.BlacklistKey(attester))
	if err != nil {
		return false, err
	}
	return bz != nil, nil
}

// RemoveBlacklisted removes an attester from the blacklist (governance action).
func (k Keeper) RemoveBlacklisted(ctx sdk.Context, attester string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Delete(types.BlacklistKey(attester))
}

// ============================================================
// Endorser Set
// ============================================================

// SetEndorsement records that `endorser` has endorsed `attestationID`.
func (k Keeper) SetEndorsement(ctx sdk.Context, attestationID, endorser string) error {
	kvStore := k.storeService.OpenKVStore(ctx)
	return kvStore.Set(types.EndorserSetKey(attestationID, endorser), []byte{0x01})
}

// HasEndorsement returns true if the endorser has already endorsed the attestation.
func (k Keeper) HasEndorsement(ctx sdk.Context, attestationID, endorser string) (bool, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	bz, err := kvStore.Get(types.EndorserSetKey(attestationID, endorser))
	if err != nil {
		return false, err
	}
	return bz != nil, nil
}

// CountEndorsements returns the number of unique endorsers for an attestation.
func (k Keeper) CountEndorsements(ctx sdk.Context, attestationID string) (uint32, error) {
	kvStore := k.storeService.OpenKVStore(ctx)
	// EndorserSetKey = 0x08 | attestation_id | "|" | endorser
	// So the prefix for all endorsers of this attestation is:
	prefix := append([]byte{types.EndorserSetPrefix}, []byte(attestationID+"|")...)
	iter, err := kvStore.Iterator(prefix, prefixEndBytes(prefix))
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	var count uint32
	for ; iter.Valid(); iter.Next() {
		count++
	}
	if err := iter.Error(); err != nil {
		return 0, err
	}
	return count, nil
}

// ============================================================
// High-level business logic helpers
// ============================================================

// PublishAttestationRecord validates, indexes, and stores a new attestation.
// It also enqueues the expiry, updates the attester index, and bumps the epoch counter.
func (k Keeper) PublishAttestationRecord(ctx sdk.Context, rec types.AttestationRecord) error {
	params, err := k.GetParams(ctx)
	if err != nil {
		return err
	}

	// Check blacklist
	bl, err := k.IsBlacklisted(ctx, rec.Attester)
	if err != nil {
		return err
	}
	if bl {
		return types.ErrAttesterBlacklisted
	}

	// Check epoch rate limit
	epoch := types.CurrentEpoch(ctx.BlockHeight())
	count, err := k.GetEpochCount(ctx, epoch, rec.Attester)
	if err != nil {
		return err
	}
	if count >= params.MaxAttestationsPerEpoch {
		return types.ErrRateLimitExceeded
	}

	// Ensure no duplicate
	exists, err := k.HasAttestation(ctx, rec.ID)
	if err != nil {
		return err
	}
	if exists {
		return errors.Wrapf(types.ErrDuplicateAttestation, "id=%s", rec.ID)
	}

	// Persist the record
	if err := k.SetAttestation(ctx, rec); err != nil {
		return err
	}

	// Update indexes
	if err := k.AddArtifactIndexEntry(ctx, rec.ArtifactSHA256, rec.ID); err != nil {
		return err
	}
	if err := k.AddAttesterIndexEntry(ctx, rec.Attester, rec.ID); err != nil {
		return err
	}

	// Enqueue expiry
	if err := k.EnqueueExpiry(ctx, rec.ExpiresAt, rec.ID); err != nil {
		return err
	}

	// Bump epoch counter
	if err := k.IncrementEpochCount(ctx, epoch, rec.Attester); err != nil {
		return err
	}

	// Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypePublishAttestation,
		sdk.NewAttribute(types.AttributeKeyAttestationID, rec.ID),
		sdk.NewAttribute(types.AttributeKeyAttester, rec.Attester),
		sdk.NewAttribute(types.AttributeKeyArtifactType, rec.ArtifactType.String()),
		sdk.NewAttribute(types.AttributeKeyArtifactSHA256, rec.ArtifactSHA256),
	))

	k.logger.Info("attestation published",
		"id", rec.ID,
		"attester", rec.Attester,
		"artifact_type", rec.ArtifactType.String(),
		"expires_at", rec.ExpiresAt,
	)
	return nil
}

// ExpireAttestation marks an attestation EXPIRED and removes it from indexes.
func (k Keeper) ExpireAttestation(ctx sdk.Context, id string) error {
	rec, err := k.GetAttestation(ctx, id)
	if err != nil {
		return err
	}

	// Mark expired
	rec.Status = types.AttestationStatus_EXPIRED
	if err := k.SetAttestation(ctx, rec); err != nil {
		return err
	}

	// Remove from expiry queue
	if err := k.DequeueExpiry(ctx, rec.ExpiresAt, id); err != nil {
		return err
	}

	// Remove from artifact index
	if err := k.RemoveArtifactIndexEntry(ctx, rec.ArtifactSHA256, id); err != nil {
		return err
	}

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeExpireAttestation,
		sdk.NewAttribute(types.AttributeKeyAttestationID, id),
	))
	return nil
}

// RevokeAttestationRecord revokes an attestation by the original attester.
func (k Keeper) RevokeAttestationRecord(ctx sdk.Context, id, attester, reason string) error {
	rec, err := k.GetAttestation(ctx, id)
	if err != nil {
		return err
	}
	if rec.Attester != attester {
		return errors.Wrapf(types.ErrUnauthorizedRevoke, "not the original attester")
	}
	if rec.Status != types.AttestationStatus_ACTIVE {
		return errors.Wrapf(types.ErrAlreadyRevoked, "status=%s", rec.Status.String())
	}

	rec.Status = types.AttestationStatus_REVOKED
	rec.RevokeReason = reason
	if err := k.SetAttestation(ctx, rec); err != nil {
		return err
	}
	if err := k.RemoveArtifactIndexEntry(ctx, rec.ArtifactSHA256, id); err != nil {
		return err
	}
	if err := k.DequeueExpiry(ctx, rec.ExpiresAt, id); err != nil {
		return err
	}

	// Slight reputation penalty for revocation (self-correction is still valuable)
	_ = k.repKeeper.SubReputation(ctx, attester, 2)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeRevokeAttestation,
		sdk.NewAttribute(types.AttributeKeyAttestationID, id),
		sdk.NewAttribute(types.AttributeKeyAttester, attester),
	))
	return nil
}

// EndorseAttestationRecord adds an endorsement and bumps the endorsement count.
func (k Keeper) EndorseAttestationRecord(ctx sdk.Context, id, endorser string) error {
	rec, err := k.GetAttestation(ctx, id)
	if err != nil {
		return err
	}
	if rec.Status != types.AttestationStatus_ACTIVE {
		return errors.Wrapf(types.ErrNotActive, "cannot endorse status=%s", rec.Status.String())
	}
	if rec.Attester == endorser {
		return types.ErrSelfEndorse
	}

	already, err := k.HasEndorsement(ctx, id, endorser)
	if err != nil {
		return err
	}
	if already {
		return types.ErrAlreadyEndorsed
	}

	if err := k.SetEndorsement(ctx, id, endorser); err != nil {
		return err
	}

	rec.EndorsementCount++
	if err := k.SetAttestation(ctx, rec); err != nil {
		return err
	}

	// Reputation reward for both attester and endorser
	_ = k.repKeeper.AddReputation(ctx, rec.Attester, 1)
	_ = k.repKeeper.AddReputation(ctx, endorser, 1)

	ctx.EventManager().EmitEvent(sdk.NewEvent(
		types.EventTypeEndorseAttestation,
		sdk.NewAttribute(types.AttributeKeyAttestationID, id),
		sdk.NewAttribute(types.AttributeKeyEndorser, endorser),
	))
	return nil
}

// ============================================================
// IsMalicious query helpers
// ============================================================

// IsMaliciousBySHA256 returns the highest-severity active attestation for an artifact SHA-256.
func (k Keeper) IsMaliciousBySHA256(ctx sdk.Context, sha256 string) (bool, *types.AttestationRecord, error) {
	ids, err := k.GetArtifactIndex(ctx, sha256)
	if err != nil {
		return false, nil, err
	}
	return k.bestActiveRecord(ctx, ids)
}

func (k Keeper) bestActiveRecord(ctx sdk.Context, ids []string) (bool, *types.AttestationRecord, error) {
	var best *types.AttestationRecord
	for _, id := range ids {
		rec, err := k.GetAttestation(ctx, id)
		if err != nil {
			continue
		}
		if rec.Status != types.AttestationStatus_ACTIVE {
			continue
		}
		if best == nil || types.SeverityValue(rec.Severity) > types.SeverityValue(best.Severity) {
			r := rec
			best = &r
		}
	}
	if best == nil {
		return false, nil, nil
	}
	return true, best, nil
}

// ============================================================
// Utility
// ============================================================

// prefixEndBytes returns the lexicographic end key for a given prefix
// (increments the last byte, handling overflow).
func prefixEndBytes(prefix []byte) []byte {
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
	return nil // overflow — no upper bound
}