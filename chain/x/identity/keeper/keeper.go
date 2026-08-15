// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"encoding/json"
	"fmt"

	"cosmossdk.io/math"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/store/v2/prefix"
	storetypes "github.com/cosmos/cosmos-sdk/store/v2/types"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/types"
)

// Keeper is the x/identity module keeper.  It holds a reference to the KV store
// and the codec, plus optional references to other module keepers needed for
// trust-score updates and stake queries.
type Keeper struct {
	storeKey storetypes.StoreKey
	cdc      codec.BinaryCodec

	// bankKeeper is used to query utat balances for stake tier checks.
	// Typed as interface to avoid a hard import cycle.
	bankKeeper BankKeeper

	// stakingKeeper is used to query delegations for tier-1 qualification.
	stakingKeeper StakingKeeper
}

// BankKeeper defines the bank module methods used by x/identity.
type BankKeeper interface {
	GetAllBalances(ctx sdk.Context, addr sdk.AccAddress) sdk.Coins
}

// StakingKeeper defines the staking module methods used by x/identity.
type StakingKeeper interface {
	TotalBondedTokens(ctx sdk.Context) (math.Int, error)
}

// NewKeeper constructs a new identity Keeper.
func NewKeeper(
	storeKey storetypes.StoreKey,
	cdc codec.BinaryCodec,
	bankKeeper BankKeeper,
	stakingKeeper StakingKeeper,
) Keeper {
	return Keeper{
		storeKey:      storeKey,
		cdc:           cdc,
		bankKeeper:    bankKeeper,
		stakingKeeper: stakingKeeper,
	}
}

// ============================================================
// Params
// ============================================================

// SetParams stores module params in the KV store.
func (k Keeper) SetParams(ctx sdk.Context, p types.Params) {
	store := ctx.KVStore(k.storeKey)
	bz, _ := json.Marshal(p)
	store.Set([]byte{types.ParamsKey}, bz)
}

// GetParams loads module params from the KV store.
func (k Keeper) GetParams(ctx sdk.Context) types.Params {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get([]byte{types.ParamsKey})
	if bz == nil {
		return types.DefaultParams()
	}
	var p types.Params
	_ = json.Unmarshal(bz, &p)
	return p
}

// ============================================================
// DNSIdentityRecord CRUD
// ============================================================

// SetRecord stores a DNSIdentityRecord in all three indexes:
//   - idrecord/{cosmosAddr}
//   - iddomain/{domain}  → cosmosAddr
//   - idbyid/{identityID} → cosmosAddr
func (k Keeper) SetRecord(ctx sdk.Context, rec types.DNSIdentityRecord) error {
	bz, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal identity record: %w", err)
	}
	store := ctx.KVStore(k.storeKey)
	store.Set(types.IDRecordKey(rec.CosmosAddr), bz)
	store.Set(types.IDDomainKey(rec.Domain), []byte(rec.CosmosAddr))
	store.Set(types.IDByIDKey(rec.IdentityID), []byte(rec.CosmosAddr))
	return nil
}

// GetRecord retrieves a DNSIdentityRecord by Cosmos address.
// Returns (record, true) if found, (zero, false) if not.
func (k Keeper) GetRecord(ctx sdk.Context, cosmosAddr string) (types.DNSIdentityRecord, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.IDRecordKey(cosmosAddr))
	if bz == nil {
		return types.DNSIdentityRecord{}, false
	}
	var rec types.DNSIdentityRecord
	if err := json.Unmarshal(bz, &rec); err != nil {
		return types.DNSIdentityRecord{}, false
	}
	return rec, true
}

// GetRecordByDomain looks up a DNSIdentityRecord by normalized domain name.
func (k Keeper) GetRecordByDomain(ctx sdk.Context, domain string) (types.DNSIdentityRecord, bool) {
	store := ctx.KVStore(k.storeKey)
	addrBz := store.Get(types.IDDomainKey(domain))
	if addrBz == nil {
		return types.DNSIdentityRecord{}, false
	}
	return k.GetRecord(ctx, string(addrBz))
}

// GetRecordByID looks up a DNSIdentityRecord by its identity ID.
func (k Keeper) GetRecordByID(ctx sdk.Context, identityID string) (types.DNSIdentityRecord, bool) {
	store := ctx.KVStore(k.storeKey)
	addrBz := store.Get(types.IDByIDKey(identityID))
	if addrBz == nil {
		return types.DNSIdentityRecord{}, false
	}
	return k.GetRecord(ctx, string(addrBz))
}

// DeleteRecord removes a DNSIdentityRecord and its domain/id indexes.
// The record must still have CosmosAddr and Domain set.
func (k Keeper) DeleteRecord(ctx sdk.Context, rec types.DNSIdentityRecord) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.IDRecordKey(rec.CosmosAddr))
	store.Delete(types.IDDomainKey(rec.Domain))
	store.Delete(types.IDByIDKey(rec.IdentityID))
}

// HasRecord returns true if a record exists for cosmosAddr.
func (k Keeper) HasRecord(ctx sdk.Context, cosmosAddr string) bool {
	store := ctx.KVStore(k.storeKey)
	return store.Has(types.IDRecordKey(cosmosAddr))
}

// HasDomain returns true if a record exists for the given domain.
func (k Keeper) HasDomain(ctx sdk.Context, domain string) bool {
	store := ctx.KVStore(k.storeKey)
	return store.Has(types.IDDomainKey(domain))
}

// ============================================================
// Pending records
// ============================================================

// SetPending stores a pending identity record (PENDING status before first
// DNS verification epoch).
func (k Keeper) SetPending(ctx sdk.Context, rec types.DNSIdentityRecord) error {
	bz, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal pending record: %w", err)
	}
	store := ctx.KVStore(k.storeKey)
	store.Set(types.IDPendingKey(rec.CosmosAddr), bz)
	return nil
}

// GetPending retrieves a pending record by Cosmos address.
func (k Keeper) GetPending(ctx sdk.Context, cosmosAddr string) (types.DNSIdentityRecord, bool) {
	store := ctx.KVStore(k.storeKey)
	bz := store.Get(types.IDPendingKey(cosmosAddr))
	if bz == nil {
		return types.DNSIdentityRecord{}, false
	}
	var rec types.DNSIdentityRecord
	if err := json.Unmarshal(bz, &rec); err != nil {
		return types.DNSIdentityRecord{}, false
	}
	return rec, true
}

// DeletePending removes a pending record.
func (k Keeper) DeletePending(ctx sdk.Context, cosmosAddr string) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.IDPendingKey(cosmosAddr))
}

// PromotePending promotes a PENDING record to ACTIVE: removes from pending
// store, sets status ACTIVE, and indexes in the main store.
func (k Keeper) PromotePending(ctx sdk.Context, cosmosAddr string, now int64) error {
	rec, found := k.GetPending(ctx, cosmosAddr)
	if !found {
		return types.ErrIdentityNotFound.Wrapf("no pending record for %s", cosmosAddr)
	}
	rec.Status = types.DNSIDStatus_ACTIVE
	rec.LastVerifiedAt = now
	if err := k.SetRecord(ctx, rec); err != nil {
		return err
	}
	k.DeletePending(ctx, cosmosAddr)
	return nil
}

// ============================================================
// Expiry queue
// ============================================================

// EnqueueExpiry adds cosmosAddr to the expiry queue with the given expiry time.
func (k Keeper) EnqueueExpiry(ctx sdk.Context, expiresAt int64, cosmosAddr string) {
	store := ctx.KVStore(k.storeKey)
	key := types.IDExpiryKey(expiresAt, cosmosAddr)
	store.Set(key, []byte(cosmosAddr))
}

// DequeueExpired iterates the expiry queue and returns all addresses whose
// expiry time is <= now.  The caller is responsible for updating their records.
func (k Keeper) DequeueExpired(ctx sdk.Context, now int64) []string {
	store := ctx.KVStore(k.storeKey)
	pStore := prefix.NewStore(store, []byte{types.IDExpiryPrefix})
	iter := pStore.Iterator(nil, types.IDExpiryKey(now+1, "")[1:]) // strip prefix byte
	defer iter.Close()

	var addrs []string
	for ; iter.Valid(); iter.Next() {
		addrs = append(addrs, string(iter.Value()))
	}
	return addrs
}

// RemoveExpiryEntry removes a specific entry from the expiry queue.
func (k Keeper) RemoveExpiryEntry(ctx sdk.Context, expiresAt int64, cosmosAddr string) {
	store := ctx.KVStore(k.storeKey)
	store.Delete(types.IDExpiryKey(expiresAt, cosmosAddr))
}

// ============================================================
// Iterator helpers
// ============================================================

// IterateRecords iterates over all active DNSIdentityRecords.
// The callback receives each record; returning true stops iteration.
func (k Keeper) IterateRecords(ctx sdk.Context, cb func(rec types.DNSIdentityRecord) bool) {
	store := ctx.KVStore(k.storeKey)
	pStore := prefix.NewStore(store, []byte{types.IDRecordPrefix})
	iter := pStore.Iterator(nil, nil)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		var rec types.DNSIdentityRecord
		if err := json.Unmarshal(iter.Value(), &rec); err != nil {
			continue
		}
		if cb(rec) {
			break
		}
	}
}

// CountRecordsByAddress counts how many distinct domain records exist for addr.
func (k Keeper) CountRecordsByAddress(ctx sdk.Context, cosmosAddr string) int {
	count := 0
	k.IterateRecords(ctx, func(rec types.DNSIdentityRecord) bool {
		if rec.CosmosAddr == cosmosAddr {
			count++
		}
		return false
	})
	return count
}

// ============================================================
// Logger
// ============================================================

func (k Keeper) Logger(ctx sdk.Context) interface{ Info(string, ...interface{}) } {
	return ctx.Logger().With("module", types.ModuleName)
}
