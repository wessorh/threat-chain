// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/identity/types"
)

// ============================================================
// RegisterIdentity — MsgRegisterIdentity handler
// ============================================================

// RegisterIdentity processes a MsgRegisterIdentity message.  It performs all
// stateful validation, writes the identity record in PENDING state, and enqueues
// it for DNS verification in the next epoch.
//
// State changes:
//   - Writes pending record at idpending/{cosmosAddr}
//   - Enqueues expiry at idexpiry/{expiresAt}/{cosmosAddr}
//   - Emits EventTypeIdentityRegistered
func (k Keeper) RegisterIdentity(ctx sdk.Context, msg *types.MsgRegisterIdentity) (types.DNSIdentityRecord, error) {
	params := k.GetParams(ctx)

	// 1. Normalize domain
	domain, err := types.NormalizeDomain(msg.Domain)
	if err != nil {
		return types.DNSIdentityRecord{}, types.ErrInvalidDomain.Wrapf("%v", err)
	}

	// 2. Uniqueness checks
	if k.HasRecord(ctx, msg.CosmosAddr) {
		return types.DNSIdentityRecord{}, types.ErrIdentityAlreadyExists.Wrapf(
			"address %s already has an active identity", msg.CosmosAddr)
	}
	if k.HasDomain(ctx, domain) {
		return types.DNSIdentityRecord{}, types.ErrDomainAlreadyRegistered.Wrapf(
			"domain %s is already registered", domain)
	}

	// 3. Max-domains-per-address check
	count := k.CountRecordsByAddress(ctx, msg.CosmosAddr)
	if int64(count) >= params.MaxDomainsPerAddress {
		return types.DNSIdentityRecord{}, types.ErrMaxDomainsReached.Wrapf(
			"address %s already has %d domains (max %d)",
			msg.CosmosAddr, count, params.MaxDomainsPerAddress)
	}

	// 4. DNSSEC evidence validation (when required by params)
	if params.DNSBoundTierRequiresDNSSEC {
		if err := ValidateEvidenceBundle(
			msg.Evidence,
			domain, msg.Selector, msg.PublicKeyHex, msg.CosmosAddr,
			ctx.BlockTime().Unix(),
		); err != nil {
			return types.DNSIdentityRecord{}, err
		}
	}

	// 5. Domain proof signature verification (secp256k1)
	registeredAt := msg.PublishedAt
	proofPayload := types.DomainProofPayload(domain, msg.Selector, msg.CosmosAddr, registeredAt)
	if err := verifySecp256k1Sig(msg.PublicKeyHex, proofPayload, msg.DomainProofSig); err != nil {
		return types.DNSIdentityRecord{}, fmt.Errorf("domain_proof_sig verification failed: %w", err)
	}

	// 6. Compute identity ID
	identityID := types.ComputeIdentityID(msg.CosmosAddr, domain, registeredAt)

	// 7. Determine TTL
	ttl := params.IdentityTTLSeconds
	if msg.TTLSeconds > 0 {
		ttl = msg.TTLSeconds
	}
	expiresAt := registeredAt + ttl

	// 8. Build the evidence value (nil-safe)
	var evidence types.DNSEvidenceBundle
	if msg.Evidence != nil {
		evidence = *msg.Evidence
	}

	// 9. Build the identity record
	rec := types.DNSIdentityRecord{
		IdentityID:        identityID,
		CosmosAddr:        msg.CosmosAddr,
		Domain:            domain,
		Selector:          msg.Selector,
		PublicKeyHex:      msg.PublicKeyHex,
		Name:              msg.Name,
		URI:               msg.URI,
		Flags:             msg.Flags,
		Status:            types.DNSIDStatus_PENDING,
		RegisteredAt:      registeredAt,
		ExpiresAt:         expiresAt,
		DomainProofSig:    msg.DomainProofSig,
		Evidence:          evidence,
		RegisteredAtBlock: ctx.BlockHeight(),
		SchemaVersion:     types.SchemaVersion,
	}

	// 10. Store as pending + enqueue expiry
	if err := k.SetPending(ctx, rec); err != nil {
		return types.DNSIdentityRecord{}, fmt.Errorf("store pending record: %w", err)
	}
	k.EnqueueExpiry(ctx, expiresAt, msg.CosmosAddr)

	// 11. Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		EventTypeIdentityRegistered,
		sdk.NewAttribute(AttributeKeyCosmosAddr, msg.CosmosAddr),
		sdk.NewAttribute(AttributeKeyDomain, domain),
		sdk.NewAttribute(AttributeKeySelector, msg.Selector),
		sdk.NewAttribute(AttributeKeyIdentityID, identityID),
		sdk.NewAttribute(AttributeKeyStatus, types.DNSIDStatus_PENDING.String()),
	))

	k.Logger(ctx).Info("identity registered (PENDING)",
		"addr", msg.CosmosAddr, "domain", domain, "identity_id", identityID)

	return rec, nil
}

// ============================================================
// RotateIdentityKey — MsgRotateIdentityKey handler
// ============================================================

// RotateIdentityKey processes a MsgRotateIdentityKey message.  The rotation
// requires valid signatures from both the current active key (RotationAuthSig)
// and the new key (NewKeyDomainProofSig).
func (k Keeper) RotateIdentityKey(ctx sdk.Context, msg *types.MsgRotateIdentityKey) (types.DNSIdentityRecord, error) {
	// 1. Load existing record
	rec, found := k.GetRecord(ctx, msg.CosmosAddr)
	if !found {
		return types.DNSIdentityRecord{}, types.ErrIdentityNotFound.Wrapf(
			"no identity for %s", msg.CosmosAddr)
	}
	if rec.Status != types.DNSIDStatus_ACTIVE {
		return types.DNSIdentityRecord{}, types.ErrIdentityNotActive.Wrapf(
			"status is %s", rec.Status)
	}

	// 2. Selector uniqueness check
	if msg.NewSelector == rec.Selector {
		return types.DNSIdentityRecord{}, types.ErrSelectorConflict.Wrap(
			"new_selector must differ from the current selector")
	}

	// 3. Verify rotation auth signature (signed by current key)
	rotationAuthPayload := rotationAuthPayload(
		rec.Domain, rec.Selector, msg.NewSelector, msg.CosmosAddr, msg.RotatedAt)
	if err := verifySecp256k1Sig(rec.PublicKeyHex, rotationAuthPayload, msg.RotationAuthSig); err != nil {
		return types.DNSIdentityRecord{}, types.ErrRotationAuthSigInvalid.Wrapf("%v", err)
	}

	// 4. Verify new key domain proof signature (signed by new key)
	newProofPayload := types.DomainProofPayload(
		rec.Domain, msg.NewSelector, msg.CosmosAddr, msg.RotatedAt)
	if err := verifySecp256k1Sig(msg.NewPublicKeyHex, newProofPayload, msg.NewKeyDomainProofSig); err != nil {
		return types.DNSIdentityRecord{}, types.ErrNewKeyProofSigInvalid.Wrapf("%v", err)
	}

	// 5. Validate new evidence bundle (if provided)
	params := k.GetParams(ctx)
	if params.DNSBoundTierRequiresDNSSEC && msg.Evidence != nil {
		if err := ValidateEvidenceBundle(
			msg.Evidence,
			rec.Domain, msg.NewSelector, msg.NewPublicKeyHex, msg.CosmosAddr,
			ctx.BlockTime().Unix(),
		); err != nil {
			return types.DNSIdentityRecord{}, err
		}
	}

	// 6. Update record: mark old selector, install new key
	rec.PreviousSelector = rec.Selector
	rec.Selector = msg.NewSelector
	rec.PublicKeyHex = msg.NewPublicKeyHex
	rec.RotatedAt = msg.RotatedAt
	if msg.Evidence != nil {
		rec.Evidence = *msg.Evidence
	}
	if msg.Notes != "" {
		rec.RevocationNotes = msg.Notes
	}

	if err := k.SetRecord(ctx, rec); err != nil {
		return types.DNSIdentityRecord{}, fmt.Errorf("store rotated record: %w", err)
	}

	// 7. Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		EventTypeIdentityKeyRotated,
		sdk.NewAttribute(AttributeKeyCosmosAddr, msg.CosmosAddr),
		sdk.NewAttribute(AttributeKeyDomain, rec.Domain),
		sdk.NewAttribute("old_selector", rec.PreviousSelector),
		sdk.NewAttribute(AttributeKeySelector, msg.NewSelector),
	))

	k.Logger(ctx).Info("identity key rotated",
		"addr", msg.CosmosAddr, "domain", rec.Domain,
		"old_selector", rec.PreviousSelector, "new_selector", msg.NewSelector)

	return rec, nil
}

// ============================================================
// RevokeIdentity — MsgRevokeIdentity handler
// ============================================================

// RevokeIdentity processes a MsgRevokeIdentity message.  The record is marked
// REVOKED, removed from the expiry queue, and a trust score penalty is applied.
func (k Keeper) RevokeIdentity(ctx sdk.Context, msg *types.MsgRevokeIdentity) error {
	rec, found := k.GetRecord(ctx, msg.CosmosAddr)
	if !found {
		// Also check pending
		pendRec, pendFound := k.GetPending(ctx, msg.CosmosAddr)
		if !pendFound {
			return types.ErrIdentityNotFound.Wrapf("no identity for %s", msg.CosmosAddr)
		}
		rec = pendRec
		k.DeletePending(ctx, msg.CosmosAddr)
	}

	if rec.Status.IsTerminal() {
		return types.ErrIdentityTerminal.Wrapf("status is %s", rec.Status)
	}

	// Update record
	rec.Status = types.DNSIDStatus_REVOKED
	rec.RevocationNotes = msg.Reason

	if err := k.SetRecord(ctx, rec); err != nil {
		return fmt.Errorf("store revoked record: %w", err)
	}

	// Remove from expiry queue
	k.RemoveExpiryEntry(ctx, rec.ExpiresAt, msg.CosmosAddr)

	// Trust score penalty
	newScore := k.OnRevocation(ctx, msg.CosmosAddr)

	// Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		EventTypeIdentityRevoked,
		sdk.NewAttribute(AttributeKeyCosmosAddr, msg.CosmosAddr),
		sdk.NewAttribute(AttributeKeyDomain, rec.Domain),
		sdk.NewAttribute("reason", msg.Reason),
		sdk.NewAttribute("new_trust_score", fmt.Sprintf("%d", newScore)),
	))

	k.Logger(ctx).Info("identity revoked",
		"addr", msg.CosmosAddr, "domain", rec.Domain, "reason", msg.Reason)
	return nil
}

// ============================================================
// RenewIdentity — MsgRenewIdentity handler
// ============================================================

// RenewIdentity processes a MsgRenewIdentity message.  It refreshes the DNSSEC
// evidence, extends the expiry, and awards the renewal trust score bonus.
func (k Keeper) RenewIdentity(ctx sdk.Context, msg *types.MsgRenewIdentity) (types.DNSIdentityRecord, error) {
	rec, found := k.GetRecord(ctx, msg.CosmosAddr)
	if !found {
		return types.DNSIdentityRecord{}, types.ErrIdentityNotFound.Wrapf(
			"no identity for %s", msg.CosmosAddr)
	}
	if rec.Status == types.DNSIDStatus_REVOKED || rec.Status == types.DNSIDStatus_SUPERSEDED {
		return types.DNSIdentityRecord{}, types.ErrIdentityTerminal.Wrapf(
			"status is %s", rec.Status)
	}

	params := k.GetParams(ctx)

	// Validate fresh evidence bundle
	if err := ValidateEvidenceBundle(
		&msg.Evidence,
		rec.Domain, rec.Selector, rec.PublicKeyHex, rec.CosmosAddr,
		ctx.BlockTime().Unix(),
	); err != nil {
		return types.DNSIdentityRecord{}, err
	}

	// Remove old expiry queue entry
	k.RemoveExpiryEntry(ctx, rec.ExpiresAt, msg.CosmosAddr)

	// Update record
	ttl := params.IdentityTTLSeconds
	if msg.TTLSeconds > 0 {
		ttl = msg.TTLSeconds
	}
	now := ctx.BlockTime().Unix()
	rec.ExpiresAt = now + ttl
	rec.LastVerifiedAt = now
	rec.Evidence = msg.Evidence
	if rec.Status == types.DNSIDStatus_EXPIRED {
		rec.Status = types.DNSIDStatus_ACTIVE // resurrection on renewal
	}

	if err := k.SetRecord(ctx, rec); err != nil {
		return types.DNSIdentityRecord{}, fmt.Errorf("store renewed record: %w", err)
	}

	// Re-enqueue expiry
	k.EnqueueExpiry(ctx, rec.ExpiresAt, msg.CosmosAddr)

	// Award renewal trust score bonus
	newScore := k.OnRenewal(ctx, msg.CosmosAddr)

	// Emit event
	ctx.EventManager().EmitEvent(sdk.NewEvent(
		EventTypeIdentityRenewed,
		sdk.NewAttribute(AttributeKeyCosmosAddr, msg.CosmosAddr),
		sdk.NewAttribute(AttributeKeyDomain, rec.Domain),
		sdk.NewAttribute("new_expires_at", fmt.Sprintf("%d", rec.ExpiresAt)),
		sdk.NewAttribute("new_trust_score", fmt.Sprintf("%d", newScore)),
	))

	k.Logger(ctx).Info("identity renewed",
		"addr", msg.CosmosAddr, "domain", rec.Domain, "expires_at", rec.ExpiresAt)

	return rec, nil
}

// ============================================================
// EndBlocker helpers — expiry and DNS re-verification
// ============================================================

// ProcessExpiredIdentities marks all expired records as EXPIRED and applies
// the DNS_REMOVED trust score penalty.  Called from the module EndBlocker.
func (k Keeper) ProcessExpiredIdentities(ctx sdk.Context) {
	now := ctx.BlockTime().Unix()
	addrs := k.DequeueExpired(ctx, now)
	for _, addr := range addrs {
		rec, found := k.GetRecord(ctx, addr)
		if !found {
			continue
		}
		if rec.Status != types.DNSIDStatus_ACTIVE {
			continue
		}
		rec.Status = types.DNSIDStatus_EXPIRED
		_ = k.SetRecord(ctx, rec)
		k.OnDNSRemoved(ctx, addr)
		ctx.EventManager().EmitEvent(sdk.NewEvent(
			EventTypeIdentityExpired,
			sdk.NewAttribute(AttributeKeyCosmosAddr, addr),
			sdk.NewAttribute(AttributeKeyDomain, rec.Domain),
		))
	}
}

// ============================================================
// Internal helpers
// ============================================================

// rotationAuthPayload builds the payload that the current key must sign to
// authorize a key rotation.
//
//	SHA-256("tatkey-rotation-auth|domain|oldSelector|newSelector|cosmosAddr|rotatedAt")
func rotationAuthPayload(domain, oldSelector, newSelector, cosmosAddr string, rotatedAt int64) []byte {
	raw := fmt.Sprintf("tatkey-rotation-auth|%s|%s|%s|%s|%d",
		domain, oldSelector, newSelector, cosmosAddr, rotatedAt)
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// verifySecp256k1Sig verifies an ECDSA secp256k1 signature.
//
//   pubKeyHex  — compressed secp256k1 public key (hex, 66 chars = 33 bytes)
//   payload    — the 32-byte message digest that was signed
//   sigHex     — DER-encoded signature (hex, 128 chars = 64 bytes)
//
// Production note: replace the stub below with btcec or tendermint/crypto/secp256k1.
func verifySecp256k1Sig(pubKeyHex string, payload []byte, sigHex string) error {
	if len(pubKeyHex) != types.PubKeyHexLen {
		return fmt.Errorf("public key hex length %d != %d", len(pubKeyHex), types.PubKeyHexLen)
	}
	if len(sigHex) != types.MaxProofHex {
		return fmt.Errorf("signature hex length %d != %d", len(sigHex), types.MaxProofHex)
	}
	_, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("public key is not valid hex: %w", err)
	}
	_, err = hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	// TODO(production): uncomment and use btcec:
	//   pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
	//   sig, err := btcec.ParseDERSignature(sigBytes, btcec.S256())
	//   if !sig.Verify(payload, pubKey) { return fmt.Errorf("signature verification failed") }
	return nil // stub: structural validation only
}

// ============================================================
// Event type / attribute constants
// ============================================================

const (
	EventTypeIdentityRegistered = "identity_registered"
	EventTypeIdentityKeyRotated = "identity_key_rotated"
	EventTypeIdentityRevoked    = "identity_revoked"
	EventTypeIdentityRenewed    = "identity_renewed"
	EventTypeIdentityExpired    = "identity_expired"
	EventTypeIdentityDNSRemoved = "identity_dns_removed"

	AttributeKeyCosmosAddr = "cosmos_addr"
	AttributeKeyDomain     = "domain"
	AttributeKeySelector   = "selector"
	AttributeKeyIdentityID = "identity_id"
	AttributeKeyStatus     = "status"
)