// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import "cosmossdk.io/errors"

var (
	// ── Input validation ─────────────────────────────────────────────────────
	ErrInvalidDomain           = errors.Register(ModuleName, 2, "invalid or non-normalizable domain name")
	ErrInvalidSelector         = errors.Register(ModuleName, 3, "invalid DNS selector (must be a valid single DNS label)")
	ErrInvalidPublicKey        = errors.Register(ModuleName, 4, "invalid secp256k1 public key hex (must be 66 hex chars)")
	ErrInvalidDomainProofSig   = errors.Register(ModuleName, 5, "domain_proof_sig is not a valid 128-hex ECDSA signature")
	ErrInvalidName             = errors.Register(ModuleName, 6, "name exceeds maximum length or contains HTML")
	ErrInvalidURI              = errors.Register(ModuleName, 7, "uri is not a valid https:// URI or exceeds maximum length")
	ErrInvalidNotes            = errors.Register(ModuleName, 8, "notes field exceeds maximum length or contains HTML")
	ErrMissingEvidence         = errors.Register(ModuleName, 9, "dns_evidence_bundle is required for DNS_BOUND tier registration")
	ErrEvidenceTooOld          = errors.Register(ModuleName, 10, "dns_evidence_bundle was collected more than 1 hour before submission")
	ErrWeakDNSSECAlgorithm     = errors.Register(ModuleName, 11, "DNSSEC evidence uses a rejected algorithm (RSASHA1/5 not accepted)")
	ErrEvidenceMissingRRSIG    = errors.Register(ModuleName, 12, "dns_evidence_bundle missing required RRSIG records")
	ErrEvidenceMissingDNSKEY   = errors.Register(ModuleName, 13, "dns_evidence_bundle missing required DNSKEY records")
	ErrEvidenceMissingDS       = errors.Register(ModuleName, 14, "dns_evidence_bundle missing required DS records")

	// ── State / lifecycle ────────────────────────────────────────────────────
	ErrIdentityNotFound        = errors.Register(ModuleName, 20, "identity record not found for this address")
	ErrIdentityAlreadyExists   = errors.Register(ModuleName, 21, "identity already registered for this address")
	ErrDomainAlreadyRegistered = errors.Register(ModuleName, 22, "domain is already registered by another address")
	ErrIdentityNotActive       = errors.Register(ModuleName, 23, "identity record is not in ACTIVE status")
	ErrIdentityTerminal        = errors.Register(ModuleName, 24, "identity record is in a terminal state (REVOKED or SUPERSEDED)")
	ErrIdentityExpired         = errors.Register(ModuleName, 25, "identity record has expired")
	ErrMaxDomainsReached       = errors.Register(ModuleName, 26, "address has reached max_domains_per_address limit")
	ErrSelectorConflict        = errors.Register(ModuleName, 27, "selector is already in use for this domain")

	// ── Authorization ────────────────────────────────────────────────────────
	ErrNotIdentityOwner        = errors.Register(ModuleName, 30, "signer is not the registered identity owner")
	ErrInsufficientStake       = errors.Register(ModuleName, 31, "signer does not meet min_registration_stake requirement")
	ErrRotationAuthSigInvalid  = errors.Register(ModuleName, 32, "rotation_auth_sig is invalid (must be signed by the current active key)")
	ErrNewKeyProofSigInvalid   = errors.Register(ModuleName, 33, "new_key_domain_proof_sig is invalid (must be signed by the new key)")

	// ── Compliance tier ──────────────────────────────────────────────────────
	ErrTierDowngrade           = errors.Register(ModuleName, 40, "operation would result in a tier downgrade")
	ErrExpertTierRequirements  = errors.Register(ModuleName, 41, "address does not meet expert_tier_min_reputation_score requirement")
)