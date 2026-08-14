// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import "cosmossdk.io/errors"

var (
	// ── Artifact / input validation ─────────────────────────────────────────────
	ErrInvalidArtifactType      = errors.Register(ModuleName, 2, "invalid artifact type")
	ErrInvalidSHA256            = errors.Register(ModuleName, 3, "invalid sha256 hash")
	ErrTimestampSkew            = errors.Register(ModuleName, 4, "published_at timestamp outside tolerance window")
	ErrTTLOutOfRange            = errors.Register(ModuleName, 5, "ttl_seconds outside allowed range")
	ErrInvalidConfidence        = errors.Register(ModuleName, 6, "confidence must be 0-100")
	ErrMissingThreatCategory    = errors.Register(ModuleName, 7, "threat_category must have at least one entry")
	ErrInvalidThreatCategory    = errors.Register(ModuleName, 8, "unrecognized threat_category code")
	ErrDescriptionTooLong       = errors.Register(ModuleName, 9, "description exceeds 1024 bytes")
	ErrHTMLInDescription        = errors.Register(ModuleName, 10, "description must not contain HTML tags")
	ErrHTMLNotAllowed           = ErrHTMLInDescription // alias used in msgs
	ErrInsufficientDelegation   = errors.Register(ModuleName, 11, "attester does not meet minimum delegation requirement")
	ErrReservedIPv4             = errors.Register(ModuleName, 12, "ipv4 address is within an IANA reserved range")
	ErrIPv4LowConfidence        = errors.Register(ModuleName, 13, "ipv4 attestation confidence below minimum")
	ErrIPv4TTLExceeded          = errors.Register(ModuleName, 14, "ipv4 attestation ttl exceeds maximum allowed")
	ErrInvalidIPFSCID           = errors.Register(ModuleName, 15, "rule_ipfs_cid is not a valid CIDv1 string")
	ErrInvalidCID               = ErrInvalidIPFSCID // alias used in msgs
	ErrCIDv0Deprecated          = errors.Register(ModuleName, 16, "CIDv0 format is deprecated; use CIDv1")
	ErrTooManyRules             = errors.Register(ModuleName, 17, "detection_rules exceeds maximum allowed count")
	ErrAttesterBlacklisted      = errors.Register(ModuleName, 18, "attester address is blacklisted")
	ErrRateLimitExceeded        = errors.Register(ModuleName, 19, "attester exceeded max attestations per epoch")
	ErrAttestationNotFound      = errors.Register(ModuleName, 20, "attestation not found")
	ErrAttestationNotActive     = errors.Register(ModuleName, 21, "attestation is not in ACTIVE status")
	ErrNotActive                = ErrAttestationNotActive // alias used in keeper/msg_server
	ErrSelfEndorsement          = errors.Register(ModuleName, 22, "endorser cannot be the original attester")
	ErrSelfEndorse              = ErrSelfEndorsement // alias used in keeper
	ErrDuplicateEndorsement     = errors.Register(ModuleName, 23, "address has already endorsed this attestation")
	ErrAlreadyEndorsed          = ErrDuplicateEndorsement // alias used in keeper
	ErrInvalidDisputeGround     = errors.Register(ModuleName, 24, "dispute ground must not be UNSPECIFIED")
	ErrInsufficientDisputeBond  = errors.Register(ModuleName, 25, "insufficient funds for dispute bond")
	ErrSupersedeMismatch        = errors.Register(ModuleName, 26, "supersedes target belongs to a different attester")
	ErrUnauthorized             = errors.Register(ModuleName, 27, "unauthorized: only the original attester may perform this action")
	ErrUnauthorizedRevoke       = ErrUnauthorized // alias used in keeper
	ErrDisputeNotFound          = errors.Register(ModuleName, 28, "dispute not found")
	ErrEmptyArtifactHash        = errors.Register(ModuleName, 29, "artifact_sha256 must not be the hash of empty bytes")
	ErrInvalidTagLength         = errors.Register(ModuleName, 30, "each tag must not exceed 32 bytes")
	ErrTagTooLong               = ErrInvalidTagLength // alias used in msgs
	ErrTooManyTags              = errors.Register(ModuleName, 31, "tags array exceeds maximum of 16 entries")
	ErrInvalidThreatCategoryLen = errors.Register(ModuleName, 32, "threat_category array exceeds maximum of 8 entries")
	ErrTooManyCategories        = ErrInvalidThreatCategoryLen // alias used in msgs

	// ── Additional errors (codes 33+) ────────────────────────────────────────────
	ErrInvalidAttesterAddress = errors.Register(ModuleName, 33, "invalid attester bech32 address")
	ErrInvalidSignature       = errors.Register(ModuleName, 34, "attestation signature is invalid")
	ErrInsufficientReputation = errors.Register(ModuleName, 35, "attester reputation score below required threshold")
	ErrTooManyRelatedTo       = errors.Register(ModuleName, 36, "related_to array exceeds maximum allowed entries")
	ErrMissingRawValue        = errors.Register(ModuleName, 37, "raw_value is required for url/ipv4 artifact types")
	ErrSHA256Mismatch         = errors.Register(ModuleName, 38, "artifact_sha256 does not match sha256(raw_value)")
	ErrInvalidURL             = errors.Register(ModuleName, 39, "raw_value is not a valid URL")
	ErrAlreadyRevoked         = errors.Register(ModuleName, 40, "attestation is already revoked")
	ErrSelfDispute            = errors.Register(ModuleName, 41, "attester cannot dispute their own attestation")
	ErrReputation             = errors.Register(ModuleName, 42, "reputation service error")
	ErrInvalidParams          = errors.Register(ModuleName, 43, "invalid module parameters")
	ErrDuplicateAttestation   = errors.Register(ModuleName, 44, "identical attestation already exists and is active")

	// ── PUA / Adware / Phishing URL / Domain (codes 45+) ─────────────────────
	ErrInvalidDomain                  = errors.Register(ModuleName, 45, "raw_value is not a valid domain name")
	ErrCategoryArtifactMismatch       = errors.Register(ModuleName, 46, "threat_category is not valid for the specified artifact_type")
	ErrPUARequiresFile                = errors.Register(ModuleName, 47, "TATST:PUA category requires ArtifactType FILE")
	ErrAdwareRequiresDomainOrURL      = errors.Register(ModuleName, 48, "TATST:ADWARE/MALVERTISING category requires ArtifactType URL or DOMAIN")
	ErrPhishingURLRequiresDomainOrURL = errors.Register(ModuleName, 49, "TATST:PHISHING_URL/PHISHING_SITE category requires ArtifactType URL or DOMAIN")
	ErrPUABehaviorNotesToolong        = errors.Register(ModuleName, 50, "pua_info.behavior_notes exceeds 512 bytes")
	ErrPUAInfoOnNonFile               = errors.Register(ModuleName, 51, "pua_info may only be set when artifact_type is FILE")
	ErrDomainSHA256Mismatch           = errors.Register(ModuleName, 52, "artifact_sha256 does not match sha256(normalized_domain)")
	ErrIncentivePoolEmpty             = errors.Register(ModuleName, 53, "incentive pool is empty")
	ErrSubscriptionNotFound           = errors.Register(ModuleName, 54, "subscription not found")
	ErrInvalidTier                    = errors.Register(ModuleName, 55, "invalid subscription tier")
	ErrInvalidHollomanSignature       = errors.Register(ModuleName, 56, "invalid holloman signature (must be 32 lowercase hex chars)")
	ErrInvalidHammingMask             = errors.Register(ModuleName, 57, "invalid hamming mask (must be 0-128)")
	ErrHollomanSignatureRequired      = errors.Register(ModuleName, 58, "holloman_signature is required for EMAIL_BODY artifacts")
)
