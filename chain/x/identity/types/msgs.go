// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// htmlTagRe detects any HTML tag in free-text fields.
var htmlTagRe = regexp.MustCompile(`<[^>]+>`)

// MaxTimestampSkewSeconds is the maximum allowed drift between the client
// published_at timestamp and the chain's current block time.
const MaxTimestampSkewSeconds = 300 // 5 minutes

// ============================================================
// MsgRegisterIdentity
// ============================================================

// MsgRegisterIdentity registers a new DNS-anchored signing identity on-chain.
// The transaction must be signed by the Cosmos key at CosmosAddr.
type MsgRegisterIdentity struct {
	// Cosmos bech32 address of the registrant (must match tx signer)
	CosmosAddr string `json:"cosmos_addr"`

	// Normalized domain name (will also be normalized server-side)
	Domain string `json:"domain"`

	// DNS selector for the TAT key record
	Selector string `json:"selector"`

	// Compressed secp256k1 public key (hex, 66 chars)
	PublicKeyHex string `json:"public_key_hex"`

	// Human-readable identity name (optional)
	Name string `json:"name,omitempty"`

	// Identity URI (optional, must be https://)
	URI string `json:"uri,omitempty"`

	// IdentityFlag bitmask
	Flags IdentityFlag `json:"flags,omitempty"`

	// Domain proof signature (hex, 128 chars)
	// Signs DomainProofPayload(domain, selector, cosmosAddr, publishedAt)
	DomainProofSig string `json:"domain_proof_sig"`

	// Unix timestamp used as registeredAt anchor for the proof payload;
	// must be within MaxTimestampSkewSeconds of the block time.
	PublishedAt int64 `json:"published_at"`

	// DNSSEC evidence bundle (required when params.DNSBoundTierRequiresDNSSEC)
	Evidence *DNSEvidenceBundle `json:"evidence,omitempty"`

	// TTL override in seconds (0 = use params.IdentityTTLSeconds)
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// ValidateBasic performs stateless validation of MsgRegisterIdentity.
func (m *MsgRegisterIdentity) ValidateBasic() error {
	if strings.TrimSpace(m.CosmosAddr) == "" {
		return fmt.Errorf("cosmos_addr is required")
	}
	if _, err := NormalizeDomain(m.Domain); err != nil {
		return ErrInvalidDomain.Wrapf("%v", err)
	}
	if err := ValidateSelector(m.Selector); err != nil {
		return ErrInvalidSelector.Wrapf("%v", err)
	}
	if len(m.PublicKeyHex) != PubKeyHexLen {
		return ErrInvalidPublicKey.Wrapf("got %d chars, want %d", len(m.PublicKeyHex), PubKeyHexLen)
	}
	if !isHex(m.PublicKeyHex) {
		return ErrInvalidPublicKey.Wrap("not valid hex")
	}
	if len(m.DomainProofSig) != MaxProofHex {
		return ErrInvalidDomainProofSig.Wrapf("got %d chars, want %d", len(m.DomainProofSig), MaxProofHex)
	}
	if !isHex(m.DomainProofSig) {
		return ErrInvalidDomainProofSig.Wrap("not valid hex")
	}
	if m.PublishedAt <= 0 {
		return fmt.Errorf("published_at must be a positive Unix timestamp")
	}
	if skew := abs64(time.Now().Unix() - m.PublishedAt); skew > MaxTimestampSkewSeconds {
		return fmt.Errorf("published_at skew %d s exceeds maximum %d s", skew, MaxTimestampSkewSeconds)
	}
	if m.Name != "" {
		if len(m.Name) > MaxNameLen {
			return ErrInvalidName.Wrapf("name length %d > %d", len(m.Name), MaxNameLen)
		}
		if htmlTagRe.MatchString(m.Name) {
			return ErrInvalidName.Wrap("name must not contain HTML tags")
		}
	}
	if m.URI != "" {
		if len(m.URI) > MaxURILen {
			return ErrInvalidURI.Wrapf("uri length %d > %d", len(m.URI), MaxURILen)
		}
		if !strings.HasPrefix(m.URI, "https://") {
			return ErrInvalidURI.Wrap("uri must start with https://")
		}
	}
	if m.TTLSeconds != 0 &&
		(m.TTLSeconds < MinIdentityTTLSeconds || m.TTLSeconds > MaxIdentityTTLSeconds) {
		return fmt.Errorf("ttl_seconds %d outside [%d, %d]",
			m.TTLSeconds, MinIdentityTTLSeconds, MaxIdentityTTLSeconds)
	}
	return nil
}

// ============================================================
// MsgRotateIdentityKey
// ============================================================

// MsgRotateIdentityKey performs a DKIM-style dual-selector key rotation.
// Both the old key (via RotationAuthSig) and the new key (via NewKeyDomainProofSig)
// must produce valid signatures to authorize the rotation.
type MsgRotateIdentityKey struct {
	// Cosmos bech32 address of the identity owner
	CosmosAddr string `json:"cosmos_addr"`

	// New selector for the replacement TAT key record
	NewSelector string `json:"new_selector"`

	// New compressed secp256k1 public key (hex, 66 chars)
	NewPublicKeyHex string `json:"new_public_key_hex"`

	// Rotation authorization signature by the CURRENT active key.
	// Signs SHA-256("tatkey-rotation-auth|domain|oldSelector|newSelector|cosmosAddr|rotatedAt")
	RotationAuthSig string `json:"rotation_auth_sig"`

	// Domain proof signature by the NEW key.
	// Signs DomainProofPayload(domain, newSelector, cosmosAddr, rotatedAt)
	NewKeyDomainProofSig string `json:"new_key_domain_proof_sig"`

	// Unix timestamp anchoring both rotation signatures
	RotatedAt int64 `json:"rotated_at"`

	// Updated DNSSEC evidence bundle for the new selector
	Evidence *DNSEvidenceBundle `json:"evidence,omitempty"`

	// Optional notes about the rotation reason
	Notes string `json:"notes,omitempty"`
}

// ValidateBasic performs stateless validation of MsgRotateIdentityKey.
func (m *MsgRotateIdentityKey) ValidateBasic() error {
	if strings.TrimSpace(m.CosmosAddr) == "" {
		return fmt.Errorf("cosmos_addr is required")
	}
	if err := ValidateSelector(m.NewSelector); err != nil {
		return ErrInvalidSelector.Wrapf("new_selector: %v", err)
	}
	if len(m.NewPublicKeyHex) != PubKeyHexLen || !isHex(m.NewPublicKeyHex) {
		return ErrInvalidPublicKey.Wrap("new_public_key_hex invalid")
	}
	if len(m.RotationAuthSig) != MaxProofHex || !isHex(m.RotationAuthSig) {
		return ErrRotationAuthSigInvalid.Wrap("rotation_auth_sig invalid")
	}
	if len(m.NewKeyDomainProofSig) != MaxProofHex || !isHex(m.NewKeyDomainProofSig) {
		return ErrNewKeyProofSigInvalid.Wrap("new_key_domain_proof_sig invalid")
	}
	if m.RotatedAt <= 0 {
		return fmt.Errorf("rotated_at must be a positive Unix timestamp")
	}
	if skew := abs64(time.Now().Unix() - m.RotatedAt); skew > MaxTimestampSkewSeconds {
		return fmt.Errorf("rotated_at skew %d s exceeds maximum %d s", skew, MaxTimestampSkewSeconds)
	}
	if m.Notes != "" {
		if len(m.Notes) > MaxNotesLen {
			return ErrInvalidNotes.Wrapf("notes length %d > %d", len(m.Notes), MaxNotesLen)
		}
		if htmlTagRe.MatchString(m.Notes) {
			return ErrInvalidNotes.Wrap("notes must not contain HTML tags")
		}
	}
	return nil
}

// ============================================================
// MsgRevokeIdentity
// ============================================================

// MsgRevokeIdentity voluntarily revokes an active identity record.
// Once revoked, the record cannot be reinstated; a new registration is required.
type MsgRevokeIdentity struct {
	// Cosmos bech32 address of the identity owner (must match tx signer)
	CosmosAddr string `json:"cosmos_addr"`

	// Human-readable revocation reason (optional, max 512 chars)
	Reason string `json:"reason,omitempty"`
}

// ValidateBasic performs stateless validation of MsgRevokeIdentity.
func (m *MsgRevokeIdentity) ValidateBasic() error {
	if strings.TrimSpace(m.CosmosAddr) == "" {
		return fmt.Errorf("cosmos_addr is required")
	}
	if m.Reason != "" {
		if len(m.Reason) > MaxNotesLen {
			return ErrInvalidNotes.Wrapf("reason length %d > %d", len(m.Reason), MaxNotesLen)
		}
		if htmlTagRe.MatchString(m.Reason) {
			return ErrInvalidNotes.Wrap("reason must not contain HTML tags")
		}
	}
	return nil
}

// ============================================================
// MsgRenewIdentity
// ============================================================

// MsgRenewIdentity extends the expiry of an active identity record and
// refreshes the DNSSEC evidence bundle.
type MsgRenewIdentity struct {
	// Cosmos bech32 address of the identity owner (must match tx signer)
	CosmosAddr string `json:"cosmos_addr"`

	// Fresh DNSSEC evidence bundle (required; must have been collected within 1 h)
	Evidence DNSEvidenceBundle `json:"evidence"`

	// TTL extension in seconds (0 = use params.IdentityTTLSeconds)
	TTLSeconds int64 `json:"ttl_seconds,omitempty"`
}

// ValidateBasic performs stateless validation of MsgRenewIdentity.
func (m *MsgRenewIdentity) ValidateBasic() error {
	if strings.TrimSpace(m.CosmosAddr) == "" {
		return fmt.Errorf("cosmos_addr is required")
	}
	if len(m.Evidence.TXTRecords) == 0 {
		return ErrMissingEvidence.Wrap("evidence.txt_records is empty")
	}
	if len(m.Evidence.TXTRRSIGs) == 0 {
		return ErrEvidenceMissingRRSIG.Wrap("evidence.txt_rrsigs is empty")
	}
	if m.TTLSeconds != 0 &&
		(m.TTLSeconds < MinIdentityTTLSeconds || m.TTLSeconds > MaxIdentityTTLSeconds) {
		return fmt.Errorf("ttl_seconds %d outside [%d, %d]",
			m.TTLSeconds, MinIdentityTTLSeconds, MaxIdentityTTLSeconds)
	}
	return nil
}

// ============================================================
// Helpers
// ============================================================

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}