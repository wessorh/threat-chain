// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ============================================================
// Constants
// ============================================================

const (
	// SchemaVersion is the current identity record schema version.
	SchemaVersion = 1

	// DNS record field constraints
	MaxSelectorLen   = 63  // DNS label max length
	MaxDomainLen     = 253 // DNS name max length
	MaxNameLen       = 128 // human-readable name
	MaxURILen        = 512 // identity URI
	MaxNotesLen      = 512 // revocation/rotation notes
	MaxProofHex      = 128 // 64-byte ECDSA sig → 128 hex chars
	PubKeyHexLen     = 66  // compressed secp256k1 pubkey → 33 bytes → 66 hex chars

	// Trust score deltas (in Reputation Score units)
	TrustScoreRegistration  int64 = 200
	TrustScoreMilestone30d  int64 = 50
	TrustScoreRenewal       int64 = 10
	TrustScoreDNSRemoved    int64 = -200
	TrustScoreRevoked       int64 = -100

	// Default TTL values (seconds)
	DefaultIdentityTTLSeconds int64 = 365 * 24 * 3600 // 1 year
	MinIdentityTTLSeconds     int64 = 30 * 24 * 3600  // 30 days
	MaxIdentityTTLSeconds     int64 = 3 * 365 * 24 * 3600 // 3 years

	// DNSSEC algorithm identifiers (RFC 4034 §A.1)
	AlgRSASHA1         = 5  // REJECTED
	AlgRSASHA256       = 8  // ALLOWED
	AlgRSASHA512       = 10 // ALLOWED
	AlgECDSAP256SHA256 = 13 // RECOMMENDED
	AlgECDSAP384SHA384 = 14 // ALLOWED
	AlgED25519         = 15 // ALLOWED

	// TXT record version tag
	TATKeyVersion = "TAT1"

	// Domain proof payload prefix
	DomainProofPrefix = "tatkey-domain-proof"
)

// ============================================================
// DNSIDStatus — lifecycle state of a DNS identity record
// ============================================================

type DNSIDStatus int32

const (
	DNSIDStatus_UNKNOWN     DNSIDStatus = 0
	DNSIDStatus_PENDING     DNSIDStatus = 1 // registered, awaiting first DNS verification epoch
	DNSIDStatus_ACTIVE      DNSIDStatus = 2 // verified and live
	DNSIDStatus_EXPIRED     DNSIDStatus = 3 // TTL elapsed without renewal
	DNSIDStatus_REVOKED     DNSIDStatus = 4 // explicitly revoked by owner or governance
	DNSIDStatus_DNS_REMOVED DNSIDStatus = 5 // DNS TXT record no longer resolves
	DNSIDStatus_SUPERSEDED  DNSIDStatus = 6 // replaced by a rotation
)

func (s DNSIDStatus) String() string {
	switch s {
	case DNSIDStatus_PENDING:
		return "PENDING"
	case DNSIDStatus_ACTIVE:
		return "ACTIVE"
	case DNSIDStatus_EXPIRED:
		return "EXPIRED"
	case DNSIDStatus_REVOKED:
		return "REVOKED"
	case DNSIDStatus_DNS_REMOVED:
		return "DNS_REMOVED"
	case DNSIDStatus_SUPERSEDED:
		return "SUPERSEDED"
	default:
		return "UNKNOWN"
	}
}

// IsTerminal returns true if the status is a terminal (non-recoverable) state.
func (s DNSIDStatus) IsTerminal() bool {
	return s == DNSIDStatus_REVOKED || s == DNSIDStatus_SUPERSEDED
}

// ============================================================
// IdentityFlags — bitmask for optional identity capabilities
// ============================================================

type IdentityFlag uint32

const (
	IdentityFlag_NONE           IdentityFlag = 0
	IdentityFlag_EXPERT         IdentityFlag = 1 << 0 // Tier-3 expert designation
	IdentityFlag_ORGANIZATION   IdentityFlag = 1 << 1 // organizational identity
	IdentityFlag_GOVERNMENT     IdentityFlag = 1 << 2 // government entity
	IdentityFlag_SECURITY_FIRM  IdentityFlag = 1 << 3 // professional security firm
	IdentityFlag_AUTOMATED      IdentityFlag = 1 << 4 // automated/bot identity
	IdentityFlag_MULTISIG       IdentityFlag = 1 << 5 // key is a multisig key
)

// ============================================================
// ComplianceTier — attestation weight multiplier tiers
// ============================================================

type ComplianceTier int32

const (
	ComplianceTier_ANONYMOUS  ComplianceTier = 0 // 0.25× weight
	ComplianceTier_STAKED     ComplianceTier = 1 // 0.50× weight
	ComplianceTier_DNS_BOUND  ComplianceTier = 2 // 1.00× weight
	ComplianceTier_EXPERT     ComplianceTier = 3 // 2.00× weight
)

// TierMultiplierNumerator returns the numerator of tier weight fraction (denom=4).
// Tier0=1/4, Tier1=2/4, Tier2=4/4, Tier3=8/4
func (t ComplianceTier) TierMultiplierNumerator() int64 {
	switch t {
	case ComplianceTier_STAKED:
		return 2
	case ComplianceTier_DNS_BOUND:
		return 4
	case ComplianceTier_EXPERT:
		return 8
	default: // ANONYMOUS
		return 1
	}
}

func (t ComplianceTier) String() string {
	switch t {
	case ComplianceTier_STAKED:
		return "STAKED"
	case ComplianceTier_DNS_BOUND:
		return "DNS_BOUND"
	case ComplianceTier_EXPERT:
		return "EXPERT"
	default:
		return "ANONYMOUS"
	}
}

// ============================================================
// DNSEvidenceBundle — attester-supplied DNSSEC proof material
// ============================================================

// RRSIGRecord holds one RRSIG resource record (RFC 4034 §3).
type RRSIGRecord struct {
	TypeCovered  string `json:"type_covered"`   // e.g. "TXT"
	Algorithm    int    `json:"algorithm"`       // DNSSEC algorithm number
	Labels       int    `json:"labels"`
	OriginalTTL  uint32 `json:"original_ttl"`
	Expiration   int64  `json:"expiration"`      // Unix timestamp
	Inception    int64  `json:"inception"`       // Unix timestamp
	KeyTag       int    `json:"key_tag"`
	SignerName   string `json:"signer_name"`
	Signature    string `json:"signature"`       // base64
}

// DNSKEYRecord holds one DNSKEY resource record (RFC 4034 §2).
type DNSKEYRecord struct {
	Flags     int    `json:"flags"`     // 256=ZSK, 257=KSK
	Protocol  int    `json:"protocol"`  // must be 3
	Algorithm int    `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64
	KeyTag    int    `json:"key_tag"`    // computed
}

// DSRecord holds one DS resource record (RFC 4034 §5).
type DSRecord struct {
	KeyTag     int    `json:"key_tag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digest_type"` // 2=SHA-256
	Digest     string `json:"digest"`      // hex
}

// DNSEvidenceBundle carries the full DNSSEC validation chain for a single
// domain's TAT key record at the time of on-chain registration.
type DNSEvidenceBundle struct {
	// The raw TXT record value(s) at {selector}._tatkey.{domain}
	TXTRecords []string `json:"txt_records"`
	// RRSIG covering the TXT RRset
	TXTRRSIGs []RRSIGRecord `json:"txt_rrsigs"`
	// DNSKEY RRset at the zone apex
	ZoneDNSKEYs []DNSKEYRecord `json:"zone_dnskeys"`
	// RRSIG covering the DNSKEY RRset
	DNSKEYRRSIGs []RRSIGRecord `json:"dnskey_rrsigs"`
	// DS record from parent zone (proves KSK delegation)
	ParentDS []DSRecord `json:"parent_ds"`
	// Unix timestamp when this bundle was collected
	CollectedAt int64 `json:"collected_at"`
	// Resolver that produced this bundle (informational)
	Resolver string `json:"resolver,omitempty"`
}

// ============================================================
// DNSIdentityRecord — the on-chain "identity block"
// ============================================================

// DNSIdentityRecord is the canonical on-chain identity record that ties a
// Cosmos address to a DNSSEC-secured domain name.  It is stored at key
// idrecord/{cosmosAddr} and indexed by domain and identity ID.
type DNSIdentityRecord struct {
	// ── Identity fields ──────────────────────────────────────────────────────
	// Globally unique identity ID: SHA-256(cosmosAddr|"|"|domain|"|"|registeredAt)
	IdentityID string `json:"identity_id"`

	// Cosmos bech32 address of the identity owner
	CosmosAddr string `json:"cosmos_addr"`

	// Normalized domain name (lowercase, no leading www., no trailing dot)
	Domain string `json:"domain"`

	// DNS selector for the TAT key record: {selector}._tatkey.{domain}
	Selector string `json:"selector"`

	// Compressed secp256k1 public key (hex, 66 chars = 33 bytes)
	PublicKeyHex string `json:"public_key_hex"`

	// Human-readable identity name (optional, max 128 chars)
	Name string `json:"name,omitempty"`

	// Identity URI — link to a profile, policy page, or contact (optional)
	URI string `json:"uri,omitempty"`

	// Bitmask of IdentityFlag values
	Flags IdentityFlag `json:"flags,omitempty"`

	// ── Lifecycle fields ─────────────────────────────────────────────────────

	Status DNSIDStatus `json:"status"`

	// Unix timestamp of initial registration (never changes)
	RegisteredAt int64 `json:"registered_at"`

	// Unix timestamp of last successful DNS re-verification
	LastVerifiedAt int64 `json:"last_verified_at,omitempty"`

	// Unix timestamp after which the record is considered expired
	ExpiresAt int64 `json:"expires_at"`

	// ── Proof fields ─────────────────────────────────────────────────────────

	// Domain proof signature (hex, 128 chars = 64 bytes ECDSA sig)
	// Signs SHA-256("tatkey-domain-proof|domain|selector|cosmosAddr|registeredAt")
	DomainProofSig string `json:"domain_proof_sig"`

	// DNSSEC evidence bundle supplied at registration time
	Evidence DNSEvidenceBundle `json:"evidence"`

	// ── Attestation cross-reference ─────────────────────────────────────────

	// ID of the TATST:IDENTITY attestation published for this record
	AttestationID string `json:"attestation_id,omitempty"`

	// Cosmos block height at which the record was registered
	RegisteredAtBlock int64 `json:"registered_at_block,omitempty"`

	// ── Rotation tracking ───────────────────────────────────────────────────

	// Previous selector (populated during key rotation)
	PreviousSelector string `json:"previous_selector,omitempty"`

	// Unix timestamp when rotation was completed
	RotatedAt int64 `json:"rotated_at,omitempty"`

	// Notes supplied at revocation time (max 512 chars)
	RevocationNotes string `json:"revocation_notes,omitempty"`

	// SchemaVersion of this record
	SchemaVersion int `json:"schema_version"`
}

// ============================================================
// Identity ID computation
// ============================================================

// ComputeIdentityID computes the canonical identity ID from its three
// primary anchors.  The result is a lower-hex SHA-256 digest.
//
//	identity_id = hex(SHA-256(cosmosAddr + "|" + domain + "|" + strconv.FormatInt(registeredAt, 10)))
func ComputeIdentityID(cosmosAddr, domain string, registeredAt int64) string {
	payload := fmt.Sprintf("%s|%s|%d", cosmosAddr, domain, registeredAt)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ============================================================
// Domain proof payload construction
// ============================================================

// DomainProofPayload returns the 32-byte SHA-256 digest that the identity key
// must sign to prove simultaneous control of both the domain and the Cosmos key.
//
//	payload = SHA-256("tatkey-domain-proof|" + domain + "|" + selector + "|" + cosmosAddr + "|" + registeredAt)
func DomainProofPayload(domain, selector, cosmosAddr string, registeredAt int64) []byte {
	raw := fmt.Sprintf("%s|%s|%s|%s|%d",
		DomainProofPrefix, domain, selector, cosmosAddr, registeredAt)
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// ============================================================
// Domain normalization helpers
// ============================================================

var domainLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$`)

// NormalizeDomain lowercases, strips scheme/port/path/trailing dot, and
// optionally strips a leading "www." subdomain.  Returns an error if the
// result is not a valid DNS name with at least two labels.
func NormalizeDomain(raw string) (string, error) {
	d := strings.TrimSpace(raw)
	if d == "" {
		return "", fmt.Errorf("domain is empty")
	}

	// Strip scheme if present.
	if idx := strings.Index(d, "://"); idx != -1 {
		u, err := url.Parse(d)
		if err != nil {
			return "", fmt.Errorf("cannot parse domain URL: %w", err)
		}
		d = u.Hostname()
	}

	// Strip port if present.
	if h, _, err := net.SplitHostPort(d); err == nil {
		d = h
	}

	// Lowercase and strip trailing dot.
	d = strings.ToLower(strings.TrimSuffix(d, "."))

	// Strip leading www.
	d = strings.TrimPrefix(d, "www.")

	if len(d) == 0 || len(d) > MaxDomainLen {
		return "", fmt.Errorf("domain length %d outside valid range [1,%d]", len(d), MaxDomainLen)
	}

	// Validate each label.
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must have at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 {
			return "", fmt.Errorf("domain has empty label")
		}
		if !domainLabelRe.MatchString(label) {
			return "", fmt.Errorf("invalid domain label %q", label)
		}
	}
	return d, nil
}

// ValidateSelector validates a DNS selector (must be a valid single DNS label).
func ValidateSelector(sel string) error {
	if len(sel) == 0 || len(sel) > MaxSelectorLen {
		return fmt.Errorf("selector length %d outside valid range [1,%d]", len(sel), MaxSelectorLen)
	}
	if !domainLabelRe.MatchString(sel) {
		return fmt.Errorf("selector %q is not a valid DNS label", sel)
	}
	return nil
}

// TATKeyFQDN returns the fully qualified DNS name for the TAT key record.
//
//	{selector}._tatkey.{domain}
func TATKeyFQDN(selector, domain string) string {
	return fmt.Sprintf("%s._tatkey.%s", selector, domain)
}

// TATProofFQDN returns the FQDN for the domain proof TXT record.
//
//	_tatproof.{domain}
func TATProofFQDN(domain string) string {
	return fmt.Sprintf("_tatproof.%s", domain)
}

// TATActiveSelectorFQDN returns the FQDN for the active selector pointer.
//
//	_tatkey.{domain}
func TATActiveSelectorFQDN(domain string) string {
	return fmt.Sprintf("_tatkey.%s", domain)
}

// ============================================================
// GenesisState
// ============================================================

// GenesisState is the genesis state of the x/identity module.
type GenesisState struct {
	Params  Params              `json:"params"`
	Records []DNSIdentityRecord `json:"records,omitempty"`
}

// DefaultGenesisState returns the default genesis state.
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		Params:  DefaultParams(),
		Records: nil,
	}
}

// Validate performs basic validation of the genesis state.
func (gs GenesisState) Validate() error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid params: %w", err)
	}
	seen := make(map[string]bool)
	for i, r := range gs.Records {
		if seen[r.CosmosAddr] {
			return fmt.Errorf("record[%d]: duplicate cosmos_addr %q", i, r.CosmosAddr)
		}
		seen[r.CosmosAddr] = true
		if r.Domain == "" {
			return fmt.Errorf("record[%d]: empty domain", i)
		}
		if r.IdentityID == "" {
			return fmt.Errorf("record[%d]: empty identity_id", i)
		}
	}
	return nil
}

// ---- unused import guard ----
var _ = time.Now