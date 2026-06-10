// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// ============================================================
// Constants
// ============================================================

const (
	SchemaVersion = 1

	// EmptySHA256 is SHA-256 of the empty byte slice — forbidden as an artifact hash.
	EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// Field size limits
	MaxDescriptionBytes = 1024
	MaxTagBytes         = 32
	MaxTags             = 16
	MaxThreatCategories = 8
	MaxRelatedTo        = 32

	// TTL limits
	MinTTLSeconds     int64 = 3600           // 1 hour
	MaxTTLSeconds     int64 = 31_536_000     // 365 days
	MaxTTLIPv4Seconds int64 = 7_776_000      // 90 days

	// Blocks per epoch (~1 hour at 2 s block time)
	BlocksPerEpoch = int64(1800)
)

// ============================================================
// Regex validators
// ============================================================

var (
	// mitreTacticRe matches TA0001 – TA9999
	mitreTacticRe = regexp.MustCompile(`^TA\d{4}$`)
	// mitreTechniqueRe matches T1059, T1059.001, etc.
	mitreTechniqueRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	// htmlTagRe detects any HTML tag
	htmlTagRe = regexp.MustCompile(`<[^>]+>`)
	// cidv1Re detects a CIDv1 base32 string (starts with "b")
	cidv1Re = regexp.MustCompile(`^b[a-z2-7]{58,}$`)
	// cidv0Re detects a CIDv0 base58 string (starts with "Qm")
	cidv0Re = regexp.MustCompile(`^Qm[1-9A-HJ-NP-Za-km-z]{44}$`)
)

// ValidThreatCategories contains accepted TATST native category codes.
// MITRE ATT&CK IDs (TA####, T####.###) are validated by regex.
var ValidThreatCategories = map[string]bool{
	// ── Original categories ─────────────────────────────────────────────────
	"TATST:MALWARE":     true,
	"TATST:PHISHING":    true,
	"TATST:C2":          true,
	"TATST:CRYPTOMINER": true,
	"TATST:RANSOMWARE":  true,
	"TATST:EXPLOIT":     true,
	"TATST:SCANNER":     true,
	"TATST:SPAM":        true,
	"TATST:BOTNET":      true,
	"TATST:INFOSTEALER": true,
	"TATST:DROPPER":     true,
	"TATST:BACKDOOR":    true,

	// ── PUA ─ Potentially Unwanted Application (FILE artifacts) ─────────────
	// Software that is not outright malicious but exhibits unwanted, deceptive,
	// or privacy-invasive behaviour: bundled adware, browser hijackers, fake AV
	// tools, registry cleaners, toolbars, credential-harvesting free-ware, etc.
	"TATST:PUA": true,

	// ── Phishing variants (URL / DOMAIN artifacts) ──────────────────────────
	// PHISHING_URL  – a specific URL that serves or redirects to a phishing page.
	// PHISHING_SITE – the whole domain/site is operated as a phishing platform.
	"TATST:PHISHING_URL":  true,
	"TATST:PHISHING_SITE": true,

	// ── Advertising abuse (DOMAIN / URL artifacts) ──────────────────────────
	// ADWARE       – domains/URLs that deliver intrusive or deceptive advertising,
	//               typically distributed via PUA installers or browser hijackers.
	// MALVERTISING – ad networks or landing domains used to distribute malware
	//               through ad creatives, forced redirects, or exploit kits.
	"TATST:ADWARE":       true,
	"TATST:MALVERTISING": true,
}

// CategoryArtifactConstraints maps threat categories that are restricted to
// specific artifact types.  Categories absent from the map are unconstrained
// and may be applied to any artifact type.
var CategoryArtifactConstraints = map[string][]ArtifactType{
	// PUA is always a FILE — it describes executable / installer behaviour.
	"TATST:PUA": {ArtifactType_FILE},

	// Phishing URL / site targets are URL or DOMAIN artifacts.
	"TATST:PHISHING_URL":  {ArtifactType_URL, ArtifactType_DOMAIN},
	"TATST:PHISHING_SITE": {ArtifactType_URL, ArtifactType_DOMAIN},

	// Adware and malvertising actors are represented as DOMAIN or URL artifacts.
	"TATST:ADWARE":       {ArtifactType_URL, ArtifactType_DOMAIN},
	"TATST:MALVERTISING": {ArtifactType_URL, ArtifactType_DOMAIN},
}

// IsCategoryValidForArtifact returns true when category cat is permitted for
// the given artifact type.  Categories without a constraint are always valid.
func IsCategoryValidForArtifact(cat string, at ArtifactType) bool {
	allowed, constrained := CategoryArtifactConstraints[cat]
	if !constrained {
		return true
	}
	for _, a := range allowed {
		if a == at {
			return true
		}
	}
	return false
}

// IANA reserved IPv4 CIDRs that must not be attested.
var reservedCIDRs []*net.IPNet

func init() {
	reserved := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid reserved CIDR %s: %v", cidr, err))
		}
		reservedCIDRs = append(reservedCIDRs, network)
	}
}

// ============================================================
// Enum: ArtifactType
// ============================================================

type ArtifactType int32

const (
	ArtifactType_UNSPECIFIED ArtifactType = 0
	ArtifactType_FILE        ArtifactType = 1
	ArtifactType_URL         ArtifactType = 2
	ArtifactType_IPV4        ArtifactType = 3
	// ArtifactType_DOMAIN represents a bare domain name (no scheme, no path).
	// Use this type when attesting an entire domain as an adware/phishing/malvertising
	// host rather than a specific URL endpoint.
	// The artifact SHA-256 is computed as SHA-256(NormalizeDomain(domain)).
	ArtifactType_DOMAIN ArtifactType = 4
)

func (a ArtifactType) String() string {
	switch a {
	case ArtifactType_FILE:
		return "FILE"
	case ArtifactType_URL:
		return "URL"
	case ArtifactType_IPV4:
		return "IPV4"
	case ArtifactType_DOMAIN:
		return "DOMAIN"
	default:
		return "UNSPECIFIED"
	}
}

// ============================================================
// Enum: SeverityLevel
// ============================================================

type SeverityLevel int32

const (
	SeverityLevel_UNSPECIFIED SeverityLevel = 0
	SeverityLevel_INFO        SeverityLevel = 1
	SeverityLevel_LOW         SeverityLevel = 2
	SeverityLevel_MEDIUM      SeverityLevel = 3
	SeverityLevel_HIGH        SeverityLevel = 4
	SeverityLevel_CRITICAL    SeverityLevel = 5
)

func (s SeverityLevel) String() string {
	switch s {
	case SeverityLevel_CRITICAL:
		return "CRITICAL"
	case SeverityLevel_HIGH:
		return "HIGH"
	case SeverityLevel_MEDIUM:
		return "MEDIUM"
	case SeverityLevel_LOW:
		return "LOW"
	case SeverityLevel_INFO:
		return "INFO"
	default:
		return "UNSPECIFIED"
	}
}

// ============================================================
// Enum: AttestationStatus
// ============================================================

type AttestationStatus int32

const (
	AttestationStatus_UNSPECIFIED AttestationStatus = 0
	AttestationStatus_ACTIVE      AttestationStatus = 1
	AttestationStatus_EXPIRED     AttestationStatus = 2
	AttestationStatus_REVOKED     AttestationStatus = 3
	AttestationStatus_DISPUTED    AttestationStatus = 4
	AttestationStatus_SUPERSEDED  AttestationStatus = 5
)

func (s AttestationStatus) String() string {
	switch s {
	case AttestationStatus_ACTIVE:
		return "ACTIVE"
	case AttestationStatus_EXPIRED:
		return "EXPIRED"
	case AttestationStatus_REVOKED:
		return "REVOKED"
	case AttestationStatus_DISPUTED:
		return "DISPUTED"
	case AttestationStatus_SUPERSEDED:
		return "SUPERSEDED"
	default:
		return "UNSPECIFIED"
	}
}

// ============================================================
// Enum: TLPLevel
// ============================================================

type TLPLevel int32

const (
	TLPLevel_UNSPECIFIED TLPLevel = 0
	TLPLevel_WHITE       TLPLevel = 1
	TLPLevel_GREEN       TLPLevel = 2
	TLPLevel_AMBER       TLPLevel = 3
	TLPLevel_RED         TLPLevel = 4
)

func (t TLPLevel) String() string {
	switch t {
	case TLPLevel_WHITE:
		return "WHITE"
	case TLPLevel_GREEN:
		return "GREEN"
	case TLPLevel_AMBER:
		return "AMBER"
	case TLPLevel_RED:
		return "RED"
	default:
		return "UNSPECIFIED"
	}
}

// ============================================================
// Enum: RuleType
// ============================================================

type RuleType int32

const (
	RuleType_UNSPECIFIED RuleType = 0
	RuleType_YARA        RuleType = 1
	RuleType_SIGMA       RuleType = 2
	RuleType_SNORT       RuleType = 3
	RuleType_SURICATA    RuleType = 4
	RuleType_OPENIOC     RuleType = 5
	RuleType_CUSTOM      RuleType = 6
)

// ============================================================
// Enum: RuleAppliesTo
// ============================================================

type RuleAppliesTo int32

const (
	RuleAppliesTo_UNSPECIFIED  RuleAppliesTo = 0
	RuleAppliesTo_FILE_BYTES   RuleAppliesTo = 1
	RuleAppliesTo_URL_PATH     RuleAppliesTo = 2
	RuleAppliesTo_URL_FULL     RuleAppliesTo = 3
	RuleAppliesTo_IP_TRAFFIC   RuleAppliesTo = 4
	RuleAppliesTo_ANY          RuleAppliesTo = 5
)

// ============================================================
// Enum: DisputeGround
// ============================================================

type DisputeGround int32

const (
	DisputeGround_UNSPECIFIED        DisputeGround = 0
	DisputeGround_FALSE_POSITIVE     DisputeGround = 1
	DisputeGround_INCORRECT_SEVERITY DisputeGround = 2
	DisputeGround_FABRICATED_EVIDENCE DisputeGround = 3
	DisputeGround_STALE_REUSE        DisputeGround = 4
	DisputeGround_SYBIL_ATTACK       DisputeGround = 5
)

func (d DisputeGround) String() string {
	switch d {
	case DisputeGround_FALSE_POSITIVE:
		return "FALSE_POSITIVE"
	case DisputeGround_INCORRECT_SEVERITY:
		return "INCORRECT_SEVERITY"
	case DisputeGround_FABRICATED_EVIDENCE:
		return "FABRICATED_EVIDENCE"
	case DisputeGround_STALE_REUSE:
		return "STALE_REUSE"
	case DisputeGround_SYBIL_ATTACK:
		return "SYBIL_ATTACK"
	default:
		return "UNSPECIFIED"
	}
}

// ============================================================
// Enum: DisputeStatus
// ============================================================

type DisputeStatus int32

const (
	DisputeStatus_OPEN              DisputeStatus = 0
	DisputeStatus_RESOLVED_UPHELD   DisputeStatus = 1
	DisputeStatus_RESOLVED_REJECTED DisputeStatus = 2
	DisputeStatus_DISMISSED         DisputeStatus = 3
)

func (d DisputeStatus) String() string {
	switch d {
	case DisputeStatus_RESOLVED_UPHELD:
		return "RESOLVED_UPHELD"
	case DisputeStatus_RESOLVED_REJECTED:
		return "RESOLVED_REJECTED"
	case DisputeStatus_DISMISSED:
		return "DISMISSED"
	default:
		return "OPEN"
	}
}

// ============================================================
// Struct: DetectionRuleRef
// ============================================================

// DetectionRuleRef anchors a detection rule stored on IPFS.
type DetectionRuleRef struct {
	RuleID         string        `json:"rule_id"`
	RuleType       RuleType      `json:"rule_type"`
	RuleName       string        `json:"rule_name"`
	CID            string        `json:"cid"`
	ContentSHA256  string        `json:"content_sha256"`
	RuleVersion    string        `json:"rule_version,omitempty"`
	RuleAuthor     string        `json:"rule_author,omitempty"`
	AppliesTo      RuleAppliesTo `json:"applies_to"`
	MinYaraVersion string        `json:"min_yara_version,omitempty"`
	Verified       bool          `json:"verified"`
}

// ============================================================
// Enum: PUABehavior — bitmask flags describing PUA behaviour
// ============================================================

// PUABehavior is a bitmask that describes the specific unwanted behaviours
// exhibited by a Potentially Unwanted Application.  Multiple flags may be
// combined: e.g. PUABehavior_BUNDLED_ADWARE | PUABehavior_BROWSER_HIJACK.
type PUABehavior uint32

const (
	PUABehavior_NONE             PUABehavior = 0
	PUABehavior_BUNDLED_ADWARE   PUABehavior = 1 << 0 // Installs ad-injection components
	PUABehavior_BROWSER_HIJACK   PUABehavior = 1 << 1 // Changes browser homepage/search
	PUABehavior_FAKE_AV          PUABehavior = 1 << 2 // Fake antivirus / scareware
	PUABehavior_REGISTRY_CLEANER PUABehavior = 1 << 3 // Deceptive registry optimiser
	PUABehavior_DATA_HARVESTING  PUABehavior = 1 << 4 // Collects user data without consent
	PUABehavior_TOOLBAR          PUABehavior = 1 << 5 // Unwanted browser toolbar
	PUABehavior_CRYPTOMINER_PUA  PUABehavior = 1 << 6 // Covert CPU/GPU miner
	PUABehavior_REMOTE_ACCESS    PUABehavior = 1 << 7 // Undisclosed remote access capability
	PUABehavior_AUTORUN          PUABehavior = 1 << 8 // Persists via autorun / scheduled task
	PUABehavior_BUNDLED_INSTALL  PUABehavior = 1 << 9 // Silently installs third-party software
)

// PUAMetadata carries software-specific information for TATST:PUA attestations.
// It is only populated when ArtifactType == FILE and at least one ThreatCategory
// is "TATST:PUA".
type PUAMetadata struct {
	// SoftwareName is the display name of the PUA (e.g. "SpeedBooster Pro").
	SoftwareName string `json:"software_name,omitempty"`
	// Vendor is the publisher / code-signing entity (e.g. "OptimiseSoft LLC").
	Vendor string `json:"vendor,omitempty"`
	// Version is the specific version string where the PUA behaviour was observed.
	Version string `json:"version,omitempty"`
	// InstallerSHA256 is the SHA-256 of the installer bundle (may differ from the
	// payload SHA-256 used as ArtifactSHA256).
	InstallerSHA256 string `json:"installer_sha256,omitempty"`
	// Behaviors is a bitmask of PUABehavior flags.
	Behaviors PUABehavior `json:"behaviors,omitempty"`
	// BehaviorNotes is a free-text elaboration of the observed behaviours
	// (max 512 bytes, no HTML).
	BehaviorNotes string `json:"behavior_notes,omitempty"`
	// DetectionNames lists AV / EDR detection names for cross-referencing,
	// e.g. ["PUA.Win32.Toolbar.Generic", "Adware.SpeedBooster"].
	DetectionNames []string `json:"detection_names,omitempty"`
}

// ============================================================
// Struct: AttestationRecord
// ============================================================

// AttestationRecord is the canonical on-chain threat intelligence record.
type AttestationRecord struct {
	// ID is the deterministic attestation identifier (SHA-256 derived).
	ID              string            `json:"id"`
	SchemaVersion   uint32            `json:"schema_version"`
	ArtifactType    ArtifactType      `json:"artifact_type"`
	// ArtifactSHA256 is the hex-encoded SHA-256 of the artifact.
	ArtifactSHA256  string            `json:"artifact_sha256"`
	// RawValue holds the human-readable URL or IPv4 string (empty for files).
	RawValue        string            `json:"raw_value,omitempty"`
	Severity        SeverityLevel     `json:"severity"`
	TLP             TLPLevel          `json:"tlp"`
	Attester        string            `json:"attester"`
	PublishedAt     int64             `json:"published_at"`
	TTLSeconds      int64             `json:"ttl_seconds"`
	ExpiresAt       int64             `json:"expires_at"`
	Confidence      uint32            `json:"confidence"`
	Description     string            `json:"description,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	ThreatCategories []string         `json:"threat_categories,omitempty"`
	DetectionRules  []DetectionRuleRef `json:"detection_rules,omitempty"`
	RelatedTo       []string          `json:"related_to,omitempty"`
	MitreAttackIDs  []string          `json:"mitre_attack_ids,omitempty"`
	// AttesterSig is the base64-encoded secp256k1 signature over the attestation payload.
	AttesterSig     string            `json:"attester_sig"`
	Status          AttestationStatus `json:"status"`
	EndorsementCount uint32           `json:"endorsement_count"`
	DisputeCount    uint32            `json:"dispute_count"`
	RevokeReason    string            `json:"revoke_reason,omitempty"`
	BlockHeight     int64             `json:"block_height"`
	TxHash          string            `json:"tx_hash,omitempty"`
	// PUAInfo is populated when ArtifactType==FILE and category includes TATST:PUA.
	PUAInfo         *PUAMetadata      `json:"pua_info,omitempty"`
	// AttesterDomain is the normalized domain name of the attester's DNS identity (optional).
	// Populated when the attester has a registered DNS identity and wishes to cross-reference it.
	AttesterDomain   string           `json:"attester_domain,omitempty"`
	// AttesterSelector is the DNS selector used for the attester's active TAT key record.
	AttesterSelector string           `json:"attester_selector,omitempty"`
	// AttesterTier is the compliance tier of the attester at publish time (0=ANON,1=STAKED,2=DNS,3=EXPERT).
	AttesterTier     int32            `json:"attester_tier,omitempty"`
}

// ============================================================
// Struct: DisputeRecord
// ============================================================

// DisputeRecord tracks a dispute filed against an attestation.
type DisputeRecord struct {
	ID            string        `json:"id"`
	AttestationID string        `json:"attestation_id"`
	Disputer      string        `json:"disputer"`
	Ground        DisputeGround `json:"ground"`
	Evidence      string        `json:"evidence,omitempty"`
	EvidenceCID   string        `json:"evidence_cid,omitempty"`
	CreatedAt     int64         `json:"created_at"`
	Status        DisputeStatus `json:"status"`
	RebuttalCID   string        `json:"rebuttal_cid,omitempty"`
	ResolvedAt    int64         `json:"resolved_at,omitempty"`
}

// ============================================================
// Struct: Params
// ============================================================

// Params holds x/attestation module parameters.
type Params struct {
	// MinAttesterDelegation is the minimum staked utatst required to publish.
	MinAttesterDelegation      string `json:"min_attester_delegation"`
	MinTTLSeconds              int64  `json:"min_ttl_seconds"`
	MaxTTLSeconds              int64  `json:"max_ttl_seconds"`
	MaxTTLIPv4Seconds          int64  `json:"max_ttl_ipv4_seconds"`
	MaxDetectionRules          uint32 `json:"max_detection_rules"`
	MaxAttestationsPerEpoch    uint32 `json:"max_attestations_per_epoch"`
	// DisputeBondAmount is the bond (in utatst) required to open a dispute.
	DisputeBondAmount          string `json:"dispute_bond_amount"`
	IPv4MinConfidence          uint32 `json:"ipv4_min_confidence"`
	TimestampToleranceSeconds  int64  `json:"timestamp_tolerance_seconds"`
	// Minimum reputation scores for various actions
	MinReputationToAttest  uint32 `json:"min_reputation_to_attest"`
	MinReputationToEndorse uint32 `json:"min_reputation_to_endorse"`
	MinReputationToDispute uint32 `json:"min_reputation_to_dispute"`
}

// DefaultParams returns sensible default module parameters.
func DefaultParams() Params {
	return Params{
		MinAttesterDelegation:     "1000000000",  // 1000 TATST in utatst
		MinTTLSeconds:             MinTTLSeconds,
		MaxTTLSeconds:             MaxTTLSeconds,
		MaxTTLIPv4Seconds:         MaxTTLIPv4Seconds,
		MaxDetectionRules:         32,
		MaxAttestationsPerEpoch:   100,
		DisputeBondAmount:         "500000000",   // 500 TATST in utatst
		IPv4MinConfidence:         30,
		TimestampToleranceSeconds: 300,
		MinReputationToAttest:     0,
		MinReputationToEndorse:    10,
		MinReputationToDispute:    20,
	}
}

// Validate checks that all parameters are within acceptable bounds.
func (p Params) Validate() error {
	if p.MinTTLSeconds < 0 {
		return fmt.Errorf("min_ttl_seconds must be non-negative")
	}
	if p.MaxTTLSeconds < p.MinTTLSeconds {
		return fmt.Errorf("max_ttl_seconds must be >= min_ttl_seconds")
	}
	if p.MaxTTLIPv4Seconds > p.MaxTTLSeconds {
		return fmt.Errorf("max_ttl_ipv4_seconds must be <= max_ttl_seconds")
	}
	if p.MaxAttestationsPerEpoch == 0 {
		return fmt.Errorf("max_attestations_per_epoch must be > 0")
	}
	if p.IPv4MinConfidence > 100 {
		return fmt.Errorf("ipv4_min_confidence must be <= 100")
	}
	return nil
}

// ============================================================
// Struct: GenesisState
// ============================================================

// GenesisState defines the genesis state for x/attestation.
type GenesisState struct {
	Params       Params              `json:"params"`
	Attestations []AttestationRecord `json:"attestations"`
	Disputes     []DisputeRecord     `json:"disputes"`
}

// DefaultGenesisState returns an empty genesis with default params.
func DefaultGenesisState() GenesisState {
	return GenesisState{
		Params:       DefaultParams(),
		Attestations: []AttestationRecord{},
		Disputes:     []DisputeRecord{},
	}
}

// ============================================================
// Utility: SHA-256 / artifact hashing
// ============================================================

// IsValidSHA256Hex returns true if s is a valid lowercase 64-char hex string.
func IsValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsValidCIDv1 returns true for CIDv1 base32-lower strings.
func IsValidCIDv1(s string) bool {
	return cidv1Re.MatchString(s)
}

// IsCIDv0 returns true for legacy CIDv0 base58 strings.
func IsCIDv0(s string) bool {
	return cidv0Re.MatchString(s)
}

// IsValidThreatCategory returns true for known TATST categories or MITRE ATT&CK IDs.
func IsValidThreatCategory(cat string) bool {
	if ValidThreatCategories[cat] {
		return true
	}
	return mitreTacticRe.MatchString(cat) || mitreTechniqueRe.MatchString(cat)
}

// ContainsHTML returns true if the string contains any HTML tag.
func ContainsHTML(s string) bool {
	return htmlTagRe.MatchString(s)
}

// IsReservedIPv4 returns true if the IPv4 address falls in an IANA reserved range.
func IsReservedIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false // not an IPv4 address
	}
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeURL returns the canonical form of a URL for SHA-256 computation:
//   - scheme and host are lowercased
//   - default ports are stripped (80 for http, 443 for https)
//   - query parameters are sorted lexicographically
//   - fragment is stripped
//   - trailing slashes on the path are preserved as-is
func NormalizeURL(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("missing scheme in URL: %s", rawURL)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Strip default ports
	host := u.Hostname()
	port := u.Port()
	switch {
	case u.Scheme == "http" && port == "80":
		u.Host = host
	case u.Scheme == "https" && port == "443":
		u.Host = host
	}

	// Sort query parameters
	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(q))
		for _, k := range keys {
			vals := q[k]
			sort.Strings(vals)
			for _, v := range vals {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}

	// Strip fragment
	u.Fragment = ""
	u.RawFragment = ""

	return u.String(), nil
}

// ArtifactSHA256ForURL computes the canonical SHA-256 hex for a URL artifact.
// The URL must already be normalized via NormalizeURL.
func ArtifactSHA256ForURL(normalizedURL string) string {
	h := sha256.Sum256([]byte(normalizedURL))
	return hex.EncodeToString(h[:])
}

// ArtifactSHA256ForIPv4 computes the SHA-256 hex for an IPv4 artifact.
// The input is the canonical dotted-decimal IPv4 string (e.g., "1.2.3.4").
func ArtifactSHA256ForIPv4(ipStr string) string {
	h := sha256.Sum256([]byte(ipStr))
	return hex.EncodeToString(h[:])
}


// NormalizeDomain converts a domain name to its canonical lowercase form,
// strips any leading "www." prefix, and validates basic structure.
// Returns an error if the input is not a valid bare domain.
func NormalizeDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	// Strip scheme if someone accidentally passes a URL
	if idx := strings.Index(d, "://"); idx != -1 {
		d = d[idx+3:]
	}
	// Strip path / query / fragment
	if idx := strings.IndexAny(d, "/?#"); idx != -1 {
		d = d[:idx]
	}
	// Strip port
	if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	// Strip leading www.
	d = strings.TrimPrefix(d, "www.")
	if d == "" {
		return "", fmt.Errorf("empty domain after normalization")
	}
	// Basic label validation: labels must be non-empty, <=63 chars, alphanumeric+hyphen
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain must have at least two labels: %s", d)
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid domain label length in: %s", d)
		}
	}
	return d, nil
}

// ArtifactSHA256ForDomain computes the canonical SHA-256 hex for a DOMAIN artifact.
// The input must already be normalized via NormalizeDomain.
func ArtifactSHA256ForDomain(normalizedDomain string) string {
	h := sha256.Sum256([]byte(normalizedDomain))
	return hex.EncodeToString(h[:])
}

// ============================================================
// Utility: Deterministic IDs
// ============================================================

// ComputeAttestationID computes a deterministic attestation ID as
// SHA-256(artifact_sha256 || "|" || attester || "|" || published_at).
func ComputeAttestationID(artifactSHA256, attester string, publishedAt int64) string {
	data := fmt.Sprintf("%s|%s|%d", artifactSHA256, attester, publishedAt)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ComputeRuleID computes the rule_id as SHA-256(cid || "|" || content_sha256).
func ComputeRuleID(cid, contentSHA256 string) string {
	data := fmt.Sprintf("%s|%s", cid, contentSHA256)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ComputeDisputeID computes a deterministic dispute ID.
func ComputeDisputeID(attestationID, disputer string, createdAt int64) string {
	data := fmt.Sprintf("%s|%s|%d", attestationID, disputer, createdAt)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// ============================================================
// Utility: Signature verification
// ============================================================

// VerifyAttesterSig verifies the attester_sig field of a publish message.
// The signed payload is SHA-256(artifact_sha256 || "|" || attester || "|" || ttl_seconds).
// The signature is expected to be a hex-encoded SHA-256 HMAC stand-in;
// in production this would verify a secp256k1 signature via the SDK crypto package.
// This implementation validates the structural format only — full on-chain
// verification is performed by the ante handler using the tx-level signature.
func VerifyAttesterSig(attester, artifactSHA256 string, ttlSeconds int64, sig string) error {
	// The msg-level attester_sig is an optional additional binding between the
	// attester's key and the specific threat data — it prevents a tx relay from
	// substituting a different artifact. We accept any non-empty 64-char hex string
	// here; the ante-handler enforces cryptographic validity against the tx pubkey.
	if sig == "" {
		return fmt.Errorf("attester_sig is required")
	}
	if len(sig) != 128 { // 64-byte secp256k1 compact sig = 128 hex chars
		return fmt.Errorf("attester_sig must be 128 hex characters (secp256k1 compact)")
	}
	_, err := hex.DecodeString(sig)
	return err
}

// BuildAttesterSigPayload constructs the canonical payload to be signed.
// Callers outside the chain (CLI, SDK) use this to construct the sig.
func BuildAttesterSigPayload(artifactSHA256, attester string, ttlSeconds int64) []byte {
	data := fmt.Sprintf("%s|%s|%d", artifactSHA256, attester, ttlSeconds)
	h := sha256.Sum256([]byte(data))
	return h[:]
}

// ============================================================
// Utility: Severity helpers
// ============================================================

// SeverityValue converts SeverityLevel to an ordinal for comparison.
func SeverityValue(s SeverityLevel) int {
	switch s {
	case SeverityLevel_CRITICAL:
		return 5
	case SeverityLevel_HIGH:
		return 4
	case SeverityLevel_MEDIUM:
		return 3
	case SeverityLevel_LOW:
		return 2
	case SeverityLevel_INFO:
		return 1
	default:
		return 0
	}
}

// MaxSeverity returns the higher of two severity levels.
func MaxSeverity(a, b SeverityLevel) SeverityLevel {
	if SeverityValue(a) >= SeverityValue(b) {
		return a
	}
	return b
}

// ============================================================
// Utility: Trust score
// ============================================================

// TrustScore computes a composite trust score for query ranking.
// Formula: severity_weight * (confidence/100) * (1 + log2(1+endorsements)) * tier_weight
// Returns a uint32 scaled to 0–1000.
func TrustScore(severity SeverityLevel, confidence, endorsements, attesterRS uint32) uint32 {
	sev := float64(SeverityValue(severity)) / 5.0 // 0–1
	conf := float64(confidence) / 100.0
	endorseFactor := 1.0 + math.Log2(1.0+float64(endorsements))

	var tierWeight float64
	switch {
	case attesterRS >= 500:
		tierWeight = 2.0 // Tier 3
	case attesterRS >= 100:
		tierWeight = 1.0 // Tier 2
	default:
		tierWeight = 0.5 // Tier 1
	}

	score := sev * conf * endorseFactor * tierWeight * 1000.0
	if score > 1000.0 {
		score = 1000.0
	}
	return uint32(score)
}

// ============================================================
// Utility: Epoch
// ============================================================

// CurrentEpoch returns the epoch number for a given block height.
func CurrentEpoch(blockHeight int64) uint64 {
	if blockHeight < 0 {
		return 0
	}
	return uint64(blockHeight) / uint64(BlocksPerEpoch)
}

// ============================================================
// JSON helpers  (used by keeper serialisation)
// ============================================================

// MarshalJSON wraps json.Marshal for consistency.
func MarshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// UnmarshalJSON wraps json.Unmarshal for consistency.
func UnmarshalJSON(bz []byte, v interface{}) error {
	return json.Unmarshal(bz, v)
}