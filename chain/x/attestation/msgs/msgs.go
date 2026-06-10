// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package msgs

import (
	"time"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/attestation/types"
)

// ============================================================
// MsgPublishAttestation
// ============================================================

// MsgPublishAttestation submits a new threat attestation to the chain.
type MsgPublishAttestation struct {
	Attester         string                    `json:"attester"`
	ArtifactType     types.ArtifactType        `json:"artifact_type"`
	// ArtifactSHA256 is the canonical SHA-256 hex of the artifact.
	// For URL: SHA-256 of the normalized UTF-8 URL bytes.
	// For IPv4: SHA-256 of the 4-byte big-endian packed address.
	// For FILE: SHA-256 of the raw file bytes.
	ArtifactSHA256   string                    `json:"artifact_sha256"`
	// RawValue is the human-readable value (URL string, IPv4 string, or empty for files).
	RawValue         string                    `json:"raw_value,omitempty"`
	Severity         types.SeverityLevel       `json:"severity"`
	TLP              types.TLPLevel            `json:"tlp"`
	TTLSeconds       int64                     `json:"ttl_seconds"`
	Confidence       uint32                    `json:"confidence"`
	Description      string                    `json:"description,omitempty"`
	Tags             []string                  `json:"tags,omitempty"`
	ThreatCategories []string                  `json:"threat_categories,omitempty"`
	DetectionRules   []types.DetectionRuleRef  `json:"detection_rules,omitempty"`
	RelatedTo        []string                  `json:"related_to,omitempty"`
	MitreAttackIDs   []string                  `json:"mitre_attack_ids,omitempty"`
	AttesterSig      string                    `json:"attester_sig"`
	// PUAInfo carries Potentially Unwanted Application metadata.
	// Must only be set when ArtifactType == FILE and ThreatCategories contains "TATST:PUA".
	PUAInfo          *types.PUAMetadata        `json:"pua_info,omitempty"`
	// AttesterDomain is the normalized domain name of the attester's DNS identity.
	// When set, the keeper will cross-check that a live DNS identity record exists
	// for msg.Attester with this domain and selector before storing the attestation.
	AttesterDomain   string                    `json:"attester_domain,omitempty"`
	// AttesterSelector is the DNS selector for the attester's active TAT key record.
	AttesterSelector string                    `json:"attester_selector,omitempty"`
}

// Route implements sdk.Msg (legacy).
func (m *MsgPublishAttestation) Route() string { return types.ModuleName }

// Type implements sdk.Msg (legacy).
func (m *MsgPublishAttestation) Type() string { return "publish_attestation" }

// ValidateBasic performs stateless validation.
func (m *MsgPublishAttestation) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Attester); err != nil {
		return types.ErrInvalidAttesterAddress
	}
	if m.ArtifactType == types.ArtifactType_UNSPECIFIED {
		return types.ErrInvalidArtifactType
	}
	if !types.IsValidSHA256Hex(m.ArtifactSHA256) {
		return types.ErrInvalidSHA256
	}
	if m.ArtifactSHA256 == types.EmptySHA256 {
		return types.ErrInvalidSHA256
	}
	if m.TTLSeconds < types.MinTTLSeconds || m.TTLSeconds > types.MaxTTLSeconds {
		return types.ErrTTLOutOfRange
	}
	if m.Confidence > 100 {
		return types.ErrInvalidConfidence
	}
	if len(m.Description) > types.MaxDescriptionBytes {
		return types.ErrDescriptionTooLong
	}
	if types.ContainsHTML(m.Description) {
		return types.ErrHTMLNotAllowed
	}
	if len(m.Tags) > types.MaxTags {
		return types.ErrTooManyTags
	}
	for _, tag := range m.Tags {
		if len(tag) > types.MaxTagBytes {
			return types.ErrTagTooLong
		}
	}
	if len(m.ThreatCategories) > types.MaxThreatCategories {
		return types.ErrTooManyCategories
	}
	for _, cat := range m.ThreatCategories {
		if !types.IsValidThreatCategory(cat) {
			return types.ErrInvalidThreatCategory
		}
	}
	if len(m.RelatedTo) > types.MaxRelatedTo {
		return types.ErrTooManyRelatedTo
	}

	// Artifact-type-specific validation
	switch m.ArtifactType {
	case types.ArtifactType_URL:
		if m.RawValue == "" {
			return types.ErrMissingRawValue
		}
		normalized, err := types.NormalizeURL(m.RawValue)
		if err != nil {
			return types.ErrInvalidURL
		}
		expected := types.ArtifactSHA256ForURL(normalized)
		if expected != m.ArtifactSHA256 {
			return types.ErrSHA256Mismatch
		}
	case types.ArtifactType_IPV4:
		if m.RawValue == "" {
			return types.ErrMissingRawValue
		}
		if types.IsReservedIPv4(m.RawValue) {
			return types.ErrReservedIPv4
		}
		expected := types.ArtifactSHA256ForIPv4(m.RawValue)
		if expected != m.ArtifactSHA256 {
			return types.ErrSHA256Mismatch
		}
	case types.ArtifactType_FILE:
		// raw_value is optional (filename hint); SHA-256 is authoritative
	case types.ArtifactType_DOMAIN:
		if m.RawValue == "" {
			return types.ErrMissingRawValue
		}
		normDomain, err := types.NormalizeDomain(m.RawValue)
		if err != nil {
			return types.ErrInvalidDomain
		}
		expected := types.ArtifactSHA256ForDomain(normDomain)
		if expected != m.ArtifactSHA256 {
			return types.ErrDomainSHA256Mismatch
		}
	}

	// Cross-validate threat categories against artifact type
	for _, cat := range m.ThreatCategories {
		if !types.IsCategoryValidForArtifact(cat, m.ArtifactType) {
			return types.ErrCategoryArtifactMismatch
		}
	}

	// PUAInfo may only be set for FILE artifacts
	if m.PUAInfo != nil {
		if m.ArtifactType != types.ArtifactType_FILE {
			return types.ErrPUAInfoOnNonFile
		}
		if len(m.PUAInfo.BehaviorNotes) > 512 {
			return types.ErrPUABehaviorNotesToolong
		}
		if types.ContainsHTML(m.PUAInfo.BehaviorNotes) {
			return types.ErrHTMLNotAllowed
		}
	}

	// Validate detection rule refs
	for _, rule := range m.DetectionRules {
		if !types.IsValidCIDv1(rule.CID) {
			return types.ErrInvalidCID
		}
		if !types.IsValidSHA256Hex(rule.ContentSHA256) {
			return types.ErrInvalidSHA256
		}
	}

	// Validate attester DNS identity cross-reference (optional fields)
	if m.AttesterDomain != "" {
		if _, err := types.NormalizeDomain(m.AttesterDomain); err != nil {
			return types.ErrInvalidDomain.Wrapf("attester_domain: %v", err)
		}
		// selector is required when domain is provided
		if m.AttesterSelector == "" {
			return types.ErrInvalidDomain.Wrap("attester_selector is required when attester_domain is set")
		}
		// selector must be a valid DNS label (1-63 chars, alnum+hyphen)
		if len(m.AttesterSelector) > 63 {
			return types.ErrInvalidDomain.Wrapf("attester_selector too long: %d > 63", len(m.AttesterSelector))
		}
	}
	if m.AttesterSelector != "" && m.AttesterDomain == "" {
		return types.ErrInvalidDomain.Wrap("attester_domain is required when attester_selector is set")
	}

	return nil
}

// GetSigners returns the required signers.
func (m *MsgPublishAttestation) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Attester)
	return []sdk.AccAddress{addr}
}

// ProtoMessage implements proto.Message.
func (m *MsgPublishAttestation) ProtoMessage() {}

// Reset implements proto.Message.
func (m *MsgPublishAttestation) Reset() {}

// String implements proto.Message.
func (m *MsgPublishAttestation) String() string { return m.ArtifactSHA256 }

// ============================================================
// MsgEndorseAttestation
// ============================================================

// MsgEndorseAttestation adds an endorsement to an existing attestation.
type MsgEndorseAttestation struct {
	Endorser      string `json:"endorser"`
	AttestationID string `json:"attestation_id"`
	Comment       string `json:"comment,omitempty"`
}

func (m *MsgEndorseAttestation) Route() string { return types.ModuleName }
func (m *MsgEndorseAttestation) Type() string  { return "endorse_attestation" }

func (m *MsgEndorseAttestation) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Endorser); err != nil {
		return types.ErrInvalidAttesterAddress
	}
	if m.AttestationID == "" {
		return types.ErrAttestationNotFound
	}
	if len(m.Comment) > types.MaxDescriptionBytes {
		return types.ErrDescriptionTooLong
	}
	if types.ContainsHTML(m.Comment) {
		return types.ErrHTMLNotAllowed
	}
	return nil
}

func (m *MsgEndorseAttestation) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Endorser)
	return []sdk.AccAddress{addr}
}

func (m *MsgEndorseAttestation) ProtoMessage() {}
func (m *MsgEndorseAttestation) Reset()        {}
func (m *MsgEndorseAttestation) String() string { return m.AttestationID }

// ============================================================
// MsgRevokeAttestation
// ============================================================

// MsgRevokeAttestation revokes an attestation published by the sender.
type MsgRevokeAttestation struct {
	Attester      string `json:"attester"`
	AttestationID string `json:"attestation_id"`
	Reason        string `json:"reason,omitempty"`
}

func (m *MsgRevokeAttestation) Route() string { return types.ModuleName }
func (m *MsgRevokeAttestation) Type() string  { return "revoke_attestation" }

func (m *MsgRevokeAttestation) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Attester); err != nil {
		return types.ErrInvalidAttesterAddress
	}
	if m.AttestationID == "" {
		return types.ErrAttestationNotFound
	}
	if len(m.Reason) > types.MaxDescriptionBytes {
		return types.ErrDescriptionTooLong
	}
	return nil
}

func (m *MsgRevokeAttestation) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Attester)
	return []sdk.AccAddress{addr}
}

func (m *MsgRevokeAttestation) ProtoMessage() {}
func (m *MsgRevokeAttestation) Reset()        {}
func (m *MsgRevokeAttestation) String() string { return m.AttestationID }

// ============================================================
// MsgDisputeAttestation
// ============================================================

// MsgDisputeAttestation files a dispute against an existing attestation.
type MsgDisputeAttestation struct {
	Disputer      string                `json:"disputer"`
	AttestationID string                `json:"attestation_id"`
	Ground        types.DisputeGround   `json:"ground"`
	Evidence      string                `json:"evidence,omitempty"`
	EvidenceCID   string                `json:"evidence_cid,omitempty"`
}

func (m *MsgDisputeAttestation) Route() string { return types.ModuleName }
func (m *MsgDisputeAttestation) Type() string  { return "dispute_attestation" }

func (m *MsgDisputeAttestation) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Disputer); err != nil {
		return types.ErrInvalidAttesterAddress
	}
	if m.AttestationID == "" {
		return types.ErrAttestationNotFound
	}
	if m.Ground == types.DisputeGround_UNSPECIFIED {
		return types.ErrInvalidDisputeGround
	}
	if len(m.Evidence) > types.MaxDescriptionBytes {
		return types.ErrDescriptionTooLong
	}
	if types.ContainsHTML(m.Evidence) {
		return types.ErrHTMLNotAllowed
	}
	if m.EvidenceCID != "" && !types.IsValidCIDv1(m.EvidenceCID) {
		return types.ErrInvalidCID
	}
	return nil
}

func (m *MsgDisputeAttestation) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Disputer)
	return []sdk.AccAddress{addr}
}

func (m *MsgDisputeAttestation) ProtoMessage() {}
func (m *MsgDisputeAttestation) Reset()        {}
func (m *MsgDisputeAttestation) String() string { return m.AttestationID }

// ============================================================
// MsgUpdateParams (governance)
// ============================================================

// MsgUpdateParams updates the module parameters via governance proposal.
type MsgUpdateParams struct {
	Authority string       `json:"authority"`
	Params    types.Params `json:"params"`
}

func (m *MsgUpdateParams) Route() string { return types.ModuleName }
func (m *MsgUpdateParams) Type() string  { return "update_params" }

func (m *MsgUpdateParams) ValidateBasic() error {
	if _, err := sdk.AccAddressFromBech32(m.Authority); err != nil {
		return types.ErrInvalidAttesterAddress
	}
	return m.Params.Validate()
}

func (m *MsgUpdateParams) GetSigners() []sdk.AccAddress {
	addr, _ := sdk.AccAddressFromBech32(m.Authority)
	return []sdk.AccAddress{addr}
}

func (m *MsgUpdateParams) ProtoMessage() {}
func (m *MsgUpdateParams) Reset()        {}
func (m *MsgUpdateParams) String() string { return "update_params" }

// ============================================================
// Response types
// ============================================================

type MsgPublishAttestationResponse struct {
	AttestationID string    `json:"attestation_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type MsgEndorseAttestationResponse struct {
	EndorsementCount uint32 `json:"endorsement_count"`
}

type MsgRevokeAttestationResponse struct{}

type MsgDisputeAttestationResponse struct {
	DisputeID string `json:"dispute_id"`
}

type MsgUpdateParamsResponse struct{}