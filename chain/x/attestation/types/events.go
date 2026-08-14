// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

// Event type constants for the attestation module.
const (
	EventTypePublishAttestation = "publish_attestation"
	EventTypeEndorseAttestation = "endorse_attestation"
	EventTypeRevokeAttestation  = "revoke_attestation"
	EventTypeDisputeAttestation = "dispute_attestation"
	EventTypeExpireAttestation  = "expire_attestation"
	EventTypeSybilFlag          = "sybil_flag"
	EventTypeUpdateParams       = "update_params"
	EventTypeClaimReward        = "claim_reward"

	AttributeKeyAttestationID  = "attestation_id"
	AttributeKeyAttester       = "attester"
	AttributeKeyEndorser       = "endorser"
	AttributeKeyDisputer       = "disputer"
	AttributeKeyDisputeID      = "dispute_id"
	AttributeKeyDisputeGround  = "dispute_ground"
	AttributeKeyArtifactType   = "artifact_type"
	AttributeKeyArtifactSHA256 = "artifact_sha256"
	AttributeKeyAuthority      = "authority"
	AttributeKeySeverity       = "severity"
	AttributeKeyTLP            = "tlp"
	AttributeKeyExpiresAt      = "expires_at"
)
