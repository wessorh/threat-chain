// Package attestation tests the query-service wire bridge (query_bridge.go),
// which adapts the handwritten QueryServer to the generated protobuf gRPC
// types. A dropped/mismapped field here makes the gRPC query "return blanks"
// — a common, silent way for the query RPC to appear broken.
package attestation

import (
	"testing"

	"github.com/threatattest/chain/x/attestation/types"
	pb "github.com/threatattest/chain/x/attestation/types/pb"
)

// wireQueryServer must satisfy the generated pb.QueryServer interface. If a
// handler is added to the proto but not bridged, this line fails to compile.
var _ pb.QueryServer = (*wireQueryServer)(nil)

// TestTypesToPbRecordFields verifies the handwritten->protobuf record
// conversion copies every key field (a dropped field = query returns blanks).
func TestTypesToPbRecordFields(t *testing.T) {
	rec := types.AttestationRecord{
		ID:                "att-1",
		SchemaVersion:     1,
		ArtifactType:      types.ArtifactType_FILE,
		ArtifactSHA256:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		HollomanSignature: "abcdef0123456789abcdef0123456789",
		HammingMask:       5,
		RawValue:          "raw",
		Severity:          types.SeverityLevel_HIGH,
		Attester:          "tatst1attester",
		PublishedAt:       1700000000,
		TTLSeconds:        86400,
		ExpiresAt:         1700086400,
		Confidence:        90,
		Description:       "desc",
		Tags:              []string{"tag1", "tag2"},
		ThreatCategories:  []string{"cat1"},
		MitreAttackIDs:    []string{"mitre1"},
		AttesterSig:       "sig",
		Status:            types.AttestationStatus_ACTIVE,
		EndorsementCount:  2,
		DisputeCount:      1,
		BlockHeight:       10,
		TxHash:            "txhash",
		AttesterDomain:    "example.com",
		AttesterSelector:  "sel",
		AttesterTier:      2,
	}

	p := typesToPbRecord(&rec)
	if p == nil {
		t.Fatal("typesToPbRecord returned nil")
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"id", p.Id, rec.ID},
		{"artifact_sha256", p.ArtifactSha256, rec.ArtifactSHA256},
		{"holloman_signature", p.HollomanSignature, rec.HollomanSignature},
		{"hamming_mask", p.HammingMask, rec.HammingMask},
		{"raw_value", p.RawValue, rec.RawValue},
		{"severity", p.Severity, int32(rec.Severity)},
		{"attester", p.Attester, rec.Attester},
		{"published_at", p.PublishedAt, rec.PublishedAt},
		{"ttl", p.TtlSeconds, rec.TTLSeconds},
		{"confidence", p.Confidence, rec.Confidence},
		{"description", p.Description, rec.Description},
		{"status", p.Status, int32(rec.Status)},
		{"endorsement_count", p.EndorsementCount, rec.EndorsementCount},
		{"attester_domain", p.AttesterDomain, rec.AttesterDomain},
		{"attester_selector", p.AttesterSelector, rec.AttesterSelector},
		{"attester_tier", p.AttesterTier, rec.AttesterTier},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("field %s: got %v, want %v", c.name, c.got, c.want)
		}
	}
	if len(p.Tags) != 2 || p.Tags[0] != "tag1" || p.Tags[1] != "tag2" {
		t.Errorf("tags mismatch: %v", p.Tags)
	}
	if len(p.MitreAttackIds) != 1 || p.MitreAttackIds[0] != "mitre1" {
		t.Errorf("mitre_attack_ids mismatch: %v", p.MitreAttackIds)
	}
}

// TestTypesParamsToPbFields verifies every param field is carried across.
func TestTypesParamsToPbFields(t *testing.T) {
	def := types.DefaultParams()
	p := typesParamsToPb(def)
	if p == nil {
		t.Fatal("typesParamsToPb returned nil")
	}
	if p.MinAttesterDelegation != def.MinAttesterDelegation ||
		p.MaxTtlSeconds != def.MaxTTLSeconds ||
		p.MinReputationToAttest != def.MinReputationToAttest ||
		p.MinReputationToEndorse != def.MinReputationToEndorse ||
		p.MinReputationToDispute != def.MinReputationToDispute {
		t.Errorf("params mismatch: got %+v want %+v", p, def)
	}
}
