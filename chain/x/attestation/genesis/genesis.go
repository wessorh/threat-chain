// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package genesis

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/threatattest/chain/x/attestation/keeper"
	"github.com/threatattest/chain/x/attestation/types"
)

// InitGenesis initialises the attestation module state from a GenesisState.
// It is called once at chain genesis (block 0).
func InitGenesis(ctx sdk.Context, k keeper.Keeper, gs types.GenesisState) error {
	// Store parameters
	if err := k.SetParams(ctx, gs.Params); err != nil {
		return fmt.Errorf("init attestation params: %w", err)
	}

	// Set epoch to zero
	if err := k.SetCurrentEpoch(ctx, 0); err != nil {
		return fmt.Errorf("init attestation epoch: %w", err)
	}

	// Load attestation records
	for _, rec := range gs.Attestations {
		if err := k.SetAttestation(ctx, rec); err != nil {
			return fmt.Errorf("init attestation record %s: %w", rec.ID, err)
		}
		// Rebuild artifact index
		if err := k.AddArtifactIndexEntry(ctx, rec.ArtifactSHA256, rec.ID); err != nil {
			return fmt.Errorf("init artifact index for %s: %w", rec.ID, err)
		}
		// Rebuild attester index
		if err := k.AddAttesterIndexEntry(ctx, rec.Attester, rec.ID); err != nil {
			return fmt.Errorf("init attester index for %s: %w", rec.ID, err)
		}
		// Re-enqueue active records into expiry queue
		if rec.Status == types.AttestationStatus_ACTIVE {
			if err := k.EnqueueExpiry(ctx, rec.ExpiresAt, rec.ID); err != nil {
				return fmt.Errorf("init expiry queue for %s: %w", rec.ID, err)
			}
		}
	}

	// Load dispute records
	for _, d := range gs.Disputes {
		if err := k.SetDispute(ctx, d); err != nil {
			return fmt.Errorf("init dispute record %s: %w", d.ID, err)
		}
	}

	return nil
}

// ExportGenesis exports the current attestation module state as a GenesisState.
func ExportGenesis(ctx sdk.Context, k keeper.Keeper) (*types.GenesisState, error) {
	params, err := k.GetParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("export attestation params: %w", err)
	}

	var attestations []types.AttestationRecord
	if err := k.IterateAttestations(ctx, func(rec types.AttestationRecord) bool {
		attestations = append(attestations, rec)
		return false
	}); err != nil {
		return nil, fmt.Errorf("export attestations: %w", err)
	}

	var disputes []types.DisputeRecord
	if err := k.IterateDisputes(ctx, func(d types.DisputeRecord) bool {
		disputes = append(disputes, d)
		return false
	}); err != nil {
		return nil, fmt.Errorf("export disputes: %w", err)
	}

	return &types.GenesisState{
		Params:       params,
		Attestations: attestations,
		Disputes:     disputes,
	}, nil
}

// ValidateGenesis performs stateless validation of a GenesisState.
func ValidateGenesis(gs types.GenesisState) error {
	if err := gs.Params.Validate(); err != nil {
		return fmt.Errorf("invalid attestation params: %w", err)
	}

	// Validate attestation IDs are unique
	seen := make(map[string]bool, len(gs.Attestations))
	for _, rec := range gs.Attestations {
		if rec.ID == "" {
			return fmt.Errorf("attestation record has empty ID")
		}
		if seen[rec.ID] {
			return fmt.Errorf("duplicate attestation ID: %s", rec.ID)
		}
		seen[rec.ID] = true

		if !types.IsValidSHA256Hex(rec.ArtifactSHA256) {
			return fmt.Errorf("attestation %s: invalid artifact_sha256", rec.ID)
		}
		if rec.ArtifactType == types.ArtifactType_UNSPECIFIED {
			return fmt.Errorf("attestation %s: unspecified artifact_type", rec.ID)
		}
		if rec.PublishedAt <= 0 {
			return fmt.Errorf("attestation %s: invalid published_at", rec.ID)
		}
		if rec.ExpiresAt <= rec.PublishedAt {
			return fmt.Errorf("attestation %s: expires_at must be after published_at", rec.ID)
		}
	}

	// Validate dispute IDs are unique and reference known attestations
	disputeSeen := make(map[string]bool, len(gs.Disputes))
	for _, d := range gs.Disputes {
		if d.ID == "" {
			return fmt.Errorf("dispute record has empty ID")
		}
		if disputeSeen[d.ID] {
			return fmt.Errorf("duplicate dispute ID: %s", d.ID)
		}
		disputeSeen[d.ID] = true

		if !seen[d.AttestationID] {
			return fmt.Errorf("dispute %s references unknown attestation %s",
				d.ID, d.AttestationID)
		}
	}

	return nil
}