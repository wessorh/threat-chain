// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

import "fmt"

// Params holds module-level governance parameters for x/identity.
type Params struct {
	// MinRegistrationStake is the minimum utat staked by the attester in order
	// to register a DNS identity.  Default: 1_000_000 utat (1 TAT).
	MinRegistrationStake int64 `json:"min_registration_stake"`

	// IdentityTTLSeconds is the default TTL for a newly registered identity.
	// Default: 31_536_000 (365 days).
	IdentityTTLSeconds int64 `json:"identity_ttl_seconds"`

	// DNSVerificationEpochBlocks is how often (in blocks) the chain re-checks
	// DNS records for active identities.  Default: 43_200 (~24 h at 2 s/block).
	DNSVerificationEpochBlocks int64 `json:"dns_verification_epoch_blocks"`

	// MaxDomainsPerAddress is the maximum number of distinct domain names a
	// single Cosmos address may register.  Default: 5.
	MaxDomainsPerAddress int64 `json:"max_domains_per_address"`

	// ExpertTierMinReputationScore is the minimum reputation score required for
	// Tier-3 (EXPERT) designation.  Default: 5_000.
	ExpertTierMinReputationScore int64 `json:"expert_tier_min_reputation_score"`

	// StakedTierMinDelegation is the minimum utat delegation (staked) required
	// to qualify for Tier-1 (STAKED).  Default: 500_000 utat (0.5 TAT).
	StakedTierMinDelegation int64 `json:"staked_tier_min_delegation"`

	// DNSBoundTierRequiresDNSSEC controls whether Tier-2 (DNS_BOUND) requires a
	// valid DNSSEC evidence bundle.  Default: true.
	DNSBoundTierRequiresDNSSEC bool `json:"dns_bound_tier_requires_dnssec"`
}

// DefaultParams returns the default module parameters.
func DefaultParams() Params {
	return Params{
		MinRegistrationStake:         1_000_000,
		IdentityTTLSeconds:           DefaultIdentityTTLSeconds,
		DNSVerificationEpochBlocks:   43_200,
		MaxDomainsPerAddress:         5,
		ExpertTierMinReputationScore: 5_000,
		StakedTierMinDelegation:      500_000,
		DNSBoundTierRequiresDNSSEC:   true,
	}
}

// Validate performs basic sanity checks on Params.
func (p Params) Validate() error {
	if p.MinRegistrationStake < 0 {
		return fmt.Errorf("min_registration_stake must be non-negative")
	}
	if p.IdentityTTLSeconds < MinIdentityTTLSeconds || p.IdentityTTLSeconds > MaxIdentityTTLSeconds {
		return fmt.Errorf("identity_ttl_seconds %d outside [%d, %d]",
			p.IdentityTTLSeconds, MinIdentityTTLSeconds, MaxIdentityTTLSeconds)
	}
	if p.DNSVerificationEpochBlocks < 1 {
		return fmt.Errorf("dns_verification_epoch_blocks must be >= 1")
	}
	if p.MaxDomainsPerAddress < 1 {
		return fmt.Errorf("max_domains_per_address must be >= 1")
	}
	if p.ExpertTierMinReputationScore < 0 {
		return fmt.Errorf("expert_tier_min_reputation_score must be non-negative")
	}
	if p.StakedTierMinDelegation < 0 {
		return fmt.Errorf("staked_tier_min_delegation must be non-negative")
	}
	return nil
}