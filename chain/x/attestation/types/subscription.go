// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

// SubscriptionTier represents a paid API access level.
type SubscriptionTier int32

const (
	SubscriptionTier_FREE         SubscriptionTier = 0
	SubscriptionTier_PROFESSIONAL SubscriptionTier = 1
	SubscriptionTier_ENTERPRISE   SubscriptionTier = 2
)

// String returns a human-readable name for the tier, "UNKNOWN" if invalid.
func (t SubscriptionTier) String() string {
	switch t {
	case SubscriptionTier_FREE:
		return "FREE"
	case SubscriptionTier_PROFESSIONAL:
		return "PROFESSIONAL"
	case SubscriptionTier_ENTERPRISE:
		return "ENTERPRISE"
	default:
		return "UNKNOWN"
	}
}

// TierConfig defines the rate limits and stake requirements for a tier.
type TierConfig struct {
	Name          string // human-readable name
	RateLimit     int32  // max requests per minute
	StakeRequired int64  // tokens to lock (utatst)
	Features      int32  // bitmask: 1=sha256, 2=url, 4=ipv4, 8=domain
	LockDays      int32  // stake lock duration in days
}

// TierConfigs maps each tier to its configuration.
var TierConfigs = map[SubscriptionTier]TierConfig{
	SubscriptionTier_FREE: {
		Name:          "Free",
		RateLimit:     10,
		StakeRequired: 0,
		Features:      1, // sha256 only
		LockDays:      0,
	},
	SubscriptionTier_PROFESSIONAL: {
		Name:          "Professional",
		RateLimit:     1000,
		StakeRequired: 1_000_000_000, // 1,000 TATST = 1,000,000,000 utatst
		Features:      15,            // all features (1|2|4|8)
		LockDays:      90,
	},
	SubscriptionTier_ENTERPRISE: {
		Name:          "Enterprise",
		RateLimit:     10_000,
		StakeRequired: 100_000_000_000, // 100,000 TATST
		Features:      15,
		LockDays:      365,
	},
}

// SubscriptionRecord tracks an active subscription in the KV store.
type SubscriptionRecord struct {
	Subscriber  string           `json:"subscriber"`
	Tier        SubscriptionTier `json:"tier"`
	StakeAmount int64            `json:"stake_amount"` // utatst locked
	StartedAt   int64            `json:"started_at"`   // block time
	ExpiresAt   int64            `json:"expires_at"`   // unlock time
}

// IsActive reports whether the subscription has not expired as of the given
// block time (Unix seconds).
func (s SubscriptionRecord) IsActive(now int64) bool {
	return s.ExpiresAt > now
}

// GetTierConfig returns the configuration for the subscription's tier.
func (s SubscriptionRecord) GetTierConfig() TierConfig {
	if cfg, ok := TierConfigs[s.Tier]; ok {
		return cfg
	}
	return TierConfigs[SubscriptionTier_FREE]
}
