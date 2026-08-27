// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

const (
	ModuleName = "attestation"
	StoreKey   = ModuleName
	RouterKey  = ModuleName

	// KVStore key prefixes
	AttestationKeyPrefix     = 0x00
	ArtifactIndexPrefix      = 0x01
	AttesterIndexPrefix      = 0x02
	ExpiryQueuePrefix        = 0x03
	EpochCountPrefix         = 0x04
	ParamsKey                = 0x05
	DisputeKeyPrefix         = 0x06
	BlacklistPrefix          = 0x07
	EndorserSetPrefix        = 0x08
	EpochNumberKey           = 0x09
	SubscriptionPrefix       = 0x0A
	ClaimEpochPrefix         = 0x0B
	HollomanIndexPrefix      = 0x0C
	EpochTotalCountPrefix    = 0x0D
	EpochReplenishmentPrefix = 0x0E
)

// Key builders

func AttestationKey(id string) []byte {
	return append([]byte{AttestationKeyPrefix}, []byte(id)...)
}

func ArtifactIndexKey(sha256 string) []byte {
	return append([]byte{ArtifactIndexPrefix}, []byte(sha256)...)
}

func AttesterIndexKey(attester string) []byte {
	return append([]byte{AttesterIndexPrefix}, []byte(attester)...)
}

// ExpiryQueueKey encodes expiry timestamp (big-endian uint64) + attestation_id
// so range iteration yields entries in chronological expiry order.
func ExpiryQueueKey(expiresAt int64, attestationID string) []byte {
	key := []byte{ExpiryQueuePrefix}
	key = append(key, encodeInt64BigEndian(expiresAt)...)
	key = append(key, []byte(attestationID)...)
	return key
}

func EpochCountKey(epoch uint64, attester string) []byte {
	key := []byte{EpochCountPrefix}
	key = append(key, encodeUint64BigEndian(epoch)...)
	key = append(key, []byte(attester)...)
	return key
}

func EpochTotalCountKey(epoch uint64) []byte {
	key := []byte{EpochTotalCountPrefix}
	key = append(key, encodeUint64BigEndian(epoch)...)
	return key
}

func EpochReplenishmentKey(epoch uint64) []byte {
	key := []byte{EpochReplenishmentPrefix}
	key = append(key, encodeUint64BigEndian(epoch)...)
	return key
}

func DisputeKey(disputeID string) []byte {
	return append([]byte{DisputeKeyPrefix}, []byte(disputeID)...)
}

func BlacklistKey(attester string) []byte {
	return append([]byte{BlacklistPrefix}, []byte(attester)...)
}

func EndorserSetKey(attestationID, endorser string) []byte {
	key := []byte{EndorserSetPrefix}
	key = append(key, []byte(attestationID)...)
	key = append(key, []byte("|")...)
	key = append(key, []byte(endorser)...)
	return key
}

func ClaimEpochKey(attester string) []byte {
	return append([]byte{ClaimEpochPrefix}, []byte(attester)...)
}

func HollomanIndexKey(signature string) []byte {
	return append([]byte{HollomanIndexPrefix}, []byte(signature)...)
}

func encodeInt64BigEndian(v int64) []byte {
	b := make([]byte, 8)
	uv := uint64(v)
	b[0] = byte(uv >> 56)
	b[1] = byte(uv >> 48)
	b[2] = byte(uv >> 40)
	b[3] = byte(uv >> 32)
	b[4] = byte(uv >> 24)
	b[5] = byte(uv >> 16)
	b[6] = byte(uv >> 8)
	b[7] = byte(uv)
	return b
}

func encodeUint64BigEndian(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}
