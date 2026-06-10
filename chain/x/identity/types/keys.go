// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package types

const (
	ModuleName = "identity"
	StoreKey   = ModuleName
	RouterKey  = ModuleName

	// ── KVStore key prefixes ──────────────────────────────────────────────────
	// 0x00  idrecord/{cosmosAddr}          → DNSIdentityRecord (JSON)
	// 0x01  iddomain/{normalizedDomain}    → cosmosAddr (string)
	// 0x02  idbyid/{identityID}            → cosmosAddr (string)
	// 0x03  idpending/{cosmosAddr}         → DNSIdentityRecord (JSON)
	// 0x04  idexpiry/{big-endian-unix}/{cosmosAddr} → cosmosAddr (for expiry queue)
	// 0x05  params                         → Params (JSON)

	IDRecordPrefix  = byte(0x00)
	IDDomainPrefix  = byte(0x01)
	IDByIDPrefix    = byte(0x02)
	IDPendingPrefix = byte(0x03)
	IDExpiryPrefix  = byte(0x04)
	ParamsKey       = byte(0x05)
)

// ── Key builders ──────────────────────────────────────────────────────────────

func IDRecordKey(cosmosAddr string) []byte {
	return append([]byte{IDRecordPrefix}, []byte(cosmosAddr)...)
}

func IDDomainKey(normalizedDomain string) []byte {
	return append([]byte{IDDomainPrefix}, []byte(normalizedDomain)...)
}

func IDByIDKey(identityID string) []byte {
	return append([]byte{IDByIDPrefix}, []byte(identityID)...)
}

func IDPendingKey(cosmosAddr string) []byte {
	return append([]byte{IDPendingPrefix}, []byte(cosmosAddr)...)
}

// IDExpiryKey encodes expiry timestamp (big-endian uint64) + cosmosAddr so that
// range iteration yields entries in chronological expiry order.
func IDExpiryKey(expiresAt int64, cosmosAddr string) []byte {
	key := []byte{IDExpiryPrefix}
	key = append(key, encodeInt64BigEndian(expiresAt)...)
	key = append(key, []byte(cosmosAddr)...)
	return key
}

// encodeInt64BigEndian converts i to an 8-byte big-endian slice.
func encodeInt64BigEndian(i int64) []byte {
	b := make([]byte, 8)
	v := uint64(i)
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