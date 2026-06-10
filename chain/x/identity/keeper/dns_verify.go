// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"fmt"
	"strings"
	"time"

	"github.com/threatattest/chain/x/identity/types"
)

// ============================================================
// DNSSEC Evidence Validation
// ============================================================
// The functions in this file perform the keeper-side validation of the
// DNSEvidenceBundle submitted with MsgRegisterIdentity and MsgRenewIdentity.
//
// Design notes:
//   - Full cryptographic DNSSEC chain-of-trust verification requires a live
//     DNS resolver and is intentionally left as a stub (ValidateDNSSECChain).
//     In production this would call out to a trusted DNSSEC-validating resolver
//     or use the dnssec-go library for in-process validation.
//   - Structural validation (presence of required fields, algorithm allow-list,
//     freshness) is performed fully in-process.
//   - The TAT TXT record is parsed and its fields are cross-checked against the
//     submitted MsgRegisterIdentity fields to detect substitution attacks.
// ============================================================

// AllowedDNSSECAlgorithms is the set of DNSSEC algorithm numbers accepted by
// the identity module.  Algorithm 5 (RSASHA1) is explicitly rejected.
var AllowedDNSSECAlgorithms = map[int]string{
	8:  "RSASHA256",
	10: "RSASHA512",
	13: "ECDSAP256SHA256", // RECOMMENDED
	14: "ECDSAP384SHA384",
	15: "ED25519",
}

// MaxEvidenceAgeSeconds is the maximum age of a DNSSEC evidence bundle
// (measured from CollectedAt to block submission time).
const MaxEvidenceAgeSeconds = 3600 // 1 hour

// ValidateEvidenceBundle performs all structural and policy checks on a
// DNSEvidenceBundle before it is stored on-chain.
//
// Parameters:
//   - bundle:      the evidence bundle to validate
//   - domain:      normalized domain name from MsgRegisterIdentity
//   - selector:    DNS selector from MsgRegisterIdentity
//   - pubKeyHex:   claimed public key hex from MsgRegisterIdentity
//   - cosmosAddr:  registrant's Cosmos bech32 address
//   - now:         current block Unix timestamp
func ValidateEvidenceBundle(
	bundle *types.DNSEvidenceBundle,
	domain, selector, pubKeyHex, cosmosAddr string,
	now int64,
) error {
	if bundle == nil {
		return types.ErrMissingEvidence
	}

	// 1. Freshness check
	age := now - bundle.CollectedAt
	if age < 0 {
		age = -age // tolerate small clock drift
	}
	if age > MaxEvidenceAgeSeconds {
		return types.ErrEvidenceTooOld.Wrapf(
			"bundle collected at %d, block time %d, age %d s > max %d s",
			bundle.CollectedAt, now, age, MaxEvidenceAgeSeconds,
		)
	}

	// 2. TXT records presence
	if len(bundle.TXTRecords) == 0 {
		return types.ErrMissingEvidence.Wrap("evidence.txt_records is empty")
	}

	// 3. RRSIG presence and algorithm check
	if len(bundle.TXTRRSIGs) == 0 {
		return types.ErrEvidenceMissingRRSIG.Wrap("no RRSIG for TXT RRset")
	}
	for i, rrsig := range bundle.TXTRRSIGs {
		if err := checkAlgorithm(rrsig.Algorithm); err != nil {
			return fmt.Errorf("TXT RRSIG[%d]: %w", i, err)
		}
	}

	// 4. DNSKEY presence and algorithm check
	if len(bundle.ZoneDNSKEYs) == 0 {
		return types.ErrEvidenceMissingDNSKEY.Wrap("no DNSKEY records in bundle")
	}
	for i, key := range bundle.ZoneDNSKEYs {
		if err := checkAlgorithm(key.Algorithm); err != nil {
			return fmt.Errorf("DNSKEY[%d]: %w", i, err)
		}
		if key.Protocol != 3 {
			return fmt.Errorf("DNSKEY[%d]: protocol must be 3, got %d", i, key.Protocol)
		}
	}

	// 5. DNSKEY RRSIG presence
	if len(bundle.DNSKEYRRSIGs) == 0 {
		return types.ErrEvidenceMissingRRSIG.Wrap("no RRSIG for DNSKEY RRset")
	}
	for i, rrsig := range bundle.DNSKEYRRSIGs {
		if err := checkAlgorithm(rrsig.Algorithm); err != nil {
			return fmt.Errorf("DNSKEY RRSIG[%d]: %w", i, err)
		}
	}

	// 6. DS record presence
	if len(bundle.ParentDS) == 0 {
		return types.ErrEvidenceMissingDS.Wrap("no DS records from parent zone")
	}
	for i, ds := range bundle.ParentDS {
		if ds.DigestType != 2 {
			return fmt.Errorf("DS[%d]: digest_type must be 2 (SHA-256), got %d", i, ds.DigestType)
		}
		if len(ds.Digest) == 0 {
			return fmt.Errorf("DS[%d]: digest is empty", i)
		}
	}

	// 7. Parse and cross-check TAT TXT record
	if err := validateTATTXTRecord(bundle.TXTRecords, domain, selector, pubKeyHex, cosmosAddr); err != nil {
		return fmt.Errorf("TAT TXT record validation: %w", err)
	}

	// 8. RRSIG expiration check (not-yet-expired at bundle collection time)
	bundleTime := time.Unix(bundle.CollectedAt, 0)
	for i, rrsig := range bundle.TXTRRSIGs {
		expTime := time.Unix(rrsig.Expiration, 0)
		if bundleTime.After(expTime) {
			return fmt.Errorf("TXT RRSIG[%d]: expired at %d (bundle collected %d)", i, rrsig.Expiration, bundle.CollectedAt)
		}
		inceptTime := time.Unix(rrsig.Inception, 0)
		if bundleTime.Before(inceptTime) {
			return fmt.Errorf("TXT RRSIG[%d]: not yet valid at bundle collection time", i)
		}
	}

	// 9. Full cryptographic chain-of-trust (stub — see ValidateDNSSECChain)
	return ValidateDNSSECChain(bundle, domain)
}

// validateTATTXTRecord parses all TXT records in the bundle looking for a
// valid TAT key record that matches the submitted registration fields.
func validateTATTXTRecord(
	txtRecords []string,
	domain, selector, pubKeyHex, cosmosAddr string,
) error {
	for _, txt := range txtRecords {
		fields, err := parseTATKeyRecord(txt)
		if err != nil {
			continue // not a TAT key record
		}

		// v= must be TAT1
		if fields["v"] != types.TATKeyVersion {
			continue
		}

		// p= must match submitted pubkey (case-insensitive)
		if !strings.EqualFold(fields["p"], pubKeyHex) {
			return fmt.Errorf("TXT record p= %q does not match submitted public_key_hex %q",
				fields["p"], pubKeyHex)
		}

		// a= must match submitted cosmos address
		if fields["a"] != "" && fields["a"] != cosmosAddr {
			return fmt.Errorf("TXT record a= %q does not match submitted cosmos_addr %q",
				fields["a"], cosmosAddr)
		}

		// k= must be secp256k1
		if k, ok := fields["k"]; ok && k != "secp256k1" {
			return fmt.Errorf("TXT record k= %q; only secp256k1 is supported", k)
		}

		return nil // found a matching record
	}
	return fmt.Errorf("no valid TAT1 key record found in TXT records for %s._tatkey.%s",
		selector, domain)
}

// parseTATKeyRecord parses a TAT TXT record value into a key→value map.
// Format: "v=TAT1 k=secp256k1 p={hex} a={addr} n={name} t={unix} exp={unix} u={uri} flags={int}"
func parseTATKeyRecord(txt string) (map[string]string, error) {
	fields := make(map[string]string)
	parts := strings.Fields(txt)
	for _, part := range parts {
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(part[:idx])
		v := strings.TrimSpace(part[idx+1:])
		if k != "" {
			fields[k] = v
		}
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("no key=value pairs found")
	}
	return fields, nil
}

// checkAlgorithm returns an error if algNum is not in the allow-list or is
// explicitly rejected (RSASHA1 = 5).
func checkAlgorithm(algNum int) error {
	if algNum == types.AlgRSASHA1 {
		return types.ErrWeakDNSSECAlgorithm.Wrapf(
			"algorithm %d (RSASHA1) is explicitly rejected", algNum)
	}
	if _, ok := AllowedDNSSECAlgorithms[algNum]; !ok {
		return types.ErrWeakDNSSECAlgorithm.Wrapf(
			"algorithm %d is not in the allow-list", algNum)
	}
	return nil
}

// ValidateDNSSECChain validates the full cryptographic DNSSEC chain of trust
// for the submitted evidence bundle.
//
// Production implementation note:
//   In a production deployment this function would:
//   1. Verify each RRSIG over the TXT RRset using the matching DNSKEY.
//   2. Verify each DNSKEY RRSIG using the KSK.
//   3. Verify the KSK matches the DS record from the parent zone.
//   4. Recurse up to the root trust anchor (IANA root KSK).
//
// Current implementation:
//   Returns nil (passes) so that the rest of the validation pipeline works
//   during development.  Replace this stub with the dnssec-go or miekg/dns
//   library calls for production.
func ValidateDNSSECChain(bundle *types.DNSEvidenceBundle, domain string) error {
	// TODO(production): Implement full RFC 4035 chain-of-trust verification.
	// Stub: structural validation is done in ValidateEvidenceBundle above.
	_ = bundle
	_ = domain
	return nil
}