// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/threatattest/chain/x/identity/types"
)

// In-process DNSSEC chain-of-trust verification (RFC 4034/4035).
//
// The evidence bundle carries the DS record (from the parent zone), the zone's
// DNSKEY RRset, and the RRSIGs covering the DNSKEY and TAT TXT RRsets. We
// reconstruct the canonical RRsets, rebuild the RRSIG signed data, and verify
// the signatures cryptographically, in addition to checking that the DS record
// matches the zone's key-signing key (KSK).

// DNS RR type codes used by this module.
const (
	dnsTypeTXT    = 16
	dnsTypeDNSKEY = 48
)

func rrtypeCode(s string) uint16 {
	switch strings.ToUpper(s) {
	case "TXT":
		return dnsTypeTXT
	case "DNSKEY":
		return dnsTypeDNSKEY
	default:
		return 0
	}
}

// encodeName encodes a presentation-format domain name into DNS wire format.
func encodeName(name string) []byte {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}

// dnskeyRDATAWire encodes a DNSKEY record's RDATA in wire format:
// flags(2) | protocol(1) | algorithm(1) | public_key(raw).
func dnskeyRDATAWire(k types.DNSKEYRecord) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("DNSKEY public_key is not valid base64: %w", err)
	}
	out := make([]byte, 0, 4+len(pub))
	out = append(out, byte(k.Flags>>8), byte(k.Flags&0xff))
	out = append(out, byte(k.Protocol), byte(k.Algorithm))
	out = append(out, pub...)
	return out, nil
}

// txtRDATAWire encodes a single-string TXT RDATA in wire format.
func txtRDATAWire(txt string) []byte {
	out := make([]byte, 0, len(txt)+1)
	out = append(out, byte(len(txt)))
	out = append(out, txt...)
	return out
}

// rrsigTimeToWire converts a Unix timestamp to the DNSSEC 32-bit wire value.
// RRSIG signature expiration/inception are stored as seconds since the Unix
// epoch (RFC 4034 §3.1.5), which is what the evidence bundle already holds.
func rrsigTimeToWire(unix int64) uint32 {
	return uint32(unix)
}

// canonicalRRSet builds the canonical wire form of an RRset (RFC 4034 §6).
func canonicalRRSet(owner string, rdatas [][]byte, rrtype uint16, originalTTL uint32) []byte {
	sorted := make([][]byte, len(rdatas))
	copy(sorted, rdatas)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i], sorted[j]) < 0
	})
	ownerWire := encodeName(owner)
	var out []byte
	for _, rd := range sorted {
		out = append(out, ownerWire...)
		out = append(out, byte(rrtype>>8), byte(rrtype&0xff))
		out = append(out, 0, 1) // CLASS IN
		out = append(out, byte(originalTTL>>24), byte(originalTTL>>16), byte(originalTTL>>8), byte(originalTTL&0xff))
		out = append(out, byte(len(rd)>>8), byte(len(rd)&0xff))
		out = append(out, rd...)
	}
	return out
}

// rrsigSignedData constructs the data covered by an RRSIG (RFC 4035 §5.3.3):
// the RRSIG RDATA (without the signature) followed by the canonical RRset.
func rrsigSignedData(rrsig types.RRSIGRecord, canonicalRR []byte) []byte {
	var out []byte
	tc := rrtypeCode(rrsig.TypeCovered)
	out = append(out, byte(tc>>8), byte(tc&0xff))
	out = append(out, byte(rrsig.Algorithm), byte(rrsig.Labels))
	ttl := rrsig.OriginalTTL
	out = append(out, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl&0xff))
	exp := rrsigTimeToWire(rrsig.Expiration)
	inc := rrsigTimeToWire(rrsig.Inception)
	out = append(out, byte(exp>>24), byte(exp>>16), byte(exp>>8), byte(exp&0xff))
	out = append(out, byte(inc>>24), byte(inc>>16), byte(inc>>8), byte(inc&0xff))
	out = append(out, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag&0xff))
	out = append(out, encodeName(rrsig.SignerName)...)
	out = append(out, canonicalRR...)
	return out
}

// verifyRRSIG verifies an RRSIG over a canonical RRset using the given DNSKEY.
func verifyRRSIG(rrsig types.RRSIGRecord, key types.DNSKEYRecord, canonicalRR []byte) error {
	sig, err := base64.StdEncoding.DecodeString(rrsig.Signature)
	if err != nil {
		return fmt.Errorf("RRSIG signature is not valid base64: %w", err)
	}
	data := rrsigSignedData(rrsig, canonicalRR)

	switch rrsig.Algorithm {
	case 8: // RSASHA256
		return verifyRSASig(key, data, sig, crypto.SHA256)
	case 10: // RSASHA512
		return verifyRSASig(key, data, sig, crypto.SHA512)
	case 13: // ECDSAP256SHA256
		return verifyECDSASig(key, data, sig, elliptic.P256(), crypto.SHA256)
	case 14: // ECDSAP384SHA384
		return verifyECDSASig(key, data, sig, elliptic.P384(), crypto.SHA512)
	case 15: // ED25519
		return verifyEd25519Sig(key, data, sig)
	default:
		return fmt.Errorf("unsupported DNSSEC algorithm %d for in-process verification", rrsig.Algorithm)
	}
}

// verifyECDSASig verifies an ECDSA DNSSEC signature (RFC 6605): the DNSKEY
// public key is the uncompressed point (X||Y) and the signature is R||S.
func verifyECDSASig(key types.DNSKEYRecord, data, sig []byte, curve elliptic.Curve, hash crypto.Hash) error {
	pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return fmt.Errorf("DNSKEY public_key is not valid base64: %w", err)
	}
	coordLen := (curve.Params().BitSize + 7) / 8
	if len(pub) != 2*coordLen {
		return fmt.Errorf("ECDSA public key must be %d bytes (X||Y), got %d", 2*coordLen, len(pub))
	}
	if len(sig) != 2*coordLen {
		return fmt.Errorf("ECDSA signature must be %d bytes (R||S), got %d", 2*coordLen, len(sig))
	}
	x := new(big.Int).SetBytes(pub[:coordLen])
	y := new(big.Int).SetBytes(pub[coordLen:])
	r := new(big.Int).SetBytes(sig[:coordLen])
	s := new(big.Int).SetBytes(sig[coordLen:])
	pk := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		digest = d[:]
	default:
		return fmt.Errorf("unsupported hash %v", hash)
	}

	if !ecdsa.Verify(pk, digest, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// verifyEd25519Sig verifies an Ed25519 DNSSEC signature.
func verifyEd25519Sig(key types.DNSKEYRecord, data, sig []byte) error {
	pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return fmt.Errorf("DNSKEY public_key is not valid base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("Ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// verifyRSASig verifies an RSA DNSSEC signature (RFC 3110 public key format).
func verifyRSASig(key types.DNSKEYRecord, data, sig []byte, hash crypto.Hash) error {
	pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return fmt.Errorf("DNSKEY public_key is not valid base64: %w", err)
	}
	// RFC 3110: exponent length (1 or 3 bytes) + exponent + modulus.
	idx := 0
	expLen := int(pub[idx])
	idx++
	if expLen == 0 {
		if len(pub) < 3 {
			return fmt.Errorf("malformed RSA DNSKEY public key")
		}
		expLen = int(pub[idx])<<8 | int(pub[idx+1])
		idx += 2
	}
	if idx+expLen >= len(pub) {
		return fmt.Errorf("malformed RSA DNSKEY public key")
	}
	e := new(big.Int).SetBytes(pub[idx : idx+expLen])
	idx += expLen
	n := new(big.Int).SetBytes(pub[idx:])
	rsaPub := &rsa.PublicKey{N: n, E: int(e.Int64())}

	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(data)
		digest = d[:]
	default:
		return fmt.Errorf("unsupported hash %v", hash)
	}

	if err := rsa.VerifyPKCS1v15(rsaPub, hash, digest, sig); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}
	return nil
}

// verifyDSLinkage verifies that each DS record matches a DNSKEY in the zone:
// SHA-256 of (canonical owner name || DNSKEY RDATA) must equal the DS digest
// (RFC 4034 §5.1, digest type 2).
func verifyDSLinkage(dsRecords []types.DSRecord, dnskeyRecords []types.DNSKEYRecord, domain string) error {
	nameWire := encodeName(domain)
	for _, ds := range dsRecords {
		if ds.DigestType != 2 {
			return fmt.Errorf("DS digest_type must be 2 (SHA-256), got %d", ds.DigestType)
		}
		matched := false
		for _, key := range dnskeyRecords {
			if key.KeyTag != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			rdata, err := dnskeyRDATAWire(key)
			if err != nil {
				return err
			}
			h := sha256.New()
			h.Write(nameWire)
			h.Write(rdata)
			if strings.EqualFold(fmt.Sprintf("%x", h.Sum(nil)), ds.Digest) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("DS record (key_tag=%d, algorithm=%d) does not match any zone DNSKEY", ds.KeyTag, ds.Algorithm)
		}
	}
	return nil
}

// ValidateDNSSECChain verifies the DNSSEC chain-of-trust contained in an
// evidence bundle:
//  1. The DS record (from the parent zone) matches the zone's KSK.
//  2. The RRSIG over the DNSKEY RRset verifies against a zone DNSKEY.
//  3. The RRSIG over the TAT TXT RRset verifies against a zone DNSKEY.
func ValidateDNSSECChain(bundle *types.DNSEvidenceBundle, domain, selector string) error {
	if bundle == nil {
		return types.ErrMissingEvidence
	}

	keys := make(map[int]types.DNSKEYRecord, len(bundle.ZoneDNSKEYs))
	for _, k := range bundle.ZoneDNSKEYs {
		keys[k.KeyTag] = k
	}

	// 1. DS -> KSK linkage.
	if err := verifyDSLinkage(bundle.ParentDS, bundle.ZoneDNSKEYs, domain); err != nil {
		return fmt.Errorf("DS/DNSKEY linkage: %w", err)
	}

	// 2. RRSIG over the DNSKEY RRset.
	if len(bundle.DNSKEYRRSIGs) == 0 {
		return fmt.Errorf("no RRSIG over the DNSKEY RRset")
	}
	dnskeyRdatas := make([][]byte, 0, len(bundle.ZoneDNSKEYs))
	for _, k := range bundle.ZoneDNSKEYs {
		rd, err := dnskeyRDATAWire(k)
		if err != nil {
			return err
		}
		dnskeyRdatas = append(dnskeyRdatas, rd)
	}
	dnskeyRR := canonicalRRSet(domain, dnskeyRdatas, dnsTypeDNSKEY, bundle.DNSKEYRRSIGs[0].OriginalTTL)
	for _, rrsig := range bundle.DNSKEYRRSIGs {
		key, ok := keys[rrsig.KeyTag]
		if !ok {
			return fmt.Errorf("RRSIG(DNSKEY) key_tag %d not found in zone DNSKEYs", rrsig.KeyTag)
		}
		if err := verifyRRSIG(rrsig, key, dnskeyRR); err != nil {
			return fmt.Errorf("RRSIG(DNSKEY) verification failed: %w", err)
		}
	}

	// 3. RRSIG over the TXT RRset.
	if len(bundle.TXTRRSIGs) == 0 {
		return fmt.Errorf("no RRSIG over the TXT RRset")
	}
	txtOwner := selector + "._tatkey." + domain
	txtRdatas := make([][]byte, 0, len(bundle.TXTRecords))
	for _, txt := range bundle.TXTRecords {
		txtRdatas = append(txtRdatas, txtRDATAWire(txt))
	}
	txtRR := canonicalRRSet(txtOwner, txtRdatas, dnsTypeTXT, bundle.TXTRRSIGs[0].OriginalTTL)
	for _, rrsig := range bundle.TXTRRSIGs {
		key, ok := keys[rrsig.KeyTag]
		if !ok {
			return fmt.Errorf("RRSIG(TXT) key_tag %d not found in zone DNSKEYs", rrsig.KeyTag)
		}
		if err := verifyRRSIG(rrsig, key, txtRR); err != nil {
			return fmt.Errorf("RRSIG(TXT) verification failed: %w", err)
		}
	}

	return nil
}
