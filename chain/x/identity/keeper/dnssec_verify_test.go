// Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

package keeper

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	decredsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/threatattest/chain/x/identity/types"
)

// ── verifySecp256k1Sig ───────────────────────────────────────────────────────

func TestVerifySecp256k1Sig(t *testing.T) {
	priv, err := decredsecp.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())

	payload := sha256.Sum256([]byte("tatkey-domain-proof|example.com|tat2026a|cosmos1x|1700000000"))
	compact := decredecdsa.SignCompact(priv, payload[:], false)
	sigHex := hex.EncodeToString(compact[1:]) // 64-byte R||S

	if err := verifySecp256k1Sig(pubHex, payload[:], sigHex); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Tampered payload must fail.
	badPayload := sha256.Sum256([]byte("tampered"))
	if err := verifySecp256k1Sig(pubHex, badPayload[:], sigHex); err == nil {
		t.Fatalf("tampered payload accepted")
	}

	// Wrong public key must fail.
	other, _ := decredsecp.GeneratePrivateKey()
	otherPubHex := hex.EncodeToString(other.PubKey().SerializeCompressed())
	if err := verifySecp256k1Sig(otherPubHex, payload[:], sigHex); err == nil {
		t.Fatalf("wrong public key accepted")
	}
}

// ── ValidateDNSSECChain ─────────────────────────────────────────────────────

func dnsKeyRecord(flags, protocol, algorithm int, pub []byte) (types.DNSKEYRecord, []byte) {
	rec := types.DNSKEYRecord{
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	rdata, _ := dnskeyRDATAWire(rec)
	rec.KeyTag = dnskeyKeyTag(rdata)
	return rec, rdata
}

func dnskeyKeyTag(rdata []byte) int {
	ac := 0
	for i, b := range rdata {
		if i%2 == 0 {
			ac += int(b) << 8
		} else {
			ac += int(b)
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return ac & 0xFFFF
}

func ecdsaPubXY(pub *cryptoecdsa.PublicKey) []byte {
	// Uncompressed EC point (X||Y, 64 bytes for P-256).
	b := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	return b[1:] // drop the 0x04 prefix
}

func signRRSet(signer types.DNSKEYRecord, key *cryptoecdsa.PrivateKey, typeCovered, owner, signerName string, labels int, canonicalRR []byte) types.RRSIGRecord {
	rrsig := types.RRSIGRecord{
		TypeCovered: typeCovered,
		Algorithm:   13,
		Labels:      labels,
		OriginalTTL: 3600,
		Expiration:  time.Now().Add(24 * time.Hour).Unix(),
		Inception:   time.Now().Add(-1 * time.Hour).Unix(),
		KeyTag:      signer.KeyTag,
		SignerName:  signerName,
	}
	data := rrsigSignedData(rrsig, canonicalRR)
	digest := sha256.Sum256(data)
	r, s, err := cryptoecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	coordLen := 32
	sig := make([]byte, 2*coordLen)
	r.FillBytes(sig[:coordLen])
	s.FillBytes(sig[coordLen:])
	rrsig.Signature = base64.StdEncoding.EncodeToString(sig)
	return rrsig
}

func TestValidateDNSSECChain(t *testing.T) {
	domain := "example.com"
	selector := "tat2026a"
	signerName := domain + "."

	ksk, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	zsk, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	kskRec, kskRdata := dnsKeyRecord(257, 3, 13, ecdsaPubXY(&ksk.PublicKey))
	zskRec, zskRdata := dnsKeyRecord(256, 3, 13, ecdsaPubXY(&zsk.PublicKey))

	// DNSKEY RRset signed by the KSK.
	dnskeyRR := canonicalRRSet(domain, [][]byte{kskRdata, zskRdata}, dnsTypeDNSKEY, 3600)
	dnskeyRRSIG := signRRSet(kskRec, ksk, "DNSKEY", domain, signerName, 2, dnskeyRR)

	// TXT RRset signed by the ZSK.
	txtValue := "v=TAT1 k=secp256k1 p=deadbeef a=cosmos1test"
	txtOwner := selector + "._tatkey." + domain
	txtRR := canonicalRRSet(txtOwner, [][]byte{txtRDATAWire(txtValue)}, dnsTypeTXT, 3600)
	txtRRSIG := signRRSet(zskRec, zsk, "TXT", txtOwner, signerName, 4, txtRR)

	// DS record pointing at the KSK: H(canonical owner name || DNSKEY RDATA).
	h := sha256.New()
	h.Write(encodeName(domain))
	h.Write(kskRdata)
	ds := types.DSRecord{
		KeyTag:     kskRec.KeyTag,
		Algorithm:  13,
		DigestType: 2,
		Digest:     hex.EncodeToString(h.Sum(nil)),
	}

	bundle := &types.DNSEvidenceBundle{
		TXTRecords:    []string{txtValue},
		TXTRRSIGs:     []types.RRSIGRecord{txtRRSIG},
		ZoneDNSKEYs:   []types.DNSKEYRecord{kskRec, zskRec},
		DNSKEYRRSIGs:  []types.RRSIGRecord{dnskeyRRSIG},
		ParentDS:      []types.DSRecord{ds},
		CollectedAt:   time.Now().Unix(),
	}

	if err := ValidateDNSSECChain(bundle, domain, selector); err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}

	// Tampered DS digest must fail.
	bad := *bundle
	bad.ParentDS = []types.DSRecord{{
		KeyTag:     kskRec.KeyTag,
		Algorithm:  13,
		DigestType: 2,
		Digest:     strings.Repeat("00", 32),
	}}
	if err := ValidateDNSSECChain(&bad, domain, selector); err == nil {
		t.Fatalf("tampered DS accepted")
	}

	// Tampered TXT record must fail (RRSIG no longer matches).
	bad = *bundle
	bad.TXTRecords = []string{"v=TAT1 k=secp256k1 p=00000000 a=cosmos1evil"}
	if err := ValidateDNSSECChain(&bad, domain, selector); err == nil {
		t.Fatalf("tampered TXT record accepted")
	}
}
