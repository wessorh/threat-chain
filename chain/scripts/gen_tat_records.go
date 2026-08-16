// gen_tat_records generates the DNS TXT records for a ThreatAttest
// DNS-bound identity. It produces a recoverable BIP39 mnemonic, derives the
// secp256k1 key (default Cosmos path m/44'/118'/0'/0/0), computes the
// bech32 "tatst" address, and signs the domain-proof payload.
//
// Usage:
//   go run ./scripts/gen_tat_records.go [selector] [domain]
//
// Defaults: selector=tat2026a  domain=plan10.org
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	sdksecp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/go-bip39"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func main() {
	selector := "tat2026a"
	domain := "plan10.org"
	if len(os.Args) > 1 {
		selector = os.Args[1]
	}
	if len(os.Args) > 2 {
		domain = os.Args[2]
	}

	// 1. Generate a 24-word BIP39 mnemonic (recoverable via `threatattestd keys add --recover`).
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		panic(err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		panic(err)
	}

	// 2. Derive the secp256k1 key at the default Cosmos path.
	seed := bip39.NewSeed(mnemonic, "")
	master, chainCode := hd.ComputeMastersFromSeed(seed)
	path := hd.NewParams(44, 118, 0, false, 0) // m/44'/118'/0'/0/0
	privBytes, err := hd.DerivePrivateKeyForPath(master, chainCode, path.String())
	if err != nil {
		panic(err)
	}
	priv := &sdksecp256k1.PrivKey{Key: privBytes}
	pub := priv.PubKey()

	pubHex := hex.EncodeToString(pub.Bytes()) // 33-byte compressed pubkey

	// 3. Bech32 account address (prefix "tatst") = RIPEMD160(SHA256(pubkey)).
	addr, err := sdk.Bech32ifyAddressBytes("tatst", pub.Address().Bytes())
	if err != nil {
		panic(err)
	}

	// 4. Domain-proof payload: SHA-256("tatkey-domain-proof|domain|selector|addr|t")
	registeredAt := time.Now().Unix()
	raw := fmt.Sprintf("tatkey-domain-proof|%s|%s|%s|%d", domain, selector, addr, registeredAt)
	payload := sha256.Sum256([]byte(raw))

	// 5. Sign the 32-byte digest directly with a 64-byte R||S signature
	//    (SignCompact returns 1 recovery byte + R + S; we drop the byte).
	dpriv := secp256k1.PrivKeyFromBytes(privBytes)
	compact := ecdsa.SignCompact(dpriv, payload[:], false)
	sigHex := hex.EncodeToString(compact[1:]) // 64 bytes = 128 hex chars (MaxProofHex)

	// Self-check: the SDK's VerifySignature hashes msg with SHA-256 and
	// verifies the signature over that digest, i.e. exactly what we signed.
	if !pub.VerifySignature([]byte(raw), compact[1:]) {
		fmt.Fprintln(os.Stderr, "ERROR: self-check signature verification failed")
		os.Exit(1)
	}

	keyRecord := fmt.Sprintf("v=TAT1 k=secp256k1 p=%s a=%s", pubHex, addr)
	proofRecord := fmt.Sprintf("v=TAT1 sel=%s proof=%s t=%d", selector, sigHex, registeredAt)
	activeRecord := fmt.Sprintf("sel=%s", selector)

	fmt.Println("=== ThreatAttest DNS identity — generated records ===")
	fmt.Printf("Domain:            %s\n", domain)
	fmt.Printf("Selector:          %s\n", selector)
	fmt.Printf("Registered at:     %d\n\n", registeredAt)

	fmt.Println("--- Key material (STORE SECURELY) ---")
	fmt.Printf("Mnemonic (24 words): %s\n", mnemonic)
	fmt.Printf("Private key hex:     %s\n", hex.EncodeToString(privBytes))
	fmt.Printf("Public key hex:      %s\n", pubHex)
	fmt.Printf("Cosmos address:      %s\n\n", addr)

	fmt.Println("--- Proof ---")
	fmt.Printf("Payload digest:      %x\n", payload)
	fmt.Printf("Signature hex:       %s\n\n", sigHex)

	fmt.Println("--- DNS TXT records (zone-file format) ---")
	fmt.Printf("%s._tatkey.%s.   3600  IN  TXT  \"%s\"\n", selector, domain, keyRecord)
	fmt.Printf("_tatproof.%s.    3600  IN  TXT  \"%s\"\n", domain, proofRecord)
	fmt.Printf("_tatkey.%s.      3600  IN  TXT  \"%s\"\n\n", domain, activeRecord)

	fmt.Println("--- Verify propagation ---")
	fmt.Printf("dig +short TXT %s._tatkey.%s\n", selector, domain)
	fmt.Printf("dig +short TXT _tatproof.%s\n", domain)
	fmt.Printf("dig +short TXT _tatkey.%s\n", domain)
}
