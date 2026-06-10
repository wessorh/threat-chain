# ThreatAttest — Demo

This directory contains everything you need to run a live demonstration of the
ThreatAttest blockchain: a Cosmos SDK chain for publishing cryptographically
verifiable threat intelligence attestations for files, URLs, and IPv4 addresses.

---

## Contents

| File | Purpose |
|------|---------|
| `sample_malicious.txt` | Sample "malicious" file used as the attestation subject |
| `attest_file.sh` | Quick demo: hash a file and produce an attestation spec |
| `run_demo.sh` | Full end-to-end demo: init chain → start node → publish → query |
| `README.md` | This file |
| `MANPAGE.md` | Full markdown man page for all demo commands |

---

## Quick Start (2 minutes)

### 1. Build the binary

```bash
cd ..                      # project root (threatattest/)
export PATH=/usr/local/go/bin:$PATH
go build -o bin/threatattestd ./cmd/threatattestd
```

### 2. Run the file attestation demo

```bash
cd demo
chmod +x attest_file.sh
./attest_file.sh sample_malicious.txt
```

This will:
- Compute the SHA-256 of `sample_malicious.txt`
- Validate all attestation parameters locally
- Write `sample_malicious_attestation.json` with the full `MsgPublishAttestation` spec
- Print the exact `tx attestation publish` command to broadcast it on-chain

**Expected output:**

```
  ╔══════════════════════════════════════════════════════════╗
  ║           ThreatAttest — File Attestation Demo           ║
  ╚══════════════════════════════════════════════════════════╝

ℹ  File    : sample_malicious.txt
ℹ  Output  : sample_malicious_attestation.json

── Step 1/4  Compute SHA-256 ──────────────────────────────────
ℹ  sha256sum preview : 53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665

── Step 2/4  Run threatattestd attest-file ────────────────────

  ╔══════════════════════════════════════════════════════════════╗
  ║           ThreatAttest — File Attestation                   ║
  ╚══════════════════════════════════════════════════════════════╝

  File        : sample_malicious.txt
  Size        : 1220 bytes
  SHA-256     : 53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665
  Severity    : HIGH
  Confidence  : 90%
  TTL         : 86400 seconds (1 days)
  ...

✔  Attestation spec written to: sample_malicious_attestation.json
```

---

## Full Node Demo (10–15 minutes)

The full demo initialises a single-node ThreatAttest chain, publishes an
attestation on-chain, and queries it back.

### Prerequisites

```bash
# jq is required for JSON processing
apt-get install -y jq       # Debian/Ubuntu
brew install jq             # macOS
```

### Run

```bash
cd demo
chmod +x run_demo.sh
./run_demo.sh
```

The script walks through these steps automatically:

| Step | Action |
|------|--------|
| 0 | Preflight checks (binary, jq, sample file) |
| 1 | Clean previous demo state |
| 2 | `threatattestd init` — initialise chain config and genesis |
| 3 | `threatattestd keys add` — create the `demo-attester` key |
| 4 | `threatattestd add-genesis-account` — fund the genesis account |
| 5 | `threatattestd gentx` — create genesis validator transaction |
| 6 | `threatattestd collect-gentxs` — finalise genesis.json |
| 7 | `threatattestd validate` — validate the genesis file |
| 8 | `threatattestd start` — start the node (background) |
| 9 | `threatattestd attest-file` — hash file and write spec |
| 10 | `threatattestd tx attestation publish` — broadcast attestation |
| 11 | `threatattestd query attestation is-malicious` — verify result |
| 12 | `threatattestd query attestation get` — fetch full record |
| 13 | `threatattestd tx attestation endorse` — endorse the attestation |

### Environment overrides

All scripts respect these environment variables:

```bash
BINARY=../bin/threatattestd   # path to the binary
CHAIN_ID=threatattest-demo-1  # chain identifier
NODE=http://127.0.0.1:26657   # RPC endpoint
KEY_NAME=demo-attester        # key to use for signing
DENOM=utatst                  # native token denomination
FEES=500utatst                # transaction fee
```

Example with custom values:

```bash
CHAIN_ID=mychain NODE=http://10.0.0.1:26657 ./attest_file.sh malware.bin
```

---

## Manual Step-by-Step

If you prefer to run each command individually, here is the complete sequence.

### 1. Initialise

```bash
threatattestd init my-node --chain-id threatattest-1 --home ~/.threatattestd
```

### 2. Create a key

```bash
threatattestd keys add attester \
  --keyring-backend test \
  --home ~/.threatattestd
```

### 3. Fund genesis

```bash
ADDR=$(threatattestd keys show attester --keyring-backend test --home ~/.threatattestd --address)
threatattestd add-genesis-account "$ADDR" 10000000utatst \
  --keyring-backend test --home ~/.threatattestd
```

### 4. Genesis validator

```bash
threatattestd gentx attester 1000000utatst \
  --chain-id threatattest-1 \
  --keyring-backend test \
  --home ~/.threatattestd

threatattestd collect-gentxs --home ~/.threatattestd
threatattestd validate        --home ~/.threatattestd
```

### 5. Start the node

```bash
threatattestd start --home ~/.threatattestd
```

### 6. Hash the file and produce the spec

```bash
threatattestd attest-file sample_malicious.txt \
  --severity    HIGH \
  --confidence  92 \
  --ttl         604800 \
  --description "Ransomware dropper with C2 beaconing" \
  --tags        "ransomware,dropper,c2" \
  --category    "RANSOMWARE,TROJAN" \
  --output      attestation.json
```

### 7. Publish on-chain

```bash
SHA256=$(jq -r '.artifact_sha256' attestation.json)

threatattestd tx attestation publish \
  --artifact-sha256 "$SHA256" \
  --artifact-type   FILE \
  --severity        HIGH \
  --confidence      92 \
  --ttl             604800 \
  --description     "Ransomware dropper with C2 beaconing" \
  --tags            "ransomware,dropper,c2" \
  --category        "RANSOMWARE,TROJAN" \
  --from            attester \
  --chain-id        threatattest-1 \
  --fees            500utatst \
  --yes
```

### 8. Query

```bash
# Is this file flagged as malicious?
threatattestd query attestation is-malicious --sha256 "$SHA256"

# Full attestation record
threatattestd query attestation get --sha256 "$SHA256"

# All attestations for this artifact
threatattestd query attestation list-by-artifact --sha256 "$SHA256"
```

### 9. Endorse

```bash
threatattestd tx attestation endorse \
  --attestation-id "$SHA256" \
  --reason "Independent sandbox analysis confirms behavior" \
  --from   attester \
  --chain-id threatattest-1 \
  --fees   500utatst \
  --yes
```

---

## Attestation Spec Format

The `attest-file` command writes a JSON file in this format:

```json
{
  "schema_version": "1.0",
  "artifact_type": "FILE",
  "artifact_sha256": "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665",
  "severity": "HIGH",
  "confidence": 92,
  "ttl_seconds": 604800,
  "description": "Simulated ransomware dropper with C2 beaconing",
  "tags": ["ransomware", "dropper", "c2", "persistence"],
  "threat_category": ["RANSOMWARE", "TROJAN"],
  "attester": "tatst1abc123...",
  "published_at": 1773521751,
  "expires_at": 1774126551,
  "chain_id": "threatattest-1",
  "file_size_bytes": 1220,
  "file_name": "sample_malicious.txt"
}
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `binary not found` | Run `go build -o bin/threatattestd ./cmd/threatattestd` from project root |
| `jq not found` | `apt-get install jq` or `brew install jq` |
| `port already in use` | Kill the previous node: `pkill threatattestd` |
| `connection refused` | Node hasn't started yet — wait a few seconds |
| `insufficient funds` | Increase the genesis account balance in step 4 |
| `tx failed: reputation` | tatmint module requires reputation score; use genesis account |
| Node stuck at block 0 | Check logs: `tail -f /tmp/threatattestd-demo.log` |

---

## Architecture Overview

```
threatattestd
├── x/attestation   Publish, endorse, revoke, dispute file/URL/IP attestations
├── x/reputation    Reputation scores gating who can publish
├── x/tatmint       Block rewards and fee distribution
├── x/ipfsverify    IPFS CID pinning and verification for detection rules
└── app/            Cosmos SDK app wiring (CometBFT consensus)
```

See [MANPAGE.md](MANPAGE.md) for the full command reference.