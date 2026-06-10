# MANPAGE — threatattestd(1)

---

## NAME

**threatattestd** — ThreatAttest blockchain node and CLI

---

## SYNOPSIS

```
threatattestd [GLOBAL FLAGS] <command> [SUBCOMMAND] [FLAGS] [ARGS]
```

---

## DESCRIPTION

`threatattestd` is the all-in-one binary for the ThreatAttest blockchain — a
Cosmos SDK application-specific chain designed for publishing, endorsing, and
querying cryptographically verifiable threat intelligence attestations.

Attestations record the SHA-256 hash of a malicious artefact (file, URL, or
IPv4 address) together with metadata such as severity, confidence score, and
threat categories. Each attestation is:

- **Immutable** — stored in CometBFT consensus state
- **Attributable** — signed by the attester's on-chain key
- **Reputation-gated** — publishing requires a minimum reputation score
- **Time-limited** — every attestation carries a TTL after which it expires
- **Endorsable** — other analysts can co-sign an attestation to raise its trust score
- **Disputable** — any participant can file a dispute with evidence

The binary has two primary modes:

1. **Node mode** (`start`) — runs a full CometBFT validator/full node
2. **Client mode** — all other commands operate as a CLI client

---

## GLOBAL FLAGS

These flags are accepted by every subcommand.

| Flag | Default | Description |
|------|---------|-------------|
| `--home string` | `~/.threatattestd` | Directory for config, data, and keys |
| `--log_level string` | `info` | Log verbosity: `trace\|debug\|info\|warn\|error\|fatal\|panic\|disabled` |
| `--log_format string` | `plain` | Log format: `plain\|json` |
| `--log_no_color` | false | Disable ANSI colour in log output |
| `--trace` | false | Print full stack trace on errors |
| `-h, --help` | — | Show help for the command |

---

## COMMANDS

---

### `attest-file` — Hash a file and produce an attestation spec

#### Synopsis

```
threatattestd attest-file <FILE> [FLAGS]
```

#### Description

`attest-file` reads a local file, computes its SHA-256 digest, validates all
supplied attestation parameters, and writes a complete `MsgPublishAttestation`
JSON document to disk. No network connection is required; this command operates
entirely locally.

The output JSON can then be passed as input to `tx attestation publish` to
broadcast the attestation to a live ThreatAttest node.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `FILE` | Yes | Path to the file to attest (any type) |

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--severity string` | `MEDIUM` | Severity level: `UNSPECIFIED\|LOW\|MEDIUM\|HIGH\|CRITICAL` |
| `--confidence int` | `80` | Analyst confidence 0–100 that the artefact is malicious |
| `--ttl int` | `86400` | Time-to-live in seconds (max 2592000 = 30 days) |
| `--description string` | `""` | Human-readable description (max 1024 bytes, no HTML) |
| `--tags strings` | `[]` | Comma-separated tags, e.g. `ransomware,dropper` (max 16, each ≤ 32 bytes) |
| `--category strings` | `[]` | Comma-separated threat categories (max 8) |
| `--attester string` | placeholder | Bech32 attester address (`tatst1…`). Set via `keys show` |
| `--chain-id string` | `threatattest-1` | Chain ID to embed in the spec |
| `--output string` | `attestation.json` | Output file path for the JSON spec |
| `--dry-run` | false | Validate and print spec without writing to disk |

#### Valid Severity Values

| Value | Numeric | Use when |
|-------|---------|----------|
| `UNSPECIFIED` | 0 | Not yet assessed |
| `LOW` | 1 | Minimal risk, e.g. adware, PUP |
| `MEDIUM` | 2 | Moderate risk, e.g. spyware |
| `HIGH` | 3 | Serious risk, e.g. RAT, infostealer |
| `CRITICAL` | 4 | Catastrophic risk, e.g. wiper, ransomware |

#### Valid Threat Categories

`UNKNOWN`, `RANSOMWARE`, `TROJAN`, `WORM`, `VIRUS`, `SPYWARE`, `ADWARE`,
`ROOTKIT`, `BACKDOOR`, `KEYLOGGER`, `BOTNET`, `CRYPTOMINER`, `INFOSTEALER`,
`EXPLOIT`, `DROPPER`, `DOWNLOADER`, `PHISHING`, `SCAM`

#### Output JSON Schema

```json
{
  "schema_version": "1.0",
  "artifact_type":  "FILE",
  "artifact_sha256": "<hex>",
  "severity":       "HIGH",
  "confidence":     92,
  "ttl_seconds":    604800,
  "description":    "...",
  "tags":           ["ransomware", "dropper"],
  "threat_category":["RANSOMWARE", "TROJAN"],
  "attester":       "tatst1...",
  "published_at":   1773521751,
  "expires_at":     1774126551,
  "chain_id":       "threatattest-1",
  "file_size_bytes":1220,
  "file_name":      "sample_malicious.txt"
}
```

#### Examples

```bash
# Attest with default parameters (dry-run)
threatattestd attest-file sample_malicious.txt --dry-run

# Attest a suspicious binary as CRITICAL
threatattestd attest-file /path/to/malware.exe \
  --severity    CRITICAL \
  --confidence  99 \
  --ttl         2592000 \
  --description "Wiper malware targeting industrial control systems" \
  --tags        "wiper,ics,critical-infrastructure" \
  --category    "WORM,EXPLOIT" \
  --output      wiper_attestation.json

# Attest and include your on-chain address
ADDR=$(threatattestd keys show attester --keyring-backend test --address)
threatattestd attest-file suspicious.pdf \
  --severity    MEDIUM \
  --confidence  75 \
  --description "PDF with embedded JavaScript and external URL load" \
  --attester    "$ADDR" \
  --output      pdf_attestation.json
```

---

### `init` — Initialise chain configuration

#### Synopsis

```
threatattestd init <MONIKER> [FLAGS]
```

#### Description

Creates the node's home directory structure, generates node keys, and writes
the initial `genesis.json`, `config.toml`, and `app.toml` configuration files.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `MONIKER` | Yes | Human-readable node name |

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--chain-id string` | `threatattest-1` | Chain identifier written into genesis |
| `--home string` | `~/.threatattestd` | Directory to initialise |
| `--overwrite` | false | Overwrite existing genesis.json |
| `--default-denom string` | `utatst` | Default staking denomination |

#### Example

```bash
threatattestd init my-node --chain-id threatattest-1 --home ~/.threatattestd
```

---

### `keys` — Key management

#### Synopsis

```
threatattestd keys <subcommand> [FLAGS]
```

#### Subcommands

| Subcommand | Description |
|------------|-------------|
| `add <name>` | Generate a new key or recover from mnemonic |
| `list` | List all keys in the keyring |
| `show <name>` | Display key info (address, pubkey) |
| `delete <name>` | Delete a key |
| `export <name>` | Export private key (encrypted) |
| `import <name> <file>` | Import an encrypted private key |

#### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--keyring-backend string` | `os` | Keyring backend: `os\|file\|test\|memory` |
| `--home string` | `~/.threatattestd` | Home directory for key storage |
| `--output string` | `text` | Output format: `text\|json` |

#### Examples

```bash
# Create a new key
threatattestd keys add attester --keyring-backend test

# Recover key from mnemonic
threatattestd keys add attester --keyring-backend test --recover

# Show address
threatattestd keys show attester --keyring-backend test --address

# List all keys
threatattestd keys list --keyring-backend test --output json
```

---

### `add-genesis-account` — Fund a genesis account

#### Synopsis

```
threatattestd add-genesis-account <ADDRESS|KEY_NAME> <COINS> [FLAGS]
```

#### Description

Adds an account to `genesis.json` with the specified coin balance. Must be run
before `gentx` and `collect-gentxs`.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `ADDRESS\|KEY_NAME` | Yes | Bech32 address or key name |
| `COINS` | Yes | Comma-separated coin amounts, e.g. `10000000utatst` |

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--keyring-backend string` | `os` | Keyring backend |
| `--home string` | `~/.threatattestd` | Home directory |
| `--vesting-amount string` | `""` | Vesting amount (optional) |
| `--vesting-end-time int` | `0` | Unix timestamp for vesting end |

#### Example

```bash
ADDR=$(threatattestd keys show attester --keyring-backend test --address)
threatattestd add-genesis-account "$ADDR" 10000000utatst \
  --keyring-backend test \
  --home ~/.threatattestd
```

---

### `gentx` — Create genesis validator transaction

#### Synopsis

```
threatattestd gentx <KEY_NAME> <AMOUNT> [FLAGS]
```

#### Description

Generates a signed genesis transaction that creates a validator with a
self-delegation. The transaction is written to `<home>/config/gentx/`.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `KEY_NAME` | Yes | Name of the key to use for signing |
| `AMOUNT` | Yes | Self-delegation amount, e.g. `1000000utatst` |

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--chain-id string` | `threatattest-1` | Chain ID |
| `--keyring-backend string` | `os` | Keyring backend |
| `--home string` | `~/.threatattestd` | Home directory |
| `--moniker string` | hostname | Validator moniker |
| `--commission-rate string` | `0.1` | Initial commission rate |
| `--commission-max-rate string` | `0.2` | Maximum commission rate |
| `--commission-max-change-rate string` | `0.01` | Max commission change per day |
| `--min-self-delegation string` | `1` | Minimum self-delegation |

#### Example

```bash
threatattestd gentx attester 1000000utatst \
  --chain-id        threatattest-1 \
  --keyring-backend test \
  --home            ~/.threatattestd \
  --moniker         "my-validator"
```

---

### `collect-gentxs` — Collect genesis transactions

#### Synopsis

```
threatattestd collect-gentxs [FLAGS]
```

#### Description

Reads all `gentx` files from `<home>/config/gentx/`, validates them, and
merges them into `genesis.json`. Run this after all validators have submitted
their `gentx`.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--home string` | `~/.threatattestd` | Home directory |
| `--gentx-dir string` | `<home>/config/gentx` | Directory containing gentx files |

#### Example

```bash
threatattestd collect-gentxs --home ~/.threatattestd
```

---

### `validate` — Validate genesis file

#### Synopsis

```
threatattestd validate [GENESIS_FILE] [FLAGS]
```

#### Description

Validates the genesis file for structural correctness, consistent balances,
valid validator keys, and module-specific invariants.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `GENESIS_FILE` | No | Path to genesis file (default: `<home>/config/genesis.json`) |

#### Example

```bash
threatattestd validate --home ~/.threatattestd
```

---

### `start` — Start the node

#### Synopsis

```
threatattestd start [FLAGS]
```

#### Description

Starts the ThreatAttest full node. The node connects to peers, participates in
CometBFT consensus, and exposes RPC, gRPC, and REST API endpoints.

#### Key Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--home string` | `~/.threatattestd` | Home directory |
| `--log_level string` | `info` | Log verbosity |
| `--rpc.laddr string` | `tcp://127.0.0.1:26657` | RPC listen address |
| `--p2p.laddr string` | `tcp://0.0.0.0:26656` | P2P listen address |
| `--grpc.address string` | `localhost:9090` | gRPC listen address |
| `--grpc.enable` | `true` | Enable gRPC server |
| `--api.enable` | `false` | Enable REST API server |
| `--api.address string` | `tcp://localhost:1317` | REST API listen address |
| `--minimum-gas-prices string` | `""` | Minimum gas price (e.g. `0.01utatst`) |
| `--with-comet` | `true` | Run with CometBFT consensus engine |

#### Example

```bash
# Development node (all endpoints, verbose logging)
threatattestd start \
  --home        ~/.threatattestd \
  --log_level   debug \
  --rpc.laddr   tcp://127.0.0.1:26657 \
  --api.enable  \
  --api.address tcp://127.0.0.1:1317

# Production node (minimal logging, custom gas price)
threatattestd start \
  --home                ~/.threatattestd \
  --log_level           warn \
  --minimum-gas-prices  "0.01utatst"
```

---

### `tx attestation` — Attestation transactions

All transaction subcommands share these common flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--from string` | — | Key name or address to sign with (**required**) |
| `--chain-id string` | `""` | Chain ID (**required**) |
| `--keyring-backend string` | `os` | Keyring backend |
| `--home string` | `~/.threatattestd` | Home directory |
| `--node string` | `tcp://localhost:26657` | RPC node address |
| `--fees string` | `""` | Transaction fees, e.g. `500utatst` |
| `--gas string` | `200000` | Gas limit (or `auto`) |
| `--gas-adjustment float` | `1.0` | Gas adjustment multiplier (with `--gas auto`) |
| `--yes` | false | Skip confirmation prompt |
| `--output string` | `text` | Output format: `text\|json` |
| `--broadcast-mode string` | `sync` | Broadcast mode: `sync\|async\|block` |

---

#### `tx attestation publish` — Publish an attestation

```
threatattestd tx attestation publish [FLAGS]
```

Publishes a new `MsgPublishAttestation` to the chain. Requires the attester to
have a minimum reputation score (set in module params).

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--artifact-sha256 string` | Yes | Hex-encoded SHA-256 of the artefact |
| `--artifact-type string` | Yes | Artefact type: `FILE\|URL\|IPV4` |
| `--severity string` | Yes | `UNSPECIFIED\|LOW\|MEDIUM\|HIGH\|CRITICAL` |
| `--confidence int` | Yes | Confidence score 0–100 |
| `--ttl int` | Yes | Time-to-live in seconds (max 2592000) |
| `--description string` | No | Human-readable description (max 1024 bytes) |
| `--tags strings` | No | Comma-separated tags (max 16) |
| `--category strings` | No | Comma-separated threat categories (max 8) |
| `--raw-value string` | No | Raw artefact value (URL or IPv4 string) |
| `--ipfs-cid string` | No | IPFS CID of supporting evidence |

**Example:**

```bash
threatattestd tx attestation publish \
  --artifact-sha256 "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --artifact-type   FILE \
  --severity        HIGH \
  --confidence      92 \
  --ttl             604800 \
  --description     "Ransomware dropper with C2 beaconing and AES-256 encryption" \
  --tags            "ransomware,dropper,c2,persistence" \
  --category        "RANSOMWARE,TROJAN" \
  --from            attester \
  --chain-id        threatattest-1 \
  --fees            500utatst \
  --yes
```

**URL attestation example:**

```bash
threatattestd tx attestation publish \
  --artifact-sha256 "$(echo -n 'https://malicious.example.com/payload' | sha256sum | awk '{print $1}')" \
  --artifact-type   URL \
  --raw-value       "https://malicious.example.com/payload" \
  --severity        HIGH \
  --confidence      88 \
  --ttl             86400 \
  --description     "Malware distribution endpoint" \
  --tags            "malware-distribution,c2" \
  --from            attester \
  --chain-id        threatattest-1 \
  --fees            500utatst \
  --yes
```

**IPv4 attestation example:**

```bash
threatattestd tx attestation publish \
  --artifact-sha256 "$(echo -n '192.168.1.100' | sha256sum | awk '{print $1}')" \
  --artifact-type   IPV4 \
  --raw-value       "192.168.1.100" \
  --severity        MEDIUM \
  --confidence      70 \
  --ttl             172800 \
  --description     "Observed C2 beacon destination" \
  --tags            "c2,beacon" \
  --from            attester \
  --chain-id        threatattest-1 \
  --fees            500utatst \
  --yes
```

---

#### `tx attestation endorse` — Endorse an attestation

```
threatattestd tx attestation endorse [FLAGS]
```

Co-signs an existing attestation to increase its trust/consensus score.
A given address can only endorse each attestation once. Self-endorsement is
rejected by the module.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--attestation-id string` | Yes | SHA-256 (artefact ID) of the attestation to endorse |
| `--reason string` | No | Free-text reason for endorsement (max 512 bytes) |

**Example:**

```bash
threatattestd tx attestation endorse \
  --attestation-id "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --reason         "Independent sandbox analysis confirms ransomware behaviour" \
  --from           second-analyst \
  --chain-id       threatattest-1 \
  --fees           500utatst \
  --yes
```

---

#### `tx attestation revoke` — Revoke an attestation

```
threatattestd tx attestation revoke [FLAGS]
```

Marks an attestation as `REVOKED`. Only the original attester may revoke their
own attestation.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--attestation-id string` | Yes | SHA-256 of the attestation to revoke |
| `--reason string` | No | Reason for revocation (max 512 bytes) |

**Example:**

```bash
threatattestd tx attestation revoke \
  --attestation-id "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --reason         "False positive — file was confirmed benign by vendor" \
  --from           attester \
  --chain-id       threatattest-1 \
  --fees           500utatst \
  --yes
```

---

#### `tx attestation dispute` — Dispute an attestation

```
threatattestd tx attestation dispute [FLAGS]
```

Files a formal dispute against an attestation. The dispute is recorded on-chain
and triggers governance review. The disputer cannot be the original attester.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--attestation-id string` | Yes | SHA-256 of the attestation to dispute |
| `--ground string` | Yes | Ground for dispute: `FALSE_POSITIVE\|INSUFFICIENT_EVIDENCE\|WRONG_SEVERITY\|OTHER` |
| `--evidence string` | No | Free-text evidence or IPFS CID (max 2048 bytes) |

**Example:**

```bash
threatattestd tx attestation dispute \
  --attestation-id "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --ground         FALSE_POSITIVE \
  --evidence       "VirusTotal shows 0/72 detections. IPFS analysis: ipfs://Qm..." \
  --from           third-party \
  --chain-id       threatattest-1 \
  --fees           500utatst \
  --yes
```

---

### `query attestation` — Attestation queries

All query subcommands share these common flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--node string` | `tcp://localhost:26657` | RPC node address |
| `--home string` | `~/.threatattestd` | Home directory |
| `--output string` | `text` | Output format: `text\|json` |
| `--height int` | `0` | Query at a specific block height (0 = latest) |

---

#### `query attestation is-malicious` — Check if a SHA-256 is flagged

```
threatattestd query attestation is-malicious [FLAGS]
```

Returns a boolean result indicating whether any active, non-revoked attestation
exists for the given SHA-256.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--sha256 string` | Yes | Hex SHA-256 to query |

**Example:**

```bash
threatattestd query attestation is-malicious \
  --sha256  "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --node    http://127.0.0.1:26657 \
  --output  json
```

**Response:**

```json
{
  "is_malicious": true,
  "attestation_count": 1,
  "highest_severity": "HIGH",
  "consensus_score": 92
}
```

---

#### `query attestation get` — Fetch a full attestation record

```
threatattestd query attestation get [FLAGS]
```

Retrieves the complete attestation record for a given SHA-256, including all
metadata, endorsement count, and status.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--sha256 string` | Yes | Hex SHA-256 to query |

**Example:**

```bash
threatattestd query attestation get \
  --sha256  "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --node    http://127.0.0.1:26657 \
  --output  json
```

**Response:**

```json
{
  "attestation": {
    "id": "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665",
    "artifact_type": "FILE",
    "attester": "tatst1abc123...",
    "severity": "HIGH",
    "confidence": 92,
    "description": "Ransomware dropper with C2 beaconing",
    "tags": ["ransomware", "dropper", "c2"],
    "threat_category": ["RANSOMWARE", "TROJAN"],
    "status": "ACTIVE",
    "endorsement_count": 1,
    "trust_score": 95,
    "published_at": "2025-05-11T20:55:55Z",
    "expires_at": "2025-05-18T20:55:55Z"
  }
}
```

---

#### `query attestation list-by-artifact` — List all attestations for an artefact

```
threatattestd query attestation list-by-artifact [FLAGS]
```

Returns all attestations (across attesters) that reference the same SHA-256.

**Flags:**

| Flag | Required | Description |
|------|----------|-------------|
| `--sha256 string` | Yes | Hex SHA-256 to query |
| `--limit int` | No | Maximum number of results (default 20) |
| `--offset int` | No | Pagination offset |

**Example:**

```bash
threatattestd query attestation list-by-artifact \
  --sha256  "53aa45cf908f57fa1f74627aa0b14964387c28e24b763bdf2b20a8228583f665" \
  --limit   10 \
  --node    http://127.0.0.1:26657 \
  --output  json
```

---

### `status` — Query node status

#### Synopsis

```
threatattestd status [FLAGS]
```

#### Description

Returns the current node status: node info, sync state, validator info, and
latest block height.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--node string` | `tcp://localhost:26657` | RPC node address |

#### Example

```bash
threatattestd status --node http://127.0.0.1:26657
```

---

### `wait-tx` — Wait for a transaction to be included

#### Synopsis

```
threatattestd wait-tx [FLAGS]
```

#### Description

Polls the chain until a submitted transaction is included in a block, then
prints the result. Useful after `--broadcast-mode async`.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--hash string` | — | Transaction hash to wait for |
| `--node string` | `tcp://localhost:26657` | RPC node address |
| `--timeout duration` | `15s` | Maximum wait time |

#### Example

```bash
threatattestd wait-tx \
  --hash  ABCDEF1234567890... \
  --node  http://127.0.0.1:26657
```

---

### `version` — Print version information

```
threatattestd version [--long] [--output json|text]
```

Prints the binary version, commit hash, build date, Go version, and Cosmos SDK
version.

```bash
threatattestd version --long --output json
```

---

### `query tx` — Query a transaction by hash

```
threatattestd query tx <TX_HASH> [FLAGS]
```

Fetches full transaction details including events, logs, and gas usage.

```bash
threatattestd query tx ABCDEF1234... \
  --node http://127.0.0.1:26657 \
  --output json
```

---

### `query block` — Query a block by height

```
threatattestd query block <HEIGHT> [FLAGS]
```

```bash
threatattestd query block 100 --node http://127.0.0.1:26657
```

---

### `comet` — CometBFT subcommands

```
threatattestd comet <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `show-node-id` | Print the node's p2p ID |
| `show-validator` | Print the node's validator key |
| `show-address` | Print the validator consensus address |
| `version` | Print CometBFT version |
| `unsafe-reset-all` | Reset all CometBFT data (DESTRUCTIVE) |

---

### `debug` — Debugging utilities

```
threatattestd debug <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `pubkey` | Decode a public key |
| `addr` | Convert address formats |
| `raw-bytes` | Convert raw bytes to hex |

---

### `snapshots` — Manage local snapshots

```
threatattestd snapshots <subcommand>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List local snapshots |
| `load <archive>` | Load a snapshot archive |
| `restore <height> <format>` | Restore state from snapshot |
| `export` | Export current state to snapshot |
| `dump <height> <format>` | Dump snapshot to archive |
| `delete <height> <format>` | Delete a snapshot |

---

### `rollback` — Roll back one block

```
threatattestd rollback [FLAGS]
```

Rolls back the Cosmos SDK and CometBFT state by exactly one block. Use this to
recover from an app-hash mismatch.

| Flag | Default | Description |
|------|---------|-------------|
| `--hard` | false | Remove the last block from CometBFT state |

---

### `export` — Export chain state to JSON

```
threatattestd export [FLAGS]
```

Exports the full application state as a JSON genesis document. Useful for
chain migrations and backups.

| Flag | Default | Description |
|------|---------|-------------|
| `--height int` | `0` | Export at height (0 = latest) |
| `--for-zero-height` | false | Export for migration (reset heights) |
| `--jail-allowed-addrs strings` | `""` | Validator addresses to un-jail |

---

## ENVIRONMENT VARIABLES

| Variable | Description |
|----------|-------------|
| `TATST_HOME` | Overrides `--home` |
| `TATST_CHAIN_ID` | Overrides `--chain-id` |
| `TATST_NODE` | Overrides `--node` |
| `TATST_KEYRING_BACKEND` | Overrides `--keyring-backend` |
| `TATST_LOG_LEVEL` | Overrides `--log_level` |
| `TATST_LOG_FORMAT` | Overrides `--log_format` |

---

## FILES

| Path | Description |
|------|-------------|
| `~/.threatattestd/config/config.toml` | CometBFT configuration |
| `~/.threatattestd/config/app.toml` | Application configuration (API, gRPC, etc.) |
| `~/.threatattestd/config/genesis.json` | Chain genesis state |
| `~/.threatattestd/config/priv_validator_key.json` | Validator private key (**keep secret**) |
| `~/.threatattestd/config/node_key.json` | Node p2p identity key |
| `~/.threatattestd/data/` | CometBFT block and state databases |
| `~/.threatattestd/keyring-test/` | Test keyring key files |

---

## PORTS

| Port | Protocol | Purpose |
|------|----------|---------|
| `26656` | TCP | CometBFT p2p (peer connections) |
| `26657` | TCP/HTTP | CometBFT RPC (CLI, status, queries) |
| `26660` | TCP/HTTP | Prometheus metrics (if enabled) |
| `9090` | TCP | gRPC (Cosmos SDK queries and txs) |
| `9091` | TCP | gRPC-gateway (REST over gRPC) |
| `1317` | TCP/HTTP | Legacy REST API (Cosmos SDK) |

---

## ATTESTATION LIFECYCLE

```
                    ┌─────────────────────────────────┐
                    │         PENDING (genesis)        │
                    └────────────────┬────────────────┘
                                     │ MsgPublishAttestation
                                     ▼
                    ┌─────────────────────────────────┐
                    │              ACTIVE              │◄──── MsgEndorseAttestation
                    └──┬──────────────┬───────────────┘
                       │ MsgRevoke    │ TTL expires
                       ▼             ▼
               ┌────────────┐  ┌───────────┐
               │  REVOKED   │  │  EXPIRED  │
               └────────────┘  └───────────┘
                       ▲
                       │ Governance resolves dispute
               ┌────────────────┐
               │  DISPUTED      │◄──── MsgDisputeAttestation
               └────────────────┘
```

---

## TRUST SCORE FORMULA

The trust score shown in `query attestation get` is computed as:

```
TrustScore = (Severity × 20) + (Confidence × 0.5) + (EndorsementCount × 5)
             + (AttesterReputationScore × 0.1)
```

Capped at 100. An attestation with `TrustScore >= 60` is returned as
`is_malicious: true` by the `is-malicious` query.

---

## EXAMPLES — COMPLETE WORKFLOW

```bash
# 1. Initialise chain
threatattestd init demo-node --chain-id threatattest-1

# 2. Create attester key
threatattestd keys add attester --keyring-backend test

# 3. Fund genesis
ADDR=$(threatattestd keys show attester --keyring-backend test --address)
threatattestd add-genesis-account "$ADDR" 10000000utatst --keyring-backend test
threatattestd gentx attester 1000000utatst --chain-id threatattest-1 --keyring-backend test
threatattestd collect-gentxs
threatattestd validate

# 4. Start node
threatattestd start &

# 5. Hash file and create spec
threatattestd attest-file malware.bin \
  --severity HIGH --confidence 92 --ttl 604800 \
  --description "Ransomware dropper" \
  --tags "ransomware,dropper" --category "RANSOMWARE" \
  --output attestation.json

# 6. Publish
SHA256=$(jq -r .artifact_sha256 attestation.json)
threatattestd tx attestation publish \
  --artifact-sha256 "$SHA256" --artifact-type FILE \
  --severity HIGH --confidence 92 --ttl 604800 \
  --description "Ransomware dropper" \
  --tags "ransomware,dropper" --category "RANSOMWARE" \
  --from attester --chain-id threatattest-1 \
  --fees 500utatst --yes

# 7. Query
threatattestd query attestation is-malicious --sha256 "$SHA256"
threatattestd query attestation get          --sha256 "$SHA256"

# 8. Endorse
threatattestd tx attestation endorse \
  --attestation-id "$SHA256" \
  --reason "Confirmed by independent analysis" \
  --from attester --chain-id threatattest-1 --fees 500utatst --yes
```

---

## SEE ALSO

- [README.md](README.md) — Demo quick-start guide
- [Cosmos SDK Documentation](https://docs.cosmos.network)
- [CometBFT Documentation](https://docs.cometbft.com)
- [ThreatAttest Source](https://github.com/threatattest/chain)

---

## BUGS

Report issues at https://github.com/threatattest/chain/issues

---

## AUTHORS

ThreatAttest Contributors

---

## VERSION

ThreatAttest v0.1.0 · Cosmos SDK v0.50.9 · CometBFT v0.38.9 · Go 1.22

---

*Generated for ThreatAttest Demo — see `demo/` directory*