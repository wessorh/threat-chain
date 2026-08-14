# ThreatAttest — System Requirements

> Decentralized threat intelligence on a Cosmos SDK blockchain
> with a browser extension for real-time protection.

---

## 1. System Overview

ThreatAttest is a two-component system:

| Component | Description | Language | Build Output |
|-----------|-------------|----------|-------------|
| **chain/** | Cosmos SDK blockchain node (`threatattestd`) | Go 1.23 | Single binary |
| **extension/** | ThreatAttest Shield browser extension (MV3) | JavaScript | `.zip` for Chrome Web Store |

The chain publishes, endorses, disputes, and revokes cryptographically verifiable threat intelligence attestations. The extension consumes the chain's REST API to provide real-time protection in the browser — checking downloads, URLs, domains, and IPs against on-chain attestations.

---

## 2. Functional Requirements

### 2.1 Chain — Attestation Module (`x/attestation`)

**FR-ATT-01** — The system shall accept attestation publications for artifacts of type FILE, URL, IPV4, and DOMAIN.

**FR-ATT-02** — Each attestation shall be uniquely identified by `SHA-256(artifact_sha256 | attester | published_at)`.

**FR-ATT-03** — Attestations shall carry: artifact SHA-256, severity (INFO/LOW/MEDIUM/HIGH/CRITICAL), TLP level, confidence (0–100), TTL, description, tags, threat categories (17 TATST-prefixed types), detection rules (up to 32), MITRE ATT&CK IDs, and PUA metadata.

**FR-ATT-04** — Attesters shall be rate-limited per epoch (default: 100 attestations/epoch, ~1 hour).

**FR-ATT-05** — Attester confidence shall be scaled by identity compliance tier:
- Anonymous: 0.25×
- Staked: 0.50×
- DNS_Bound: 1.00×
- Expert: 2.00×

**FR-ATT-06** — The system shall support endorsement of attestations by other attesters, incrementing endorsement count and trust score.

**FR-ATT-07** — The system shall support disputes on five grounds: FALSE_POSITIVE, INCORRECT_SEVERITY, FABRICATED_EVIDENCE, STALE_REUSE, SYBIL_ATTACK.

**FR-ATT-08** — Only the original attester may revoke their own attestation.

**FR-ATT-09** — Attestations shall auto-expire after their TTL elapses (EndBlocker sweep of expiry queue).

**FR-ATT-10** — The system shall provide queries: is-malicious (by SHA-256, URL, or IPv4), get-attestation (by ID), list-by-artifact, list-by-attester, get-dispute, is-blacklisted, params.

**FR-ATT-11** — Trust score shall be computed as:
```
severity_weight × (confidence/100) × (1 + log₂(1 + endorsements)) × tier_weight
```

**FR-ATT-12** — Attesters shall claim a share of the attestation incentive pool via `MsgClaimReward`. Each claim withdraws 1% of the pool balance, is rate-limited to one claim per attester per epoch, and requires a non-empty pool.

**FR-ATT-13** — The system shall support paid API subscription tiers via `MsgSubscribe`/`MsgUnsubscribe`:

| Tier | Stake | Lock | Rate limit | Features |
|------|-------|------|------------|----------|
| FREE | 0 | — | 10 req/min | SHA-256 lookup |
| PROFESSIONAL | 1,000 TATST | 90 days | 1,000 req/min | all |
| ENTERPRISE | 100,000 TATST | 365 days | 10,000 req/min | all |

Re-subscribing refunds the prior stake before locking the new one; `MsgUnsubscribe` returns the full stake.

### 2.2 Chain — Identity Module (`x/identity`)

**FR-ID-01** — The system shall bind Cosmos addresses to DNSSEC-secured domain names via DNS TXT records.

**FR-ID-02** — Identity registration shall require: domain proof signature, DNSSEC evidence bundle (TXT records, RRSIGs, DNSKEYs, DS records), and optional flags (EXPERT, ORGANIZATION, GOVERNMENT, SECURITY_FIRM, AUTOMATED, MULTISIG).

**FR-ID-03** — The system shall support four compliance tiers affecting attestation confidence: ANONYMOUS, STAKED, DNS_BOUND, EXPERT.

**FR-ID-04** — Identity key rotation shall require dual signatures (old key + new key), following DKIM-style dual-selector rotation.

**FR-ID-05** — Identities shall expire after 1 year (default) and require renewal with fresh DNSSEC evidence.

**FR-ID-06** — Revoked identities shall incur a −100 reputation score penalty and be permanent.

**FR-ID-07** — The system shall validate DNSSEC evidence: freshness (1h max), algorithm allow-list (ECDSA P-256 SHA-256/algorithm 13 as RECOMMENDED), TXT record format (`v=TAT1 k=secp256k1 p={hex} a={addr}`).

### 2.3 Chain — Reputation Module (`x/reputation`)

**FR-REP-01** — The system shall track non-transferable reputation scores per attester address (0–10,000).

**FR-REP-02** — Scores shall decay at 10 basis points/day after 30 days of inactivity (lazy decay on read/write).

**FR-REP-03** — Lifecycle events shall adjust scores: registration +200, 30-day milestone +50, renewal +10, DNS removed −200, revoked −100.

**FR-REP-04** — The system shall support blacklisting of attesters via governance.

### 2.4 Chain — IPFS Verify Module (`x/ipfsverify`)

**FR-IPFS-01** — The system shall verify that detection rules (YARA, Sigma, Snort, Suricata, OpenIOC) stored on IPFS match their claimed SHA-256 hashes.

**FR-IPFS-02** — An off-chain verifier daemon shall submit verification reports. Verification jobs are created on-chain and enqueued; reports are submitted by whitelisted relayers.

**FR-IPFS-03** — Verification jobs shall timeout after 300 blocks (~10 minutes, configurable), with up to 3 retries.

### 2.5 Chain — Token Minting (`x/tatmint`)

**FR-MINT-01** — The system shall mint TATST tokens with a halving schedule: initial 10 TATST/block, halving every 2,102,400 blocks (~4 years), 30 halvings max, 1 billion TATST supply cap.

**FR-MINT-02** — Distribution split: 50% validators, 20% community pool, 30% attester incentives.

### 2.6 Browser Extension

**FR-EXT-01** — The extension shall check every completed download against the chain's `is-malicious` endpoint by SHA-256.

**FR-EXT-02** — The extension shall check every navigated URL and domain against the chain's `is-malicious-url` and `is-malicious` (SHA-256 of domain) endpoints.

**FR-EXT-03** — The extension shall extract IPv4 addresses from page resources (meta tags, script/img/iframe/link URLs, CSP, dns-prefetch, performance entries) and check them against the chain's `is-malicious-ipv4` endpoint.

**FR-EXT-04** — On threat detection, the extension shall:
- CRITICAL/HIGH: auto-block the action (cancel download, block navigation)
- MEDIUM/LOW/INFO: display an inline overlay banner with Block/Allow/Detail buttons
- All severities: update the toolbar badge (green = clean, yellow = MEDIUM, red = HIGH/CRITICAL)

**FR-EXT-05** — Download threats shall present a standalone decision popup with Block & Delete, Allow Once, Snooze 30 min, and Always Allow options.

**FR-EXT-06** — The extension shall display DNS identity badges for domains with on-chain identity records, showing tier, trust score, and flags.

**FR-EXT-07** — API responses shall be cached in-memory with a 5-minute TTL (2-minute for negative identity lookups).

**FR-EXT-08** — The extension shall perform periodic node health checks every 2 minutes via the `/cosmos/base/tendermint/v1beta1/node_info` endpoint.

**FR-EXT-09** — Files over 50 MB shall be skipped. Files from URLs that cannot be re-fetched (HTTP auth) shall be skipped.

**FR-EXT-10** — The extension shall support configurable node URL, severity thresholds, auto-block rules, notifications, and domain/IP whitelists.

---

## 3. Non-Functional Requirements

### 3.1 Chain

| Requirement | Value |
|-------------|-------|
| **Consensus** | CometBFT 0.38.10, 2s blocks |
| **Bech32 prefix** | `tatst` |
| **Token denom** | `utatst` (micro), `tatst` (whole) |
| **State store** | Cosmos SDK KV store (GoLevelDB default) |
| **Validators** | 100 max, 21-day unbonding |
| **Governance** | 10,000 TATST min deposit, 2-day voting, 33.4% quorum |
| **Slashing** | 5% double-sign, 1% downtime, 100-block signed window |
| **gRPC** | Port 9090 |
| **REST (LCD)** | Port 1317 |
| **RPC** | Port 26657 |
| **P2P** | Port 26656 |
| **Min attestation TTL** | 3,600 seconds (1 hour) |
| **Max attestation TTL** | 31,536,000 seconds (1 year) |
| **Max IPv4 TTL** | 7,776,000 seconds (90 days) |
| **Max detection rules** | 32 per attestation |
| **Identity TTL** | 31,536,000 seconds (1 year default) |
| **DNS verification epoch** | 43,200 blocks (~24 hours) |
| **Expert tier threshold** | 5,000 reputation score |
| **Block reward halving** | Every 2,102,400 blocks (~4 years) |

### 3.2 Extension

| Requirement | Value |
|-------------|-------|
| **Manifest version** | MV3 |
| **Browser support** | Chromium 88+ (Chrome, Edge, Brave) |
| **Default chain endpoint** | `http://localhost:1317` (dev) / `https://api.threatattest.io` (prod) |
| **API cache TTL** | 5 minutes (positive), 2 minutes (negative identity) |
| **Max download size** | 50 MB |
| **Max threats per tab** | 20 |
| **Node health interval** | 2 minutes |
| **Identity badge lookup** | On navigation + on popup open |
| **Permissions** | downloads, webRequest, storage, notifications, tabs, activeTab, scripting, alarms, declarativeNetRequest |
| **Host access** | `<all_urls>` |

### 3.3 Security

| Requirement | Value |
|-------------|-------|
| **Identity proof** | DNSSEC chain-of-trust (ECDSA P-256 SHA-256 / algorithm 13) |
| **Attestation signing** | secp256k1 (Cosmos key) |
| **Artifact hashing** | SHA-256 |
| **Attestation ID** | SHA-256(artifact_sha256 | attester | published_at) |
| **Identity ID** | SHA-256(domain | selector | cosmos_addr) |
| **Dispute bond** | 500 TATST |
| **Blacklist** | Governance-gated |
| **Confidence scaling** | By identity tier (0.25×–2.00×) |
| **IPFS rule verification** | Off-chain verifier daemon, whitelisted relayers |
| **Extension content script** | Isolated world (MV3 default) |
| **API communication** | HTTP (localhost dev) / HTTPS (production) |

---

## 4. API Endpoints (Chain REST)

### 4.1 Attestation Queries

| Method | Path | Description |
|--------|------|-------------|
| GET | `/threatattest/attestation/v1/is-malicious?artifact_sha256={hex}` | Check SHA-256 |
| GET | `/threatattest/attestation/v1/is-malicious-url?url={url}` | Check URL |
| GET | `/threatattest/attestation/v1/is-malicious-ipv4?ipv4={ip}` | Check IPv4 |
| GET | `/threatattest/attestation/v1/attestation/{id}` | Get attestation |
| GET | `/threatattest/attestation/v1/list-by-artifact?artifact_sha256={hex}` | List by SHA-256 |
| GET | `/threatattest/attestation/v1/list-by-attester?attester={addr}` | List by attester |

### 4.2 Identity Queries

| Method | Path | Description |
|--------|------|-------------|
| GET | `/identity/address/{addr}` | Get identity by address |
| GET | `/identity/domain/{domain}` | Get identity by domain |
| GET | `/identity/id/{id}` | Get identity by ID |

### 4.3 Node Status

| Method | Path | Description |
|--------|------|-------------|
| GET | `/cosmos/base/tendermint/v1beta1/node_info` | Node health + version |

---

## 5. CLI Commands (`threatattestd`)

### 5.1 Convenience Commands

| Command | Description |
|---------|-------------|
| `attest-file <file>` | Hash a file and produce attestation JSON spec |
| `attest-url <url>` | Normalize URL and produce URL attestation spec |
| `attest-domain <domain>` | Normalize domain and produce domain attestation spec |

### 5.2 Attestation Transactions

| Command | Description |
|---------|-------------|
| `tx attestation publish` | Publish a new attestation |
| `tx attestation endorse <id>` | Endorse an existing attestation |
| `tx attestation revoke <id>` | Revoke your attestation |
| `tx attestation dispute <id>` | File a dispute |

### 5.3 Identity Transactions

| Command | Description |
|---------|-------------|
| `tx identity register-identity` | Register DNS-anchored identity |
| `tx identity rotate-identity-key` | Rotate signing key |
| `tx identity revoke-identity` | Revoke identity |
| `tx identity renew-identity` | Renew with fresh DNSSEC evidence |

---

## 6. Data Flow

```
┌──────────────────────────────────────────────────────┐
│                   ThreatAttest Chain                  │
│                                                      │
│  attester ──→ PublishAttestation ──→ KV Store        │
│                   │                    ├─ ArtifactIndex│
│                   │                    ├─ AttesterIndex│
│                   ▼                    └─ ExpiryQueue  │
│              EndBlocker: Expire                        │
│              BeginBlocker: Epoch                       │
│                                                      │
│  extension ──→ REST API (LCD :1317)                  │
│    │          is-malicious?artifact_sha256=...        │
│    │          is-malicious-url?url=...                │
│    │          is-malicious-ipv4?ipv4=...              │
│    │                                                 │
│    ▼                                                 │
│  response: { malicious, attestation, trust_score }    │
└──────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│              ThreatAttest Shield Extension            │
│                                                      │
│  download ──→ SHA-256 ──→ isMaliciousBySHA256()      │
│  navigate ──→ normalize ──→ isMaliciousByURL()       │
│  navigate ──→ SHA-256(domain) ──→ isMaliciousBySHA() │
│  page IPs ──→ isMaliciousByIPv4()                    │
│                                                      │
│  → cache (5 min TTL)                                 │
│  → badge update (green/yellow/red)                   │
│  → threat overlay / popup / notification             │
└──────────────────────────────────────────────────────┘
```

---

## 7. Deployment

### 7.1 Chain (Production)

```bash
# Build
cd chain && make build

# Init
./bin/threatattestd init my-node --chain-id threatattest-1

# Start
./bin/threatattestd start --minimum-gas-prices=0.001utatst

# Docker
cd chain && docker compose up -d
```

### 7.2 Chain (Local Development)

```bash
cd chain && make localnet-init localnet-start
```

### 7.3 Extension (Development)

```bash
cd extension && make build-dev
# Load unpacked from extension/dist/ in chrome://extensions
```

### 7.4 Extension (Production)

```bash
cd extension && make pack
# Upload build/threatattest-shield-<version>.zip to Chrome Web Store
```

---

## 8. External Dependencies

| Dependency | Purpose | Version/Notes |
|------------|---------|---------------|
| Cosmos SDK | Blockchain framework | v0.50.9 |
| CometBFT | Consensus engine | v0.38.10 |
| GoLevelDB | State storage | Via cosmos-db |
| IPFS | Detection rule storage | Off-chain; gateway URL configurable |
| DNSSEC | Identity verification | TXT records, algorithm 13 (ECDSA P-256) |
| Prometheus | Metrics | Optional, via docker-compose profile |
| Grafana | Dashboards | Optional, via docker-compose profile |
| Chrome Extensions API | Browser integration | MV3, Chromium 88+ |

---

## 9. Constraints

1. **No external databases** — All chain state in Cosmos SDK KV store. No PostgreSQL, MySQL, or Redis.
2. **No direct blockchain access from extension** — Extension is read-only REST API consumer.
3. **No key material in extension** — Extension holds no private keys; cannot sign or transact.
4. **IPFS is off-chain** — Chain stores CIDs and verification results; content fetching is delegated.
5. **DNSSEC chain-of-trust is stub** — Cryptographic signature verification is structural; full chain validation pending production DNS library.
6. **Single-node in docker-compose** — Production deployment needs validator set configuration.
7. **50 MB download limit** — Extension skips files larger than 50 MB to avoid memory issues.
