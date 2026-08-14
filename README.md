# ThreatAttest

> Decentralized threat intelligence on a Cosmos SDK blockchain with a browser extension for real-time protection.

---

## Repository Structure

```
threatattest/
├── chain/                    # Cosmos SDK blockchain node (threatattestd)
│   ├── cmd/threatattestd/    # Binary entry point
│   ├── x/attestation/       # Attestation module (publish, endorse, dispute, revoke)
│   ├── x/identity/          # Identity module (DNS-bound tiers, compliance)
│   ├── ante/                 # Ante handler (compliance tier enforcement)
│   ├── app/                  # App wiring
│   ├── scripts/              # Build, localnet, protobuf scripts
│   ├── tests/                # Shell + JS integration/unit tests
│   ├── docker/               # Docker entrypoint + Prometheus config
│   ├── Makefile              # Primary chain build targets
│   ├── Dockerfile            # Multi-stage Docker build
│   └── docker-compose.yml    # Node + monitoring stack
│
├── extension/                # ThreatAttest Shield browser extension (MV3)
│   ├── src/                  # Background, content, API, DNS identity modules
│   ├── scripts/              # Build, pack, validate scripts
│   ├── manifest.json         # MV3 manifest
│   ├── Makefile              # Extension build targets
│   └── package.json          # NPM scripts + ESLint config
│
└── Makefile                  # Root orchestrator (delegates to chain/ and extension/)
```

---

## Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Go | ≥ 1.21 |
| Node.js | ≥ 20 |
| Docker | ≥ 24 |
| make | any |

### Build the chain binary

```bash
make build
# Output: chain/bin/threatattestd
```

### Run tests

```bash
# All tests (Go unit, shell integration, JS unit)
make test-all

# Shell integration tests only (no node required)
make test-shell

# JS unit tests only
make test-js

# Go unit tests with race detector
make test
```

### Start a local devnet

```bash
make localnet-init    # Initialize chain home, keys, genesis
make localnet-start   # Start node in background
make localnet-status  # Check node status
make localnet-logs    # Tail node logs
make localnet-stop    # Stop node
make localnet-reset   # Wipe and re-initialize
```

### Build the browser extension

```bash
make ext-build        # Production build → extension/dist/
make ext-validate     # Validate manifest + source files
make ext-pack         # Package into extension/build/*.zip
make ext-build-dev    # Development build (localhost API)
```

### Docker

```bash
# Build Docker image
make docker-build

# Run single node container
make docker-run

# Start with Prometheus + Grafana monitoring
make docker-compose-up COMPOSE_PROFILES=monitoring

# Stop
make docker-compose-down
```

---

## Modules

### `x/attestation`

Manages threat attestations on-chain.

| Message | Description |
|---------|-------------|
| `MsgPublishAttestation` | Publish a new threat record (FILE, URL, IPV4, DOMAIN) |
| `MsgEndorseAttestation` | Endorse an existing attestation to boost trust score |
| `MsgDisputeAttestation` | File a dispute against an attestation |
| `MsgRevokeAttestation`  | Revoke your own published attestation |
| `MsgClaimReward`        | Claim a share of the attestation incentive pool |
| `MsgSubscribe`          | Lock TATST to activate a paid API tier (PRO/ENTERPRISE) |
| `MsgUnsubscribe`        | Return locked tokens and revert to the FREE tier |

**Key fields:** `artifact_type`, `artifact_sha256`, `severity`, `confidence`, `ttl_seconds`, `attester_domain`, `attester_selector`

### `x/identity`

DNS-bound identity and compliance tier system.

| Tier | Name | Reputation Score | Confidence Multiplier |
|------|------|------------------|-----------------------|
| 0 | Anonymous | < 100 RS | 0.25× |
| 1 | Verified | ≥ 100 RS | 0.50× |
| 2 | DNS-Bound | ≥ 1000 RS + DNS record | 1.00× |
| 3 | Expert | ≥ 10000 RS + DNSSEC | 2.00× |

**DNS identity:** Attesters bind their domain via `_tat.<selector>.<domain>` TXT records. The `attester_domain` + `attester_selector` fields on attestations link to verified DNS identity.

---

## Testing

### Shell tests (no node required)

```bash
cd chain
BINARY=./bin/threatattestd bash tests/test_identity_module.sh
BINARY=./bin/threatattestd bash tests/test_attester_domain.sh
BINARY=./bin/threatattestd bash tests/test_compliance_tiers.sh
```

When a node is not running, integration sections are gracefully skipped. All CLI-structural and unit tests run offline.

### JS unit tests (151 tests)

```bash
node chain/tests/test_extension_badges.js
```

Covers all pure functions in `extension/src/dns_identity.js`: `buildIdentityBadge`, `parseIdentityFlags`, `normalizeDomain`, `resolveIdentity`, `hasActiveIdentity`, cache behaviour, DOM contracts, and stress cases.

### Extension validation

```bash
cd extension && node scripts/validate.js
```

Checks manifest validity, MV3 fields, all referenced files exist, JS syntax, version consistency, and `dns_identity.js` export contract.

---

## CI/CD

GitHub Actions workflows in `chain/.github/workflows/`:

| Workflow | Triggers | Jobs |
|----------|----------|------|
| `ci.yml` | push, PR | lint, test, build, test-shell, test-js, validate-ext |
| `release.yml` | `v*.*.*` tags | goreleaser (multi-arch), ext-release |

### Release artifacts

GoReleaser produces:
- `threatattestd_linux_amd64.tar.gz` (CGO enabled)
- `threatattestd_linux_arm64.tar.gz`
- `threatattestd_darwin_amd64.tar.gz`
- `threatattestd_darwin_arm64.tar.gz`
- `threatattestd_windows_amd64.zip`
- `checksums.txt`
- Docker manifests → `ghcr.io/threatattest/threatattestd`

Extension release:
- `threatattest-shield-<version>.zip` attached to GitHub Release

---

## Development

### Adding a new attestation field

1. Add field to `x/attestation/types/types.go`
2. Update `MsgPublishAttestation` in `x/attestation/msgs/msgs.go`
3. Add CLI flag to `cmd/threatattestd/cmd/root.go`
4. Add validation in `x/attestation/keeper/msg_server.go`
5. Update `extension/src/api.js` to surface the field
6. Add tests to `chain/tests/test_attester_domain.sh`

### Protobuf regeneration

```bash
make proto-gen    # Requires buf CLI or Docker
make proto-lint   # Lint proto files
```

### Linting

```bash
make lint         # golangci-lint (Go) + ESLint (JS)
make lint-fix     # Auto-fix where possible
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE)