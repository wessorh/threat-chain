# ThreatAttest — Getting Started

This guide walks through installing and running **ThreatAttest**: a Cosmos SDK
blockchain for decentralized threat intelligence, plus the **ThreatAttest
Shield** browser extension that consumes it for real-time protection.

It covers a from-scratch setup on Linux/macOS (and Windows via WSL/Docker).

---

## 1. Overview

ThreatAttest has two components:

| Component | Directory | Language | What it does |
|-----------|-----------|----------|--------------|
| Chain node | `chain/` | Go | `threatattestd` — publishes/endorses/disputes/revokes threat attestations |
| Browser extension | `extension/` | JavaScript | ThreatAttest Shield — checks downloads/URLs/domains/IPs against the chain |

The chain exposes three APIs:

| API | Port |
|-----|------|
| REST (LCD) | `1317` |
| gRPC | `9090` |
| CometBFT RPC | `26657` |

The extension is a **read-only** client of the REST API — it never holds keys
or signs transactions.

---

## 2. Prerequisites

| Tool | Version | Check |
|------|---------|-------|
| Go | ≥ 1.23 | `go version` |
| Node.js | ≥ 20 | `node --version` |
| make | any | `make --version` |
| Docker | ≥ 24 *(optional — for Docker deployment)* | `docker --version` |
| git | any | `git --version` |

---

## 3. Clone and install

```bash
git clone <repository-url> threatattest
cd threatattest

# Verify the toolchain and show all available build targets
make help
```

The root `Makefile` orchestrates both sub-projects. Key targets:

| Target | Purpose |
|--------|---------|
| `make build` | Build chain binary + extension |
| `make build-chain` | Build `threatattestd` only |
| `make build-ext` | Build the browser extension only |
| `make test` | Run all tests (Go + shell + JS) |
| `make localnet` | Init + start a single-node devnet |
| `make docker-build` | Build the Docker image |

---

## 4. Build the chain

```bash
# From the repo root
make build-chain
# → produces chain/bin/threatattestd
```

Verify it works:

```bash
./chain/bin/threatattestd version
```

To install the binary onto `$PATH` (`$GOPATH/bin`):

```bash
make install
```

---

## 5. Run the tests *(optional but recommended)*

```bash
make test          # everything: Go unit, shell integration, JS extension
make test-chain    # Go unit tests only
make test-shell    # offline shell integration tests (no node required)
make test-js       # extension JS tests (151 badge/identity tests)
```

The shell tests run without a node; integration sections are skipped
gracefully when no node is up.

---

## 6. Start a local devnet

The `localnet` targets script a complete single-node devnet.

```bash
make localnet        # = localnet-init + localnet-start
```

Defaults:

| Setting | Value |
|---------|-------|
| Binary | `chain/bin/threatattestd` |
| Home dir | `~/.threatattestd-local` |
| Chain ID | `threatattest-local-1` |
| Key name | `localkey` |
| Denom | `utatst` |
| Moniker | `localnode` |
| Initial balance | `200,000,000 utatst` |

Manage the node:

```bash
make localnet-status   # query node status
make localnet-log      # tail the node log
make localnet-stop     # stop the node
make localnet-reset    # wipe and re-init
```

You can override the defaults with `init-localnet.sh` options:

```bash
cd chain
./scripts/init-localnet.sh --home ~/my-node --chain my-test-1 --key alice
```

---

## 7. Interact with the chain (CLI)

With the node running, the binary is at `chain/bin/threatattestd`. Use
`--home ~/.threatattestd-local` (and `--keyring-backend test`) to reach the
devnet.

Convenience helpers that build attestation JSON specs:

```bash
threatattestd attest-file   <file>     # hash a file → attestation spec
threatattestd attest-url    <url>      # normalize URL → attestation spec
threatattestd attest-domain <domain>   # normalize domain → attestation spec
```

Attestation transactions:

```bash
threatattestd tx attestation publish  ...   # publish a new attestation
threatattestd tx attestation endorse  <id>  # endorse an attestation
threatattestd tx attestation dispute  <id>  # file a dispute
threatattestd tx attestation revoke   <id>  # revoke your own attestation
threatattestd tx attestation claim-reward   # claim a share of the incentive pool
threatattestd tx attestation subscribe ...   # lock TATST → paid API tier
threatattestd tx attestation unsubscribe    # return locked stake → FREE tier
```

Identity transactions:

```bash
threatattestd tx identity register-identity ...  # register DNS-anchored identity
threatattestd tx identity rotate-identity-key ... # rotate signing key
threatattestd tx identity renew-identity ...      # renew with fresh DNSSEC evidence
threatattestd tx identity revoke-identity ...     # revoke identity
```

Run any command with `--help` for the full flag set.

---

## 8. Install the browser extension (ThreatAttest Shield)

```bash
# From the repo root
make build-ext        # production build → extension/dist/
make build-ext-dev    # development build (points at localhost API)
make pack-ext         # package into extension/build/*.zip
```

Load it into Chrome/Edge/Brave:

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the `extension/dist/` directory.
5. Open the extension popup and set the node URL — for the local devnet use
   `http://localhost:1317`.

> The dev build (`make build-ext-dev`) already points at `localhost:1317`.
> The production build defaults to `https://api.threatattest.io`.

The extension checks every completed download (SHA-256), every navigated URL,
and page IPv4 addresses against the chain, blocking CRITICAL/HIGH threats and
showing DNS-identity badges for verified domains.

---

## 9. Bind a DNS identity *(optional but recommended)*

To publish attestations with a *DNS-bound* or *Expert* tier (higher confidence
multiplier), bind a domain to your Cosmos key with a TXT record:

```text
_tat.<selector>.<domain>.  3600  IN  TXT  "v=TAT1 k=secp256k1 p=<pubkey-hex> a=<cosmos-addr>"
```

- `<selector>` — a short DNS label (e.g. `validator`).
- `<pubkey-hex>` — the compressed secp256k1 public key (hex).
- `<cosmos-addr>` — your `tatst1...` account address.

The localnet init script prints a ready-to-use record after creating the
validator key. After publishing the record, register it on-chain:

```bash
threatattestd tx identity register-identity ... --public-key-hex <hex> --domain <domain> --selector <selector>
```

Full identity/DNSSEC details are in [`system-requirements.md`](system-requirements.md).

---

## 10. Docker *(alternative to the local devnet)*

```bash
make docker-build                    # build the image
make docker-run                      # single-node container
make docker-compose-up COMPOSE_PROFILES=monitoring   # node + Prometheus + Grafana
make docker-compose-down
```

The compose stack maps the same ports (`26656`/`26657`/`1317`/`9090`) and
supports `CHAIN_ID`, `DENOM`, `SUPPLY_AMOUNT`, etc. as environment variables.

---

## 11. Production build & release

```bash
make release-snapshot   # build all release artifacts locally (no publish)
```

Release artifacts (via GoReleaser, on `v*.*.*` tags) include multi-arch
`threatattestd` binaries, checksums, Docker manifests, and the packaged
extension zip — see [`system-requirements.md`](system-requirements.md) §8 and
`.github/workflows/release.yml`.

---

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `make build-chain` fails on a Go version error | Install Go ≥ 1.23 and re-run |
| `make localnet-start` reports the node is already running | `make localnet-reset` |
| Extension shows "node unreachable" | Confirm the node is up and the URL is `http://localhost:1317` |
| `tx ...` says "key not found" | Use `--home ~/.threatattestd-local --keyring-backend test` |
| Port already in use | Change `*_PORT` in `docker-compose.yml`, or stop the localnet |

---

## 13. Next steps

- **Architecture & requirements** — [`system-requirements.md`](system-requirements.md)
- **Deployment notes** — [`docs/dewile-net-deployment.md`](docs/dewile-net-deployment.md)
- **Steady-state / economics** — [`docs/steady-state-flow.md`](docs/steady-state-flow.md)
- **Bootstrapping a node** — [`docs/bootstrap.md`](docs/bootstrap.md)
- **The value-loop thesis** — [`blog/2026-06-19-closing-the-value-loop.md`](blog/2026-06-19-closing-the-value-loop.md)
