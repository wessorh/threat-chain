# Listening for Threats (Real-time Attestation Subscription)

> Subscribe to the ThreatAttest chain and receive new threat attestations the
> moment they are published. This is a **read-only, anonymous** feed — no keys,
> no account, no stake required.

---

## 1. Overview

Every time an attestation is published, the chain emits a `publish_attestation`
event on the CometBFT event bus. You can subscribe to that bus over the
node's websocket and stream every new threat as it lands.

ThreatAttest ships a small listener, **`txwatch`**, that does exactly this:

- **Default mode** — prints *every* transaction (publish, endorse, dispute, …).
- **`-publish-only` mode** — filters to attestation publications and prints a
  compact one-line summary of each threat.

The feed is anonymous: CometBFT's RPC has no authentication, so anyone who can
reach the node's RPC port can subscribe.

---

## 2. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Go ≥ 1.23 | to build `txwatch` |
| A running node | RPC reachable on port **26657** (see §4 for a localnet) |
| Network access to the node | TCP to `:26657` |

---

## 3. Build `txwatch`

```bash
cd chain

# Build both the node and the listener:
make build
# → bin/threatattestd  and  bin/txwatch

# Or build just the listener:
make build-txwatch

# Or directly with go:
go build -o bin/txwatch ./cmd/txwatch
```

---

## 4. Listen

### Default — all transactions

```bash
./bin/txwatch            # connects to s6l.com:26657 by default
```

Prints every transaction (height, tx hash, and each decoded message as JSON).
Useful for watching all chain activity, not just threats.

### Publish-only — threats only

```bash
./bin/txwatch -publish-only                       # s6l.com by default
./bin/txwatch -publish-only tcp://localhost:26657 # override (e.g. local devnet)
```

Filters the stream to `MsgPublishAttestation` transactions and prints one
compact line per threat.

**Flags**

| Flag | Default | Description |
|------|---------|-------------|
| `-node` | `tcp://s6l.com:26657` | CometBFT RPC node URL (default host) |
| `-publish-only` | `false` | print only attestation publications |

The node URL may also be given as a positional argument
(`txwatch tcp://host:26657`).

> **Firewall note:** if `localhost:26657` times out but the node is reachable on
> its LAN interface, use that address instead, e.g.
> `./bin/txwatch -publish-only tcp://192.168.2.44:26657`.

---

## 5. Understanding the output

`-publish-only` prints one line per published attestation:

```
publish height=1042 hash=9f2c… id=<attestation_id> attester=tatst1… type=FILE sha256=<64-hex> severity=HIGH tlp=AMBER
```

| Field | Meaning |
|-------|---------|
| `height` | block height the attestation was committed at |
| `hash` | SHA-256 of the transaction |
| `id` | server-assigned attestation ID |
| `attester` | the publishing account (bech32 `tatst1…`) |
| `type` | `FILE`, `URL`, `IPV4`, `DOMAIN`, or `EMAIL_BODY` |
| `sha256` | the attested artifact's SHA-256 |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `tlp` | Traffic Light Protocol: `WHITE`, `GREEN`, `AMBER`, `RED` |

---

## 6. How it works

`txwatch` connects to the CometBFT websocket endpoint (`/websocket`) and issues
a `subscribe` query:

| Mode | Query |
|------|-------|
| default | `tm.event='Tx'` |
| publish-only | `tm.event='Tx' AND message.action='/threatattest.attestation.MsgPublishAttestation'` |

`message.action` is the SDK type-URL of the message, so the publish-only query
selects exactly the `MsgPublishAttestation` transactions server-side.

Each publish also emits a `publish_attestation` event (see §8) whose
`attestation_id` is the value printed in the `id=` field — it is computed by the
keeper and is not present in the transaction message itself.

---

## 7. End-to-end verification

1. **Start a local devnet** (from `chain/`):

   ```bash
   make localnet-init
   make localnet-start
   ```

2. **Start the listener** in a second terminal:

   ```bash
   cd chain
   ./bin/txwatch -publish-only tcp://localhost:26657
   ```

3. **Publish a test attestation** in a third terminal (using an attester key
   that has reputation to attest — see the `GETTING_STARTED.md` "Quick Start
   (all-in-one)" for creating and funding `demo-attester`):

   ```bash
   cd chain
   SHA=$(sha256sum /etc/hostname | cut -d' ' -f1)
   ./bin/threatattestd tx attestation publish \
     --artifact-type FILE --artifact-sha256 "$SHA" \
     --severity LOW --confidence 50 --ttl 3600 \
     --description "listener test" --category TATST:MALWARE \
     --from demo-attester --chain-id threatattest-local-1 \
     --home ~/.threatattestd-local --keyring-backend test -y
   ```

4. **Watch the listener** — within a block or two a line appears:

   ```
   publish height=… hash=… id=… attester=… type=FILE sha256=<SHA> severity=LOW tlp=…
   ```

---

## 8. Event reference

The `publish_attestation` event carries these attributes
(`chain/x/attestation/keeper/keeper.go`):

| Attribute | Description |
|-----------|-------------|
| `attestation_id` | the unique attestation ID |
| `attester` | the publishing account |
| `artifact_type` | `FILE`, `URL`, `IPV4`, `DOMAIN`, `EMAIL_BODY` |
| `artifact_sha256` | the attested artifact's SHA-256 |

Other lifecycle events are also emitted on the same bus —
`endorse_attestation`, `revoke_attestation`, `dispute_attestation`,
`expire_attestation`, `update_params`, `claim_reward` — so a raw
`tm.event='Tx'` subscription (default `txwatch` mode) sees the whole lifecycle.

---

## 9. Alternative: pull-based queries

Listening is push-based (real-time). For point-in-time lookups, use the
query/REST APIs instead:

```bash
# Is an artifact malicious?
./bin/threatattestd query attestation is-malicious --artifact-sha256 "$SHA" \
  --node http://localhost:26657

# REST (LCD) on port 1317, gRPC on port 9090.
```

See `GETTING_STARTED.md` for the full query API.
