# ThreatAttest on dewile.net

> Deploy a ThreatAttest chain node and DNS-bound attester identity on `dewile.net`.

---

## 1. Overview

After deployment you will have:

- A **ThreatAttest chain node** running on `dewile.net` (or a subdomain)
- A **DNS-bound identity** proving `dewile.net` controls an attester key
- A **REST API** (LCD on port 1317) serving threat intelligence queries
- A **browser extension** configured to check downloads and URLs against your chain

### Architecture

```
dewile.net
├── DNS TXT records (identity proof)
│   ├── _tatkey.dewile.net        TXT  "v=TAT1 k=secp256k1 p=<pubkey> a=<addr>"
│   └── _tatactive.dewile.net     TXT  "dewile"
│
├── threatattestd (Cosmos SDK node)
│   ├── :26656  P2P
│   ├── :26657  RPC
│   ├── :1317   REST API (LCD) ← extension queries this
│   └── :9090   gRPC
│
└── Caddy / nginx (TLS termination for :1317 → :443)
```

---

## 2. Prerequisites

| Requirement | Check |
|---|---|
| Go ≥ 1.23 | `go version` |
| Docker ≥ 24 (optional) | `docker --version` |
| DNS control for `dewile.net` | Edit zone file or registrar panel |
| Ports 26656, 26657, 1317 open | Firewall / security group |
| TLS certificate for `api.dewile.net` | certbot / acme.sh |

---

## 3. Build the Chain Binary

```bash
cd ~/work/ai/threat-attest/chain
make build
# → bin/threatattestd

# Add to PATH (or symlink, or use full path throughout)
export PATH="$PWD/bin:$PATH"
echo 'export PATH="$HOME/work/ai/threat-attest/chain/bin:$PATH"' >> ~/.bashrc

threatattestd version
```

---

## 4. Initialize the Node

```bash
export CHAIN_ID=dewile-1
export MONIKER=dewile-validator
export HOME_DIR=~/.threatattestd-dewile

# Init
threatattestd init $MONIKER \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR

# Create validator key
threatattestd keys add validator \
  --keyring-backend file \
  --home $HOME_DIR

# Create attester key (this key will be DNS-bound to dewile.net)
threatattestd keys add dewile-attester \
  --keyring-backend file \
  --home $HOME_DIR

# ── CRITICAL: Set keyring-backend default ──────────────────────────
# The Cosmos SDK default keyring backend is "os" (OS keychain).
# Keys created with "file" are invisible to "os". Set the default
# so every subsequent command doesn't need --keyring-backend file.
sed -i 's/keyring-backend = "os"/keyring-backend = "file"/' \
  $HOME_DIR/config/client.toml

# Verify keys are accessible
threatattestd keys list --home $HOME_DIR
VALIDATOR_ADDR=$(threatattestd keys show validator -a --home $HOME_DIR)
ATTESTER_ADDR=$(threatattestd keys show dewile-attester -a --home $HOME_DIR)
echo "Validator: $VALIDATOR_ADDR"
echo "Attester:  $ATTESTER_ADDR"
```

---

## 5. Configure Genesis

```bash
VALIDATOR_ADDR=$(threatattestd keys show validator -a --home $HOME_DIR)

# Add genesis account with initial tokens
threatattestd genesis add-genesis-account $VALIDATOR_ADDR 1000000000utatst \
  --home $HOME_DIR

# Generate gentx
threatattestd genesis gentx validator 500000000utatst \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file

# Collect gentx
threatattestd genesis collect-gentxs --home $HOME_DIR
```

---

## 6. Configure app.toml (REST API)

Edit `$HOME_DIR/config/app.toml`:

```toml
[api]
enable = true
address = "tcp://0.0.0.0:1317"
swagger = true

[api-cors]
enabled = true
allowed-origins = ["*"]
allowed-methods = ["GET", "POST", "OPTIONS"]
allowed-headers = ["*"]
```

Edit `$HOME_DIR/config/config.toml` for RPC:

```toml
[rpc]
laddr = "tcp://0.0.0.0:26657"
cors_allowed_origins = ["*"]

[p2p]
laddr = "tcp://0.0.0.0:26656"
```

---

## 7. DNS Identity Setup

### 7.1 Generate the TXT Record Value

```bash
ATTESTER_ADDR=$(threatattestd keys show dewile-attester -a \
  --keyring-backend file --home $HOME_DIR)

ATTESTER_PUBKEY=$(threatattestd keys show dewile-attester -p \
  --keyring-backend file --home $HOME_DIR | jq -r '.key')

echo "v=TAT1 k=secp256k1 p=$ATTESTER_PUBKEY a=$ATTESTER_ADDR"
```

### 7.2 Publish DNS TXT Records

Add these records to the `dewile.net` DNS zone:

```
; ThreatAttest identity — selector "dewile"
_tatkey.dewile.net.    3600  IN  TXT  "v=TAT1 k=secp256k1 p=<pubkey_hex> a=<tatst_addr>"
_tatactive.dewile.net. 3600  IN  TXT  "dewile"
```

**Verify DNS propagation:**

```bash
dig +short TXT _tatkey.dewile.net
dig +short TXT _tatactive.dewile.net
```

### 7.3 DNSSEC (Recommended for Expert Tier)

DNSSEC-signed zones unlock Tier 3 (Expert, 2.00× confidence multiplier). If `dewile.net` has DNSSEC enabled, include the DS, DNSKEY, and RRSIG records in the identity registration transaction.

---

## 8. Start the Node

```bash
threatattestd start \
  --home $HOME_DIR \
  --minimum-gas-prices 0.025utatst \
  --x-crisis-skip-assert-invariants
```

For production, run under systemd:

```ini
# /etc/systemd/system/threatattestd.service
[Unit]
Description=ThreatAttest Node — dewile.net
After=network.target

[Service]
Type=simple
User=threatattest
ExecStart=/home/threatattest/bin/threatattestd start \
  --home /home/threatattest/.threatattestd-dewile \
  --minimum-gas-prices 0.025utatst
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now threatattestd
sudo systemctl status threatattestd
```

**Verify:**

```bash
curl -s http://localhost:26657/status | jq '.result.sync_info.latest_block_height'
```

---

## 9. TLS Termination for the REST API

The browser extension will query the REST API. For production, put TLS in front of port 1317.

### Option A: Caddy (simplest)

```
# /etc/caddy/Caddyfile
api.dewile.net {
    reverse_proxy localhost:1317
}
```

### Option B: nginx

```nginx
server {
    listen 443 ssl;
    server_name api.dewile.net;

    ssl_certificate     /etc/letsencrypt/live/api.dewile.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.dewile.net/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:1317;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

**Verify:**

```bash
curl -s https://api.dewile.net/cosmos/base/tendermint/v1beta1/node_info | jq '.default_node_info.version'
```

---

## 10. Fund the Attester

```bash
VALIDATOR_ADDR=$(threatattestd keys show validator -a \
  --keyring-backend file --home $HOME_DIR)
ATTESTER_ADDR=$(threatattestd keys show dewile-attester -a \
  --keyring-backend file --home $HOME_DIR)

# Send 1,000 TATST to the attester
threatattestd tx bank send $VALIDATOR_ADDR $ATTESTER_ADDR 1000000000utatst \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file \
  -y

# Verify
threatattestd query bank balances $ATTESTER_ADDR \
  --node http://localhost:26657
```

---

## 11. Register DNS Identity On-Chain

```bash
threatattestd tx identity register-identity \
  --domain dewile.net \
  --selector dewile \
  --from dewile-attester \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file \
  -y
```

After the identity registration tx confirms and passes the DNS verification epoch (~24 hours), the attester reaches **Tier 2 (DNS-Bound, 1.00× confidence)**.

To reach Tier 3 (Expert, 2.00×), the attester needs:
- DNSSEC on `dewile.net`
- 5,000+ reputation score
- `EXPERT` flag set on the identity record

---

## 12. Publish the First Attestation

```bash
SHA=$(sha256sum /etc/hostname | cut -d' ' -f1)

threatattestd tx attestation publish \
  --artifact-type FILE \
  --artifact-sha256 $SHA \
  --severity LOW \
  --confidence 50 \
  --ttl 3600 \
  --description "First attestation from dewile.net" \
  --category TATST:MALWARE \
  --attester-domain dewile.net \
  --attester-selector dewile \
  --from dewile-attester \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file \
  -y
```

**Query it back:**

```bash
threatattestd query attestation is-malicious \
  --artifact-sha256 $SHA \
  --node http://localhost:26657
```

---

## 13. Configure the Browser Extension

### 13.1 Build the Extension

```bash
cd ~/work/ai/threat-attest/extension
make build-prod
# → dist/
```

### 13.2 Set the Chain Endpoint

Before building (or in `dist/` after build), edit the API base URL:

```javascript
// extension/src/api.js (or config)
const CHAIN_API = "https://api.dewile.net";
```

Rebuild and load unpacked in `chrome://extensions`.

### 13.3 Verify

1. Navigate to any page. The toolbar badge should appear green.
2. Download a test file whose SHA-256 matches an active attestation.
3. The extension should block or warn based on severity.

---

## 14. Maintenance

### Daily

```bash
# Check node health
curl -s https://api.dewile.net/cosmos/base/tendermint/v1beta1/node_info

# Check block sync
curl -s http://localhost:26657/status | jq '.result.sync_info'
```

### Weekly

```bash
# Renew attestations near expiry
threatattestd query attestation list-by-attester $ATTESTER_ADDR --node http://localhost:26657

# Check reputation
threatattestd query reputation reputation $ATTESTER_ADDR --node http://localhost:26657

# Claim pool rewards
threatattestd tx attestation claim-reward \
  --from dewile-attester \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file -y
```

### Identity Renewal

DNS identities expire after 1 year by default. Renew before expiry:

```bash
threatattestd tx identity renew-identity \
  --domain dewile.net \
  --selector dewile \
  --from dewile-attester \
  --chain-id $CHAIN_ID \
  --home $HOME_DIR \
  --keyring-backend file -y
```

---

## 15. Troubleshooting

| Problem | Check |
|---|---|
| `validator is not a valid name or address: decoding bech32 failed` | Keyring backend mismatch. Keys created with `--keyring-backend file` but default is `os`. Fix: `sed -i 's/keyring-backend = "os"/keyring-backend = "file"/' $HOME_DIR/config/client.toml` |
| `keys show` returns nothing | Run `threatattestd keys list --home $HOME_DIR` to list keys and verify the correct backend |
| Node won't start | `journalctl -u threatattestd -n 50` |
| DNS identity stuck PENDING | DNS TXT records propagated? `dig TXT _tatkey.dewile.net` |
| Extension shows "Node offline" | TLS cert valid? `curl -v https://api.dewile.net/` |
| Attestation rejected | Reputation score ≥ minimum? Confidence in range 0–100? TTL between 1h and 1y? |
| Gas too low | `--minimum-gas-prices 0.025utatst` in app.toml or start flag |

---

## 16. Next Steps After Setup

1. **Publish real attestations** — feed low-positive malware hashes from the plan10-web pipeline.
2. **Wire up YARA rules** — pin family-level rules to IPFS, reference CIDs in attestation `DetectionRules`.
3. **Add attesters** — invite other researchers to register identities and co-attest.
4. **Enable paid subscriptions** — `MsgSubscribe`/`MsgUnsubscribe` handlers are implemented; wire the subscription-tier rate limit into the query/API layer.
5. **List on Osmosis** — governance proposal for TATST token on the Cosmos DEX.
