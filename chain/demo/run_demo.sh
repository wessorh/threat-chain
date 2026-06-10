#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
#  ThreatAttest — End-to-End Demo
#  Demonstrates the full lifecycle of a file attestation on a local single-node
#  ThreatAttest blockchain.
#
#  Prerequisites:
#    - threatattestd binary in ../bin/ (run: go build -o bin/threatattestd ./cmd/threatattestd)
#    - jq installed  (apt-get install jq  or  brew install jq)
#    - Ports 26657 (RPC) and 1317 (REST) free
#
#  Usage:
#    chmod +x run_demo.sh
#    ./run_demo.sh
# =============================================================================

set -euo pipefail

BINARY="../bin/threatattestd"
HOME_DIR="$HOME/.threatattestd-demo"
CHAIN_ID="threatattest-demo-1"
MONIKER="demo-node"
KEY_NAME="demo-attester"
DENOM="utatst"
SAMPLE_FILE="sample_malicious.txt"
ATTEST_JSON="sample_attestation.json"
LOG_FILE="/tmp/threatattestd-demo.log"

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fatal()   { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }
section() { echo -e "\n${BOLD}══════════════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}  $*${RESET}"; \
            echo -e "${BOLD}══════════════════════════════════════════════════${RESET}\n"; }
pause()   { echo -e "\n${YELLOW}Press ENTER to continue…${RESET}"; read -r; }

# ── Preflight checks ────────────────────────────────────────────────────────
section "Step 0 — Preflight checks"

[[ -x "$BINARY" ]] || fatal "Binary not found at $BINARY. Run: go build -o bin/threatattestd ./cmd/threatattestd"
command -v jq &>/dev/null || fatal "jq not found. Install with: apt-get install jq"
[[ -f "$SAMPLE_FILE" ]] || fatal "Sample file not found: $SAMPLE_FILE"

BINARY_VERSION=$("$BINARY" version 2>&1 | head -1)
info "Binary   : $BINARY"
info "Version  : $BINARY_VERSION"
info "Home dir : $HOME_DIR"
info "Chain ID : $CHAIN_ID"
success "Preflight passed"

# ── Cleanup previous run ────────────────────────────────────────────────────
section "Step 1 — Clean slate"
if [[ -d "$HOME_DIR" ]]; then
    warn "Removing previous demo home: $HOME_DIR"
    rm -rf "$HOME_DIR"
fi
success "Ready for fresh initialisation"

# ── Initialise the chain ────────────────────────────────────────────────────
section "Step 2 — Initialise the chain"
info "Running: threatattestd init"
"$BINARY" init "$MONIKER" --chain-id "$CHAIN_ID" --home "$HOME_DIR" 2>/dev/null
success "Chain initialised at $HOME_DIR"

# ── Create a demo key ───────────────────────────────────────────────────────
section "Step 3 — Create demo key"
info "Adding key: $KEY_NAME"
"$BINARY" keys add "$KEY_NAME" \
    --keyring-backend test \
    --home "$HOME_DIR" \
    --output json 2>/dev/null | tee /tmp/demo_key.json

ATTESTER_ADDR=$("$BINARY" keys show "$KEY_NAME" \
    --keyring-backend test \
    --home "$HOME_DIR" \
    --address 2>/dev/null)
success "Attester address: $ATTESTER_ADDR"

# ── Fund the genesis account ─────────────────────────────────────────────────
section "Step 4 — Fund genesis account"
info "Adding genesis account with 10,000,000 $DENOM"
"$BINARY" add-genesis-account "$ATTESTER_ADDR" "10000000$DENOM" \
    --keyring-backend test \
    --home "$HOME_DIR" 2>/dev/null
success "Genesis account funded"

# ── Create genesis validator tx ──────────────────────────────────────────────
section "Step 5 — Create genesis validator transaction"
info "Generating gentx (self-delegation: 1,000,000 $DENOM)"
"$BINARY" gentx "$KEY_NAME" "1000000$DENOM" \
    --chain-id "$CHAIN_ID" \
    --keyring-backend test \
    --home "$HOME_DIR" 2>/dev/null
success "Gentx created"

# ── Collect gentxs ──────────────────────────────────────────────────────────
section "Step 6 — Collect genesis transactions"
"$BINARY" collect-gentxs --home "$HOME_DIR" 2>/dev/null
success "genesis.json finalised"

# ── Validate genesis ─────────────────────────────────────────────────────────
section "Step 7 — Validate genesis"
"$BINARY" validate --home "$HOME_DIR" 2>/dev/null
success "Genesis file is valid"

# ── Start node in background ─────────────────────────────────────────────────
section "Step 8 — Start ThreatAttest node"
info "Starting node — logs → $LOG_FILE"
"$BINARY" start \
    --home "$HOME_DIR" \
    --log_level warn \
    --rpc.laddr tcp://127.0.0.1:26657 \
    --p2p.laddr tcp://127.0.0.1:26656 \
    --grpc.address 127.0.0.1:9090 \
    > "$LOG_FILE" 2>&1 &
NODE_PID=$!
info "Node PID: $NODE_PID"

# Wait for the node to produce the first block
info "Waiting for first block…"
for i in $(seq 1 30); do
    sleep 2
    STATUS=$(curl -s http://127.0.0.1:26657/status 2>/dev/null || true)
    BLOCK=$(echo "$STATUS" | jq -r '.result.sync_info.latest_block_height // "0"' 2>/dev/null || echo "0")
    if [[ "$BLOCK" -ge 1 ]]; then
        success "Node is live — block height: $BLOCK"
        break
    fi
    info "  Attempt $i/30 — height=$BLOCK"
done

if [[ "$BLOCK" -lt 1 ]]; then
    warn "Node did not reach block 1 in 60 s — check $LOG_FILE"
    warn "Continuing demo in offline mode (attest-file + tx generation only)"
fi

# ── Step 9: Compute SHA-256 and create attestation spec ──────────────────────
section "Step 9 — Compute SHA-256 and create attestation spec"
info "Running: threatattestd attest-file $SAMPLE_FILE"
"$BINARY" attest-file "$SAMPLE_FILE" \
    --severity HIGH \
    --confidence 92 \
    --ttl 604800 \
    --description "Simulated ransomware dropper with C2 beaconing, file encryption and persistence" \
    --tags "ransomware,dropper,c2,persistence,aes256" \
    --category "RANSOMWARE,TROJAN" \
    --attester "$ATTESTER_ADDR" \
    --chain-id "$CHAIN_ID" \
    --output "$ATTEST_JSON"

SHA256=$(jq -r '.artifact_sha256' "$ATTEST_JSON")
success "SHA-256 : $SHA256"
success "Spec written to $ATTEST_JSON"

# ── Step 10: Broadcast attestation transaction ───────────────────────────────
section "Step 10 — Publish attestation on-chain"

if [[ "$BLOCK" -ge 1 ]]; then
    info "Broadcasting MsgPublishAttestation…"
    DESCRIPTION=$(jq -r '.description' "$ATTEST_JSON")
    TAGS=$(jq -r '.tags | join(",")' "$ATTEST_JSON")
    CATEGORIES=$(jq -r '.threat_category | join(",")' "$ATTEST_JSON")

    TX_RESULT=$("$BINARY" tx attestation publish \
        --artifact-sha256 "$SHA256" \
        --artifact-type FILE \
        --severity HIGH \
        --confidence 92 \
        --ttl 604800 \
        --description "$DESCRIPTION" \
        --tags "$TAGS" \
        --category "$CATEGORIES" \
        --from "$KEY_NAME" \
        --chain-id "$CHAIN_ID" \
        --keyring-backend test \
        --home "$HOME_DIR" \
        --fees "500$DENOM" \
        --yes \
        --output json 2>/dev/null || echo '{"error":"tx failed"}')

    TX_HASH=$(echo "$TX_RESULT" | jq -r '.txhash // "unknown"' 2>/dev/null || echo "unknown")
    if [[ "$TX_HASH" != "unknown" && "$TX_HASH" != "" ]]; then
        success "Transaction submitted — TxHash: $TX_HASH"
        info "Waiting for confirmation (2 blocks)…"
        sleep 6
    else
        warn "Transaction could not be submitted. Node may still be syncing."
        warn "To broadcast manually, see MANPAGE.md §4."
    fi
else
    warn "Skipping broadcast — node not reachable (offline mode)"
fi

# ── Step 11: Query is-malicious ──────────────────────────────────────────────
section "Step 11 — Query: is this file malicious?"

if [[ "$BLOCK" -ge 1 ]]; then
    info "Running: threatattestd query attestation is-malicious --sha256 $SHA256"
    sleep 2
    "$BINARY" query attestation is-malicious \
        --sha256 "$SHA256" \
        --node http://127.0.0.1:26657 \
        --home "$HOME_DIR" \
        --output json 2>/dev/null | jq . || warn "Query returned no result yet — retry after a few blocks"
else
    warn "Skipping query — node not reachable (offline mode)"
    info "To query manually once a node is running:"
    echo "  $BINARY query attestation is-malicious --sha256 $SHA256 --node http://127.0.0.1:26657"
fi

# ── Step 12: Query full attestation record ───────────────────────────────────
section "Step 12 — Query: full attestation record"

if [[ "$BLOCK" -ge 1 ]]; then
    info "Running: threatattestd query attestation get --sha256 $SHA256"
    "$BINARY" query attestation get \
        --sha256 "$SHA256" \
        --node http://127.0.0.1:26657 \
        --home "$HOME_DIR" \
        --output json 2>/dev/null | jq . || warn "No record found yet — retry after a few blocks"
else
    warn "Skipping query — node not reachable (offline mode)"
fi

# ── Step 13: Endorse the attestation ─────────────────────────────────────────
section "Step 13 — Endorse the attestation"

if [[ "$BLOCK" -ge 1 ]]; then
    info "Broadcasting MsgEndorseAttestation…"
    "$BINARY" tx attestation endorse \
        --attestation-id "$SHA256" \
        --reason "Independent sandbox analysis confirms ransomware behavior" \
        --from "$KEY_NAME" \
        --chain-id "$CHAIN_ID" \
        --keyring-backend test \
        --home "$HOME_DIR" \
        --fees "500$DENOM" \
        --yes \
        --output json 2>/dev/null | jq -r '.txhash // "failed"' | \
        xargs -I{} echo "Endorsement TxHash: {}" || warn "Endorsement tx failed"
else
    warn "Skipping endorse — node not reachable (offline mode)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
section "Demo Complete"

echo -e "${GREEN}"
echo "  ✔  Chain initialised    : $HOME_DIR"
echo "  ✔  Attester key         : $KEY_NAME  ($ATTESTER_ADDR)"
echo "  ✔  Sample file          : $SAMPLE_FILE"
echo "  ✔  SHA-256              : $SHA256"
echo "  ✔  Attestation spec     : $ATTEST_JSON"
if [[ "$BLOCK" -ge 1 ]]; then
    echo "  ✔  Node running         : PID $NODE_PID  (logs: $LOG_FILE)"
    echo "  ✔  On-chain attestation : broadcast (check block explorer)"
fi
echo -e "${RESET}"

echo "To stop the node:  kill $NODE_PID"
echo "To view logs:      tail -f $LOG_FILE"
echo ""
echo "See MANPAGE.md for full command reference."

# Trap to kill node on script exit
if [[ "$BLOCK" -ge 1 ]]; then
    echo ""
    warn "Node is still running (PID $NODE_PID). Press ENTER to stop it, or Ctrl-C to leave it running."
    read -r
    kill "$NODE_PID" 2>/dev/null && success "Node stopped." || warn "Node already stopped."
fi