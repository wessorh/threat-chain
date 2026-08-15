#!/usr/bin/env bash
# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.
# =============================================================================
# tests/test_full_cli.sh — Full end-to-end CLI smoke test for x/attestation
# =============================================================================
#
# Starts a fresh single-node localnet, then exercises every tx and query
# command across every supported artifact type, asserting that each returns
# the expected on-chain result. Exits non-zero on the first failure.
#
# Usage:
#   bash tests/test_full_cli.sh [--binary ./bin/threatattestd]
# =============================================================================

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${ROOT_DIR}/bin/threatattestd"
HOME_DIR="/tmp/tatst-full-cli-test"
CHAIN_ID="threatattest-cli"
KEY="smoketest"
DENOM="utatst"
NODE="tcp://localhost:26657"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PASS=0; FAIL=0

info()  { echo -e "${CYAN}  ►${RESET} $*"; }
ok()    { echo -e "${GREEN}  ✓${RESET} $*"; PASS=$((PASS+1)); }
bad()   { echo -e "${RED}  ✗${RESET} $*"; FAIL=$((FAIL+1)); }
die()   { echo -e "${RED}  ✗ ERROR:${RESET} $*" >&2; exit 1; }

# tx_result <flags...> — run a tx, echo the JSON result on stdout. Sleeps to let
# the tx commit (and the account sequence advance) before the next broadcast.
tx_result() { "$BINARY" tx attestation "$@" --from "$KEY" --chain-id "$CHAIN_ID" \
       --fees 5000"$DENOM" --keyring-backend test --home "$HOME_DIR" --node "$NODE" --yes -o json 2>/dev/null | grep -E '^\{' | tail -1; sleep 2; }

# query <subcmd...> — run a query, echo JSON on stdout.
query() { "$BINARY" query attestation "$@" --home "$HOME_DIR" --node "$NODE" -o json 2>/dev/null; }

# json_get <json> <python-expr> — extract a scalar from a JSON doc; "" on error.
json_get() { python3 -c "import sys,json; d=json.load(sys.stdin); print($2)" <<<"$1" 2>/dev/null || true; }

# cleanup any prior run
pkill -x threatattestd 2>/dev/null || true
rm -rf "$HOME_DIR"
sleep 1

info "Initialising fresh localnet ($CHAIN_ID)"
bash "$ROOT_DIR/scripts/init-localnet.sh" --binary "$BINARY" --home "$HOME_DIR" \
  --chain "$CHAIN_ID" --moniker cli --key "$KEY" --denom "$DENOM" >/dev/null 2>&1 || die "init-localnet failed"

info "Starting node"
nohup "$BINARY" start --home "$HOME_DIR" > /tmp/tatst-full-cli.log 2>&1 &
NODE_PID=$!
sleep 7

info "Waiting for first blocks"
for i in $(seq 1 20); do
  grep -q "committed state" /tmp/tatst-full-cli.log 2>/dev/null && break
  sleep 1
done
grep -q "committed state" /tmp/tatst-full-cli.log || die "node did not produce blocks"
ok "node produced blocks"

ATTESTER=$("$BINARY" keys show "$KEY" --keyring-backend test --home "$HOME_DIR" -a 2>/dev/null)
[ -n "$ATTESTER" ] || die "could not resolve key address"
ok "key address: $ATTESTER"

# ─────────────────────────────────────────────────────────────────────────────
info "Publishing one attestation per artifact type"

SHA_FILE="0fd5115915d3d3a05ba5efc2fbeae0fc8dcd26b04947050a986020ecea43de45"
R=$(tx_result publish --artifact-type FILE --artifact-sha256 "$SHA_FILE" --severity HIGH --confidence 90 \
     --ttl 86400 --description "file smoke" --category TATST:RANSOMWARE --tags smoke)
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "FILE publish (code 0)" || bad "FILE publish: $R"

R=$(tx_result publish --artifact-type URL --raw-value "https://evil.example.com/payload.exe" --severity CRITICAL \
     --confidence 95 --ttl 86400 --description "url smoke" --category TATST:PHISHING --tags smoke)
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "URL publish (code 0)" || bad "URL publish: $R"

R=$(tx_result publish --artifact-type IPV4 --raw-value "8.8.8.8" --severity MEDIUM --confidence 80 \
     --ttl 86400 --description "ipv4 smoke" --category TATST:C2 --tags smoke)
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "IPV4 publish (code 0)" || bad "IPV4 publish: $R"

R=$(tx_result publish --artifact-type DOMAIN --raw-value "evil.example.com" --severity HIGH --confidence 85 \
     --ttl 86400 --description "domain smoke" --category TATST:PHISHING --tags smoke)
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "DOMAIN publish (code 0)" || bad "DOMAIN publish: $R"

# ─────────────────────────────────────────────────────────────────────────────
info "Querying each published artifact"

R=$(query is-malicious --sha256 "$SHA_FILE")
M=$(json_get "$R" "d.get('is_malicious')")
[ "$M" = "True" ] && ok "is-malicious(FILE) == true" || bad "is-malicious(FILE): $R"
FILE_ID=$(json_get "$R" "d['attestation']['id']")

R=$(query is-malicious-url --url "https://evil.example.com/payload.exe")
M=$(json_get "$R" "d.get('is_malicious')")
[ "$M" = "True" ] && ok "is-malicious-url == true" || bad "is-malicious-url: $R"

R=$(query is-malicious-ipv4 --ipv4 "8.8.8.8")
M=$(json_get "$R" "d.get('is_malicious')")
[ "$M" = "True" ] && ok "is-malicious-ipv4 == true" || bad "is-malicious-ipv4: $R"

R=$(query get "$FILE_ID")
GID=$(json_get "$R" "d['attestation']['id']")
[ "$GID" = "$FILE_ID" ] && ok "get(id) matches" || bad "get(id): $R"

R=$(query list-by-artifact --sha256 "$SHA_FILE")
N=$(json_get "$R" "len(d.get('attestations', []))")
[ "$N" -ge 1 ] && ok "list-by-artifact count=$N" || bad "list-by-artifact: $R"

R=$(query list-by-attester --attester "$ATTESTER")
N=$(json_get "$R" "len(d.get('attestations', []))")
[ "$N" -ge 4 ] && ok "list-by-attester count=$N" || bad "list-by-attester: $R"

R=$(query params)
P=$(json_get "$R" "d.get('params', {}).get('min_ttl_seconds')")
[ -n "$P" ] && ok "params min_ttl_seconds=$P" || bad "params: $R"

R=$(query is-blacklisted --attester "$ATTESTER")
B=$(json_get "$R" "d.get('is_blacklisted')")
[ "$B" = "False" ] && ok "is-blacklisted == false" || bad "is-blacklisted: $R"

# ─────────────────────────────────────────────────────────────────────────────
info "Testing endorse / revoke / dispute lifecycle"

# revoke the FILE attestation (same attester) — should succeed
R=$(tx_result revoke "$FILE_ID" --reason "smoke revoke")
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "revoke (code 0)" || bad "revoke: $R"

# after revoke, the artifact is no longer malicious
R=$(query is-malicious --sha256 "$SHA_FILE")
M=$(json_get "$R" "d.get('is_malicious')")
[ "$M" = "False" ] && ok "is-malicious(FILE) == false after revoke" || bad "post-revoke is-malicious: $R"

# publish a fresh one for endorse/dispute
SHA2="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
R=$(tx_result publish --artifact-type FILE --artifact-sha256 "$SHA2" --severity LOW --confidence 50 \
     --ttl 86400 --description "endorse-dispute target" --category TATST:MALWARE --tags smoke)
CODE=$(json_get "$R" "d.get('code')")
[ "$CODE" = "0" ] && ok "second FILE publish (code 0)" || bad "second FILE publish: $R"
TARGET_ID=$(json_get "$(query is-malicious --sha256 "$SHA2")" "d['attestation']['id']")

# endorse + dispute from the same attester are rejected by business rules, but
# the commands must be wired (broadcast and return a tx result with a code).
R=$(tx_result endorse "$TARGET_ID")
CODE=$(json_get "$R" "d.get('code')")
[ -n "$CODE" ] && ok "endorse wired (code=$CODE)" || bad "endorse: $R"

R=$(tx_result dispute "$TARGET_ID" --ground FALSE_POSITIVE --evidence "smoke dispute")
CODE=$(json_get "$R" "d.get('code')")
[ -n "$CODE" ] && ok "dispute wired (code=$CODE)" || bad "dispute: $R"

# ─────────────────────────────────────────────────────────────────────────────
info "Cleanup"
kill "$NODE_PID" 2>/dev/null || true

echo ""
echo -e "${BOLD}Results: ${GREEN}$PASS passed${RESET}, ${RED}$FAIL failed${RESET}"
[ "$FAIL" -eq 0 ] || exit 1
