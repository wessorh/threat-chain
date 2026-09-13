#!/usr/bin/env bash
#
# check_threatattestd — Nagios/Icinga plugin for the threatattestd blockchain
# daemon (CometBFT / Cosmos SDK node).
#
# Remote check: talks only to the node's CometBFT RPC endpoint over TCP. No
# local process/filesystem access is used, so it can monitor a node on any
# reachable host.
#
# Checks (all via the RPC /status endpoint):
#   1. the RPC endpoint responds
#   2. the node is not "catching up" (still syncing)  -> WARNING
#   3. the latest committed block is recent (not stalled)
#
# Exit codes follow the Nagios plugin spec: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
#
# Usage:
#   check_threatattestd [-H host] [-p port] [-w warn_secs] [-c crit_secs]

set -u

HOST="127.0.0.1"
PORT="26657"
WARN_AGE=60      # seconds: latest block older than this => WARNING
CRIT_AGE=300     # seconds: latest block older than this => CRITICAL
TIMEOUT=5

usage() {
    echo "Usage: $0 [-H host] [-p port] [-w warn_secs] [-c crit_secs]"
    echo
    echo "  -H  CometBFT RPC host            (default $HOST)"
    echo "  -p  CometBFT RPC port            (default $PORT)"
    echo "  -w  block-age WARNING threshold  (seconds, default $WARN_AGE)"
    echo "  -c  block-age CRITICAL threshold (seconds, default $CRIT_AGE)"
}

while getopts "H:p:w:c:h" opt; do
    case "$opt" in
        H) HOST="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        w) WARN_AGE="$OPTARG" ;;
        c) CRIT_AGE="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 3 ;;
    esac
done

RPC="http://${HOST}:${PORT}"
TARGET="${HOST}:${PORT}"

# 1. Is the RPC endpoint reachable and responding?
status_json="$(curl -s --max-time "$TIMEOUT" "$RPC/status" 2>/dev/null)"
if [ -z "$status_json" ]; then
    echo "CRITICAL - no response from $RPC/status"
    exit 2
fi

# 2. Parse /status and assess. python3 handles the JSON + timestamp arithmetic;
#    it emits "STATE height age" which we split into three variables.
read -r state height age <<< "$(WARN_AGE="$WARN_AGE" CRIT_AGE="$CRIT_AGE" python3 -c '
import json, sys, os, datetime

warn = float(os.environ["WARN_AGE"])
crit = float(os.environ["CRIT_AGE"])

try:
    d = json.load(sys.stdin)
except Exception:
    print("UNKNOWN 0 -1")
    raise SystemExit

if "error" in d:
    print("UNKNOWN 0 -1")
    raise SystemExit

si = d.get("result", {}).get("sync_info")
if not si:
    print("UNKNOWN 0 -1")
    raise SystemExit

catching_up = si.get("catching_up", False)
height = str(si.get("latest_block_height", "0"))
block_time = si.get("latest_block_time", "")

age = -1.0
if block_time:
    try:
        t = datetime.datetime.fromisoformat(block_time.replace("Z", "+00:00"))
        age = (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds()
    except ValueError:
        pass

# A syncing node is WARNING regardless of block age (its latest block is
# legitimately old while it replays history). For an in-sync node, block age
# reflects whether it has stalled.
if catching_up:
    print("WARNING %s %d" % (height, age))
elif age >= crit:
    print("CRITICAL %s %d" % (height, age))
elif age >= warn:
    print("WARNING %s %d" % (height, age))
else:
    print("OK %s %d" % (height, age))
' <<< "$status_json")"

case "$state" in
    OK)
        echo "OK - $TARGET healthy (height=$height, block age=${age}s) | block_age=${age}s;$WARN_AGE;$CRIT_AGE"
        exit 0 ;;
    WARNING)
        echo "WARNING - $TARGET (height=$height, block age=${age}s) | block_age=${age}s;$WARN_AGE;$CRIT_AGE"
        exit 1 ;;
    CRITICAL)
        echo "CRITICAL - $TARGET (height=$height, block age=${age}s) | block_age=${age}s;$WARN_AGE;$CRIT_AGE"
        exit 2 ;;
    *)
        echo "UNKNOWN - could not parse $RPC/status"
        exit 3 ;;
esac
