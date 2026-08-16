#!/usr/bin/env bash
set -euo pipefail

# collect_evidence.sh — collect a DNSSEC evidence bundle for a ThreatAttest
# DNS-bound identity registration.
#
# Queries the DNSSEC records for a domain's TAT key record and emits a
# DNSEvidenceBundle JSON document on stdout, suitable for:
#
#   threatattestd tx identity register-identity --evidence-file evidence.json ...
#   threatattestd tx identity renew-identity    --evidence-file evidence.json ...
#
# Usage:
#   ./scripts/collect_evidence.sh <domain> [selector] [resolver]
#
# Environment:
#   DNS_RESOLVER — default resolver (overridden by the 3rd positional arg)
#
# Requires: dig, python3 (jq is NOT required).

DOMAIN="${1:-}"
SELECTOR="${2:-tat2026a}"
RESOLVER="${3:-${DNS_RESOLVER:-8.8.8.8}}"

if [ -z "$DOMAIN" ]; then
  echo "usage: collect_evidence.sh <domain> [selector] [resolver]" >&2
  exit 2
fi

# Normalize the domain (lowercase, strip trailing dot).
DOMAIN="$(printf '%s' "$DOMAIN" | tr 'A-Z' 'a-z' | sed 's/\.$//')"
KEY_NAME="${SELECTOR}._tatkey.${DOMAIN}"

for c in dig python3; do
  command -v "$c" >/dev/null 2>&1 || { echo "error: $c is required but not found" >&2; exit 1; }
done

RESOLVER="$RESOLVER" DOMAIN="$DOMAIN" KEY_NAME="$KEY_NAME" SELECTOR="$SELECTOR" \
python3 - <<'PY'
import base64
import datetime
import json
import os
import re
import struct
import subprocess
import sys
import time

resolver  = os.environ["RESOLVER"]
domain    = os.environ["DOMAIN"]
key_name  = os.environ["KEY_NAME"]
selector  = os.environ["SELECTOR"]


def dig(rrtype, name, dnssec=False):
    args = ["dig", rrtype, name, "@" + resolver, "+noall", "+answer", "+tries=3", "+time=8"]
    if dnssec:
        args.append("+dnssec")
    out = subprocess.run(args, capture_output=True, text=True).stdout
    return out.splitlines()


def records(lines):
    """Yield (rrtype, rdata) from dig answer lines.

    dig answer format is `<name> <ttl> IN <TYPE> <rdata...>`. The first four
    fields are single whitespace-separated tokens; rdata may contain spaces
    (long base64 is wrapped), so we split into at most 5 parts.
    """
    for ln in lines:
        parts = ln.split(None, 4)
        if len(parts) < 5:
            continue
        yield parts[3], parts[4]


def dnssec_time(s):
    """YYYYMMDDHHMMSS -> Unix epoch (UTC)."""
    dt = datetime.datetime.strptime(s, "%Y%m%d%H%M%S")
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp())


def join_ws(s):
    """dig wraps long base64 RDATA with internal spaces — rejoin."""
    return "".join(s.split())


def parse_txt(lines):
    vals = []
    for rrtype, rdata in records(lines):
        if rrtype != "TXT":
            continue
        chunks = re.findall(r'"([^"]*)"', rdata)
        if chunks:
            vals.append("".join(chunks))
    return vals


def parse_rrsig(lines, want_type):
    recs = []
    for rrtype, rdata in records(lines):
        if rrtype != "RRSIG":
            continue
        # rdata: type_covered algorithm labels orig_ttl exp inc key_tag signer signature
        f = rdata.split(None, 8)
        if len(f) < 9:
            continue
        tc, alg, labels, origttl, exp, inc, keytag, signer = f[:8]
        if tc != want_type:
            continue
        recs.append({
            "type_covered": tc,
            "algorithm": int(alg),
            "labels": int(labels),
            "original_ttl": int(origttl),
            "expiration": dnssec_time(exp),
            "inception": dnssec_time(inc),
            "key_tag": int(keytag),
            "signer_name": signer,
            "signature": join_ws(f[8]),
        })
    return recs


def dnskey_keytag(flags, protocol, algorithm, pubkey_b64):
    """RFC 4034 Appendix B key tag over the DNSKEY RDATA."""
    rdata = struct.pack("!HBB", flags, protocol, algorithm) + base64.b64decode(pubkey_b64)
    ac = 0
    for i, b in enumerate(rdata):
        ac += (b << 8) if (i & 1) == 0 else b
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def parse_dnskey(lines):
    recs = []
    for rrtype, rdata in records(lines):
        if rrtype != "DNSKEY":
            continue
        # rdata: flags protocol algorithm public_key(base64, may wrap)
        f = rdata.split(None, 3)
        if len(f) < 4:
            continue
        flags, proto, alg, pub = f[0], f[1], f[2], join_ws(f[3])
        recs.append({
            "flags": int(flags),
            "protocol": int(proto),
            "algorithm": int(alg),
            "public_key": pub,
            "key_tag": dnskey_keytag(int(flags), int(proto), int(alg), pub),
        })
    return recs


def parse_ds(lines):
    recs = []
    for rrtype, rdata in records(lines):
        if rrtype != "DS":
            continue
        # rdata: key_tag algorithm digest_type digest(hex, may wrap)
        f = rdata.split(None, 3)
        if len(f) < 4:
            continue
        keytag, alg, dtype, digest = f[0], f[1], f[2], join_ws(f[3])
        recs.append({
            "key_tag": int(keytag),
            "algorithm": int(alg),
            "digest_type": int(dtype),
            "digest": digest.lower(),
        })
    return recs


# One +dnssec query yields both the RRset and its covering RRSIG.
txt_lines    = dig("TXT", key_name, dnssec=True)
dnskey_lines = dig("DNSKEY", domain, dnssec=True)
ds_lines     = dig("DS", domain)

bundle = {
    "txt_records":     parse_txt(txt_lines),
    "txt_rrsigs":      parse_rrsig(txt_lines, "TXT"),
    "zone_dnskeys":    parse_dnskey(dnskey_lines),
    "dnskey_rrsigs":   parse_rrsig(dnskey_lines, "DNSKEY"),
    "parent_ds":       parse_ds(ds_lines),
    "collected_at":    int(time.time()),
    "resolver":        resolver,
}

# Warn (on stderr) about any empty section so the caller knows before
# submitting an on-chain tx that will be rejected by ValidateEvidenceBundle.
missing = []
if not bundle["txt_records"]:
    missing.append("txt_records (publish the TXT record at %s first)" % key_name)
if not bundle["txt_rrsigs"]:
    missing.append("txt_rrsigs (is the zone DNSSEC-signed?)")
if not bundle["zone_dnskeys"]:
    missing.append("zone_dnskeys")
if not bundle["dnskey_rrsigs"]:
    missing.append("dnskey_rrsigs")
if not bundle["parent_ds"]:
    missing.append("parent_ds (no DS record at the parent zone?)")
if missing:
    print("warning: empty evidence sections — " + "; ".join(missing), file=sys.stderr)

json.dump(bundle, sys.stdout, indent=2)
print()
PY
