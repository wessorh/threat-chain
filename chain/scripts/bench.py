#!/usr/bin/env python3
"""
bench.py — baseline wall-clock latency for threatattestd CLI commands.

Times each command (1 warm-up + N runs) against a node and prints a usability
table + writes timing.csv. Read-only query commands are timed as-is; write
commands use a per-run unique artifact sha256 so they don't hit dedup.

Usage:
    python3 scripts/bench.py --node tcp://192.168.2.128:26657 \
        --attester <bech32-addr> [--sha <64hex>] [--id <attestation-id>] [--n 7]
"""

import argparse
import hashlib
import os
import statistics
import subprocess
import sys
import time


def run(argv, timeout=120):
    t0 = time.perf_counter()
    rc = subprocess.call(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout
    )
    return time.perf_counter() - t0, rc


def bench(fn, n):
    """fn(i) -> argv for run i. Returns (times, all_exit_zero)."""
    run(fn(0))  # warm-up (Go runtime, keyring unlock, store warm)
    times, rcs = [], []
    for i in range(1, n + 1):
        dt, rc = run(fn(i))
        times.append(dt)
        rcs.append(rc)
    return times, all(r == 0 for r in rcs)


def verdict(m):
    if m < 0.1:
        return "instant"
    if m < 1.0:
        return "fast"
    if m < 5.0:
        return "acceptable"
    if m < 10.0:
        return "slow"
    return "unusable"


def ms(x):
    return f"{x*1000:6.0f}ms"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=7, help="timed runs per command")
    ap.add_argument("--binary", default="./bin/threatattestd")
    ap.add_argument("--home", default=os.path.expanduser("~/.threatattestd-local"))
    ap.add_argument("--chain", default="threatattest-local-1")
    ap.add_argument("--node", default="tcp://127.0.0.1:26657",
                    help="RPC node, e.g. tcp://192.168.2.128:26657")
    ap.add_argument("--attester", default="", help="attester bech32 address")
    ap.add_argument("--sha", default="", help="seeded artifact sha256 (64 hex)")
    ap.add_argument("--id", default="", help="seeded attestation id")
    a = ap.parse_args()

    B, H, C, N = a.binary, a.home, a.chain, a.n
    node = ["--node", a.node]
    kr = ["--home", H, "--keyring-backend", "test"]
    q = [B, "--home", H] + node
    tx = [B, "--home", H, "--keyring-backend", "test", "--chain-id", C] + node

    def sha(i):
        return hashlib.sha256(f"bench-run-{i}".encode()).hexdigest()

    # (label, fn(i) -> argv)
    cmds = [
        # ── local (no RPC) ──────────────────────────────────────────────
        ("version", lambda i: [B, "version"]),
        ("keys list", lambda i: [B, "keys", "list"] + kr),
        (
            "attest-file (spec gen)",
            lambda i: [B, "attest-file", "/tmp/sample.bin", "--output",
                       f"/tmp/spec-{i}.json", "--severity", "HIGH"],
        ),
        # ── query (read RPC) ────────────────────────────────────────────
        ("status", lambda i: [B, "status", "--home", H] + node),
        ("q attestation params", lambda i: q + ["query", "attestation", "params", "-o", "json"]),
        (
            "q list-by-attester",
            lambda i: q + ["query", "attestation", "list-by-attester",
                           "--attester", a.attester, "-o", "json"],
        ),
        ("q get", lambda i: q + ["query", "attestation", "get", a.id, "-o", "json"]),
        (
            "q is-malicious",
            lambda i: q + ["query", "attestation", "is-malicious",
                           "--artifact-sha256", a.sha, "-o", "json"],
        ),
        ("q validator-set", lambda i: q + ["query", "comet-validator-set"]),
        (
            "q ipfsverify pending",
            lambda i: q + ["query", "ipfsverify", "pending-jobs", "-o", "json"],
        ),
        # ── write (tx RPC) — unique sha per run ─────────────────────────
        (
            "tx publish (gas=200000, sync)",
            lambda i: tx + ["tx", "attestation", "publish", "--artifact-type", "FILE",
                           "--artifact-sha256", sha(i), "--severity", "HIGH",
                           "--confidence", "90", "--ttl", "86400",
                           "--description", "bench", "--category", "MALWARE",
                           "--from", "localkey", "--gas", "200000", "-b", "sync",
                           "-y", "-o", "json"],
        ),
        (
            "tx publish (gas=auto, sync)",
            lambda i: tx + ["tx", "attestation", "publish", "--artifact-type", "FILE",
                           "--artifact-sha256", sha(i), "--severity", "HIGH",
                           "--confidence", "90", "--ttl", "86400",
                           "--description", "bench", "--category", "MALWARE",
                           "--from", "localkey", "--gas", "auto",
                           "--gas-adjustment", "1.5", "-b", "sync", "-y", "-o", "json"],
        ),
        (
            "tx publish (async)",
            lambda i: tx + ["tx", "attestation", "publish", "--artifact-type", "FILE",
                           "--artifact-sha256", sha(i), "--severity", "HIGH",
                           "--confidence", "90", "--ttl", "86400",
                           "--description", "bench", "--category", "MALWARE",
                           "--from", "localkey", "--gas", "200000", "-b", "async",
                           "-y", "-o", "json"],
        ),
    ]

    print(f"{'command':28s} {'class':7s} {'min':>7s} {'median':>7s} {'max':>7s}  verdict")
    print("-" * 78)
    rows = []
    for label, fn in cmds:
        times, ok = bench(fn, N)
        med = statistics.median(times)
        klass = "local" if label.split()[0] in ("version", "keys", "attest-file") else (
            "query" if label.startswith("q ") or label == "status" else "write")
        rows.append((label, klass, min(times), med, max(times), ok, verdict(med)))
        print(f"{label:28s} {klass:7s} {ms(min(times)):>7s} {ms(med):>7s} {ms(max(times)):>7s}  "
              f"{verdict(med) + ('  ⚠ ERR' if not ok else '')}")

    with open("timing.csv", "w") as f:
        f.write("command,class,min_s,median_s,max_s,all_ok,verdict\n")
        for label, klass, mn, med, mx, ok, v in rows:
            f.write(f"{label},{klass},{mn:.4f},{med:.4f},{mx:.4f},{ok},{v}\n")
    print("\nwrote timing.csv")


if __name__ == "__main__":
    main()
