"""Independent observer: authenticated lab KIE round trips and dishonest NF-agent reports.

Do not confuse NF-colocated test agent counters with native 5GC counters.
All features are derived from live responses to real network probes.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import http.client
import json
import os
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment.collect import probe
from experiment.features import IP, NODES

SIGNERS = ("nrf", "smf")
KIE_FIELDS = [
    "kie_present", "kie_valid", "kie_rtt_ms", "kie_claimed_received",
    "kie_observer_received", "kie_counter_gap", "kie_invariant_error",
    "kie_agent_local_up", "kie_request_bytes", "kie_response_bytes",
]
FIELDS = ["ts", "trial", "tick", "phase", "node", "policy", "label", "up",
          "rtt_ms", "age", "observed", "probe_kind", *KIE_FIELDS]


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def per_node_key(master: bytes, node: str) -> bytes:
    return hmac.new(master, node.encode(), hashlib.sha256).digest()


def sign(key: bytes, data: dict) -> str:
    return hmac.new(key, canonical(data), hashlib.sha256).hexdigest()


def authenticated_kie(node: str, seq: int, master: bytes, timeout: float = 2.0) -> dict:
    """Reject invalid MAC, unexpected nonce/node/sequence or stale response."""
    key = per_node_key(master, node)
    challenge = {"node": node, "seq": seq, "ts": time.time(),
                 "nonce": secrets.token_hex(16)}
    challenge["mac"] = sign(key, challenge)
    sent = canonical(challenge)
    conn = http.client.HTTPConnection(f"10.45.0.{IP[node]}", 18080, timeout=timeout)
    start = time.monotonic_ns()
    try:
        conn.request("POST", "/kie/v1/challenge", body=sent,
                     headers={"Content-Type": "application/json"})
        res = conn.getresponse()
        body = res.read(4097)
        rtt = (time.monotonic_ns() - start) / 1e6
        if res.status != 200 or len(body) > 4096:
            raise RuntimeError(f"KIE reply HTTP {res.status}")
        reply = json.loads(body)
        supplied = reply.pop("mac", None)
        if (not isinstance(supplied, str) or
            not hmac.compare_digest(sign(key, reply), supplied) or
            reply.get("node") != node or reply.get("seq") != seq or
            reply.get("nonce") != challenge["nonce"] or
            not isinstance(reply.get("ts"), (int, float)) or
            abs(time.time() - reply["ts"]) > 60):
            raise ValueError("Invalid authenticated KIE response")
        counter = int(reply["claimed_received"])
        components = reply["claimed_components"]
        return {"kie_present": 1, "kie_valid": 1, "kie_rtt_ms": rtt,
                "kie_claimed_received": counter,
                "kie_invariant_error": abs(counter - sum(map(int, components.values()))),
                "kie_agent_local_up": int(reply["local_port_open"]),
                "kie_request_bytes": len(sent), "kie_response_bytes": len(body)}
    finally:
        conn.close()


def docker(*args: str) -> None:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            timeout=15)
    if result.returncode:
        raise RuntimeError(f"docker {' '.join(args)} failed: {result.stderr[-500:]}")


def run(args: argparse.Namespace) -> None:
    master = bytes.fromhex(os.environ["KIE_TEST_KEY"])
    if len(master) < 32:
        raise RuntimeError("Lab KIE_TEST_KEY must be >= 32 cryptographic bytes")
    if args.trials < 4:
        raise ValueError("Four independent trials are required for train/val/test")
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = 0
    phases = [("baseline", args.baseline), ("spoof_smf", args.spoof),
              ("recovery", args.recovery)]
    try:
        with out.open("w", newline="", encoding="utf8") as handle:
            writer = csv.DictWriter(handle, FIELDS)
            writer.writeheader()
            for trial in range(args.trials):
                observed = {node: 0 for node in SIGNERS}
                # Agent counters persist between trials; compare increments, not absolute.
                offset = {node: None for node in SIGNERS}
                tick = 0
                for phase, count in phases:
                    if phase == "spoof_smf":
                        docker("exec", "kie-smf", "touch", "/tmp/kie-spoof")
                    try:
                        for _ in range(count):
                            now = datetime.now(timezone.utc).isoformat()
                            replies = {n: probe(n, args.timeout) for n in NODES}
                            kie_results = {}
                            for node in SIGNERS:
                                seq = trial * 100000 + tick + 1
                                result = authenticated_kie(node, seq, master, args.timeout)
                                if not result["kie_valid"]:
                                    raise RuntimeError(f"Authenticated KIE missing for {node}")
                                observed[node] += 1
                                claimed = result["kie_claimed_received"]
                                if offset[node] is None:
                                    offset[node] = claimed - observed[node]
                                result["kie_observer_received"] = observed[node]
                                result["kie_counter_gap"] = abs(
                                    observed[node] + offset[node] - claimed)
                                kie_results[node] = result
                            for node in NODES:
                                r = replies[node]
                                aux = kie_results.get(node, {})
                                writer.writerow({
                                    "ts": now, "trial": trial, "tick": tick,
                                    "phase": phase, "node": node,
                                    "policy": "authenticated_full",
                                    "label": int(phase == "spoof_smf" and node == "smf"),
                                    "up": r["up"], "rtt_ms": r["rtt_ms"],
                                    "age": 0, "observed": 1,
                                    "probe_kind": "live_sba_http2_plus_signed_agent",
                                    **{k: aux.get(k, 0) for k in KIE_FIELDS},
                                })
                                rows += 1
                            handle.flush()
                            tick += 1
                            time.sleep(args.interval)
                    finally:
                        if phase == "spoof_smf":
                            docker("exec", "kie-smf", "rm", "-f", "/tmp/kie-spoof")
    finally:
        # A failed run must never leave the lab attacker switch active.
        try:
            docker("exec", "kie-smf", "rm", "-f", "/tmp/kie-spoof")
        except RuntimeError:
            pass
    if rows != args.trials * sum(x[1] for x in phases) * len(NODES):
        raise RuntimeError("Incomplete observation grid")
    out.with_suffix(".metadata.json").write_text(json.dumps({
        "kind": "live_5g_sba_authenticated_agent_spoof",
        "note": "MAC authenticated NF-co-located test agent, not stock NF or 3GPP KIE",
        "intervention": "SMF agent signs stale challenge receipt counter; no core NF compromise",
        "trials": args.trials, "rows": rows,
        "kie_signers": SIGNERS, "timestamp": datetime.now(timezone.utc).isoformat(),
        "github_sha": os.environ.get("GITHUB_SHA", "local"),
        "simulated_data": False,
    }, indent=2), encoding="utf8")
    print(f"Collected {rows} independently observed real-lab rows to {out}", flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="results/signed_kie.csv")
    p.add_argument("--trials", type=int, default=4)
    p.add_argument("--baseline", type=int, default=12)
    p.add_argument("--spoof", type=int, default=10)
    p.add_argument("--recovery", type=int, default=10)
    p.add_argument("--interval", type=float, default=0.4)
    p.add_argument("--timeout", type=float, default=2.5)
    run(p.parse_args())


if __name__ == "__main__":
    main()
