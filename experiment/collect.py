"""Real Open5GS SBA probe collection and controlled NF availability faults.

KIE-*equivalent* challenges are nonce-bearing HTTP/2 requests to the actual
SBA listeners. The unmodified NF does NOT verify/return a MAC: this is not
a cryptographically authenticated KIE implementation.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from experiment.features import IP, NODES, online_vector

FIELDS = ["ts", "policy", "trial", "tick", "phase", "node", "observed",
          "up", "rtt_ms", "age", "http_code", "http_version", "request_bytes",
          "response_body_bytes", "label", "fault_node", "probe_kind"]


def shell(*args: str, timeout: int = 20) -> str:
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{' '.join(args)}: {p.stderr[-600:]}")
    return p.stdout


def probe(node: str, timeout_s: float) -> dict:
    """Probe the real NF SBI socket; 404 over HTTP/2 means NF is reachable."""
    nonce = secrets.token_hex(12)
    path = "/nnrf-nfm/v1/nf-instances" if node == "nrf" else "/"
    ip = f"10.45.0.{IP[node]}"
    cmd = ["curl", "--noproxy", "*", "-sS", "--http2-prior-knowledge",
           "--max-time", str(timeout_s), "-o", "/dev/null",
           "-H", f"X-Experiment-CIE-Nonce: {nonce}",
           "-H", "Accept: application/json",
           "-w", "%{http_code}|%{time_total}|%{http_version}|%{size_request}|%{size_download}",
           f"http://{ip}:7777{path}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 2)
        fields = p.stdout.strip().split("|")
        if p.returncode != 0 or len(fields) != 5:
            raise ValueError(p.stderr[-100:])
        code, seconds, version, n_req, n_reply = fields
        return {"up": int(100 <= int(code) < 600 and version.startswith("2")),
                "rtt_ms": round(1000 * float(seconds), 3),
                "http_code": int(code), "http_version": version,
                "request_bytes": int(float(n_req)),
                "response_body_bytes": int(float(n_reply))}
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return {"up": 0, "rtt_ms": float("nan"),
                "http_code": 0, "http_version": "",
                "request_bytes": 0, "response_body_bytes": 0}


def select_nodes(policy: str, tick: int, state: dict, budget: int,
                 model, rng: random.Random) -> set[str]:
    if policy == "full" or tick == 0:
        return set(NODES)
    if policy == "rotation":
        return {NODES[(tick * budget + k) % len(NODES)] for k in range(budget)}
    if policy != "adaptive" or model is None:
        raise ValueError("Adaptive monitoring needs a previously trained model")
    # Higher anomaly score -> prioritize next verification, plus bounded
    # exploration of stale nodes to prevent permanent blind spots.
    candidates = []
    for node in NODES:
        vec = np.asarray([online_vector(state, node)])
        anomaly = -float(model.decision_function(vec)[0])
        freshness = min(state[node]["age"] / 8, 3.0)
        priority = anomaly + 0.25 * freshness + rng.uniform(0, 0.005)
        candidates.append((priority, node))
    return {node for _, node in sorted(candidates, reverse=True)[:budget]}


def ensure_live() -> None:
    shell("docker", "info")
    ver = shell("curl", "-V")
    if "HTTP2" not in ver and "HTTP/2" not in ver:
        raise RuntimeError("curl must support HTTP/2 prior knowledge")
    good = probe("nrf", 2)
    if not good["up"]:
        raise RuntimeError("NRF not reachable via real HTTP/2 SBA. Refusing synthetic fallback")


def run(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    policy_model = joblib.load(args.policy_model) if args.policy_model else None
    if args.policy == "adaptive" and policy_model is None:
        raise ValueError("--policy-model required for adaptive policy")
    if not 1 <= args.budget <= len(NODES):
        raise ValueError("Budget must be within 1..8")
    ensure_live()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    records = 0
    metadata = {
        "evidence": "live_5gc_sba_http2",
        "kie_status": "nonce-bearing probes; no NF-side authentication or MAC",
        "fault_type": "Docker NF pause (availability), not verified malicious compromise",
        "policy": args.policy, "budget": args.budget,
        "runner_sha": os.getenv("GITHUB_SHA", "local"),
        "trials": args.trials, "seed": args.seed,
        "faults": args.faults, "start_utc": datetime.now(timezone.utc).isoformat(),
    }
    phases = [("baseline", "", args.baseline)]
    for target in args.faults:
        if target not in NODES:
            raise ValueError(f"Unknown NF: {target}")
        phases += [(f"fault_{target}", target, args.fault),
                   (f"recovery_{target}", "", args.recovery)]
    with out.open("w", newline="", encoding="utf8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for trial in range(args.trials):
            state = {n: {"up": 1.0, "rtt_ms": float("nan"),
                         "age": 99.0} for n in NODES}
            tick = 0
            for phase, fault, count in phases:
                if fault:
                    shell("docker", "pause", f"open5gs-{fault}")
                try:
                    for _ in range(count):
                        chosen = select_nodes(args.policy, tick, state, args.budget,
                                              policy_model, rng)
                        now = datetime.now(timezone.utc).isoformat()
                        for node in NODES:
                            selected = node in chosen
                            if selected:
                                response = probe(node, args.timeout)
                                state[node] = {"up": float(response["up"]),
                                               "rtt_ms": response["rtt_ms"], "age": 0.0}
                            else:
                                response = {"up": int(state[node]["up"]),
                                            "rtt_ms": state[node]["rtt_ms"],
                                            "http_code": 0, "http_version": "",
                                            "request_bytes": 0, "response_body_bytes": 0}
                                state[node]["age"] += 1.0
                            writer.writerow({
                                "ts": now, "policy": args.policy, "trial": trial,
                                "tick": tick, "phase": phase, "node": node,
                                "observed": int(selected), "up": response["up"],
                                "rtt_ms": response["rtt_ms"], "age": state[node]["age"],
                                "http_code": response["http_code"],
                                "http_version": response["http_version"],
                                "request_bytes": response["request_bytes"],
                                "response_body_bytes": response["response_body_bytes"],
                                "label": int(bool(fault) and node == fault),
                                "fault_node": fault, "probe_kind": "live_sba_http2",
                            })
                            records += 1
                        handle.flush()
                        tick += 1
                        time.sleep(args.interval)
                finally:
                    if fault:
                        shell("docker", "unpause", f"open5gs-{fault}")
                        time.sleep(args.recovery_wait)
    metadata["records"] = records
    metadata["end_utc"] = datetime.now(timezone.utc).isoformat()
    out.with_suffix(".metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf8")
    print(f"Wrote {records} LIVE observations to {out}", flush=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--policy", choices=["full", "rotation", "adaptive"], default="full")
    p.add_argument("--policy-model")
    p.add_argument("--budget", type=int, default=3)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--baseline", type=int, default=20)
    p.add_argument("--fault", type=int, default=12)
    p.add_argument("--recovery", type=int, default=12)
    p.add_argument("--recovery-wait", type=float, default=3)
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--faults", nargs="+", default=["smf", "nrf"])
    run(p.parse_args())


if __name__ == "__main__":
    main()
