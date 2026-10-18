"""Online ML-prioritized *authenticated* KIE with an explicit probe budget.

All policy experiments send real authenticated challenges to the live agents.
No offline counterfactual KIE messages are counted as network traffic.
Policies run as independent campaigns, not paired measurements.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from experiment.active_gnn import OnlineGraphScheduler, fresh_transport
from experiment.collect import probe
from experiment.features import NODES
from experiment.secure_collect import SIGNERS, authenticated_kie, docker

COLS = [
    "timestamp", "policy", "trial", "tick", "phase", "node", "attack_target",
    "label", "sba_up", "sba_rtt_ms", "kie_queried", "kie_valid",
    "kie_rtt_ms", "kie_gap_new", "kie_gap_last", "kie_age_ticks",
    "kie_request_bytes", "kie_response_bytes", "alarm", "probe_kind",
    "gnn_risk_before", "gnn_selected",
]
MODEL_COLS = ("kie_rtt_ms", "kie_counter_gap", "up", "age")


def fit_prior(pilot_path: Path, seed: int) -> tuple[IsolationForest, int]:
    raw = pd.read_csv(pilot_path)
    if "probe_kind" not in raw or set(raw["probe_kind"].unique()) != {"live_sba_http2_plus_signed_agent"}:
        raise ValueError("The ranking prior must use previously measured LIVE signed agent data")
    subset = raw[
        (raw["phase"] == "baseline") &
        (raw["node"].isin(SIGNERS)) &
        (raw["kie_valid"] == 1) &
        (raw["label"] == 0)
    ]
    if len(subset) < 20:
        raise ValueError("Need >=20 honest LIVE pilot signed KIE observations")
    if set(subset["node"].unique()) != set(SIGNERS):
        raise ValueError("Pilot must include independent signed reports from both agents")
    if subset["kie_rtt_ms"].isna().any():
        raise ValueError("Pilot cannot have missing verified signed RTT")
    X = np.column_stack([
        subset["kie_rtt_ms"].to_numpy(dtype=float),
        subset["kie_counter_gap"].to_numpy(dtype=float),
        subset["kie_agent_local_up"].to_numpy(dtype=float),
        np.zeros(len(subset), dtype=float),
    ])
    model = IsolationForest(n_estimators=100, contamination=.06,
                            random_state=seed, n_jobs=1).fit(X)
    return model, len(subset)


def select_signed(
    policy: str, tick: int, states: dict[str, dict], model: IsolationForest,
    rng: random.Random, budget: int, max_age: int,
) -> set[str]:
    if policy == "full" or tick == 0:
        return set(SIGNERS)
    if budget >= len(SIGNERS):
        return set(SIGNERS)
    if policy == "rotation":
        return {SIGNERS[(tick + i) % len(SIGNERS)] for i in range(budget)}
    if policy != "ml_adaptive":
        raise ValueError(f"Unsupported policy {policy}")
    scores = []
    for node in SIGNERS:
        s = states[node]
        vec = np.asarray([[s["rtt"], s["gap"], s["up"], s["age"]]], dtype=float)
        novelty = -float(model.decision_function(vec)[0])
        # An overdue node must be probed regardless of previous risk estimate.
        overdue = s["age"] >= max_age
        score = (1000 if overdue else 0) + novelty + (
            .45 * min(s["age"], max_age)) + (0.7 * min(s["gap"], 3))
        score += rng.uniform(0, 0.001)
        scores.append((score, node))
    return {node for _, node in sorted(scores, reverse=True)[:budget]}


def phases(rng: random.Random, baseline: int, attack: int, recovery: int,
           nuisance: int) -> list[tuple[str, str | None, int]]:
    targets = list(SIGNERS)
    rng.shuffle(targets)
    benign = rng.choice(targets)
    result = [("baseline", None, baseline),
              ("benign_delay", benign, nuisance)]
    for node in targets:
        result += [("spoof", node, attack), ("recovery", node, recovery)]
    return result


def run(args: argparse.Namespace) -> dict:
    if args.signed_budget < 1 or args.signed_budget > len(SIGNERS):
        raise ValueError("Signed probe budget must be between 1 and 2")
    if args.trials < 2:
        raise ValueError("Need at least two independent repetitions per policy")
    if args.max_age < 2:
        raise ValueError("Max probe age must be at least two ticks")
    master = bytes.fromhex(os.environ["KIE_TEST_KEY"])
    if len(master) < 32:
        raise ValueError("KIE_TEST_KEY must have >=256 bits")
    rng = random.Random(args.seed)
    model, pilot_n = fit_prior(Path(args.pilot), args.seed)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Permutation avoids always letting one policy run on the freshest core.
    order = list(args.policies)
    rng.shuffle(order)
    normal = {"full", "rotation", "ml_adaptive"}
    with_gnn = normal | {"gnn_guided"}
    if set(order) not in (normal, with_gnn):
        raise ValueError("Policies must be full/rotation/ml_adaptive, optionally gnn_guided")
    if "gnn_guided" in order and not args.gnn_model:
        raise ValueError("gnn_guided requires a trained --gnn-model")
    graph_enabled = "gnn_guided" in order
    seq = {n: 1_000_000 for n in SIGNERS}
    rows = 0
    interventions = []
    signed_counts = {policy: 0 for policy in order}
    with output.open("w", encoding="utf8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=COLS)
        writer.writeheader()
        try:
            for policy in order:
                for trial in range(args.trials):
                    trial_phases = phases(rng, args.baseline, args.attack,
                                          args.recovery, args.nuisance)
                    interventions.append({
                        "policy": policy, "trial": trial,
                        "schedule": [list(phase) for phase in trial_phases],
                    })
                    state = {
                        n: dict(age=99, gap=0.0, up=1.0, rtt=2.0, seen=0,
                                claimed_offset=None, last_selected=False) for n in SIGNERS
                    }
                    tick = 0
                    last_transport = fresh_transport()
                    graph = OnlineGraphScheduler(Path(args.gnn_model)) if policy == "gnn_guided" else None
                    for phase, target, count in trial_phases:
                        switch = ("kie-spoof-counter-only" if phase == "spoof"
                                  else "kie-delay-only" if phase == "benign_delay"
                                  else None)
                        try:
                            if switch:
                                docker("exec", f"kie-{target}", "touch",
                                       f"/tmp/{switch}")
                            for _ in range(count):
                                risks = graph.risks(tick, state, last_transport) if graph else {}
                                if graph is not None:
                                    if tick == 0:
                                        chosen = set(SIGNERS)
                                    else:
                                        # A stale signer is forced into the budget.
                                        # Otherwise the learned next-tick posterior is
                                        # combined with observed age and prior verified gap.
                                        ranks = []
                                        for n in SIGNERS:
                                            age = state[n]["age"]
                                            priority = ((1000.0 if age >= args.max_age else 0.0)
                                                        + risks[n] + .12 * min(age, args.max_age)
                                                        + .20 * min(state[n]["gap"], 4))
                                            ranks.append((priority + rng.uniform(0, .00001), n))
                                        chosen = {n for _, n in sorted(
                                            ranks, reverse=True)[:args.signed_budget]}
                                else:
                                    chosen = select_signed(policy, tick, state, model, rng,
                                                           args.signed_budget, args.max_age)
                                now = datetime.now(timezone.utc).isoformat()
                                # All eight real SBA listeners are measured every
                                # tick, separate from budgeted authenticated KIEs.
                                transport = {n: probe(n, args.timeout) for n in NODES}
                                # Current tick transport is observed AFTER decision.
                                last_transport = transport
                                observed = {}
                                for node in SIGNERS:
                                    s = state[node]
                                    if node in chosen:
                                        seq[node] += 1
                                        signed = authenticated_kie(node, seq[node],
                                                                   master, args.timeout)
                                        if signed["kie_valid"] != 1:
                                            raise RuntimeError("Invalid signed KIE")
                                        signed_counts[policy] += 1
                                        s["seen"] += 1
                                        claimed = signed["kie_claimed_received"]
                                        if s["claimed_offset"] is None:
                                            s["claimed_offset"] = claimed - s["seen"]
                                        gap = abs(s["seen"] + s["claimed_offset"] - claimed)
                                        s.update(gap=float(gap), rtt=signed["kie_rtt_ms"],
                                                 up=signed["kie_agent_local_up"], age=0,
                                                 last_selected=True)
                                        observed[node] = {
                                            "kie_queried": 1, "kie_valid": 1,
                                            "kie_rtt_ms": signed["kie_rtt_ms"],
                                            "kie_gap_new": gap,
                                            "kie_request_bytes": signed["kie_request_bytes"],
                                            "kie_response_bytes": signed["kie_response_bytes"],
                                        }
                                    else:
                                        s["age"] += 1
                                        s["last_selected"] = False
                                        # No KIE sent or received. Last verified
                                        # value and its age are kept explicitly.
                                        observed[node] = {
                                            "kie_queried": 0, "kie_valid": 0,
                                            "kie_rtt_ms": "",
                                            "kie_gap_new": "",
                                            "kie_request_bytes": 0,
                                            "kie_response_bytes": 0,
                                        }
                                for node in NODES:
                                    signed = observed.get(node, {
                                        "kie_queried": 0, "kie_valid": 0,
                                        "kie_rtt_ms": "", "kie_gap_new": "",
                                        "kie_request_bytes": 0,
                                        "kie_response_bytes": 0,
                                    })
                                    current = state.get(node)
                                    writer.writerow({
                                        "timestamp": now, "policy": policy,
                                        "trial": trial, "tick": tick,
                                        "phase": phase, "node": node,
                                        "attack_target": target or "",
                                        "label": int(phase == "spoof" and target == node),
                                        "sba_up": transport[node]["up"],
                                        "sba_rtt_ms": transport[node]["rtt_ms"],
                                        **signed,
                                        "kie_gap_last": current["gap"] if current else "",
                                        "kie_age_ticks": current["age"] if current else "",
                                        # Persistent verified alarm, including
                                        # post-fault staleness until next query.
                                        "alarm": int(bool(current and current["gap"] > 0)),
                                        "probe_kind": "LIVE_SIGNED_AGENT_HTTP11_AND_SBA_HTTP2",
                                        "gnn_risk_before": risks.get(node, ""),
                                        "gnn_selected": int(bool(graph and node in chosen)),
                                    })
                                    rows += 1
                                file.flush()
                                tick += 1
                                time.sleep(args.interval)
                        finally:
                            if switch:
                                docker("exec", f"kie-{target}", "rm", "-f",
                                       f"/tmp/{switch}")
        finally:
            for node in SIGNERS:
                for flag in ("kie-spoof", "kie-spoof-counter-only", "kie-delay-only"):
                    try:
                        docker("exec", f"kie-{node}", "rm", "-f", f"/tmp/{flag}")
                    except RuntimeError:
                        pass
    metadata = {
        "provenance": "LIVE_OPEN5GS_PLUS_SIGNED_NF_COLOCATED_AGENT",
        "pilot_source": args.pilot, "pilot_normal_samples": pilot_n,
        "graph_model_path": args.gnn_model,
        "graph_features": "PAST-ONLY cached authenticated KIE, age and PREVIOUS SBA",
        "graph_training_source": "previous Phase 3 full-policy campaigns; no Phase 4 fine-tuning",
        "all_policies": order, "budgets_after_tick_zero": {
            "full": len(SIGNERS), "rotation": args.signed_budget,
            "ml_adaptive": args.signed_budget,
            **({"gnn_guided": args.signed_budget} if graph_enabled else {}),
        }, "signed_counts": signed_counts, "rows": rows,
        "schedule": interventions, "random_seed": args.seed,
        "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "limits": "Two test signers, no native NF counters; campaigns are not paired",
    }
    output.with_suffix(".metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf8")
    return metadata


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pilot", default="results/signed_kie.csv")
    p.add_argument("--output", default="results/adaptive_signed.csv")
    p.add_argument("--policies", nargs="+",
                   default=["full", "rotation", "ml_adaptive"])
    p.add_argument("--signed-budget", type=int, default=1)
    p.add_argument("--gnn-model")
    p.add_argument("--max-age", type=int, default=3)
    p.add_argument("--trials", type=int, default=2)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--baseline", type=int, default=6)
    p.add_argument("--attack", type=int, default=9)
    p.add_argument("--recovery", type=int, default=6)
    p.add_argument("--nuisance", type=int, default=6)
    p.add_argument("--interval", type=float, default=.3)
    p.add_argument("--timeout", type=float, default=2.5)
    result = run(p.parse_args())
    print(json.dumps({"signed_counts": result["signed_counts"],
                      "rows": result["rows"]}, indent=2))


if __name__ == "__main__":
    main()
