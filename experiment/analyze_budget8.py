"""Fail-closed eight-NF live signed KIE policy comparison and episode delays."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from experiment.budget8_campaign import (
    ALL_POLICIES, BUDGET, PROVENANCE, TICKS, scenario,
)
from experiment.features import NODES


def analyze(path: Path, metadata: Path, output: Path,
            seed: int = 81491) -> dict:
    df = pd.read_csv(path)
    info = json.loads(metadata.read_text())
    if info.get("provenance") != PROVENANCE or set(info.get("policy_order", [])) != set(ALL_POLICIES):
        raise ValueError("Cannot compare incomplete live authenticated policies")
    if set(df.provenance.unique()) != {PROVENANCE}:
        raise ValueError("Synthetic or other-origin observation mixed with live")
    expected = {"policy", "trial", "tick", "node", "label", "kie_queried",
                "kie_valid", "kie_gap_full", "sba_up", "sba_rtt_ms",
                "signed_request_bytes", "signed_response_bytes", "alarm"}
    if expected - set(df):
        raise ValueError("Missing essential source measurements")
    expected_trials = set(range(int(info["trials"])))
    if set(df.trial.unique()) != expected_trials:
        raise ValueError("Missing independently captured policy trials")
    out = {
        "experiment": "REAL_EIGHT_NF_EQUAL_BUDGET_SIGNED_SCHEDULING",
        "provenance": PROVENANCE,
        "signed_agent_is_not_native_nf": True,
        "graph_correlated_attacks_are_staged_agent_counter_only": True,
        "heldout_separate_live_campaigns": True,
        "policies": {},
    }
    for policy in ALL_POLICIES:
        block = df[df.policy == policy]
        requests = 0
        for trial in expected_trials:
            t = block[block.trial == trial]
            for tick in range(TICKS):
                ticks = t[t.tick == tick]
                if len(ticks) != len(NODES) or set(ticks.node) != set(NODES):
                    raise ValueError(f"Incomplete LIVE eight NF observation {policy}/{trial}/{tick}")
                expected_b = len(NODES) if policy == "full" or tick == 0 else BUDGET
                if int(ticks.kie_queried.sum()) != expected_b:
                    raise ValueError("Policy violated actual signed budget")
                if (ticks.loc[ticks.kie_queried == 1, "kie_valid"] != 1).any():
                    raise ValueError("Unverified or failed HMAC KIE")
                if (ticks.loc[ticks.kie_queried == 0, "kie_valid"] != 0).any():
                    raise ValueError("Query absent but marked authenticated")
                requests += expected_b
                # labels are NEVER policy features. They are verified
                # against the precommitted experiment intervention schedule.
                attack = {e["node"] for e in scenario(seed, trial)
                          if e["family"] != "benign_delay"
                          and e["start"] <= tick < e["end"]}
                for _, row in ticks.iterrows():
                    if row["label"] != int(row["node"] in attack):
                        raise ValueError("Held-out truth schedule was modified")
        if info["sent_authenticated_kie_calls"].get(policy) != requests:
            raise ValueError("Audited signed request counts do not match actual CSV")
        if (block.sba_up != 1).any():
            raise ValueError("Real NF port reachability not maintained")
        epis = []
        for trial in expected_trials:
            t = block[block.trial == trial]
            for event in scenario(seed, trial):
                if event["family"] == "benign_delay":
                    continue
                candidates = t[(t.node == event["node"]) &
                               (t.tick >= event["start"]) & (t.tick < event["end"])]
                first = candidates[(candidates.kie_queried == 1) &
                                   (candidates.kie_gap_full > 0)].tick
                epis.append({
                    "trial": trial, "node": event["node"],
                    "family": event["family"],
                    "start": event["start"], "end": event["end"],
                    "detected": bool(len(first)),
                    "delay_ticks": int(first.min() - event["start"]) if len(first) else None,
                })
        # Last held KIE alarms can extend into recovery: keep real
        # false positives rather than discarding them from reporting.
        positives = block.label == 1
        alarms = block.alarm == 1
        tp = int((positives & alarms).sum())
        fp = int((~positives & alarms).sum())
        fn = int((positives & ~alarms).sum())
        tn = int((~positives & ~alarms).sum())
        count = int(block.kie_queried.sum())
        request_bytes = int(block.signed_request_bytes.sum())
        response_bytes = int(block.signed_response_bytes.sum())
        delays = [e["delay_ticks"] for e in epis if e["detected"]]
        out["policies"][policy] = {
            "ticks": int(TICKS * len(expected_trials)),
            "total_nf_tick_rows": len(block), "actual_signed_queries": count,
            "query_bytes": request_bytes, "response_bytes": response_bytes,
            "per_tick_budget_initial": len(NODES),
            "per_tick_budget_after_initial": len(NODES) if policy == "full" else BUDGET,
            "episode_total": len(epis),
            "episodes_detected": sum(e["detected"] for e in epis),
            "episode_recall": sum(e["detected"] for e in epis) / len(epis),
            "first_alert_delay_ticks_median_detected_only": (
                float(pd.Series(delays).median()) if delays else None),
            "episodes": epis,
            "row_confusion_tp": tp, "row_confusion_fn": fn,
            "row_confusion_fp": fp, "row_confusion_tn": tn,
            "row_recall": tp / (tp + fn) if tp + fn else None,
            "row_fpr": fp / (fp + tn) if fp + tn else None,
        }
    baseline_count = out["policies"]["full"]["actual_signed_queries"]
    for policy in ALL_POLICIES:
        out["policies"][policy]["savings_vs_full"] = (
            1. - out["policies"][policy]["actual_signed_queries"] / baseline_count)
    g = out["policies"]["graph_gru"]
    r = out["policies"]["rotation"]
    nh = out["policies"]["neighbor_heuristic"]
    no = out["policies"]["no_graph_gru"]
    # No post-hoc choice of the "right" baseline: these are all
    # pre-registered. We report whether graph actually wins.
    out["predeclared_success"] = {
        "metric": "heldout_episode_recall at same signed KIE budget and no worse row FPR",
        "threshold": "graph must exceed BOTH rotation and neighbor-heuristic and no-graph ablation by >=0.10 absolute episode recall",
        "satisfied": bool(
            all(g["episode_recall"] >= b["episode_recall"] + .10
                for b in (r, nh, no))
            and all(g["row_fpr"] <= b["row_fpr"]
                    for b in (r, nh, no))
        ),
        "confidence": "Smoke runs are insufficient for statistical significance; report effect, CI across independent deployments later",
    }
    out["important_limits"] = [
        "All agent reports are lab-only counters, NOT native Open5GS NF signaling",
        "Graph-correlated attack propagation is deliberately orchestrated, not naturally spreading malware",
        "Training sparse observations are masks over earlier FULL real KIE (not prospective queries)",
        "No model sees current signed KIE or target labels before making current selection",
        "Only small fixed-topology 8-NF lab, 2 independent test campaigns per policy in smoke",
        "Deterministic counter mismatch remains the alarm; neural model chooses recipients",
        "Matched scenario seeds across independently re-run policies create correlated episodes",
        "Architecture uses an assumed functional graph, not discovered live NF edges",
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(out, indent=2, allow_nan=False))
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/eight_active.csv"))
    p.add_argument("--metadata", type=Path, default=Path("results/eight_active.metadata.json"))
    p.add_argument("--output", type=Path, default=Path("results/eight_active_metrics.json"))
    p.add_argument("--seed", type=int, default=81491)
    a = p.parse_args()
    print(json.dumps(analyze(a.input, a.metadata, a.output, a.seed), indent=2))


if __name__ == "__main__":
    main()
