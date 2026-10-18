"""Honest comparison of ACTUALLY SENT signed KIE queries across live policies."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from experiment.secure_collect import SIGNERS


def wilson(success: int, total: int, z: float = 1.96) -> list[float] | None:
    if total == 0:
        return None
    p = success / total
    den = 1 + z * z / total
    center = (p + z * z / (2 * total)) / den
    margin = z * ((p * (1 - p) + z * z / (4 * total)) / total) ** 0.5 / den
    return [max(0, center - margin), min(1, center + margin)]


def summarize(path: Path, destination: Path) -> dict:
    raw = pd.read_csv(path)
    required = {
        "policy", "trial", "tick", "phase", "node", "label", "alarm",
        "kie_queried", "kie_valid", "kie_gap_new", "kie_age_ticks",
        "kie_request_bytes", "kie_response_bytes", "probe_kind", "attack_target",
    }
    if missing := required - set(raw.columns):
        raise ValueError(f"Required fields missing: {sorted(missing)}")
    if set(raw["probe_kind"].unique()) != {"LIVE_SIGNED_AGENT_HTTP11_AND_SBA_HTTP2"}:
        raise ValueError("Refusing any non-live probe or mixed-simulation data")
    observed_policies = set(raw["policy"].unique())
    normal = {"full", "rotation", "ml_adaptive"}
    if observed_policies not in (normal, normal | {"gnn_guided"}):
        raise ValueError("Live control policies missing or invalid")
    if raw.duplicated(["policy", "trial", "tick", "node"]).any():
        raise ValueError("Repeated row in full observation grid")
    for (_, _, _), tick in raw.groupby(["policy", "trial", "tick"], sort=False):
        if len(tick) != 8:
            raise ValueError("Incomplete eight-NF observation tick")
        signed = tick[tick["node"].isin(SIGNERS)]
        count = int(signed["kie_queried"].sum())
        policy = tick["policy"].iloc[0]
        expected = 2 if policy == "full" or int(tick["tick"].iloc[0]) == 0 else 1
        if count != expected:
            raise ValueError(f"Policy violated actual KIE budget {policy}: {count}")
        if (signed["kie_valid"] != signed["kie_queried"]).any():
            raise ValueError("Missing or invalid signature on sent challenge")
        if int(tick.loc[~tick["node"].isin(SIGNERS), "kie_queried"].sum()):
            raise ValueError("Unsigned NF incorrectly counted as signed KIE")
    out = {
        "source": str(path),
        "evidence": "ACTUALLY_TRANSMITTED_AUTHENTICATED_KIE_OVER_LIVE_TEST_AGENT_HTTP11",
        "scope": "Only two NF-colocated lab agents; stock 5G Core remains unmodified",
        "signers": SIGNERS,
        "decision_rule": "latest cryptographically verified independent/claimed challenge count discrepancy > 0",
        "policies": {},
    }
    comparison = []
    for policy, data in raw.groupby("policy", sort=True):
        signed = data[data["node"].isin(SIGNERS)].copy()
        ticks = len(data) // 8
        requests = int(signed["kie_queried"].sum())
        active_rows = signed[signed["label"] == 1]
        negatives = signed[signed["label"] == 0]
        tp = int(((signed["label"] == 1) & (signed["alarm"] == 1)).sum())
        fn = int(((signed["label"] == 1) & (signed["alarm"] == 0)).sum())
        fp = int(((signed["label"] == 0) & (signed["alarm"] == 1)).sum())
        tn = int(((signed["label"] == 0) & (signed["alarm"] == 0)).sum())
        episodes = []
        for (trial, node), s in active_rows.groupby(["trial", "node"]):
            s = s.sort_values("tick")
            alarms = s[s["alarm"] == 1]
            first = int(s.iloc[0]["tick"])
            delay = int(alarms.iloc[0]["tick"]) - first if len(alarms) else None
            episodes.append({
                "trial": int(trial), "target": node,
                "detected": bool(len(alarms)), "first_alert_delay_ticks": delay,
            })
        detected = sum(e["detected"] for e in episodes)
        lat = [e["first_alert_delay_ticks"] for e in episodes if e["detected"]]
        benign_delay = signed[signed["phase"] == "benign_delay"]
        honest_latency_false = int(benign_delay["alarm"].sum())
        control = {
            "trials": int(data["trial"].nunique()),
            "ticks": ticks, "signed_kie_calls": requests,
            "signed_kie_per_tick": requests / ticks,
            "signed_kie_fraction_of_full": requests / (2 * ticks),
            "estimated_signed_application_bytes": int(
                signed["kie_request_bytes"].sum() + signed["kie_response_bytes"].sum()),
            "normal_rows": len(negatives), "attack_rows": len(active_rows),
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": tp / (tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall_wilson95": wilson(tp, tp + fn),
            "fpr_wilson95": wilson(fp, fp + tn),
            "detected_episodes": detected, "attack_episodes": len(episodes),
            "episode_recall": detected / len(episodes) if episodes else None,
            "episode_recall_wilson95": wilson(detected, len(episodes)),
            "median_first_alert_ticks_detected_only": float(np.median(lat))
            if lat else None,
            "missed_episodes": len(episodes) - detected,
            "benign_delay_rows": len(benign_delay),
            "benign_delay_false_alarms": honest_latency_false,
            "episodes": episodes,
        }
        out["policies"][policy] = control
        comparison.append({"policy": policy, **{k: v for k, v in control.items()
                                                if not isinstance(v, (list, dict))}})
    full_queries = out["policies"]["full"]["signed_kie_per_tick"]
    for name in sorted(observed_policies - {"full"}):
        out["policies"][name]["relative_signed_query_savings"] = (
            1 - out["policies"][name]["signed_kie_per_tick"] / full_queries)
    out["limitations"] = [
        "Budget is measured for 2 signed test agents, NOT total 5G control-plane traffic",
        "All 8 NF SBA reachability HTTP2 probes continue every tick and are not included in KIE cost",
        "GNN and IsolationForest only rank recipients; binary alarms use independent signed counts",
        "Different policies have independently timed interventions, not synchronized paired trials",
        "Intervention is a synthetic dishonest test agent, not compromised Open5GS SMF/NRF",
        "Benign delay and counter-only spoof reduce but do not eliminate dataset shortcuts",
        "Small number of independent attack episodes does not support statistical superiority",
    ]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(out, indent=2, allow_nan=False), encoding="utf8")
    pd.DataFrame(comparison).to_csv(destination.with_suffix(".csv"), index=False)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/adaptive_signed.csv"))
    p.add_argument("--output", type=Path, default=Path("results/adaptive_signed_metrics.json"))
    a = p.parse_args()
    data = summarize(a.input, a.output)
    print(json.dumps({k: {
        "query_count": v["signed_kie_calls"],
        "episodes_detected": v["detected_episodes"],
        "episodes_total": v["attack_episodes"],
        "false_positives": v["fp"], "median_delay": v["median_first_alert_ticks_detected_only"],
    } for k, v in data["policies"].items()}, indent=2))


if __name__ == "__main__":
    main()
