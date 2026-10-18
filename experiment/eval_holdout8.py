"""Fail-closed evaluation of unretuned Phase10 live NF-colocated signer cohorts.

Only real, prospectively captured HMAC KIE rows from pinned Open5GS
test lab qualify. Fixtures used in unit tests have NO scientific status.
Unseen family/seeds were specified BEFORE CI starts, no test-set tuning.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from experiment.active8_graph import BUDGET
from experiment.budget8_campaign import PROVENANCE
from experiment.features import NODES
from experiment.holdout8_scenarios import (
    FAMILIES, POSITIVE, POLICIES, SEEDS, TICKS, TRIALS, scenario_for,
)


def source_paths(folder: Path, family: str) -> tuple[Path, Path]:
    stem = folder / f"eight_ood_{family}"
    return stem.with_suffix(".csv"), folder / f"eight_ood_{family}.metadata.json"


def score(folder: Path, out: Path) -> dict:
    if not (folder / "eight_bayes_frozen.json").is_file():
        raise ValueError("Historical frozen Bayesian model missing")
    bayes = json.loads((folder / "eight_bayes_frozen.json").read_text())
    if (bayes.get("kind") != "PRIOR_REAL_SIGNED_FULL_KIE_BAYESIAN_2STATE_V1"
        or bayes.get("fit_trials") != [0, 1, 2, 3, 4]
        or bayes.get("validation_trial") != 5):
        raise ValueError("Previously frozen prior-only Bayesian calibration missing")
    files = ("eight_bayes_frozen.json",
             "eight_scheduler-graph_gru.pt",
             "eight_scheduler-no_graph_gru.pt")
    for name in files:
        if not (folder / name).is_file():
            raise ValueError(f"Frozen pretrained source checkpoint missing: {name}")
    hashes = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
              for name in files}
    output = {
        "experiment": "PHASE10_PREDECLARED_UNSEEN_STAGED_AGENT_FAULT_FAMILIES",
        "true_nf_compromises": 0, "raw_packet_origin": PROVENANCE,
        "data_type": "real signed HTTP1.1 agent challenges + actual Open5GS HTTP2 listener probes",
        "native_nf_counters": False,
        "frozen_model_sha256": hashes,
        "family_results": {}, "aggregated": {},
    }
    across = {p: {"episodes": [], "truth": [], "alerts": [], "bytes": 0,
                  "queries": 0, "positive_episode_total": 0,
                  "benign_delayed_scheduled": 0,
                  "benign_delayed_signed_seen": 0}
              for p in POLICIES}
    for family in FAMILIES:
        csv_path, meta_path = source_paths(folder, family)
        if not csv_path.is_file() or not meta_path.is_file():
            raise ValueError(f"Missing prospective real HMAC data for {family}")
        data = pd.read_csv(csv_path)
        meta = json.loads(meta_path.read_text())
        if (meta.get("scenario_family") != family
            or meta.get("scenario_seed") != SEEDS[family]
            or meta.get("trials") != TRIALS
            or set(meta.get("policy_order", [])) != set(POLICIES)
            or meta.get("provenance") != PROVENANCE):
            raise ValueError("Not a complete preregistered fresh-seed 8NF campaign")
        if set(data.provenance.unique()) != {PROVENANCE} or set(data.policy.unique()) != set(POLICIES):
            raise ValueError("Missing actual signed 8NF policy provenance")
        required = {"policy", "trial", "tick", "node", "label",
                    "kie_queried", "kie_valid", "kie_gap_full",
                    "kie_rtt_ms", "sba_up", "sba_rtt_ms",
                    "signed_request_bytes", "signed_response_bytes",
                    "risk_before", "alarm", "provenance"}
        if required - set(data):
            raise ValueError("Missing required per-node packet/budget columns")
        if set(data.trial.unique()) != set(range(TRIALS)):
            raise ValueError("Missing independent acquisition trial")
        expected_events = {
            (p, tr): scenario_for(family, SEEDS[family], tr)
            for p in POLICIES for tr in range(TRIALS)
        }
        audit = {(x["policy"], x["trial"]): x["predeclared_agent_counter_modes"]
                 for x in meta.get("interventions", [])}
        if audit != expected_events:
            raise ValueError("Attack labels/intervention plan not equal to frozen scenario generator")
        family_out = {}
        for p in POLICIES:
            frame = data[data.policy == p]
            results = across[p]
            total_queries = 0
            event_out = []
            for tr in range(TRIALS):
                tdf = frame[frame.trial == tr]
                planned = expected_events[p, tr]
                for tick in range(TICKS):
                    block = tdf[tdf.tick == tick]
                    if len(block) != len(NODES) or set(block.node) != set(NODES):
                        raise ValueError(f"Missing or duplicated 8NF grid {family}/{p}/{tr}/{tick}")
                    expected_budget = len(NODES) if p == "full" or tick == 0 else BUDGET
                    queries = int(block.kie_queried.sum())
                    if queries != expected_budget:
                        raise ValueError("Unequal actual challenge budget")
                    total_queries += queries
                    checked = block[block.kie_queried == 1]
                    absent = block[block.kie_queried == 0]
                    if (checked.kie_valid != 1).any() or checked.kie_gap_full.isna().any():
                        raise ValueError("Unverified/missing actual HMAC count gap")
                    if (checked.signed_request_bytes <= 0).any() or (checked.signed_response_bytes <= 0).any():
                        raise ValueError("Missing actual signed request/response byte evidence")
                    if (absent.kie_valid != 0).any() or absent.kie_gap_full.notna().any():
                        raise ValueError("Forged information for unqueried NF")
                    if (absent.signed_request_bytes != 0).any() or (absent.signed_response_bytes != 0).any():
                        raise ValueError("Unsent NF reported HMAC traffic")
                    if (block.sba_up != 1).any():
                        raise ValueError("Open5GS transport outage confounds constant-availability experiment")
                    active = {e["node"] for e in planned
                              if e["family"] != "benign_delay" and e["start"] <= tick < e["end"]}
                    for row in block.itertuples():
                        if row.label != int(row.node in active):
                            raise ValueError("Ground-truth NF label differs from frozen interventions")
                        if row.alarm not in (0, 1):
                            raise ValueError("Invalid laboratory signer alarm")
                        results["truth"].append(int(row.label))
                        results["alerts"].append(int(row.alarm))
                    benign = {e["node"] for e in planned
                              if e["family"] == "benign_delay" and e["start"] <= tick < e["end"]}
                    results["benign_delayed_scheduled"] += len(benign)
                    results["benign_delayed_signed_seen"] += int(
                        ((checked.node.isin(benign)) & (checked.kie_rtt_ms >= 60)).sum())
                for e in planned:
                    if e["family"] == "benign_delay":
                        continue
                    part = tdf[(tdf.node == e["node"]) &
                               (tdf.tick >= e["start"]) &
                               (tdf.tick < e["end"])]
                    triggers = part[(part.kie_queried == 1) & (part.kie_gap_full > 0)]
                    delay = (int(triggers.tick.min()) - e["start"]) if len(triggers) else None
                    event_out.append({
                        "family": family, "trial": tr,
                        "event": e["family"], "node": e["node"],
                        "start": e["start"], "duration": e["end"]-e["start"],
                        "detected": delay is not None,
                        "first_delay": delay,
                        "censored_detection_delay": (
                            delay if delay is not None else e["end"]-e["start"])
                    })
            expected_total = TRIALS*(len(NODES) + (TICKS-1) *
                                     (len(NODES) if p == "full" else BUDGET))
            if (total_queries != expected_total or
                meta["sent_authenticated_kie_calls"].get(p) != total_queries or
                int(frame.kie_queried.sum()) != total_queries):
                raise ValueError("Campaign signer request audit contradicts HMAC rows")
            results["queries"] += total_queries
            results["bytes"] += int(frame.signed_request_bytes.sum() +
                                     frame.signed_response_bytes.sum())
            results["episodes"].extend(event_out)
            tp = sum(x["detected"] for x in event_out)
            family_out[p] = {
                "signed_kie": total_queries,
                "episodes": len(event_out),
                "episodes_detected": tp,
                "episode_recall": (tp / len(event_out) if event_out else None),
                "nf_tick_false_alarms": int(((frame.label == 0) & (frame.alarm == 1)).sum()),
                "nf_tick_false_positive_rate": float(
                    ((frame.label == 0) & (frame.alarm == 1)).sum() /
                    max(1, (frame.label == 0).sum())),
                "each_event": event_out,
            }
        output["family_results"][family] = family_out
    for p in POLICIES:
        obj = across[p]
        truth, alerts, events = obj["truth"], obj["alerts"], obj["episodes"]
        tp = sum(a and b for a, b in zip(truth, alerts))
        fp = sum(a and not b for a, b in zip(alerts, truth))
        fn = sum((not a) and b for a, b in zip(alerts, truth))
        tn = sum((not a) and (not b) for a, b in zip(alerts, truth))
        detected = sum(x["detected"] for x in events)
        output["aggregated"][p] = {
            "episodes": len(events), "episodes_detected": detected,
            "episode_recall": detected/len(events) if events else None,
            "TP_nf_ticks": tp, "FP_nf_ticks": fp,
            "FN_nf_ticks": fn, "TN_nf_ticks": tn,
            "row_recall": tp/(tp+fn) if tp+fn else None,
            "row_fpr": fp/(fp+tn) if fp+tn else None,
            "signed_queries": obj["queries"],
            "signed_application_bytes": obj["bytes"],
            "all_detected_median_delay_only": (
                float(pd.Series([x["first_delay"] for x in events
                                 if x["detected"]]).median())
                if detected else None),
            "censored_mean_delay_all_episodes": (
                sum(x["censored_detection_delay"] for x in events) / len(events)
                if events else None),
            "benign_window_signed_delay_samples_seen": obj["benign_delayed_signed_seen"],
            "meets_predeclared_row_fpr_1pct": (
                fp/(fp+tn) <= .01 if fp+tn else False),
        }
    p = output["aggregated"]["bayes_pomdp"]
    controls = {c: output["aggregated"][c] for c in POLICIES
                if c not in ("full", "bayes_pomdp")}
    positive_family_best = {
        fam: max(output["family_results"][fam][c]["episode_recall"]
                 for c in controls) for fam in POSITIVE
    }
    gate = {
        "registered_before_test": True,
        "metric": "All 3 unseen positive families, same signed KIE; macro episode detection recall and measured NF-tick FPR",
        "required": "POMDP absolute aggregate episode recall >= best of ALL 5 constrained policies +0.10, NF-tick FPR <=1%, and no unseen positive family worse than its best competing policy by >0.10",
        "threshold_pp": 10,
        "pass": bool(
            p["episode_recall"] >= max(x["episode_recall"] for x in controls.values()) + .10
            and p["row_fpr"] <= .01
            and all(output["family_results"][fam]["bayes_pomdp"]["episode_recall"] >=
                    positive_family_best[fam] - .10 for fam in POSITIVE)
        ),
    }
    output["predeclared_generalization_gate"] = gate
    output["caveats"] = [
        "The three new intervention families are controlled TEST SIGNER dishonesty, not native NF exploits",
        "Scenarios were registered by seed/family before this CI; test model and utility unchanged",
        "Same chosen family/trial seeds repeat across separate GitHub runners; count clusters, not independent NF-tick rows",
        "Benign-only has zero positive episodes, so recall there is undefined",
        "A low false-positive fraction from correlated alarm-hold rows is NOT a calibrated 1% population guarantee",
        "No threshold optimization at matched FPR has been performed; one fixed detector per policy is compared",
        "All NF HTTP2 reachability probes continue; 2/8 savings apply only to signed KIE",
        "No native Open5GS event attestation, no real NF compromise, no unknown software attack family",
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2, allow_nan=False), encoding="utf8")
    print(json.dumps({p: {k: v for k, v in output["aggregated"][p].items()
                          if k in ("episodes", "episodes_detected", "episode_recall",
                                   "FP_nf_ticks", "row_fpr", "signed_queries",
                                   "censored_mean_delay_all_episodes")}
                      for p in POLICIES}, indent=2))
    print(json.dumps(gate, indent=2))
    return output


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--folder", type=Path, default=Path("results"))
    p.add_argument("--output", type=Path, default=Path("results/eight_ood_generalization_metrics.json"))
    args = p.parse_args()
    score(args.folder, args.output)


if __name__ == "__main__":
    main()
