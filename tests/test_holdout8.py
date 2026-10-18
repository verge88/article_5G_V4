"""Phase10 fixtures validate provenance/causal protocol ONLY, not attack evidence."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from experiment.holdout8_scenarios import (
    SEEDS, FAMILIES, POSITIVE, POLICIES, TICKS, TRIALS, scenario_for
)
from experiment.features import NODES, NEIGHBORS
from experiment.budget8_campaign import PROVENANCE
from experiment.eval_holdout8 import score, source_paths


def test_all_future_seeds_different_and_scenarios_reproducible():
    assert len(set(SEEDS.values())) == len(SEEDS)
    assert set(SEEDS.values()).isdisjoint({107, 81491})
    for family in FAMILIES:
        for trial in range(TRIALS):
            plan = scenario_for(family, SEEDS[family], trial)
            assert plan == scenario_for(family, SEEDS[family], trial)
            assert len([x for x in plan if x["family"] != "benign_delay"]) == (0 if family == "benign_only" else 4)
            for e in plan:
                assert 0 <= e["start"] < e["end"] <= TICKS
                if e["family"] == "NON_NEIGHBOR_followup":
                    assert e["node"] not in NEIGHBORS[e["cascade_from"]]
                if e["family"] == "neighbor_followup_shifted":
                    assert e["node"] in NEIGHBORS[e["cascade_from"]]
    with pytest.raises(ValueError, match="Unregistered"):
        scenario_for("off_graph", 81491, 0)
    with pytest.raises(ValueError, match="range"):
        scenario_for("off_graph", SEEDS["off_graph"], TRIALS)


def fake_archives(folder: Path):
    """NO network traffic; internal smoke fixture must never be published."""
    (folder / "eight_bayes_frozen.json").write_text(json.dumps({
        "kind": "PRIOR_REAL_SIGNED_FULL_KIE_BAYESIAN_2STATE_V1",
        "fit_trials": [0, 1, 2, 3, 4], "validation_trial": 5}))
    (folder / "eight_scheduler-graph_gru.pt").write_bytes(b"UNIT TEST FAKE WEIGHTS")
    (folder / "eight_scheduler-no_graph_gru.pt").write_bytes(b"UNIT TEST FAKE WEIGHTS")
    for family, seed in SEEDS.items():
        rows = []
        interventions = []
        requests = {p: 0 for p in POLICIES}
        for p in POLICIES:
            for trial in range(TRIALS):
                plan = scenario_for(family, seed, trial)
                interventions.append({"policy": p, "trial": trial,
                                      "predeclared_agent_counter_modes": plan})
                for tick in range(TICKS):
                    selected = set(NODES) if tick == 0 or p == "full" else {
                        NODES[(2*tick+i) % len(NODES)] for i in range(2)}
                    active = {x["node"] for x in plan if
                              x["family"] != "benign_delay"
                              and x["start"] <= tick < x["end"]}
                    requests[p] += len(selected)
                    for n in NODES:
                        q = int(n in selected)
                        rows.append({
                            "trial": trial, "policy": p, "tick": tick,
                            "node": n, "label": int(n in active),
                            "kie_queried": q, "kie_valid": q,
                            "kie_gap_full": int(n in active) if q else None,
                            "kie_rtt_ms": 1. if q else None,
                            "sba_up": 1, "sba_rtt_ms": 1.,
                            "signed_request_bytes": 200*q,
                            "signed_response_bytes": 230*q,
                            "risk_before": None, "alarm": int(n in active and q),
                            "provenance": PROVENANCE,
                        })
        data, metadata = source_paths(folder, family)
        pd.DataFrame(rows).to_csv(data, index=False)
        metadata.write_text(json.dumps({
            "scenario_family": family, "scenario_seed": seed,
            "trials": TRIALS, "policy_order": list(POLICIES),
            "provenance": PROVENANCE, "interventions": interventions,
            "sent_authenticated_kie_calls": requests,
        }))


def test_full_ood_analyzer_and_benign_clean_controls(tmp_path: Path):
    fake_archives(tmp_path)
    report = score(tmp_path, tmp_path / "recomputed.json")
    assert report["experiment"] == "PHASE10_PREDECLARED_UNSEEN_STAGED_AGENT_FAULT_FAMILIES"
    assert set(report["family_results"]) == set(FAMILIES)
    assert report["aggregated"]["bayes_pomdp"]["signed_queries"] == 4*156
    assert report["aggregated"]["full"]["signed_queries"] == 4*576
    assert report["aggregated"]["bayes_pomdp"]["episodes"] == 24
    assert report["family_results"]["benign_only"]["bayes_pomdp"]["episode_recall"] is None
    assert "pass" in report["predeclared_generalization_gate"]


@pytest.mark.parametrize("corrupt", ["wrong_family_seed", "missing_nf", "wrong_budget",
                                      "invalid_hmac", "fake_missing_answer",
                                      "wrong_label", "missing_byte_evidence",
                                      "modified_intervention_plan"])
def test_scorer_fails_closed_on_source_tampering(tmp_path: Path, corrupt: str):
    fake_archives(tmp_path)
    data_path, meta_path = source_paths(tmp_path, "off_graph")
    if corrupt in ("wrong_family_seed", "modified_intervention_plan"):
        meta = json.loads(meta_path.read_text())
        if corrupt == "wrong_family_seed":
            meta["scenario_seed"] = 81491
        else:
            meta["interventions"][0]["predeclared_agent_counter_modes"] = []
        meta_path.write_text(json.dumps(meta))
    else:
        df = pd.read_csv(data_path)
        if corrupt == "missing_nf":
            df = df.drop(index=[0])
        elif corrupt == "wrong_budget":
            k = df.index[(df.policy == "rotation") & (df.trial == 0)
                         & (df.tick == 1) & (df.kie_queried == 1)][0]
            df.loc[k, "kie_queried"] = 0
        elif corrupt == "invalid_hmac":
            df.loc[0, "kie_valid"] = 0
        elif corrupt == "fake_missing_answer":
            i = df.index[df.kie_queried == 0][0]
            df.loc[i, "kie_gap_full"] = 1.
        elif corrupt == "wrong_label":
            df.loc[0, "label"] = 1
        elif corrupt == "missing_byte_evidence":
            df.loc[0, "signed_request_bytes"] = 0
        df.to_csv(data_path, index=False)
    with pytest.raises(ValueError):
        score(tmp_path, tmp_path / "recomputed.json")
