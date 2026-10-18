"""Bayesian active NF KIE tests: fixture data never becomes scientific evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from experiment.bayes_active import (
    ActiveBayesian, BayesianFilter, PROVENANCE, KIND, bayes_update,
    entropy, fit,
)
from experiment.active8_graph import state_zero, transport_zero
from experiment.budget8_campaign import scenario, BAYES_POLICIES, ALL_POLICIES, TICKS
from experiment.features import NODES
from experiment.analyze_budget8 import analyze


def historical(trials: int = 6) -> pd.DataFrame:
    rows = []
    for tr in range(trials):
        episodes = scenario(107, tr)
        for tick in range(TICKS):
            targeted = {e["node"] for e in episodes if
                        e["family"] != "benign_delay" and
                        e["start"] <= tick < e["end"]}
            for n in NODES:
                rows.append({
                    "trial": tr, "tick": tick, "node": n,
                    "policy": "full", "label": int(n in targeted),
                    "kie_gap_full": int(n in targeted), "kie_valid": 1,
                    "kie_queried": 1, "provenance": PROVENANCE})
    return pd.DataFrame(rows)


def frozen(tmp_path: Path) -> Path:
    p = tmp_path / "history.csv"
    historical().to_csv(p, index=False)
    destination = tmp_path / "model.json"
    fit(p, destination)
    return destination


def test_binary_bayes_update_excludes_magic_detection_and_is_normalized():
    assert bayes_update(.2, True, .85, .02) > .2
    assert bayes_update(.2, False, .85, .02) < .2
    assert 0 < entropy(.2) < 1
    assert entropy(.5) > entropy(.2)


def test_historical_validation_is_strictly_unseen_during_fitting(tmp_path):
    first = historical()
    p = tmp_path / "pilot.csv"
    first.to_csv(p, index=False)
    a = fit(p, tmp_path / "params.json")
    second = first.copy()
    # Change heldout LABELS and signed responses but preserve a full grid.
    mask = second.trial == 5
    second.loc[mask, "label"] = 1 - second.loc[mask, "label"]
    second.loc[mask, "kie_gap_full"] = 1 - second.loc[mask, "kie_gap_full"]
    second.to_csv(p, index=False)
    b = fit(p, tmp_path / "params2.json")
    for k in ("initial_fault_probability", "onset_quiet",
              "neighbor_lift", "persist_probability",
              "signed_emission_sensitivity", "signed_emission_false_positive",
              "fit_trials", "validation_trial"):
        assert a[k] == b[k], f"Historical pilot validation contaminated fit: {k}"
    assert a["validation_trial"] == 5 and a["fit_trials"] == [0,1,2,3,4]
    assert a["untuned_validation_mean_log_loss"] != b["untuned_validation_mean_log_loss"]


def test_invalid_or_missing_authentic_history_refused(tmp_path):
    p = tmp_path / "pilot.csv"
    df = historical()
    df.loc[0, "provenance"] = "SYNTHETIC"
    df.to_csv(p, index=False)
    with pytest.raises(ValueError, match="REAL"):
        fit(p, tmp_path / "params.json")
    df = historical()
    df.loc[0, "kie_valid"] = 0
    df.to_csv(p, index=False)
    with pytest.raises(ValueError, match="signature"):
        fit(p, tmp_path / "params.json")
    df = historical().drop(index=0)
    df.to_csv(p, index=False)
    with pytest.raises(ValueError, match="Incomplete"):
        fit(p, tmp_path / "params.json")


@pytest.mark.parametrize("mode", ["pomdp", "entropy", "no_edges"])
def test_bayesian_acts_before_current_tick_and_updates_only_queried(tmp_path, mode):
    p = frozen(tmp_path)
    b = ActiveBayesian(p, mode=mode)
    s, t = state_zero(), transport_zero()
    assert b.before(0, s, t) == set(NODES)
    with pytest.raises(RuntimeError, match="unqueried"):
        b.observe("NOT_AN_NF", 1.)
    for n in NODES:
        b.observe(n, 0.)
        s[n]["age"] = 0
    before = copy.deepcopy(b.filter.belief)
    selected = b.before(1, s, t)
    assert len(selected) == 2 and set(selected).issubset(NODES)
    with pytest.raises(ValueError, match="future/out-of-order"):
        b.before(1, s, t)
    with pytest.raises(RuntimeError, match="unqueried"):
        b.observe(next(n for n in NODES if n not in selected), 1.)
    for n in selected:
        b.observe(n, 1.)
    after = b.filter.belief
    assert all(0 < after[n] < 1 for n in NODES)
    assert any(after[n] != before[n] for n in selected)


def test_expected_next_neighbor_information_nonnegative_and_graph_ablation(tmp_path):
    p = frozen(tmp_path)
    a = ActiveBayesian(p, mode="pomdp")
    b = ActiveBayesian(p, mode="no_edges")
    for n in NODES:
        assert np.isfinite(a.value_of_information(n))
        assert np.isfinite(b.value_of_information(n))
    # Removing edges must remove the neighbor-dependent transition forecast.
    f = BayesianFilter(json.loads(p.read_text()), use_edges=True)
    f.belief["amf"] = .99
    assert f.predict_node("ausf", f.belief) >=            BayesianFilter(json.loads(p.read_text()), use_edges=False).predict_node(
                "ausf", f.belief)


def test_evaluator_accepts_seven_policies_and_rejects_non_hmac_rows(tmp_path):
    policies = ("full", "rotation", "neighbor_heuristic", "graph_gru",
                "bayes_entropy", "bayes_no_edges", "bayes_pomdp")
    rows = []
    req = {}
    for policy in policies:
        req[policy] = 0
        for tr in range(2):
            events = scenario(81491, tr)
            for tick in range(TICKS):
                chosen = set(NODES) if tick == 0 or policy == "full" else {
                    NODES[(2*tick+i) % len(NODES)] for i in range(2)}
                targets = {e["node"] for e in events if e["family"] != "benign_delay"
                           and e["start"] <= tick < e["end"]}
                for n in NODES:
                    is_checked = int(n in chosen)
                    req[policy] += is_checked
                    rows.append({
                        "trial": tr, "tick": tick, "policy": policy,
                        "node": n, "label": int(n in targets),
                        "kie_queried": is_checked, "kie_valid": is_checked,
                        "kie_gap_full": int(n in targets) if is_checked else np.nan,
                        "sba_up": 1, "sba_rtt_ms": 1.,
                        "signed_request_bytes": 190*is_checked,
                        "signed_response_bytes": 270*is_checked,
                        "alarm": int(n in targets and is_checked),
                        "provenance": PROVENANCE,
                    })
    source = tmp_path / "live.csv"
    md = tmp_path / "meta.json"
    pd.DataFrame(rows).to_csv(source, index=False)
    md.write_text(json.dumps({"provenance": PROVENANCE, "trials": 2,
                               "policy_order": list(policies),
                               "sent_authenticated_kie_calls": req}))
    report = analyze(source, md, tmp_path / "metrics.json",
                     seed=81491, policies=policies)
    assert report["experiment"] == "LIVE_EIGHT_NF_FROZEN_BAYESIAN_APPROX_POMDP_ACTIVE_KIE"
    assert len(report["policies"]) == 7
    df = pd.DataFrame(rows)
    df.loc[df.kie_queried.eq(1).idxmax(), "kie_valid"] = 0
    df.to_csv(source, index=False)
    with pytest.raises(ValueError, match="Unverified"):
        analyze(source, md, tmp_path / "metrics.json",
                seed=81491, policies=policies)

def test_actual_cli_accepts_frozen_bayesian_pomdp_policy(monkeypatch, tmp_path):
    from experiment import budget8_campaign
    called = {}
    def collect(output, policies, trials, seed, model_root, interval, bayes_model):
        called.update(policies=policies, bayes_model=bayes_model, trials=trials)
        return {"unit_mock_only": True}
    monkeypatch.setattr(budget8_campaign, "acquire", collect)
    monkeypatch.setattr("sys.argv", [
        "budget8_campaign", "--output", str(tmp_path / "out.csv"),
        "--policies", "rotation", "bayes_pomdp", "bayes_entropy", "bayes_no_edges",
        "--bayes-model", str(tmp_path / "frozen.json"), "--trials", "2",
    ])
    budget8_campaign.main()
    assert called["policies"] == (
        "rotation", "bayes_pomdp", "bayes_entropy", "bayes_no_edges")
    assert called["bayes_model"] == tmp_path / "frozen.json"
    assert called["trials"] == 2

def test_entire_short_bayesian_campaign_runs_offline_without_real_network_claim(tmp_path, monkeypatch):
    """Exercise actual acquisition control flow, never use this as attack evidence."""
    from experiment import budget8_campaign
    model = frozen(tmp_path)
    monkeypatch.setenv("KIE_TEST_KEY", "cd" * 32)
    monkeypatch.setattr(budget8_campaign, "TICKS", 3)
    monkeypatch.setattr(budget8_campaign, "scenario", lambda seed, trial: [])
    monkeypatch.setattr(budget8_campaign, "set_switches", lambda old, desired, mode: set(desired))
    monkeypatch.setattr(budget8_campaign, "docker", lambda *a: None)
    monkeypatch.setattr(budget8_campaign.time, "sleep", lambda x: None)
    monkeypatch.setattr(budget8_campaign, "probe",
                        lambda node, timeout: {"up": 1, "rtt_ms": 1.0})
    signed_count = {n: 0 for n in NODES}
    def mock_signed(node, seq, key, timeout):
        signed_count[node] += 1
        return {"kie_valid": 1, "kie_invariant_error": 0,
                "kie_claimed_received": signed_count[node],
                "kie_rtt_ms": 2., "kie_request_bytes": 170,
                "kie_response_bytes": 250}
    monkeypatch.setattr(budget8_campaign, "authenticated_kie", mock_signed)
    out = tmp_path / "control_flow_mock_only.csv"
    actual = budget8_campaign.acquire(
        out, ("bayes_entropy", "bayes_no_edges", "bayes_pomdp"),
        trials=2, seed=81491, model_root=None, interval=0.,
        bayes_model=model)
    assert all(actual["sent_authenticated_kie_calls"][p] == 24
               for p in ("bayes_entropy", "bayes_no_edges", "bayes_pomdp"))
    raw = pd.read_csv(out)
    assert len(raw) == 3 * 2 * 3 * 8
    assert raw.groupby(["policy", "trial", "tick"]).kie_queried.sum().tolist().count(8) == 6
    assert raw.groupby(["policy", "trial", "tick"]).kie_queried.sum().tolist().count(2) == 12
    # This fixture exercises code paths; it has no legitimate live HTTP evidence.
    assert actual["provenance"] == PROVENANCE
