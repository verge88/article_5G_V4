"""No made-up results: only validate eight-NF causal/label/budget invariants."""
from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from experiment.features import NODES, NEIGHBORS
from experiment.active8_graph import F, W, feat, state_zero, transport_zero, verified_full_samples
from experiment.budget8_campaign import BUDGET, PROVENANCE, TICKS, scenario, rank
from experiment.analyze_budget8 import analyze


def full_fixture(trials: int = 4) -> pd.DataFrame:
    rows = []
    for trial in range(trials):
        plan = scenario(107, trial)
        for tick in range(TICKS):
            attacked = {e["node"] for e in plan
                        if e["family"] != "benign_delay"
                        and e["start"] <= tick < e["end"]}
            for n in NODES:
                rows.append({
                    "trial": trial, "tick": tick, "node": n,
                    "label": int(n in attacked),
                    "kie_gap_full": int(n in attacked),
                    "kie_rtt_ms": 2.+tick,
                    "sba_up": 1, "sba_rtt_ms": 1.+tick,
                    "kie_valid": 1, "provenance": PROVENANCE,
                })
    return pd.DataFrame(rows)


def test_precommitted_cascades_follow_actual_service_graph():
    for trial in range(15):
        epis = scenario(81491, trial)
        assert len(epis) == 5
        for e in epis:
            if e["family"] == "neighbor_followup":
                assert e["node"] in NEIGHBORS[e["cascade_from"]]
                assert e["end"]-e["start"] == 3


def test_each_policy_has_actual_fixed_budget_after_initial():
    s = state_zero()
    for policy in ("rotation", "local_heuristic", "neighbor_heuristic",
                   "graph_gru", "no_graph_gru"):
        assert rank(policy, 0, s, random.Random(0), {n: .5 for n in NODES}) == set(NODES)
        result = rank(policy, 1, s, random.Random(0), {n: .5 for n in NODES})
        assert len(result) == BUDGET


def test_graph_features_prior_only_and_finite():
    x = feat(state_zero(), transport_zero())
    assert x.shape == (len(NODES), F) and np.isfinite(x).all()


def test_masked_history_does_not_see_current_tick_response(tmp_path: Path):
    df = full_fixture()
    p = tmp_path / "full.csv"
    df.to_csv(p, index=False)
    x, y = verified_full_samples(p)[0]
    assert x.shape == (4*TICKS, W, len(NODES), F)
    assert y.shape == (4*TICKS, len(NODES))
    altered = df.copy()
    mask = (altered.trial == 0) & (altered.tick == 12)
    altered.loc[mask, "kie_gap_full"] = 1000
    altered.loc[mask, "kie_rtt_ms"] = 999
    altered.to_csv(p, index=False)
    xx, yy = verified_full_samples(p)[0]
    np.testing.assert_array_equal(x[12], xx[12])
    np.testing.assert_array_equal(y[12], yy[12])
    assert not np.array_equal(x[13], xx[13])


def test_refuse_non_live_or_incomplete_training(tmp_path):
    p = tmp_path / "pilot.csv"
    df = full_fixture()
    df.loc[0, "provenance"] = "SIMULATED"
    df.to_csv(p, index=False)
    with pytest.raises(ValueError, match="genuine prior live"):
        verified_full_samples(p)
    df = full_fixture()
    df = df.drop(index=0)
    df.to_csv(p, index=False)
    with pytest.raises(ValueError, match="Missing or duplicate"):
        verified_full_samples(p)


def metadata(trials=2):
    from experiment.budget8_campaign import ALL_POLICIES
    return {
        "provenance": PROVENANCE, "trials": trials,
        "policy_order": list(ALL_POLICIES),
        "sent_authenticated_kie_calls": {
            p: trials*(8 if p=="full" else 8) + (TICKS-1)*trials*(8 if p=="full" else 2)
            for p in ALL_POLICIES},
    }


def test_fail_closed_if_no_real_signed_messages(tmp_path):
    from experiment.budget8_campaign import ALL_POLICIES
    source = tmp_path / "active.csv"
    md = tmp_path / "active.metadata.json"
    md.write_text(json.dumps(metadata()))
    rows = []
    for policy in ALL_POLICIES:
        for trial in range(2):
            plan = scenario(81491, trial)
            for tick in range(TICKS):
                sampled = set(NODES) if policy == "full" or tick == 0 else set(
                    NODES[(tick*2+i)%8] for i in range(2))
                attacked = {e["node"] for e in plan
                            if e["family"] != "benign_delay"
                            and e["start"] <= tick < e["end"]}
                for n in NODES:
                    rows.append({
                        "trial": trial, "policy": policy, "tick": tick, "node": n,
                        "label": int(n in attacked), "kie_queried": int(n in sampled),
                        "kie_valid": int(n in sampled), "kie_gap_full": int(n in attacked)
                        if n in sampled else np.nan,
                        "sba_up": 1, "sba_rtt_ms": 1.,
                        "signed_request_bytes": 200*int(n in sampled),
                        "signed_response_bytes": 200*int(n in sampled),
                        "alarm": int(n in attacked and n in sampled),
                        "provenance": PROVENANCE,
                    })
    df = pd.DataFrame(rows)
    df.to_csv(source, index=False)
    summary = analyze(source, md, tmp_path / "scores.json")
    assert summary["policies"]["rotation"]["actual_signed_queries"] == 156
    assert summary["policies"]["full"]["actual_signed_queries"] == 576
    # Fixture exists ONLY inside unit test. Tampering with one HMAC must
    # abort the experiment summary instead of being silently ignored.
    df.loc[df.kie_queried.eq(1).idxmax(), "kie_valid"] = 0
    df.to_csv(source, index=False)
    with pytest.raises(ValueError, match="Unverified"):
        analyze(source, md, tmp_path / "scores.json")
