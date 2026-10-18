from __future__ import annotations

import numpy as np
import pandas as pd

from experiment.features import NODES, FULL, enrich, online_vector
from experiment.collect import select_nodes
from experiment.evaluate import metrics


def fixture():
    rows = []
    for policy in ("full",):
        for trial in range(2):
            for tick in range(8):
                for n in NODES:
                    fault = tick >= 4 and n == "smf"
                    rows.append({
                        "policy": policy, "trial": trial, "tick": tick,
                        "node": n, "up": int(not fault),
                        "rtt_ms": np.nan if fault else 12 + tick * 0.1,
                        "age": 0, "observed": 1, "label": int(fault),
                    })
    return pd.DataFrame(rows)


def test_enrichment_is_causal_and_excludes_fault_labels():
    f = fixture()
    result = enrich(f)
    assert len(result) == len(f)
    assert set(FULL).issubset(result.columns)
    assert "label" not in FULL
    before = result.loc[(result.trial == 0) & (result.tick == 0), "prev_up"]
    assert (before == 1).all()
    smf = result.loc[(result.trial == 0) & (result.tick == 4)
                     & (result.node == "smf")].iloc[0]
    assert smf["neighbor_up"] == 1.0
    assert smf["neighbor_deviation"] == 1.0


def test_online_policy_respects_budget_and_freshness():
    class Model:
        def decision_function(self, x):
            return -np.asarray([x[0, 2] / 3])
    import random
    state = {n: {"up": 1, "rtt_ms": 10.0, "age": 0} for n in NODES}
    state["smf"]["age"] = 100
    assert select_nodes("full", 5, state, 2, Model(), random.Random(1)) == set(NODES)
    chosen = select_nodes("adaptive", 5, state, 2, Model(), random.Random(1))
    assert len(chosen) == 2
    assert "smf" in chosen
    assert len(online_vector(state, "nrf")) == 4


def test_basic_metrics():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.8, 0.9])
    result = metrics(y, scores, (scores > .5).astype(int))
    assert result["f1"] == 1
    assert result["fpr"] == 0
    assert result["pr_auc"] == 1


def test_duplicate_tick_rejected():
    f = fixture()
    try:
        enrich(pd.concat([f, f.iloc[:1]]))
    except ValueError as e:
        assert "Duplicate" in str(e)
    else:
        raise AssertionError("duplicate node must fail")
