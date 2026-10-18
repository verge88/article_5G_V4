"""Deterministic policy/budget contract tests only; NOT scientific evidence."""
from __future__ import annotations

import random

import numpy as np
import pandas as pd
import pytest

from experiment.adaptive_signed import fit_prior, phases, select_signed
from experiment.analyze_adaptive import summarize, wilson
from experiment.features import NODES
from experiment.secure_collect import SIGNERS


class FlatNovelty:
    def decision_function(self, x):
        assert x.shape == (1, 4)
        return np.zeros(1)


def states():
    return {n: dict(age=0, gap=0.0, rtt=1.0, up=1.0) for n in SIGNERS}


def test_budgets_and_forced_live_initialization():
    for policy in ("full", "rotation", "ml_adaptive"):
        assert select_signed(policy, 0, states(), FlatNovelty(),
                             random.Random(3), 1, 3) == set(SIGNERS)
        chosen = select_signed(policy, 1, states(), FlatNovelty(),
                               random.Random(3), 1, 3)
        assert len(chosen) == (2 if policy == "full" else 1)


def test_adaptive_freshness_defeats_short_term_novelty():
    x = states()
    x["nrf"]["age"] = 8
    chosen = select_signed("ml_adaptive", 7, x, FlatNovelty(),
                           random.Random(4), 1, 3)
    assert chosen == {"nrf"}


def test_both_targets_present_in_random_schedule():
    sched = phases(random.Random(2026), 6, 9, 6, 6)
    assert sum(label == "baseline" for label, _, _ in sched) == 1
    assert set(target for label, target, _ in sched if label == "spoof") == set(SIGNERS)
    assert sum(label == "benign_delay" for label, _, _ in sched) == 1


def test_reject_fabricated_pilot(tmp_path):
    p = tmp_path / "untrusted.csv"
    pd.DataFrame({"probe_kind": ["synthetic"], "phase": ["baseline"]}).to_csv(p, index=False)
    with pytest.raises(ValueError, match="LIVE"):
        fit_prior(p, 42)


def test_wilson_interval():
    lo, hi = wilson(5, 10)
    assert 0 < lo < 0.5 < hi < 1
    assert wilson(0, 0) is None


def test_live_budget_validator_rejects_over_queries(tmp_path):
    rows = []
    for policy in ("full", "rotation", "ml_adaptive"):
        for tick in range(2):
            for node in NODES:
                selected = node in SIGNERS and (policy == "full" or tick == 0 or node == "smf")
                rows.append({
                    "policy": policy, "trial": 0, "tick": tick, "phase": "baseline",
                    "node": node, "label": 0, "alarm": 0, "attack_target": "",
                    "kie_queried": int(selected), "kie_valid": int(selected),
                    "kie_gap_new": 0 if selected else np.nan,
                    "kie_age_ticks": 0, "kie_request_bytes": 200 if selected else 0,
                    "kie_response_bytes": 300 if selected else 0,
                    "probe_kind": "LIVE_SIGNED_AGENT_HTTP11_AND_SBA_HTTP2",
                })
    raw = pd.DataFrame(rows)
    sample = tmp_path / "sample.csv"
    raw.to_csv(sample, index=False)
    out = summarize(sample, tmp_path / "report.json")
    assert out["policies"]["full"]["signed_kie_calls"] == 4
    assert out["policies"]["rotation"]["signed_kie_calls"] == 3
    assert out["policies"]["ml_adaptive"]["signed_kie_calls"] == 3
    raw.loc[(raw.policy == "ml_adaptive") & (raw.tick == 1)
            & (raw.node == "nrf"), "kie_queried"] = 1
    raw.loc[(raw.policy == "ml_adaptive") & (raw.tick == 1)
            & (raw.node == "nrf"), "kie_valid"] = 1
    raw.to_csv(sample, index=False)
    with pytest.raises(ValueError, match="budget"):
        summarize(sample, tmp_path / "reject.json")
