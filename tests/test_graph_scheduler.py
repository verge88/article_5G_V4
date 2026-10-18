"""Checks for graph-scheduler temporal causality and held-out campaigns.

Artificial rows here only validate program invariants: never evidence.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from experiment.active_gnn import (
    DIM, WIDTH, fresh_state, fresh_transport, node_features, training_samples,
)
from experiment.features import NODES
from experiment.secure_collect import SIGNERS


def past_full_fixture() -> pd.DataFrame:
    rows = []
    for trial in (0, 1):
        for tick in range(4):
            for n in NODES:
                rows.append({
                    "policy": "full", "trial": trial, "tick": tick, "node": n,
                    "label": int(n == "smf" and tick >= 2),
                    "kie_gap_last": float(tick - 1 if n == "smf" and tick >= 2 else 0),
                    "kie_rtt_ms": 2.0 + tick if n in SIGNERS else np.nan,
                    "kie_queried": int(n in SIGNERS),
                    "sba_up": 1, "sba_rtt_ms": 1.0 + tick,
                    "probe_kind": "LIVE_SIGNED_AGENT_HTTP11_AND_SBA_HTTP2",
                })
    return pd.DataFrame(rows)


def test_node_context_never_reads_phase_target_or_label():
    s, t = fresh_state(), fresh_transport()
    x = node_features(s, t)
    assert x.shape == (len(NODES), DIM)
    assert np.isfinite(x).all()
    assert x[NODES.index("smf"), 6] == 1
    assert x[NODES.index("ausf"), 6] == 0


def test_offline_inputs_are_prior_to_labels_at_current_tick():
    df = past_full_fixture()
    windows = training_samples(df, seed=25)
    x, y = windows[0]
    assert x.shape == (4 * 3, WIDTH, len(NODES), DIM)
    assert y.shape == (12, len(NODES))
    assert y[1, NODES.index("smf")] == 1
    # Change the ACTUAL response at tick 2; samples for tick 2 must
    # remain unchanged because they use only data through tick 1.
    modified = df.copy()
    mask = (modified["trial"] == 0) & (modified["tick"] == 2)
    modified.loc[mask, "kie_rtt_ms"] = 800.
    modified.loc[mask, "kie_gap_last"] = 9.
    altered_x, _ = training_samples(modified, seed=25)[0]
    np.testing.assert_allclose(x[1], altered_x[1], atol=0, rtol=0)
    # But the NEXT tick can legitimately depend on the new signed reply.
    assert not np.array_equal(x[2], altered_x[2])


def test_training_fails_closed_on_incomplete_tick():
    df = past_full_fixture()
    f = df.drop(df.index[0])
    with pytest.raises(ValueError, match="Incomplete"):
        training_samples(f, seed=25)


def test_training_does_not_accept_synthetic_provenance():
    df = past_full_fixture()
    df["probe_kind"] = "SYNTHETIC"
    with pytest.raises(ValueError, match="LIVE"):
        training_samples(df, seed=25)


def test_training_must_have_two_real_full_trials():
    df = past_full_fixture()
    with pytest.raises(ValueError, match="separate"):
        training_samples(df[df.trial == 0], seed=25)
