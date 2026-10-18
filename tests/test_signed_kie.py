"""KIE authentication and causal graph-window unit tests (no generated evidence)."""
from __future__ import annotations

import os
import subprocess
import sys

import numpy as np
import pandas as pd

from experiment.features import NODES
from experiment.temporal_gnn import adjacency, aligned, windows


def test_challenge_hmac_nonce_and_replay():
    code = r'''
import time
from experiment.kie_agent import mac, verify_challenge
a = {"node":"smf", "seq":1, "nonce":"a"*32, "ts":time.time()}
a["mac"] = mac(a)
assert verify_challenge(a, time.time())
assert not verify_challenge(a, time.time()), "replay must fail"
b = {"node":"smf", "seq":2, "nonce":"b"*32, "ts":time.time()-70}
b["mac"] = mac(b)
assert not verify_challenge(b, time.time()), "stale challenge must fail"
c = {"node":"smf", "seq":3, "nonce":"c"*32, "ts":time.time()}
c["mac"] = "0"*64
assert not verify_challenge(c, time.time()), "bad MAC must fail"
d = {"node":"smf", "seq":4, "nonce":"d"*32, "ts":time.time()}
d["mac"] = mac(d)
assert verify_challenge(d, time.time())
e = {"node":"smf", "seq":3, "nonce":"e"*32, "ts":time.time()}
e["mac"] = mac(e)
assert not verify_challenge(e, time.time()), "old sequence must fail"
'''
    env = {**os.environ, "KIE_NODE": "smf", "KIE_NF_IP": "10.45.0.21",
           "KIE_TEST_KEY": "9a" * 32}
    r = subprocess.run([sys.executable, "-c", code], env=env,
                       capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, r.stderr


def test_graph_contains_self_loops_and_real_neighbor_edges():
    a = adjacency()
    assert a.shape == (len(NODES), len(NODES))
    np.testing.assert_allclose(a.sum(axis=1), 1, atol=1e-7)
    np.testing.assert_allclose(adjacency(False), np.eye(len(NODES)))
    assert (a.diagonal() > 0).all()


def test_causal_windows_and_missing_node_rejection():
    records = []
    for trial in range(2):
        for tick in range(3):
            for node in NODES:
                records.append(dict(trial=trial, tick=tick, node=node,
                                    f=float(tick + 100 * trial), label=0))
    frame = aligned(pd.DataFrame(records))
    xx, yy = windows(frame, ["f"], 3)
    assert xx.shape == (6, 3, 8, 1)
    assert yy.shape == (6, 8)
    assert (xx[0, :, :, 0] == 0).all()
    assert (xx[3, :, :, 0] == 100).all(), "trial leakage in causal windows"
    try:
        aligned(frame.iloc[:-1])
    except ValueError as e:
        assert "Incomplete" in str(e)
    else:
        raise AssertionError("Incomplete NF observations should not be padded")
