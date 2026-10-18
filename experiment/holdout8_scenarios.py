"""Precommitted, out-of-distribution lab-agent reporting faults.

These NEVER compromise Open5GS NFs. Only existing test signers'
own receipt counters are dishonestly reported; benign RTT delays
leave the counters honest. Seeds are entirely disjoint from Phase 8/9
pilot 107 and Phase 9 heldout 81491.
"""
from __future__ import annotations

import random

from experiment.features import NODES, NEIGHBORS

SEEDS = {
    "shifted_neighbor": 52937,
    "off_graph": 73417,
    "independent_short": 90371,
    "benign_only": 118901,
}
POSITIVE = ("shifted_neighbor", "off_graph", "independent_short")
FAMILIES = tuple(SEEDS)
TRAIN_SEED = 107
PREVIOUS_HOLDOUT_SEED = 81491
TRIALS = 2
TICKS = 36
POLICIES = (
    "full", "rotation", "neighbor_heuristic", "graph_gru",
    "bayes_entropy", "bayes_no_edges", "bayes_pomdp",
)


def scenario_for(family: str, seed: int, trial: int) -> list[dict]:
    if family not in SEEDS or seed != SEEDS[family]:
        raise ValueError("Unregistered family/seed: refuse post-hoc selection")
    if seed in (TRAIN_SEED, PREVIOUS_HOLDOUT_SEED):
        raise ValueError("Training/test seed reuse is forbidden")
    if not 0 <= trial < TRIALS:
        raise ValueError("Unregistered out-of-range trial")
    rng = random.Random(seed + trial * 1009)
    episodes = []
    if family in ("shifted_neighbor", "off_graph"):
        if family == "off_graph":
            eligible = [n for n in NODES
                        if set(NODES) - NEIGHBORS[n] - {n}]
            roots = rng.sample(eligible, 2)
        else:
            roots = rng.sample(list(NODES), 2)
        for root, start in zip(roots, (6, 21)):
            if family == "shifted_neighbor":
                child_choices = sorted(NEIGHBORS[root] - {root})
                child = rng.choice(child_choices)
                episodes.extend([
                    {"node": root, "start": start, "end": start+5,
                     "family": "origin_shifted", "cascade_from": None},
                    {"node": child, "start": start+2, "end": start+5,
                     "family": "neighbor_followup_shifted", "cascade_from": root},
                ])
            else:
                child_choices = sorted(set(NODES) - NEIGHBORS[root] - {root})
                child = rng.choice(child_choices)
                episodes.extend([
                    {"node": root, "start": start, "end": start+7,
                     "family": "origin", "cascade_from": None},
                    {"node": child, "start": start+4, "end": start+7,
                     "family": "NON_NEIGHBOR_followup", "cascade_from": root},
                ])
    elif family == "independent_short":
        # Uncorrelated 2-tick incidents, shorter than complete rotation
        # (4 ticks), with no predictive topology to exploit.
        nodes = rng.sample(list(NODES), 4)
        for n, start in zip(nodes, (6, 12, 21, 28)):
            episodes.append({
                "node": n, "start": start, "end": start+2,
                "family": "independent_2tick", "cascade_from": None})
    # Every family includes a harmless, actual 120ms lab signer's
    # response delay; clean_only has TWO such controls.
    delayed = rng.sample(list(NODES), 2 if family == "benign_only" else 1)
    for n, start in zip(delayed, (16, 27)):
        episodes.append({"node": n, "start": start, "end": start+4,
                         "family": "benign_delay", "cascade_from": None})
    for e in episodes:
        if not (0 <= e["start"] < e["end"] <= TICKS):
            raise ValueError("Invalid precommitted intervention bounds")
    return episodes
