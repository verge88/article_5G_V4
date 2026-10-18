"""Causal graph-GRU eight-NF active scheduler; no current/future signed data.

Historic training uses ONLY real full-polling KIE responses from this lab.
Sparse views are explicitly declared *mask augmentation* of live historic
responses. Model weight/threshold frozen for every separate active campaign.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd

from experiment.features import NODES, NEIGHBORS
from experiment.temporal_gnn import adjacency

W, F = 4, 7
BUDGET = 2


def torch_library():
    try:
        import torch
        from torch import nn
    except ImportError as exc:
        raise RuntimeError("CPU PyTorch must be installed for trainable 8NF GNN") from exc
    return torch, nn


def state_zero() -> dict:
    return {n: {"gap": 0., "age": 9, "rtt": 2., "selected": 0,
                "up": 1, "seen": 0, "offset": None} for n in NODES}


def transport_zero() -> dict:
    return {n: {"up": 1, "rtt_ms": 1.} for n in NODES}


def feat(states: dict, transport: dict) -> np.ndarray:
    """Per-node lagged measures, NO label, attack_target or current tick."""
    x = []
    for n in NODES:
        s, t = states[n], transport[n]
        x.append([
            float(t["up"]),
            np.log1p(max(0., min(1000., float(t["rtt_ms"])))) / 8.,
            min(20., float(s["gap"])) / 20.,
            min(9, int(s["age"])) / 9.,
            float(bool(s["selected"])),
            np.log1p(max(0., min(500., float(s["rtt"])))) / 8.,
            len(NEIGHBORS[n]) / 8.,
        ])
    return np.asarray(x, dtype=np.float32)


def window(history: list[np.ndarray]) -> np.ndarray:
    last = history[-W:]
    return np.stack([last[0]] * (W - len(last)) + last).astype(np.float32)


def verified_full_samples(path: Path, seed: int = 28) -> dict:
    raw = pd.read_csv(path)
    expected = {"trial", "tick", "node", "label", "kie_gap_full",
                "kie_rtt_ms", "sba_up", "sba_rtt_ms", "kie_valid", "provenance"}
    if expected - set(raw):
        raise ValueError(f"Missing real KIE columns: {sorted(expected - set(raw))}")
    if set(raw["provenance"].unique()) != {"LIVE_EIGHT_AUTHENTICATED_KIE_HTTP11_AND_OPEN5GS_HTTP2"}:
        raise ValueError("Training must use genuine prior live eight-NF KIE")
    if set(raw["kie_valid"].unique()) != {1}:
        raise ValueError("Full-polling pilot KIE signatures were not all valid")
    trials = sorted(int(x) for x in raw.trial.unique())
    if len(trials) < 4:
        raise ValueError("Need >=4 previously acquired independently timed trials")
    result = {}
    for trial in trials:
        grouped = list(raw[raw.trial == trial].groupby("tick", sort=True))
        if len(grouped) < 20:
            raise ValueError("Not enough genuine NF ticks")
        xx, yy = [], []
        for pattern in range(4):
            rng = random.Random(seed + trial * 113 + pattern * 3001)
            states, transport = state_zero(), transport_zero()
            history = []
            for tick, block in grouped:
                if len(block) != len(NODES) or set(block.node) != set(NODES):
                    raise ValueError("Missing or duplicate NF in full-polling tick")
                block = block.set_index("node")
                history.append(feat(states, transport))  # BEFORE reading tick.
                xx.append(window(history))
                yy.append(block.loc[list(NODES), "label"].to_numpy(dtype=np.float32))
                if pattern == 0 or int(tick) == 0:
                    selected = set(NODES)
                elif pattern == 1:
                    selected = {NODES[(2 * int(tick) + j) % len(NODES)]
                                for j in range(BUDGET)}
                elif pattern == 2:
                    selected = set(rng.sample(list(NODES), BUDGET))
                else:
                    ranked = sorted(NODES, key=lambda n: (
                        -states[n]["age"], rng.random()))
                    selected = set(ranked[:BUDGET])
                for n in NODES:
                    s = states[n]
                    if n in selected:
                        s.update(gap=float(block.loc[n, "kie_gap_full"]),
                                 age=0, rtt=float(block.loc[n, "kie_rtt_ms"]),
                                 selected=1)
                    else:
                        s["age"] += 1
                        s["selected"] = 0
                transport = {n: {
                    "up": float(block.loc[n, "sba_up"]),
                    "rtt_ms": float(block.loc[n, "sba_rtt_ms"]),
                } for n in NODES}
        result[trial] = (np.asarray(xx, dtype=np.float32),
                         np.asarray(yy, dtype=np.float32))
    return result


def network(graph: bool = True):
    torch, nn = torch_library()
    adj = torch.as_tensor(adjacency(graph), dtype=torch.float32)

    class GraphGRU(nn.Module):
        def __init__(self):
            super().__init__()
            self.linear = nn.Linear(2 * F, 24)
            self.gru = nn.GRU(24, 24, batch_first=True)
            self.out = nn.Linear(24, 1)

        def forward(self, x):
            # x shape [batch, past4, 8 nodes, 7 measured/masked features]
            nh = torch.einsum("ij,btjf->btif", adj, x)
            h = torch.relu(self.linear(torch.cat((x, nh), dim=-1)))
            b, t, n, d = h.shape
            h = h.permute(0, 2, 1, 3).reshape(b*n, t, d)
            out, _ = self.gru(h)
            return self.out(out[:, -1]).reshape(b, n)
    return GraphGRU()


def train(path: Path, output: Path, seed: int = 28, epochs: int = 90) -> dict:
    torch, nn = torch_library()
    torch.set_num_threads(2)
    torch.manual_seed(seed)
    np.random.seed(seed)
    samples = verified_full_samples(path, seed)
    ids = sorted(samples)
    tr, va = ids[:-1], ids[-1]
    x = torch.from_numpy(np.concatenate([samples[t][0] for t in tr]))
    y = torch.from_numpy(np.concatenate([samples[t][1] for t in tr]))
    xv = torch.from_numpy(samples[va][0])
    yv = torch.from_numpy(samples[va][1])
    if y.sum() == 0 or yv.sum() == 0:
        raise ValueError("Actual pilot train and validation must include interventions")
    output.parent.mkdir(exist_ok=True, parents=True)
    info = {"source_kind": "REAL_LIVE_SIGNED_AGENT_COUNTERS_MASKED_DURING_TRAINING",
            "data_path": str(path), "train_trials": tr, "validation_trial": va,
            "future_data_used": False, "GNN_selection_training": "supervised next-tick risks",
            "augmented_masks": "4 patterns, historical genuine FULL KIE responses selectively hidden",
            "training_examples": int(len(x)), "validation_examples": int(len(xv)),
            "seed": seed, "models": {}}
    for name, graph in (("graph_gru", True), ("no_graph_gru", False)):
        torch.manual_seed(seed)
        net = network(graph)
        opt = torch.optim.Adam(net.parameters(), lr=.004, weight_decay=1e-4)
        positives = float(y.sum())
        pos_weight = min(20., (float(y.numel()) - positives) / max(1., positives))
        lossfn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(pos_weight))
        best_val, best_weights, best_epoch = float("inf"), None, -1
        for e in range(epochs):
            net.train()
            opt.zero_grad()
            loss = lossfn(net(x), y)
            loss.backward()
            opt.step()
            net.eval()
            with torch.no_grad():
                v = float(lossfn(net(xv), yv))
            if v < best_val - 1e-5:
                best_val, best_weights, best_epoch = v, copy.deepcopy(net.state_dict()), e+1
            if e+1-best_epoch >= 16:
                break
        torch.save({"state_dict": best_weights, "graph": graph,
                    "features": F, "history": W,
                    "source": "PREVIOUS_FULL_LIVE_SAMPLES_ONLY"},
                   output.with_name(f"{output.stem}-{name}.pt"))
        info["models"][name] = {"best_epoch": best_epoch, "validation_bce": best_val}
    output.with_suffix(".metadata.json").write_text(json.dumps(info, indent=2))
    return info


class Risk:
    def __init__(self, model_path: Path, graph: bool):
        torch, _ = torch_library()
        doc = torch.load(model_path, map_location="cpu", weights_only=True)
        if doc["graph"] != graph or doc["features"] != F or doc["history"] != W:
            raise ValueError("Different graph/budget model schema")
        self.net = network(graph)
        self.net.load_state_dict(doc["state_dict"])
        self.net.eval()
        self.history = []
        self.last_tick = -1

    def before(self, tick: int, states: dict, transport: dict) -> dict:
        if tick <= self.last_tick:
            raise ValueError("Future/current tick observation cannot be reused")
        self.last_tick = tick
        self.history.append(feat(states, transport))
        torch, _ = torch_library()
        with torch.no_grad():
            scores = torch.sigmoid(self.net(
                torch.from_numpy(window(self.history))[None, ...]))[0].numpy()
        return dict(zip(NODES, map(float, scores)))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/eight_full_training.csv"))
    p.add_argument("--output", type=Path, default=Path("results/eight_scheduler.pt"))
    p.add_argument("--seed", type=int, default=28)
    a = p.parse_args()
    print(json.dumps(train(a.input, a.output, a.seed), indent=2))


if __name__ == "__main__":
    main()
