"""Causal graph-temporal *scheduler* trained from prior live signed KIE traces.

Supervised learning uses earlier Phase 3 FULL-policy campaigns only. During
training, sparse observation masks are AUGMENTATIONS applied to previously
measured live reports, not new network measurements. Online selection only
sees data from ticks strictly before the selected current tick.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd

from experiment.features import IP, NODES
from experiment.secure_collect import SIGNERS
from experiment.temporal_gnn import adjacency

SIGNER_INDICES = [NODES.index(n) for n in SIGNERS]
WIDTH = 4
DIM = 8


def _torch():
    try:
        import torch
        from torch import nn
    except ImportError as exc:
        raise RuntimeError("Install CPU PyTorch before training or using graph scheduler") from exc
    return torch, nn


def fresh_state() -> dict[str, dict]:
    return {n: {"age": 99, "gap": 0., "rtt": 2., "up": 1.,
                "last_selected": False} for n in SIGNERS}


def fresh_transport() -> dict[str, dict]:
    return {n: {"up": 1, "rtt_ms": 1.} for n in NODES}


def _finite(v: object, default: float = 1.) -> float:
    try:
        a = float(v)
        return a if np.isfinite(a) else default
    except (TypeError, ValueError):
        return default


def node_features(state: dict[str, dict], transport: dict[str, dict]) -> np.ndarray:
    """All features are lagged live state; neither current labels nor phase enter."""
    x = np.zeros((len(NODES), DIM), dtype=np.float32)
    for i, node in enumerate(NODES):
        t = transport[node]
        s = state.get(node)
        x[i] = [
            float(t["up"]),
            np.log1p(min(_finite(t["rtt_ms"], 200.), 1000.)) / 8,
            np.log1p(min(_finite(s["rtt"] if s else 0.), 200.)) / 8,
            min(_finite(s["gap"] if s else 0.), 30.) / 30,
            min(_finite(s["age"] if s else 0.), 10.) / 10,
            float(bool(s and s["last_selected"])),
            float(node in SIGNERS),
            float(bool(s and s["up"])),
        ]
    return x


def _padded(history: list[np.ndarray]) -> np.ndarray:
    if not history:
        raise ValueError("No past causal measurements")
    seq = history[-WIDTH:]
    return np.stack([seq[0]] * (WIDTH - len(seq)) + seq).astype(np.float32)


def training_samples(df: pd.DataFrame, seed: int) -> dict[int, tuple[np.ndarray, np.ndarray]]:
    """Build next-tick targets with NO current-tick KIE features in input."""
    expected = {"policy", "trial", "tick", "node", "label", "kie_gap_last",
                "kie_rtt_ms", "kie_queried", "sba_up", "sba_rtt_ms", "probe_kind"}
    if expected - set(df.columns):
        raise ValueError("Historical signed KIE observation schema incomplete")
    if set(df["probe_kind"].unique()) != {"LIVE_SIGNED_AGENT_HTTP11_AND_SBA_HTTP2"}:
        raise ValueError("Training requires only previously collected LIVE signed KIE")
    full = df[df["policy"] == "full"]
    trials = sorted(int(i) for i in full["trial"].unique())
    if len(trials) < 2:
        raise ValueError("Need >=2 earlier, separate FULL-policy trials")
    out: dict[int, tuple[np.ndarray, np.ndarray]] = {}
    for trial in trials:
        pieces = []
        groups = list(full[full["trial"] == trial].groupby("tick", sort=True))
        for pattern in range(4):
            rng = random.Random(seed + trial * 193 + pattern * 13)
            state = fresh_state()
            transport = fresh_transport()
            history: list[np.ndarray] = []
            xseq, yseq = [], []
            for tick, rows in groups:
                if len(rows) != len(NODES) or set(rows["node"]) != set(NODES):
                    raise ValueError("Incomplete historical full observation tick")
                rows = rows.set_index("node")
                # Risk at tick=t is computed using only information through t-1.
                history.append(node_features(state, transport))
                if int(tick) > 0:
                    xseq.append(_padded(history))
                    yseq.append(rows.loc[list(NODES), "label"].to_numpy(dtype=np.float32))
                if pattern == 0 or tick == 0:
                    selected = set(SIGNERS)
                elif pattern == 1:
                    selected = {SIGNERS[int(tick) % len(SIGNERS)]}
                else:
                    selected = {rng.choice(SIGNERS)}
                for node in SIGNERS:
                    s = state[node]
                    if node in selected:
                        if int(rows.loc[node, "kie_queried"]) != 1:
                            raise ValueError("Historical full policy omitted authenticated KIE")
                        # Recorded KIE values are genuinely measured; selective
                        # observation masks in these examples are artificial.
                        s.update(gap=float(rows.loc[node, "kie_gap_last"]),
                                 rtt=_finite(rows.loc[node, "kie_rtt_ms"], 200.),
                                 up=1., age=0, last_selected=True)
                    else:
                        s["age"] += 1
                        s["last_selected"] = False
                transport = {n: {
                    "up": float(rows.loc[n, "sba_up"]),
                    "rtt_ms": _finite(rows.loc[n, "sba_rtt_ms"], 200.),
                } for n in NODES}
            if not xseq:
                raise ValueError("Not enough KIE history for causal windows")
            pieces.append((np.asarray(xseq, dtype=np.float32),
                           np.asarray(yseq, dtype=np.float32)))
        out[trial] = (np.concatenate([p[0] for p in pieces]),
                      np.concatenate([p[1] for p in pieces]))
    return out


def make_network():
    torch, nn = _torch()
    a = torch.as_tensor(adjacency(True))

    class GraphTemporalPolicy(nn.Module):
        def __init__(self):
            super().__init__()
            self.proj = nn.Linear(DIM * 2, 24)
            self.gru = nn.GRU(24, 24, batch_first=True)
            self.out = nn.Linear(24, 1)

        def forward(self, x):
            # [batch, t, eight real SBA NFs, eight causal features]
            neighbors = torch.einsum("ij,btjf->btif", a, x)
            h = torch.relu(self.proj(torch.cat((x, neighbors), dim=-1)))
            b, t, n, d = h.shape
            h = h.permute(0, 2, 1, 3).reshape(b * n, t, d)
            h, _ = self.gru(h)
            return self.out(h[:, -1]).reshape(b, n)
    return GraphTemporalPolicy()


def train(input_path: Path, output: Path, seed: int = 317,
          epochs: int = 90) -> dict:
    torch, nn = _torch()
    torch.set_num_threads(2)
    torch.manual_seed(seed)
    np.random.seed(seed)
    raw = pd.read_csv(input_path)
    examples = training_samples(raw, seed)
    trials = sorted(examples)
    # Final historical full trial is validation. All subsequent ACTIVE
    # campaigns are prospectively acquired and never used to fit/tune.
    training_trials, validation_trial = trials[:-1], trials[-1]
    xx = torch.tensor(np.concatenate([examples[t][0] for t in training_trials]))
    yy = torch.tensor(np.concatenate([examples[t][1] for t in training_trials]))
    vx = torch.tensor(examples[validation_trial][0])
    vy = torch.tensor(examples[validation_trial][1])
    if yy[:, SIGNER_INDICES].sum() <= 0 or vy[:, SIGNER_INDICES].sum() <= 0:
        raise ValueError("Need observed historical attacks in train AND validation")
    net = make_network()
    optimizer = torch.optim.Adam(net.parameters(), lr=0.004, weight_decay=0.0001)
    ysign = yy[:, SIGNER_INDICES]
    positives = float(ysign.sum())
    negatives = float(ysign.numel() - positives)
    criterion = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor(min(20., negatives / max(positives, 1.))))
    best, best_state, best_epoch = float("inf"), None, 0
    for epoch in range(epochs):
        net.train()
        optimizer.zero_grad()
        loss = criterion(net(xx)[:, SIGNER_INDICES], ysign)
        loss.backward()
        optimizer.step()
        net.eval()
        with torch.no_grad():
            vl = criterion(net(vx)[:, SIGNER_INDICES], vy[:, SIGNER_INDICES]).item()
        if vl < best - 0.00001:
            best, best_state, best_epoch = vl, copy.deepcopy(net.state_dict()), epoch + 1
        if epoch + 1 - best_epoch >= 18:
            break
    if best_state is None:
        raise RuntimeError("No valid graph-temporal model")
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": best_state, "features": DIM, "window": WIDTH}, output)
    info = {
        "source": str(input_path), "source_kind": "LIVE_SIGNED_KIE",
        "training_trials": training_trials, "validation_trial": validation_trial,
        "train_augmented_windows": len(xx), "validation_augmented_windows": len(vx),
        "mask_augmentation": "measured historical full probes are selectively hidden; "
                             "no fabricated transport/counter values inserted",
        "supervision": "next tick signer anomaly labels, not current action labels",
        "online_test_policy": "no fine-tuning or future data access",
        "seed": seed, "best_epoch": best_epoch, "validation_bce": best,
    }
    output.with_suffix(".metadata.json").write_text(json.dumps(info, indent=2))
    return info


class OnlineGraphScheduler:
    def __init__(self, model_path: Path):
        torch, _ = _torch()
        state = torch.load(model_path, map_location="cpu", weights_only=True)
        if state["features"] != DIM or state["window"] != WIDTH:
            raise ValueError("Unsupported graph policy schema")
        self.net = make_network()
        self.net.load_state_dict(state["state_dict"])
        self.net.eval()
        self.history: list[np.ndarray] = []
        self.last_tick = -1

    def risks(self, tick: int, signed_state: dict[str, dict],
              last_transport: dict[str, dict]) -> dict[str, float]:
        if tick <= self.last_tick:
            raise ValueError("Online GNN cannot see same or future tick twice")
        self.last_tick = tick
        self.history.append(node_features(signed_state, last_transport))
        torch, _ = _torch()
        with torch.no_grad():
            x = torch.from_numpy(_padded(self.history))[None, ...]
            p = torch.sigmoid(self.net(x))[0].numpy()
        return {n: float(p[NODES.index(n)]) for n in SIGNERS}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/adaptive_signed.csv"))
    p.add_argument("--output", type=Path, default=Path("results/graph_scheduler.pt"))
    p.add_argument("--epochs", type=int, default=90)
    p.add_argument("--seed", type=int, default=317)
    args = p.parse_args()
    print(json.dumps(train(args.input, args.output, args.seed, args.epochs), indent=2))


if __name__ == "__main__":
    main()
