"""Trainable graph-convolution + temporal GRU anomaly detector.

Architecture: normalized service-relationship adjacency A, learned
node-neighbor convolution, GRU over CAUSAL observation windows, node logits.
Baselines and ablations share disjoint collection trials and training data.
"""
from __future__ import annotations

import argparse
import copy
import json
import random
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from experiment.evaluate import delays, metrics
from experiment.features import FULL, LINKS, LOCAL, NODES, TEMPORAL, ZONE, enrich
from experiment.secure_collect import KIE_FIELDS

SIGNED = ["kie_valid", "kie_rtt_ms", "kie_counter_gap", "kie_invariant_error",
          "kie_agent_local_up", "kie_present"]
NODE_ORDER = {name: i for i, name in enumerate(NODES)}


def adjacency(connected: bool = True) -> np.ndarray:
    mat = np.eye(len(NODES), dtype=np.float32)
    if connected:
        for a, b in LINKS:
            mat[NODE_ORDER[a], NODE_ORDER[b]] = 1
            mat[NODE_ORDER[b], NODE_ORDER[a]] = 1
    return mat / mat.sum(axis=1, keepdims=True)


def aligned(data: pd.DataFrame) -> pd.DataFrame:
    """Order all node windows unambiguously; reject absent/duplicated NF ticks."""
    result = data.copy()
    result["_node_order"] = result["node"].map(NODE_ORDER)
    if result["_node_order"].isna().any():
        raise ValueError("Unknown NF in signed dataset")
    result = result.sort_values(["trial", "tick", "_node_order"]).reset_index(drop=True)
    expected = set(NODES)
    for (_, _), block in result.groupby(["trial", "tick"], sort=False):
        if len(block) != len(NODES) or set(block["node"]) != expected:
            raise ValueError("Incomplete NF/tick observation; no synthetic padding")
    return result.drop(columns="_node_order")


def windows(data: pd.DataFrame, columns: list[str], width: int) -> tuple[np.ndarray, np.ndarray]:
    """Sequence samples consist strictly of current and previous tick in SAME trial."""
    xx, yy = [], []
    for _, subset in data.groupby("trial", sort=True):
        values = subset[columns].to_numpy(dtype=np.float32).reshape(
            -1, len(NODES), len(columns))
        labels = subset["label"].to_numpy(dtype=np.float32).reshape(-1, len(NODES))
        for t in range(len(values)):
            frames = values[max(0, t - width + 1):t + 1]
            if len(frames) < width:
                frames = np.concatenate([
                    np.repeat(frames[:1], width - len(frames), axis=0), frames], axis=0)
            xx.append(frames)
            yy.append(labels[t])
    return np.asarray(xx), np.asarray(yy)


def fit_preprocess(train: pd.DataFrame, subsets: dict[str, pd.DataFrame],
                   columns: list[str]) -> dict[str, pd.DataFrame]:
    # Fixed constant imputation is learned only via training; missing RTT -> 1000.
    prep = make_pipeline(SimpleImputer(strategy="constant", fill_value=1000),
                         StandardScaler())
    prep.fit(train[columns])
    out = {}
    for label, data in subsets.items():
        copy_df = data.copy()
        copy_df.loc[:, columns] = prep.transform(data[columns])
        out[label] = copy_df
    return out


def fit_gnn(train: pd.DataFrame, validation: pd.DataFrame,
            heldout: pd.DataFrame, columns: list[str], graph: bool, seed: int,
            epochs: int, width: int) -> dict:
    try:
        import torch
        from torch import nn
    except ImportError as exc:
        raise RuntimeError("GNN requires PyTorch CPU installed explicitly") from exc
    torch.manual_seed(seed)
    torch.set_num_threads(2)
    np.random.seed(seed)
    matrices = fit_preprocess(train, {
        "train": train, "val": validation, "test": heldout}, columns)
    xtr, ytr = windows(matrices["train"], columns, width)
    xva, yva = windows(matrices["val"], columns, width)
    xte, yte = windows(matrices["test"], columns, width)
    graph_matrix = torch.as_tensor(adjacency(graph))
    inputs = len(columns)

    class TemporalGraphNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.proj = nn.Linear(inputs * 2, 24)
            self.recurrent = nn.GRU(24, 24, batch_first=True)
            self.head = nn.Linear(24, 1)

        def forward(self, x):
            # x = [batch, time, NF, features]
            neighbors = torch.einsum("ij,btjf->btif", graph_matrix, x)
            h = torch.relu(self.proj(torch.cat((x, neighbors), dim=-1)))
            # Temporal update for each NF; graph messages mixed before GRU.
            b, w, n, d = h.shape
            h = h.permute(0, 2, 1, 3).reshape(b * n, w, d)
            out, _ = self.recurrent(h)
            return self.head(out[:, -1]).reshape(b, n)

    model = TemporalGraphNet()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.003, weight_decay=1e-4)
    positives = float(ytr.sum())
    negatives = float(ytr.size - positives)
    if positives <= 0 or negatives <= 0:
        raise RuntimeError("Graph training needs both normal and spoof rows")
    loss_fn = nn.BCEWithLogitsLoss(
        pos_weight=torch.tensor([min(30, negatives / positives)], dtype=torch.float32))
    train_x = torch.from_numpy(xtr)
    train_y = torch.from_numpy(ytr)
    val_x = torch.from_numpy(xva)
    val_y = yva.flatten().astype(int)
    best_state = None
    best_score = -1
    best_epoch = 0
    for epoch in range(epochs):
        model.train()
        # Entire short sequence fits CPU RAM; reproducible full-batch optimizer.
        optimizer.zero_grad()
        logits = model(train_x)
        loss = loss_fn(logits, train_y)
        loss.backward()
        optimizer.step()
        model.eval()
        with torch.no_grad():
            vs = torch.sigmoid(model(val_x)).numpy().flatten()
        from sklearn.metrics import average_precision_score
        quality = float(average_precision_score(val_y, vs))
        if quality > best_score + 1e-5:
            best_score = quality
            best_state = copy.deepcopy(model.state_dict())
            best_epoch = epoch + 1
        if epoch - best_epoch >= 15:
            break
    if best_state is None:
        raise RuntimeError("No valid temporal graph model")
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        val_scores = torch.sigmoid(model(val_x)).numpy().flatten()
        scores = torch.sigmoid(model(torch.from_numpy(xte))).numpy().flatten()
    # Tune threshold on the validation trial, NEVER held-out trial.
    thresholds = np.linspace(0.10, 0.90, 17)
    tuned = max(thresholds, key=lambda t: f1_score(
        val_y, val_scores >= t, zero_division=0))
    pred = (scores >= tuned).astype(int)
    result = metrics(yte.flatten().astype(int), scores, pred)
    result.update(delays(heldout, pred))
    result.update({"validation_pr_auc": best_score, "chosen_epoch": best_epoch,
                   "threshold_from_validation": float(tuned), "feature_count": inputs,
                   "sequence_window": width, "learned_graph": bool(graph)})
    return result


def evaluate(path: Path, output: Path, seed: int = 42, epochs: int = 70) -> dict:
    raw = pd.read_csv(path)
    if set(raw["probe_kind"]) != {"live_sba_http2_plus_signed_agent"}:
        raise ValueError("GNN study strictly requires live signed KIE agent data")
    if raw["trial"].nunique() < 4:
        raise ValueError("Need at least four independently acquired trials")
    if not {"spoof_smf", "baseline", "recovery"}.issubset(set(raw["phase"])):
        raise ValueError("Missing signed-report tamper/normalization phases")
    if raw.loc[(raw["node"] == "smf"), "kie_valid"].min() != 1:
        raise ValueError("SMF signature verification must succeed for every challenge")
    data = aligned(enrich(raw))
    trials = sorted(data["trial"].unique())
    train_trials, val_trial, test_trial = trials[:-2], trials[-2], trials[-1]
    train = data[data["trial"].isin(train_trials)].copy()
    val = data[data["trial"] == val_trial].copy()
    test = data[data["trial"] == test_trial].copy()
    if any(x["label"].nunique() != 2 for x in (train, val, test)):
        raise ValueError("Train, validation and test need both classes")
    random.seed(seed)
    configs = {
        "GNN_graph_temporal_KIE": (FULL + SIGNED, True),
        "GNN_temporal_KIE_no_edges": (FULL + SIGNED, False),
        "GNN_graph_temporal_without_KIE": (FULL, True),
    }
    results = {}
    for name, (columns, graph) in configs.items():
        results[name] = fit_gnn(train, val, test, columns, graph, seed,
                                epochs, width=4)
    # Classical baselines: same training trials, decision threshold chosen on VAL.
    for name, cols in {
        "RF_local": LOCAL,
        "RF_hierarchy_no_KIE": LOCAL + TEMPORAL + ZONE,
        "RF_hierarchy_signed_KIE": LOCAL + TEMPORAL + ZONE + SIGNED,
    }.items():
        model = make_pipeline(
            SimpleImputer(strategy="constant", fill_value=1000),
            RandomForestClassifier(n_estimators=180, min_samples_leaf=2,
                                   class_weight="balanced", random_state=seed,
                                   n_jobs=2))
        model.fit(train[cols], train["label"])
        vs = model.predict_proba(val[cols])[:, 1]
        thresholds = np.linspace(.05, .95, 19)
        threshold = float(max(thresholds, key=lambda t: f1_score(
            val["label"], vs >= t, zero_division=0)))
        prob = model.predict_proba(test[cols])[:, 1]
        pred = (prob >= threshold).astype(int)
        results[name] = metrics(test["label"].to_numpy(dtype=int), prob, pred)
        results[name].update(delays(test, pred))
        results[name]["threshold_from_validation"] = threshold
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "provenance": "LIVE_5G_SBA_WITH_SIGNED_COLOCATED_AGENT",
        "hypothesis": "signed KIE inconsistencies expose dishonest agent receipts",
        "boundaries": [
            "NF agent is not Open5GS native 3GPP service",
            "malicious NF compromise not demonstrated",
            "isolated lab signed-counter staleness injected by experiment",
            "GNN topology is fixed service-relationship hypothesis",
        ],
        "datafile": str(path), "train_trials": [int(x) for x in train_trials],
        "validation_trial": int(val_trial), "test_trial": int(test_trial),
        "n_train": len(train), "n_validation": len(val), "n_test": len(test),
        "seed": seed, "results": results,
    }
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf8")
    pd.DataFrame([{"model": k, **v} for k, v in results.items()]).to_csv(
        output.with_suffix(".csv"), index=False)
    return report


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="results/signed_kie.csv", type=Path)
    p.add_argument("--output", default="results/signed_gnn_metrics.json", type=Path)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--epochs", type=int, default=70)
    args = p.parse_args()
    report = evaluate(args.input, args.output, args.seed, args.epochs)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
