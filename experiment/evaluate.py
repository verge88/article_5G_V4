"""Leakage-aware comparison of local, zonal and graph/temporal detectors.

Results are measured on held-out collection TRIALS, not random rows. The
engineered graph-context ExtraTrees detector is NOT a neural GNN. No causal
benefit or new-attack generalization is asserted by this experiment.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (average_precision_score, f1_score, precision_score,
                             recall_score, roc_auc_score, confusion_matrix)
from sklearn.pipeline import make_pipeline

from experiment.features import FULL, LOCAL, TEMPORAL, ZONE, enrich


def metrics(y: np.ndarray, score: np.ndarray, pred: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    both = len(np.unique(y)) == 2
    return {
        "n": len(y), "positives": int(np.sum(y)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else None,
        "roc_auc": float(roc_auc_score(y, score)) if both else None,
        "pr_auc": float(average_precision_score(y, score)) if both else None,
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
    }


def delays(frame: pd.DataFrame, predictions: np.ndarray) -> dict:
    df = frame.copy()
    df["prediction"] = predictions
    latencies = []
    missed = 0
    for (_, trial, phase, node), s in df[df["label"] == 1].groupby(
        ["policy", "trial", "phase", "node"], sort=False
    ):
        s = s.sort_values("tick")
        hit = s[s["prediction"] == 1]
        if hit.empty:
            missed += 1
        else:
            latencies.append(int(hit.iloc[0]["tick"] - s.iloc[0]["tick"]))
    return {"detected_episodes": len(latencies), "missed_episodes": missed,
            "median_detection_delay_ticks": float(np.median(latencies))
            if latencies else None}


def experiment(fixed: Path, active: Path | None, output: Path, seed: int) -> dict:
    raw = pd.read_csv(fixed)
    if not (raw["probe_kind"] == "live_sba_http2").all():
        raise ValueError("Refusing non-live measurements for the main study")
    all_trials = sorted(raw["trial"].unique())
    if len(all_trials) < 2:
        raise ValueError("At least 2 independent trial identifiers required")
    data = enrich(raw)
    train = data[data["trial"] != all_trials[-1]].copy()
    heldout = data[data["trial"] == all_trials[-1]].copy()
    if train["label"].nunique() != 2:
        raise ValueError("Training runs need observed normal AND failure episodes")
    if heldout["label"].nunique() != 2:
        raise ValueError("Held-out run needs both classes")
    y_train = train["label"].to_numpy(dtype=int)
    configurations = {
        "M1_isolation_forest": (LOCAL, IsolationForest(
            n_estimators=128, contamination=0.05, random_state=seed)),
        "M2_local_RF": (LOCAL, RandomForestClassifier(
            n_estimators=150, min_samples_leaf=3, class_weight="balanced",
            random_state=seed, n_jobs=1)),
        "M3_hierarchical_RF": (LOCAL + TEMPORAL + ZONE, RandomForestClassifier(
            n_estimators=150, min_samples_leaf=3, class_weight="balanced",
            random_state=seed, n_jobs=1)),
        "M4_graph_temporal_ExtraTrees": (FULL, ExtraTreesClassifier(
            n_estimators=200, min_samples_leaf=3, class_weight="balanced",
            random_state=seed, n_jobs=1)),
    }
    tests = {"fixed_heldout": heldout}
    if active is not None:
        active_raw = pd.read_csv(active)
        if not (active_raw["probe_kind"] == "live_sba_http2").all():
            raise ValueError("Adaptive dataset is not live evidence")
        if not set(active_raw["policy"].unique()) == {"adaptive"}:
            raise ValueError("Expected only adaptive policy rows")
        tests["adaptive"] = enrich(active_raw)
    results = {"manifest": {
        "kind": "LIVE_5GC_SBA_FAULT_EXPERIMENT",
        "limitations": "Faults are availability Docker pause, not malicious compromise; "
                       "KIE is nonce-bearing unauthenticated HTTP2 probe; "
                       "graph is engineered context, not GNN.",
        "train_trials": [int(i) for i in all_trials[:-1]],
        "test_trials": [int(all_trials[-1])], "training_rows": len(train),
        "test_rows": {k: len(v) for k, v in tests.items()},
        "seed": seed}, "models": {}, "traffic": {}}
    fitted = {}
    for name, (cols, algo) in configurations.items():
        pipe = make_pipeline(SimpleImputer(strategy="constant", fill_value=1000),
                             algo)
        pipe.fit(train[cols], train[cols].index if isinstance(algo, IsolationForest)
                 else y_train)
        fitted[name] = (cols, pipe)
        results["models"][name] = {}
        if isinstance(algo, IsolationForest):
            normal_scores = -pipe.decision_function(train.loc[train["label"] == 0, cols])
            threshold = float(np.quantile(normal_scores, 0.99))
        else:
            threshold = 0.5
        for group, sample in tests.items():
            if isinstance(algo, IsolationForest):
                score = -pipe.decision_function(sample[cols])
            else:
                score = pipe.predict_proba(sample[cols])[:, 1]
            pred = (score >= threshold).astype(int)
            result = metrics(sample["label"].to_numpy(dtype=int), score, pred)
            result.update(delays(sample, pred))
            result["threshold"] = threshold
            results["models"][name][group] = result
    for group, sample in tests.items():
        results["traffic"][group] = {
            "queries": int(sample["observed"].sum()),
            "request_bytes_app_estimate": int(sample["request_bytes"].sum()),
            "response_body_bytes": int(sample["response_body_bytes"].sum()),
            "observed_fraction": float(sample["observed"].mean()),
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2, allow_nan=False), encoding="utf8")
    table = []
    for name, groups in results["models"].items():
        for policy, res in groups.items():
            table.append({"model": name, "policy": policy, **res})
    pd.DataFrame(table).to_csv(output.with_suffix(".csv"), index=False)
    print(json.dumps(results, indent=2, allow_nan=False))
    return results


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--fixed", required=True, type=Path)
    p.add_argument("--adaptive", type=Path)
    p.add_argument("--output", default="results/metrics.json", type=Path)
    p.add_argument("--seed", default=42, type=int)
    a = p.parse_args()
    experiment(a.fixed, a.adaptive, a.output, a.seed)


if __name__ == "__main__":
    main()
