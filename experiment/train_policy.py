"""Train a NORMAL-ONLY anomaly ranking model for later active probe selection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from experiment.features import POLICY, enrich


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("csv")
    p.add_argument("--output", default="results/policy.joblib")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    raw = pd.read_csv(args.csv)
    if not (raw["probe_kind"] == "live_sba_http2").all():
        raise ValueError("Policy training requires LIVE SBA measurements")
    feat = enrich(raw)
    train = feat[(feat["phase"] == "baseline") & (feat["label"] == 0)]
    if len(train) < 30:
        raise ValueError("Insufficient real normal samples for adaptive ranking")
    # Online collector uses a fixed RTT sentinel 1000 ms for missing responses.
    x = train[POLICY].fillna({"rtt_ms": 1000}).fillna(0).to_numpy()
    model = IsolationForest(n_estimators=128, contamination=0.05,
                            random_state=args.seed, n_jobs=1)
    model.fit(x)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, target)
    target.with_suffix(".metadata.json").write_text(json.dumps({
        "training_source": args.csv, "rows": len(train), "features": POLICY,
        "fit_only_normal": True, "random_state": args.seed,
        "evidence": "live_5gc_sba_http2",
    }, indent=2), encoding="utf8")
    print(f"Trained on {len(train)} benign observations: {target}")


if __name__ == "__main__":
    main()
