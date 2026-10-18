"""Shared feature contract for active 5G SBA observations.

Independent observations are HTTP/2 reachability/RTT measurements over the
Open5GS SBA bridge. The method does NOT modify standard NRF procedures or
claim that unmodified NFs authenticate KIE challenges.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

NODES = ("nrf", "amf", "smf", "ausf", "udm", "udr", "pcf", "bsf")
IP = {"nrf": 11, "amf": 20, "smf": 21, "ausf": 22, "udm": 23,
      "udr": 24, "pcf": 25, "bsf": 26}
# Functional adjacency is a hypothesis for context, NOT a learned true N11 trace.
LINKS = (("nrf", n) for n in NODES if n != "nrf")
LINKS = tuple(LINKS) + (("amf", "ausf"), ("amf", "udm"), ("smf", "pcf"),
                        ("smf", "udm"), ("pcf", "bsf"), ("udm", "udr"))
NEIGHBORS = {n: set() for n in NODES}
for a, b in LINKS:
    NEIGHBORS[a].add(b)
    NEIGHBORS[b].add(a)

LOCAL = ["up", "rtt_ms", "age", "observed"]
TEMPORAL = ["prev_up", "prev_rtt", "rtt_delta", "up_rolling"]
ZONE = ["zone_up", "zone_rtt", "zone_deviation"]
GRAPH = ["neighbor_up", "neighbor_rtt", "neighbor_deviation", "degree"]
FULL = LOCAL + TEMPORAL + ZONE + GRAPH
POLICY = ["up", "rtt_ms", "age", "zone_deviation"]


def enrich(data: pd.DataFrame) -> pd.DataFrame:
    """Derive only causal node/peer features. Never use fault labels as input."""
    required = {"trial", "policy", "tick", "node", "up", "rtt_ms",
                "age", "observed", "label"}
    missing = required.difference(data.columns)
    if missing:
        raise ValueError(f"Missing observed columns: {sorted(missing)}")
    df = data.copy().sort_values(["policy", "trial", "tick", "node"])
    if df.duplicated(["policy", "trial", "tick", "node"]).any():
        raise ValueError("Duplicate node observation")
    grp = df.groupby(["policy", "trial", "node"], sort=False)
    df["prev_up"] = grp["up"].shift(1).fillna(1.0)
    df["prev_rtt"] = grp["rtt_ms"].shift(1)
    df["rtt_delta"] = (df["rtt_ms"] - df["prev_rtt"]).clip(-1000, 1000)
    df["up_rolling"] = grp["up"].transform(
        lambda x: x.shift(1).rolling(5, min_periods=1).mean()
    ).fillna(1)
    out = []
    for (_, _, _), tick in df.groupby(["policy", "trial", "tick"], sort=False):
        tick = tick.copy()
        for idx, row in tick.iterrows():
            peers = tick[tick["node"] != row["node"]]
            connected = tick[tick["node"].isin(NEIGHBORS.get(row["node"], set()))]
            def avg(frame: pd.DataFrame, key: str, default: float) -> float:
                v = pd.to_numeric(frame[key], errors="coerce").dropna()
                return float(v.mean()) if len(v) else default
            zone_up = avg(peers, "up", 1.0)
            zone_rtt = avg(peers, "rtt_ms", 0.0)
            nb_up = avg(connected, "up", 1.0)
            nb_rtt = avg(connected, "rtt_ms", 0.0)
            own_rtt = row["rtt_ms"]
            tick.loc[idx, "zone_up"] = zone_up
            tick.loc[idx, "zone_rtt"] = zone_rtt
            tick.loc[idx, "zone_deviation"] = abs(row["up"] - zone_up)
            tick.loc[idx, "neighbor_up"] = nb_up
            tick.loc[idx, "neighbor_rtt"] = nb_rtt
            tick.loc[idx, "neighbor_deviation"] = abs(row["up"] - nb_up)
            tick.loc[idx, "degree"] = len(NEIGHBORS.get(row["node"], ()))
        out.append(tick)
    df = pd.concat(out, ignore_index=True) if out else df
    for col in FULL:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    # A failed probe has unknown RTT, not a magically short zero RTT.
    # Impute using TRAINING statistics in evaluate.py; preserve NaN here.
    return df


def online_vector(state: dict, node: str) -> list[float]:
    others = [x["up"] for k, x in state.items() if k != node]
    zone = float(np.mean(others)) if others else 1.0
    x = state[node]
    return [float(x["up"]), float(x["rtt_ms"] if np.isfinite(x["rtt_ms"]) else 1000),
            float(x["age"]), abs(float(x["up"]) - zone)]
