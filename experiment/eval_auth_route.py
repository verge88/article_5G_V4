"""Evaluate independent NRF/AUSF evidence with STRICT source provenance.

Real observations are unchanged. Altered destinations are copied into a
SEPARATE, clearly labeled artificial-counterfactual dataset used only for
detector integration tests, not a claim of executing cache poisoning.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from experiment.auth_witness import NRF, UDM
from experiment.features import IP

SINK = f"10.45.0.{IP['pcf']}"
FIELDS = ("trial", "kind", "ground_truth", "nrf_expected_udm",
          "ausf_observed_targets", "local_sba_all_up",
          "local_alarm", "cross_view_alarm", "provenance")


def disagreement(allowed: set[str], observed: set[str]) -> int:
    if not allowed or not observed:
        raise ValueError("Cannot infer safe routing when either observer is missing")
    if NRF in allowed:
        raise ValueError("NRF is not a UDM")
    unknown = observed - allowed - {NRF}
    return int(bool(unknown))


def row(trial: int, kind: str, truth: int, allowed: set[str],
        targets: set[str], local: dict, provenance: str) -> dict:
    if set(local) != {"nrf", "ausf", "udm"}:
        raise ValueError("All local NF availability checks are required")
    if any(int(v) not in (0, 1) for v in local.values()):
        raise ValueError("Invalid local availability status")
    return {
        "trial": trial, "kind": kind, "ground_truth": truth,
        "nrf_expected_udm": ";".join(sorted(allowed)),
        "ausf_observed_targets": ";".join(sorted(targets)),
        "local_sba_all_up": int(all(local.values())),
        "local_alarm": int(not all(local.values())),
        "cross_view_alarm": disagreement(allowed, targets),
        "provenance": provenance,
    }


def evaluate(input_path: Path, output: Path) -> dict:
    data = json.loads(input_path.read_text())
    if data.get("kind") != "LIVE_AUSF_NRF_PASSIVE_CONSISTENCY":
        raise ValueError("Refusing non-live or unverified input")
    trials = data.get("trials", [])
    if len(trials) < 2:
        raise ValueError("Need multiple independently captured live trials")
    results = []
    for t in trials:
        if t.get("source_kind") != "REAL_PASSIVE_HEADER_OBSERVATION":
            raise ValueError("Missing real capture provenance")
        allowed, observed = set(t["authorized_udm"]), set(t["observed_targets"])
        if allowed != {UDM} or not (observed & allowed):
            raise ValueError("Live NRF and AUSF were not mutually consistent")
        if not t["ue_pdu_tun"]:
            raise ValueError("Live UE must authenticate successfully")
        if disagreement(allowed, observed):
            raise ValueError("Non-benign target found in clean baseline")
        if not all(t["local_sba_up"].values()):
            raise ValueError("All NF reachability checks must pass on clean baseline")
        results.append(row(t["trial"], "genuine_5gc_baseline", 0,
                           allowed, observed, t["local_sba_up"],
                           "REAL_OBSERVATION_NO_ANOMALY"))
        # DO NOT write manipulated targets into the live capture or its JSON.
        # This is a controlled analytic intervention on copied evidence.
        cf = (observed - {UDM}) | {SINK}
        results.append(row(t["trial"], "artificial_misdirection_metadata", 1,
                           allowed, cf, t["local_sba_up"],
                           "ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK"))
    metrics = {}
    for classifier, key in (("availability_only", "local_alarm"),
                             ("cross_view_consistency", "cross_view_alarm")):
        tp = sum(v["ground_truth"] == 1 and v[key] == 1 for v in results)
        fp = sum(v["ground_truth"] == 0 and v[key] == 1 for v in results)
        fn = sum(v["ground_truth"] == 1 and v[key] == 0 for v in results)
        tn = sum(v["ground_truth"] == 0 and v[key] == 0 for v in results)
        metrics[classifier] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": tp / (tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.with_suffix(".csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, FIELDS)
        writer.writeheader()
        writer.writerows(results)
    report = {
        "experiment": "REAL_AUSF_ROUTE_BASELINE_PLUS_SEPARATE_ARTIFICIAL_COUNTERFACTUAL",
        "source": str(input_path),
        "live_positive_attack_samples": 0,
        "live_negative_observations": len(trials),
        "generated_positive_observations": len(trials),
        "not_verified": [
            "No NFStatusNotify vulnerability attempted or reproduced",
            "No AUSF cache alteration, no real traffic redirection occurred",
            "Cross-view advantage is a designed logical property of the artificial mismatch",
            "No GNN trained or compared in this phase",
            "Live Open5GS version is 2.8.0, public advisory tested 2.7.7",
        ],
        "metrics_mixed_live_and_artificial": metrics,
        "rows": len(results),
        "trust_boundaries": "NRF discovery is unauthenticated HTTP2 read; "
                            "TCP observation is an independent host-side witness",
    }
    output.write_text(json.dumps(report, indent=2), encoding="utf8")
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/auth_witness.json"))
    p.add_argument("--output", type=Path, default=Path("results/auth_route_metrics.json"))
    a = p.parse_args()
    print(json.dumps(evaluate(a.input, a.output), indent=2))


if __name__ == "__main__":
    main()
