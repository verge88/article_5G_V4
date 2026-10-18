"""Separate genuine benign UDM transitions from artificial route-mismatch controls.

This is NOT a 5G attack experiment: no live positive attack samples and
no GNN comparison. Real negative controls are compared to static pinning
and dynamic independent live-NRF authorization. Artificial positives are
never included in live-real anomaly accuracy estimates.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from experiment.auth_witness import NRF, UDM
from experiment.eval_auth_route import SINK, disagreement
from experiment.legit_udm_switch import AUTH_TYPE, UDM_ALT

FIELDS = ("transition", "origin", "label", "observed_destination",
          "nrf_authorized", "static_udm_alarm", "live_nrf_consistency_alarm",
          "availability_anchor_alarm")


def evaluate(path: Path, output: Path) -> dict:
    raw = json.loads(path.read_text(encoding="utf8"))
    if raw.get("kind") != AUTH_TYPE or raw.get("source_kind") != "REAL_NF_REGISTERED_OPEN5GS_SWITCH":
        raise ValueError("Not a genuine two-instance Open5GS UDM witness")
    if int(raw.get("true_attack_samples", -1)) != 0:
        raise ValueError("True attack count cannot be present for a benign failover study")
    trials = raw.get("trials", [])
    if len(trials) < 2 or len(trials) % 2:
        raise ValueError("Require complete real switch AND recovery cycles")
    rows = []
    for t in trials:
        if t.get("source_kind") != "REAL_AUTHORIZED_UDM_SERVICE_CHANGE_NO_ATTACK":
            raise ValueError("Unexpected trace origin, refusing to mix data")
        allowed = set(t["nrf_authorized_udms"])
        targets = set(t["ausf_actual_destinations"])
        chosen = t["selected_udm"]
        if not allowed or not allowed.issubset({UDM, UDM_ALT}) or chosen not in allowed:
            raise ValueError("Invalid real NRF-authorized UDM set")
        if chosen not in targets or not t.get("ausf_to_selected_syn_count", 0):
            raise ValueError("Missing real AUSF SYN to declared newly selected UDM")
        if not t.get("ue_registration_ok") or not all(t.get("sba_up", {}).values()):
            raise ValueError("Real UE registration / live NRF AUSF probe missing")
        if t.get("cross_view_alarm") != 0 or disagreement(allowed, targets):
            raise ValueError("Real authorized transition disagrees with live NRF")
        rows.append({
            "transition": t["transition"], "origin": "REAL_BENIGN_LIVE_NF_SWITCH",
            "label": 0, "observed_destination": ";".join(sorted(targets)),
            "nrf_authorized": ";".join(sorted(allowed)),
            # A single-UDM hardcoded policy is a deliberately poor baseline
            # when there is REAL live redundancy.
            "static_udm_alarm": disagreement({UDM}, targets),
            "live_nrf_consistency_alarm": disagreement(allowed, targets),
            "availability_anchor_alarm": int(not all(t["sba_up"].values())),
        })
        # Analytic POSITIVE is made by copying only metadata, never the
        # actual real capture, NF registration, or transport.
        generated = (targets - {UDM, UDM_ALT}) | {SINK}
        rows.append({
            "transition": t["transition"],
            "origin": "ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK",
            "label": 1, "observed_destination": ";".join(sorted(generated)),
            "nrf_authorized": ";".join(sorted(allowed)),
            "static_udm_alarm": disagreement({UDM}, generated),
            "live_nrf_consistency_alarm": disagreement(allowed, generated),
            "availability_anchor_alarm": int(not all(t["sba_up"].values())),
        })
    actual = [r for r in rows if r["origin"] == "REAL_BENIGN_LIVE_NF_SWITCH"]
    simulated = [r for r in rows if r["origin"].startswith("ARTIFICIAL_")]
    metrics = {}
    for name in ("static_udm_alarm", "live_nrf_consistency_alarm",
                 "availability_anchor_alarm"):
        metrics[name] = {
            "live_benign_trials": len(actual),
            "live_false_alarms": sum(r[name] for r in actual),
            "live_fpr": sum(r[name] for r in actual) / len(actual),
            "artificial_positive_rows": len(simulated),
            "artificial_true_positives": sum(r[name] for r in simulated),
            "artificial_recall": sum(r[name] for r in simulated) / len(simulated),
        }
    report = {
        "experiment": "REAL_LEGITIMATE_NRF_REGISTERED_UDM_SWITCH_WITH_SEPARATE_ARTIFICIAL_MISMATCH",
        "source": str(path),
        "real_authorized_negative_controls": len(actual),
        "real_positive_attacks": 0,
        "artificial_positive_controls": len(simulated),
        "metrics_by_separate_source": metrics,
        "correct_method": "current authorized UDM set independently queried via live NRF",
        "limitations": [
            "This experiment validates benign failover and an invariant, not live NFStatusNotify poisoning",
            "The artificial route-mismatch positives were never transmitted on the 5G network",
            "The second UDM is a genuine, authorized Open5GS service inside one disposable lab",
            "Static singleton UDM pinning is an intentionally inappropriate live failover baseline",
            "No GNN is trained or evaluated; Phase 4 GNN only ranks two test-agent KIEs",
            "Small number of shared-lab switching controls cannot establish false alarm performance at operator scale",
            "An NRF/NF discovery timing window may require expiry or an explicit convergence policy in production",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf8")
    with output.with_suffix(".csv").open("w", encoding="utf8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(json.dumps(metrics, indent=2))
    return report


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/legit_udm_switch.json"))
    p.add_argument("--output", type=Path, default=Path("results/legit_udm_switch_metrics.json"))
    a = p.parse_args()
    evaluate(a.input, a.output)


if __name__ == "__main__":
    main()
