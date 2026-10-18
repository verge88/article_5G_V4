"""Compare real measured AUSF route discrepancy with reachability baselines.

This phase deliberately injects *network-namespace DNAT*, not an Open5GS
NF cache poisoning exploit. Unlike previous phases' offline metadata
copies, the positive samples here need ACTUAL new AUSF TCP SYN headers
addressed to the unregistered genuine PCF endpoint. Source provenance,
ground-truth phase, and real original/restored NF observations are checked.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from experiment.auth_witness import NRF, UDM
from experiment.eval_auth_route import SINK, disagreement
from experiment.legit_udm_switch import UDM_ALT
from experiment.route_fault import KIND

FIELDS = (
    "name", "phase", "origin", "ground_truth", "nrf_authorized",
    "observed_ausf", "ue_registration_ok", "availability_only",
    "live_nrf_consistency", "static_udm_pin",
)


def evaluate(path: Path, output: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf8"))
    if doc.get("kind") != KIND:
        raise ValueError("Not an authenticated live transport-fault experiment")
    if doc.get("intervention_type") != "REAL_NETNS_TRANSPORT_REDIRECT_NOT_NF_CACHE_POISONING":
        raise ValueError("Unknown fault mechanism/provenance")
    if doc.get("NFStatusNotify_forged") is not False:
        raise ValueError("Forged NF status outside safety scope")
    trials = doc.get("trials", [])
    if len(trials) < 2 or len(trials) % 2:
        raise ValueError("Incomplete fault-and-restoration trials")
    rows = []
    for i, trial in enumerate(trials):
        truth = int(i % 2 == 0)
        if trial.get("ground_truth") != truth:
            raise ValueError("Fault and recovery phases must alternate")
        if trial.get("source_kind") != "REAL_NETWORK_HEADERS_AND_LIVE_NRF":
            raise ValueError("Missing live source provenance")
        expected_fault_kind = "CONTROLLED_NAMESPACE_NAT_OUTPUT_DNAT" if truth else "NONE"
        if trial.get("fault_kind") != expected_fault_kind:
            raise ValueError("Ground truth does not match actual declared network modification")
        allowed, observed = set(trial["nrf_authorized_udms"]), set(trial["observed_targets"])
        if not allowed or not allowed.issubset({UDM, UDM_ALT}) or UDM not in allowed:
            raise ValueError("No independent actual NRF UDM authorization")
        probes = trial.get("nrf_and_nf_probes_up", {})
        if set(probes) != {"nrf", "ausf", "udm", "pcf"} or not all(probes.values()):
            raise ValueError("Required real NF listener measurements absent")
        if truth:
            if SINK not in observed or trial.get("real_tcp_syn_to_pcf", 0) < 1:
                raise ValueError("Injected fault has NO captured real AUSF TCP SYN to PCF")
            if not set(trial.get("unregistered_targets", [])).issuperset({SINK}):
                raise ValueError("Badly attributed injected destination")
            if trial.get("real_tcp_syn_to_udm") != 0:
                raise ValueError("Fault bypassed: genuine UDM connection appeared too")
        else:
            if not allowed.intersection(observed) or trial.get("real_tcp_syn_to_udm", 0) < 1:
                raise ValueError("Restoration has NO actual AUSF TCP SYN to registered UDM")
            if trial.get("real_tcp_syn_to_pcf") != 0:
                raise ValueError("Fault persisted after cleanup")
            if trial.get("ue_registration_ok") != 1:
                raise ValueError("Real restored UE registration failed")
        cross = disagreement(allowed, observed)
        if cross != truth or trial.get("network_layer_route_error_detected") != cross:
            raise ValueError("Live alarm disagrees with actually captured packets")
        rows.append({
            "name": trial["name"],
            "phase": "real_redirected_transport" if truth else "real_clean_restoration",
            "origin": "REAL_5GC_WITH_SCOPED_NAMESPACE_FAULT",
            "ground_truth": truth,
            "nrf_authorized": ";".join(sorted(allowed)),
            "observed_ausf": ";".join(sorted(observed)),
            "ue_registration_ok": trial["ue_registration_ok"],
            "availability_only": 0 if all(probes.values()) else 1,
            "live_nrf_consistency": cross,
            "static_udm_pin": disagreement({UDM}, observed),
        })
    summary = {}
    for algo in ("availability_only", "live_nrf_consistency", "static_udm_pin"):
        tp = sum(r["ground_truth"] and r[algo] for r in rows)
        fn = sum(r["ground_truth"] and not r[algo] for r in rows)
        fp = sum(not r["ground_truth"] and r[algo] for r in rows)
        tn = sum(not r["ground_truth"] and not r[algo] for r in rows)
        summary[algo] = {
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": tp / (tp + fn) if tp + fn else None,
            "fpr": fp / (fp + tn) if fp + tn else None,
        }
    report = {
        "experiment": "GENUINE_AUSF_NETNS_TCP_MISROUTE_TO_NON_UDM_NF",
        "intervention": doc["intervention_type"],
        "real_fault_positive_samples": len(rows) // 2,
        "real_recovered_negative_samples": len(rows) // 2,
        "artificial_positive_samples": 0,
        "attack_label_scope": "intentionally injected kernel DNAT transport fault; not native 5G NF compromise",
        "metrics_on_real_captured_packets_only": summary,
        "per_experiment_rows": len(rows),
        "limitations": [
            "No NFStatusNotify poisoning or untrusted AUSF cache contents were produced",
            "Kernel-output DNAT is a real route diversion in one disposable AUSF namespace, not an AUSF application-layer decision",
            "The destination is a genuine PCF listener, not attacker-owned UDM",
            "TCP SYN proves egress destination, not full 5G SBI semantic transaction or actual authentication data compromise",
            "Monitoring NRF and PCF reachability alone lacks information about an AUSF network-namespace NAT rewrite",
            "The simple cross-view invariant is a deterministic oracle once NRF and packet destinations are available",
            "The prior graph-GRU model has no route destination input; superiority claims are not possible",
            "One lab and very few faults cannot estimate generalization or real-world detection performance",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf8")
    with output.with_suffix(".csv").open("w", newline="", encoding="utf8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, default=Path("results/real_route_fault.json"))
    p.add_argument("--output", type=Path, default=Path("results/real_route_fault_metrics.json"))
    a = p.parse_args()
    print(json.dumps(evaluate(a.input, a.output), indent=2))


if __name__ == "__main__":
    main()
