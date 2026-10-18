"""Safety, source-integrity and restored-path tests, NOT synthetic evidence."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from experiment.auth_witness import NRF, UDM
from experiment.eval_auth_route import SINK
from experiment.route_fault import KIND, SOURCES, firewall
from experiment.eval_route_fault import evaluate


def observed_sample(name: str, label: int) -> dict:
    actual = SINK if label else UDM
    return {
        "name": name, "ground_truth": label,
        "source_kind": "REAL_NETWORK_HEADERS_AND_LIVE_NRF",
        "fault_kind": "CONTROLLED_NAMESPACE_NAT_OUTPUT_DNAT" if label else "NONE",
        "nrf_authorized_udms": [UDM],
        "observed_targets": [NRF, actual],
        "unregistered_targets": [SINK] if label else [],
        "real_tcp_syn_to_pcf": int(label),
        "real_tcp_syn_to_udm": int(not label),
        "nrf_and_nf_probes_up": {"nrf": 1, "ausf": 1, "udm": 1, "pcf": 1},
        "ue_registration_ok": int(not label),
        "ue_pdu_tun": int(not label),
        "network_layer_route_error_detected": label,
    }


def fixture() -> dict:
    return {
        "kind": KIND,
        "intervention_type": "REAL_NETNS_TRANSPORT_REDIRECT_NOT_NF_CACHE_POISONING",
        "NFStatusNotify_forged": False,
        "trials": [observed_sample("0-injected", 1),
                   observed_sample("0-restored", 0)],
    }


def test_scoped_rule_may_only_reference_genuine_pinned_udms():
    with patch("experiment.route_fault.command",
               return_value=SimpleNamespace(returncode=0)) as call:
        firewall("123", "-I", UDM)
    args = call.call_args.args
    assert args[:7] == ("sudo", "nsenter", "-t", "123", "-n", "iptables", "-w")
    assert "-t" in args and "nat" in args and "OUTPUT" in args
    assert "-d" in args and UDM in args and SINK in args
    with pytest.raises(ValueError):
        firewall("123", "-I", "203.0.113.8")
    with pytest.raises(ValueError):
        firewall("123", "-F", UDM)


def test_strict_live_metric_provenance_and_real_packet_evidence(tmp_path: Path):
    p = tmp_path / "live.json"
    doc = fixture()
    before = json.dumps(doc, indent=2)
    p.write_text(before)
    summary = evaluate(p, tmp_path / "metrics.json")
    assert p.read_text() == before
    assert summary["real_fault_positive_samples"] == 1
    assert summary["real_recovered_negative_samples"] == 1
    assert summary["artificial_positive_samples"] == 0
    assert summary["metrics_on_real_captured_packets_only"]["live_nrf_consistency"] == {
        "tp": 1, "fn": 0, "fp": 0, "tn": 1, "recall": 1., "fpr": 0.}
    assert summary["metrics_on_real_captured_packets_only"]["availability_only"]["fn"] == 1
    assert "REAL_5GC_WITH_SCOPED_NAMESPACE_FAULT" in (tmp_path / "metrics.csv").read_text()


@pytest.mark.parametrize("change", [
    lambda d: d["trials"][0].update(real_tcp_syn_to_pcf=0),
    lambda d: d["trials"][0].update(observed_targets=[NRF, UDM]),
    lambda d: d["trials"][0].update(source_kind="ARTIFICIAL"),
    lambda d: d["trials"][0].update(nrf_authorized_udms=[]),
    lambda d: d["trials"][0].update(ground_truth=0),
    lambda d: d["trials"][1].update(real_tcp_syn_to_pcf=1),
    lambda d: d["trials"][1].update(ue_registration_ok=0),
    lambda d: d.update(NFStatusNotify_forged=True),
    lambda d: d.update(intervention_type="UNKNOWN"),
])
def test_fail_closed_on_missing_or_mislabeled_real_evidence(tmp_path, change):
    raw = fixture()
    change(raw)
    p = tmp_path / "source.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        evaluate(p, tmp_path / "result.json")


def test_refuse_incomplete_fault_recovery_pair(tmp_path: Path):
    raw = fixture()
    raw["trials"].pop()
    p = tmp_path / "source.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="Incomplete"):
        evaluate(p, tmp_path / "metrics.json")
