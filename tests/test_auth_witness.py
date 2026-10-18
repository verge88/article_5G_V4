"""Fixture tests for READ-ONLY AUSF/NRF consistency witness."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from experiment.auth_witness import (
    AUSF, UDM, command, nrf_udm_discovery, tcp_syn_targets,
)
from experiment.eval_auth_route import disagreement, evaluate


def test_parse_only_outbound_tcp_syn_and_never_app_payload():
    capture = (
        f"1710.111 IP {AUSF}.54122 > {UDM}.7777: Flags [S], seq 1, win 1024\n"
        f"1710.222 IP {AUSF}.54122 > {UDM}.7777: Flags [P.], seq 1\n"
        f"1710.333 IP {UDM}.7777 > {AUSF}.54122: Flags [S.], seq 1\n"
        f"1710.444 IP {AUSF}.45555 > 10.45.0.11.7777: Flags [S], seq 42\n"
    )
    assert tcp_syn_targets(capture) == [UDM, "10.45.0.11"]


def test_retrieve_udm_from_nrf_discovery_only():
    payload = {"nfInstances": [
        {"nfType": "UDM", "nfInstanceId": "test-1", "nfStatus": "REGISTERED",
         "nfServices": [{
             "serviceName": "nudm-ueau", "ipEndPoints": [
                 {"ipv4Address": UDM, "port": 7777}]}]},
    ]}
    with patch("experiment.auth_witness.command",
               return_value=SimpleNamespace(stdout=json.dumps(payload))):
        doc = nrf_udm_discovery()
    assert doc["udm_ips"] == [UDM]
    assert doc["instance_count"] == 1


def test_nrf_untrusted_endpoint_rejected():
    payload = {"nfInstances": [
        {"nfType": "UDM", "nfStatus": "REGISTERED",
         "nfServices": [{
             "serviceName": "nudm-ueau", "ipEndPoints": [
                 {"ipv4Address": "198.51.100.7"}]}]},
    ]}
    with patch("experiment.auth_witness.command",
               return_value=SimpleNamespace(stdout=json.dumps(payload))):
        with pytest.raises(RuntimeError, match="Unexpected live NRF"):
            nrf_udm_discovery()


def test_cross_view_observer_rejects_mismatched_route():
    assert disagreement({UDM}, {UDM, "10.45.0.11"}) == 0
    assert disagreement({UDM}, {"10.45.0.25"}) == 1
    with pytest.raises(ValueError):
        disagreement(set(), {UDM})


def test_offline_counterfactual_keeps_real_trace_immutable(tmp_path: Path):
    original = {"kind": "LIVE_AUSF_NRF_PASSIVE_CONSISTENCY",
                "trials": []}
    for trial in range(2):
        original["trials"].append({
            "trial": trial, "authorized_udm": [UDM],
            "observed_targets": [UDM, "10.45.0.11"],
            "ue_pdu_tun": 1,
            "local_sba_up": {"nrf": 1, "ausf": 1, "udm": 1},
            "source_kind": "REAL_PASSIVE_HEADER_OBSERVATION",
        })
    source = tmp_path / "input.json"
    before = json.dumps(original, indent=2)
    source.write_text(before)
    metrics = evaluate(source, tmp_path / "out.json")
    assert source.read_text() == before
    assert metrics["live_positive_attack_samples"] == 0
    assert metrics["generated_positive_observations"] == 2
    assert metrics["metrics_mixed_live_and_artificial"]["availability_only"]["tp"] == 0
    assert metrics["metrics_mixed_live_and_artificial"]["cross_view_consistency"]["tp"] == 2
    rows = (tmp_path / "out.csv").read_text()
    assert "ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK" in rows
