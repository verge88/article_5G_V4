"""Only structural unit tests. Fixtures are not live NF measurements."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from experiment.auth_witness import NRF, UDM, nrf_udm_discovery
from experiment.legit_udm_switch import (
    UDM_ALT, AUTH_TYPE, confirm_transition,
)
from experiment.eval_legit_switch import evaluate


def discovered(*addresses: str):
    return SimpleNamespace(stdout=json.dumps({
        "nfInstances": [
            {"nfType": "UDM", "nfInstanceId": f"udm-{i}",
             "nfStatus": "REGISTERED",
             "nfServices": [{
                 "serviceName": "nudm-ueau",
                 "ipEndPoints": [{"ipv4Address": addr, "port": 7777}],
             }]}
            for i, addr in enumerate(addresses)
        ]
    }))


def test_legacy_singleton_nrf_allowlist_still_enforced():
    with patch("experiment.auth_witness.command",
               return_value=discovered(UDM, UDM_ALT)):
        with pytest.raises(RuntimeError, match="Unexpected live NRF"):
            nrf_udm_discovery()


def test_explicit_second_udm_is_accepted_only_when_nrf_reports_it():
    with patch("experiment.auth_witness.command",
               return_value=discovered(UDM, UDM_ALT)):
        answer = nrf_udm_discovery({UDM, UDM_ALT})
    assert set(answer["udm_ips"]) == {UDM, UDM_ALT}
    with patch("experiment.auth_witness.command",
               return_value=discovered(UDM, "10.45.0.44")):
        with pytest.raises(RuntimeError, match="Unexpected live NRF"):
            nrf_udm_discovery({UDM, UDM_ALT})


def test_authorized_second_udm_route_no_alarm():
    result = confirm_transition(
        nrf={"udm_ips": [UDM, UDM_ALT]},
        observed=[NRF, UDM_ALT], target=UDM_ALT, registered=True,
        all_sba={"nrf": 1, "ausf": 1})
    assert result["cross_view_alarm"] == 0
    assert result["real_nf_registry_consistent"] == 1


def test_denies_unregistered_routing_even_if_ue_attaches():
    with pytest.raises(RuntimeError, match="REGISTERED"):
        confirm_transition(
            nrf={"udm_ips": [UDM]}, observed=[UDM_ALT],
            target=UDM_ALT, registered=True, all_sba={"nrf": 1, "ausf": 1})


def test_denies_non_udm_route_even_when_target_present():
    with pytest.raises(RuntimeError, match="Unexpected real"):
        confirm_transition(
            nrf={"udm_ips": [UDM, UDM_ALT]},
            observed=[UDM_ALT, "10.45.0.25"], target=UDM_ALT,
            registered=True, all_sba={"nrf": 1, "ausf": 1})


def test_denies_absent_ue_registration():
    with pytest.raises(RuntimeError, match="registration"):
        confirm_transition(
            nrf={"udm_ips": [UDM, UDM_ALT]},
            observed=[UDM_ALT], target=UDM_ALT,
            registered=False, all_sba={"nrf": 1, "ausf": 1})


def fixture_switches():
    trials = []
    for i, selected in enumerate((UDM_ALT, UDM)):
        trials.append({
            "transition": f"0-{i}", "selected_udm": selected,
            "nrf_authorized_udms": [UDM, UDM_ALT] if i == 0 else [UDM],
            "ausf_actual_destinations": [NRF, selected],
            "ausf_to_selected_syn_count": 1,
            "ue_registration_ok": 1,
            "sba_up": {"nrf": 1, "ausf": 1},
            "cross_view_alarm": 0,
            "source_kind": "REAL_AUTHORIZED_UDM_SERVICE_CHANGE_NO_ATTACK",
        })
    return {"kind": AUTH_TYPE,
            "source_kind": "REAL_NF_REGISTERED_OPEN5GS_SWITCH",
            "true_attack_samples": 0,
            "trials": trials}


def test_real_benign_and_generated_counterfactual_not_mixed(tmp_path: Path):
    src = tmp_path / "source.json"
    content = json.dumps(fixture_switches(), indent=2)
    src.write_text(content)
    report = evaluate(src, tmp_path / "metrics.json")
    assert src.read_text() == content
    assert report["real_authorized_negative_controls"] == 2
    assert report["real_positive_attacks"] == 0
    assert report["artificial_positive_controls"] == 2
    method = report["metrics_by_separate_source"]["live_nrf_consistency_alarm"]
    assert method["live_fpr"] == 0.0 and method["artificial_recall"] == 1.0
    pin = report["metrics_by_separate_source"]["static_udm_alarm"]
    assert pin["live_false_alarms"] == 1
    assert "ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK" in (
        tmp_path / "metrics.csv").read_text()


def test_hard_fail_for_missing_recovery_row(tmp_path: Path):
    raw = fixture_switches()
    raw["trials"].pop()
    p = tmp_path / "input.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="complete real switch"):
        evaluate(p, tmp_path / "metrics.json")


def test_refuse_fake_network_origin(tmp_path: Path):
    raw = fixture_switches()
    raw["trials"][0]["source_kind"] = "ARTIFICIAL"
    p = tmp_path / "input.json"
    p.write_text(json.dumps(raw))
    with pytest.raises(ValueError, match="origin"):
        evaluate(p, tmp_path / "metrics.json")
