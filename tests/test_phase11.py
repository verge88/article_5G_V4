"""Only synthetic fixtures for Phase 11 verifier integrity; NOT live 5G evidence."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from experiment.auth_witness import AUSF, NRF, UDM
from experiment.eval_auth_route import SINK
from experiment.eval_phase11 import (
    ALARM, KIND, NORMAL, UNKNOWN, EXPECTED, canonical_bytes, decide,
    digest, evaluate, raw_nrf_udm_addresses,
)


def test_three_valued_rule_never_conflates_missing_with_normal():
    assert decide([UDM], [NRF, UDM]) == NORMAL
    assert decide([UDM], [NRF, SINK]) == ALARM
    assert decide([UDM], [NRF]) == UNKNOWN
    assert decide([UDM], []) == UNKNOWN
    assert decide([], [UDM]) == UNKNOWN
    assert decide(None, [UDM]) == UNKNOWN
    assert decide([UDM], None) == UNKNOWN


def test_raw_nrf_parser_uses_actual_udm_service_not_arbitrary_nf():
    good = {"nfInstances": [
        {"nfType": "PCF", "nfServices": [{"serviceName": "npcf",
                                        "ipEndPoints": [{"ipv4Address": SINK}]}]},
        {"nfType": "UDM", "nfServices": [{"serviceName": "nudm-ueau",
                                        "ipEndPoints": [{"ipv4Address": UDM}]}]},
    ]}
    assert raw_nrf_udm_addresses(json.dumps(good).encode()) == [UDM]
    good["nfInstances"].pop()
    with pytest.raises(ValueError):
        raw_nrf_udm_addresses(json.dumps(good).encode())


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True,
                   capture_output=True, timeout=15)


def fake_syn(dest: str) -> str:
    return f"12:00:00.000000 IP {AUSF}.49152 > {dest}.7777: Flags [S], seq 1, win 65535\n"


def synthetic_signed_fixture(folder: Path):
    """Synthetic bytes are intentionally constructed, never actual packets."""
    secret = folder / "private-TEST-ONLY.pem"
    public = folder / "phase11_observer_pubkey.pem"
    openssl("genpkey", "-algorithm", "ED25519", "-out", secret)
    openssl("pkey", "-in", secret, "-pubout", "-out", public)
    nrf = json.dumps({"nfInstances": [
        {"nfType": "UDM", "nfServices": [
            {"serviceName": "nudm-ueau",
             "ipEndPoints": [{"ipv4Address": UDM}]}]}
    ]})
    index = {
        "kind": KIND, "source_sha": "SYNTHETIC_TEST_FIXTURE",
        "lab_scope": "PINNED_DISPOSABLE_OPEN5GS_UERANSIM",
        "public_key": public.name,
        "public_key_sha256": digest(public.read_bytes()),
        "rows": [],
    }
    for name, mask, truth in EXPECTED:
        audit = fake_syn(SINK if truth else UDM)
        policy = "" if mask == "packet_blind" else audit
        raw = {"audit": audit.encode(), "policy": policy.encode(),
               "nrf": nrf.encode()}
        files = {kind: f"phase11-{name}.{kind}.txt" for kind in raw}
        for kind, data in raw.items():
            (folder / files[kind]).write_bytes(data)
        policy_nrf = None if mask == "nrf_blind" else [UDM]
        record = {
            "kind": KIND, "source_kind": "REAL_HOST_TCP_HEADERS_AND_LIVE_NRF",
            "id": name, "mask": mask, "ground_truth": truth,
            "intervention": "REAL_AUSF_NETNS_DNAT_TO_PCF" if truth else "NONE_RESTORED",
            "nrf_source": "LIVE_NNRF_NFDISC_HTTP2",
            "files": files, "sha256": {k: digest(v) for k, v in raw.items()},
            "audit_authorized_udms": [UDM],
            "policy_authorized_udms": policy_nrf,
            "audit_targets": [SINK if truth else UDM],
            "policy_targets": [] if mask == "packet_blind" else [SINK if truth else UDM],
            "nf_probes_up": {n: True for n in ("nrf", "ausf", "udm", "pcf")},
            "ue_registration_ok": not truth, "ue_pdu_tun": not truth,
            "policy_decision": decide(policy_nrf,
                                      [] if mask == "packet_blind" else [SINK if truth else UDM]),
        }
        manifest = folder / f"phase11-{name}.manifest.json"
        sig = folder / f"phase11-{name}.sig"
        manifest.write_bytes(canonical_bytes(record))
        openssl("pkeyutl", "-sign", "-rawin", "-inkey", secret,
                "-in", manifest, "-out", sig)
        index["rows"].append({"manifest": manifest.name, "signature": sig.name})
    path = folder / "phase11_native_observability.json"
    path.write_text(json.dumps(index))
    return path


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI unavailable")
def test_six_synthetic_signed_fixture_rows_are_audited_not_scored_as_live(tmp_path: Path):
    # Fixture verifies algorithm/cryptography, NOT an empirical 5G outcome.
    index = synthetic_signed_fixture(tmp_path)
    m = evaluate(index, tmp_path / "metrics.json")
    assert m["three_valued"]["decided"] == 2
    assert m["three_valued"]["unresolved_faults"] == 2
    assert m["three_valued"]["unresolved_clean"] == 2
    assert m["three_valued"]["tp"] == 1 and m["three_valued"]["tn"] == 1
    assert m["fail_open"]["fn"] == 2
    assert m["fail_closed"]["fp"] == 2
    assert m["availability_only"]["fn"] == 3
    assert (tmp_path / "metrics.csv").is_file()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI unavailable")
@pytest.mark.parametrize("tamper", ["audit", "nrf", "manifest", "signature", "missing"])
def test_signed_real_evidence_auditor_rejects_tampering(tmp_path: Path, tamper: str):
    index = synthetic_signed_fixture(tmp_path)
    item = json.loads(index.read_text())["rows"][0]
    manifest = tmp_path / item["manifest"]
    signature = tmp_path / item["signature"]
    row = json.loads(manifest.read_text())
    if tamper == "audit":
        (tmp_path / row["files"]["audit"]).write_text("fabricated normal packet")
    elif tamper == "nrf":
        (tmp_path / row["files"]["nrf"]).write_text("{}")
    elif tamper == "manifest":
        manifest.write_bytes(manifest.read_bytes() + b" ")
    elif tamper == "signature":
        signature.write_bytes(b"invalid")
    else:
        (tmp_path / row["files"]["policy"]).unlink()
    with pytest.raises(ValueError):
        evaluate(index, tmp_path / "metrics.json")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL CLI unavailable")
def test_refuse_incomplete_frozen_live_trial_grid(tmp_path: Path):
    index = synthetic_signed_fixture(tmp_path)
    doc = json.loads(index.read_text())
    doc["rows"].pop()
    index.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="Incomplete"):
        evaluate(index, tmp_path / "metrics.json")
