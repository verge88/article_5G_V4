"""Verify a REAL, authorized UDM service change under NRF supervision.

Defense-only experiment: starts/stops redundant genuine Open5GS UDMs in a
disposable lab. No forged NF notifications, bogus NF registration, route
poisoning, subscriber data interception or altered authentication messages.
Capture only TCP SYN headers and query NRF's actual HTTP/2 NFDiscovery.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment.auth_witness import (
    NRF, UDM, SBI, capture_one, command, nrf_udm_discovery, pid_ausf,
    tcp_syn_targets,
)
from experiment.collect import probe

UDM_ALT = "10.45.0.33"
AUTH_TYPE = "REAL_AUTHORIZED_UDM_ROUTING_TRANSITION"
POLL_TIMEOUT_SECONDS = 65


def server_up(host: str) -> bool:
    """TCP transport reachability is NOT NF service-function success."""
    try:
        with socket.create_connection((host, SBI), timeout=1.5):
            return True
    except OSError:
        return False


def wait_current_udm(target: str, timeout_seconds: int = POLL_TIMEOUT_SECONDS) -> dict:
    """Require a LIVE NRF UDM service record and a real listening target."""
    if target not in {UDM, UDM_ALT}:
        raise ValueError("Only the two pinned lab UDM endpoints are authorized")
    deadline = time.monotonic() + timeout_seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            snapshot = nrf_udm_discovery({UDM, UDM_ALT})
            if target in snapshot["udm_ips"] and server_up(target):
                return snapshot
            last = f"NRF registered {snapshot['udm_ips']}, tcp_up={server_up(target)}"
        except (RuntimeError, OSError) as exc:
            last = str(exc)
        time.sleep(2)
    raise RuntimeError(f"Live NRF never advertised reachable UDM {target}: {last}")


def confirm_transition(*, nrf: dict, observed: list[str], target: str,
                       registered: bool, all_sba: dict) -> dict:
    allowed = set(nrf["udm_ips"])
    if not allowed or not allowed.issubset({UDM, UDM_ALT}):
        raise RuntimeError("Real NRF endpoints not the pinned authorized UDMs")
    if target not in allowed or target not in observed:
        raise RuntimeError("Actual AUSF connection to selected REGISTERED UDM absent")
    if not registered:
        raise RuntimeError("UE did not complete real 5G-AKA registration")
    if set(all_sba) != {"nrf", "ausf"} or not all(all_sba.values()):
        raise RuntimeError("Core trust anchors NRF/AUSF unavailable")
    unexpected = set(observed) - allowed - {NRF}
    if unexpected:
        raise RuntimeError(f"Unexpected real AUSF->non-UDM destination: {sorted(unexpected)}")
    return {
        "real_nf_registry_consistent": 1,
        "cross_view_unexpected": [],
        "cross_view_alarm": 0,
        "availability_alarm_nrf_ausf": 0,
        # Deliberate switched-off previous UDM must not count as attack:
        # checking all formerly active UDMs is the WRONG baseline.
        "previous_udm_is_intentionally_offline": 1,
    }


def do_reauth(lab: Path, target: str, trial_id: str, nrf: dict,
              out_dir: Path, seconds: int) -> dict:
    # AMF's old NAS security context must not silently skip 5G-AKA.
    for args in (
        ("docker", "compose", "restart", "amf"),
        ("docker", "compose", "--profile", "ran", "restart", "gnb"),
    ):
        command(*args, cwd=str(lab), timeout=70)
    time.sleep(4)
    command("docker", "compose", "restart", "ausf", cwd=str(lab), timeout=70)
    for _ in range(35):
        if probe("ausf", 2)["up"]:
            break
        time.sleep(1)
    else:
        raise RuntimeError("AUSF unavailable after clean restart")
    capture_path = out_dir / f"real-authorized-switch-{trial_id}.txt"
    registered, tunnel = capture_one(pid_ausf(), capture_path,
                                     str(lab), seconds)
    observed = tcp_syn_targets(capture_path.read_text(encoding="utf8"))
    if not observed:
        raise RuntimeError("No live AUSF outgoing TCP SYN after switch")
    checks = {n: probe(n, 2)["up"] for n in ("nrf", "ausf")}
    result = confirm_transition(nrf=nrf, observed=observed, target=target,
                                registered=registered, all_sba=checks)
    return {
        "transition": trial_id, "capture_source": "LIVE_TCP_SYN_HEADER_ONLY",
        "nrf_source": "LIVE_NNRF_NFDISC_HTTP2",
        "source_kind": "REAL_AUTHORIZED_UDM_SERVICE_CHANGE_NO_ATTACK",
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "selected_udm": target, "nrf_authorized_udms": nrf["udm_ips"],
        "nrff_nf_ids": nrf["nf_instance_ids"],
        "ausf_actual_destinations": sorted(set(observed)),
        "ausf_to_selected_syn_count": observed.count(target),
        "ue_registration_ok": int(registered), "ue_pdu_tun": int(tunnel),
        "sba_up": checks, "capture_path": str(capture_path), **result,
    }


def collect(lab: Path, output: Path, overlay: Path, cycles: int = 1,
            seconds: int = 24) -> dict:
    if os.environ.get("CI_5GC_READONLY_AUTH_WITNESS") != "YES":
        raise RuntimeError("Explicit isolated-lab opt-in required")
    if lab.name != "open5gs-lab" or not (lab / "docker-compose.yml").is_file():
        raise RuntimeError("Only the pinned disposable Open5GS lab supported")
    if cycles < 1 or cycles > 4:
        raise ValueError("Expect 1-4 genuine switching cycles")
    if not overlay.is_file():
        raise FileNotFoundError(overlay)
    command("which", "tcpdump")
    command("which", "nsenter")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": AUTH_TYPE, "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "source_kind": "REAL_NF_REGISTERED_OPEN5GS_SWITCH",
        "lab": "pinned Open5GS 2.8.0, isolated disposable UERANSIM 5G SA",
        "not_attack": "No NFStatusNotify forgery, no cache poisoning; only actual NF process redundancy",
        "true_attack_samples": 0, "trials": [], "discovery": [],
    }
    # The original UDM is alive and stable after Phase 5:
    baseline = nrf_udm_discovery()
    if baseline["udm_ips"] != [UDM] or not server_up(UDM):
        raise RuntimeError("Original live single-UDM baseline unavailable")
    report["discovery"].append({"period": "before_redundant_udm",
                                "nrf_udm_ips": baseline["udm_ips"]})
    # Overlay is merged with the SAME upstream docker-compose.yml; it
    # supplies a real second process and never alters primary NF configs.
    stack = ("docker", "compose", "-f", "docker-compose.yml", "-f",
             str(overlay.resolve()))
    command(*stack, "config", "--quiet", cwd=str(lab), timeout=20)
    command(*stack, "up", "-d", "udm-alt", cwd=str(lab), timeout=120)
    concurrent = wait_current_udm(UDM_ALT)
    if UDM not in concurrent["udm_ips"]:
        raise RuntimeError("Dual-UDM NRF coexistence was never proven")
    report["discovery"].append({"period": "both_live_udms",
                                "nrf_udm_ips": concurrent["udm_ips"]})
    output.write_text(json.dumps(report, indent=2), encoding="utf8")
    for cycle in range(cycles):
        # Legitimate withdrawal of original live UDM, not DNS manipulation,
        # forged status callbacks or forced AUSF route alteration.
        command("docker", "compose", "stop", "udm", cwd=str(lab), timeout=85)
        if server_up(UDM):
            raise RuntimeError("Primary UDM still listening after controlled stop")
        nr_alt = wait_current_udm(UDM_ALT)
        result_alt = do_reauth(lab, UDM_ALT, f"{cycle}-original-to-alt",
                               nr_alt, output.parent, seconds)
        report["trials"].append(result_alt)
        output.write_text(json.dumps(report, indent=2), encoding="utf8")
        print(json.dumps({"transition": result_alt["transition"],
                          "selected": result_alt["selected_udm"],
                          "observed": result_alt["ausf_actual_destinations"],
                          "registered": result_alt["ue_registration_ok"]}),
              flush=True)

        # Restore original NRF-registered *real* UDM, retire the alternate
        # and prove authenticated traffic can be routed back without alarms.
        command(*stack, "stop", "udm-alt", cwd=str(lab), timeout=85)
        if server_up(UDM_ALT):
            raise RuntimeError("Alternate UDM still listening after stop")
        command("docker", "compose", "up", "-d", "udm", cwd=str(lab), timeout=95)
        nr_original = wait_current_udm(UDM)
        result_orig = do_reauth(lab, UDM, f"{cycle}-alt-to-original",
                                nr_original, output.parent, seconds)
        report["trials"].append(result_orig)
        output.write_text(json.dumps(report, indent=2), encoding="utf8")
        print(json.dumps({"transition": result_orig["transition"],
                          "selected": result_orig["selected_udm"],
                          "observed": result_orig["ausf_actual_destinations"],
                          "registered": result_orig["ue_registration_ok"]}),
              flush=True)
        if cycle + 1 < cycles:
            command(*stack, "up", "-d", "udm-alt", cwd=str(lab), timeout=95)
            both = wait_current_udm(UDM_ALT)
            if UDM not in both["udm_ips"]:
                raise RuntimeError("Dual-UDM NRF not recovered between cycles")
    return report


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("results/legit_udm_switch.json"))
    p.add_argument("--overlay", type=Path, required=True)
    p.add_argument("--cycles", type=int, default=1)
    p.add_argument("--seconds", type=int, default=24)
    a = p.parse_args()
    report = collect(a.lab, a.output, a.overlay, a.cycles, a.seconds)
    print(json.dumps({"genuine_authorized_transitions": len(report["trials"]),
                      "true_attack_samples": 0}, indent=2))


if __name__ == "__main__":
    main()
