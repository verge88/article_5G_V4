"""LIVE 5G SA transport-layer misrouting fault, only in disposable AUSF netns.

This is NOT a forged NFStatusNotify, NF-cache poisoning, or AUSF compromise.
One temporary iptables OUTPUT DNAT rule diverts genuine AUSF TCP sessions
intended for lab UDM service to a REAL non-UDM PCF listener. The traffic,
NRF authority and restoration are observed independently and retained.
Only TCP SYN headers are recorded; no subscriber payloads or secrets.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment.auth_witness import (
    NRF, UDM, capture_one, command, nrf_udm_discovery, pid_ausf,
    tcp_syn_targets,
)
from experiment.collect import probe
from experiment.eval_auth_route import SINK
from experiment.legit_udm_switch import UDM_ALT, server_up

KIND = "LIVE_ISOLATED_AUSF_KERNEL_DNAT_MISROUTE"
SOURCES = (UDM, UDM_ALT)


def firewall(pid: str, mode: str, source: str):
    """The only permitted egress modification is a port-specific lab DNAT."""
    if mode not in ("-C", "-I", "-D") or source not in SOURCES:
        raise ValueError("Unsupported firewall modification")
    args = ("OUTPUT",) + (("1",) if mode == "-I" else ()) + (
        "-p", "tcp", "-d", source, "--dport", "7777",
        "-j", "DNAT", "--to-destination", SINK)
    return command("sudo", "nsenter", "-t", pid, "-n",
                   "iptables", "-w", "-t", "nat", mode, *args,
                   timeout=12, check=mode != "-C")


def reboot_auth_path(lab: Path) -> str:
    # Deliberately fresh AMF NAS context and AUSF process. Root firewall
    # rules are installed only AFTER the new AUSF namespace exists.
    command("docker", "compose", "restart", "amf", cwd=str(lab), timeout=70)
    command("docker", "compose", "--profile", "ran", "restart", "gnb",
            cwd=str(lab), timeout=70)
    time.sleep(4)
    command("docker", "compose", "restart", "ausf", cwd=str(lab), timeout=70)
    for _ in range(35):
        if probe("ausf", 2)["up"]:
            return pid_ausf()
        time.sleep(1)
    raise RuntimeError("AUSF unavailable after clean reboot")


def live_discovery() -> dict:
    nrf = nrf_udm_discovery(set(SOURCES))
    # Legitimately switched-off UDM_ALT may remain briefly registered;
    # never assume it has been purged. Instead verify that PCF is NEVER
    # claimed by NRF as a nudm-ueau service.
    if SINK in nrf["udm_ips"] or UDM not in nrf["udm_ips"]:
        raise RuntimeError("Unexpected NRF UDM authority during fault")
    return nrf


def live_sample(lab: Path, out: Path, name: str, expected: str) -> dict:
    nrf = live_discovery()  # GET real NRF before observing egress.
    pid = reboot_auth_path(lab)
    # A reboot can affect NF discoveries; re-read actual NRF state.
    nrf = live_discovery()
    cap = out / f"real-ausf-route-{name}.txt"
    rules = []
    try:
        if expected == "misdirected_pcf":
            # Both possible NRF-allowed UDM candidates are redirected to
            # the same fixed non-UDM PCF: prevents stale NRF service order
            # from selecting a bypass route.
            for src in SOURCES:
                if firewall(pid, "-C", src).returncode == 0:
                    raise RuntimeError(f"Preexisting lab DNAT rule for {src}")
                firewall(pid, "-I", src)
                rules.append(src)
                if firewall(pid, "-C", src).returncode:
                    raise RuntimeError("Cannot verify installed live netns DNAT")
        elif expected != "authentic_udm":
            raise ValueError("Unknown live sample expectation")
        registered, tunnel = capture_one(pid, cap, str(lab), 29)
        targets = tcp_syn_targets(cap.read_text(encoding="utf8"))
        trusted_up = {n: probe(n, 3)["up"] for n in ("nrf", "ausf", "udm", "pcf")}
        if not all(trusted_up.values()):
            raise RuntimeError("Required real NF probe failed in live observation")
        allowed = set(nrf["udm_ips"])
        unauthorized = sorted(set(targets) - allowed - {NRF})
        if expected == "misdirected_pcf":
            if SINK not in targets or not unauthorized:
                raise RuntimeError("Real network misrouting to PCF NOT observed")
            if not all(x in {NRF, SINK} for x in targets):
                raise RuntimeError(f"Unexpected extra egress target: {targets}")
        else:
            if not allowed.intersection(targets) or unauthorized:
                raise RuntimeError("Restored AUSF->UDM egress not genuinely verified")
            if not registered:
                raise RuntimeError("Restored UE did not register after removal of DNAT")
        return {
            "name": name, "time_utc": datetime.now(timezone.utc).isoformat(),
            "source_kind": "REAL_NETWORK_HEADERS_AND_LIVE_NRF",
            "fault_kind": "CONTROLLED_NAMESPACE_NAT_OUTPUT_DNAT" if rules else "NONE",
            "ground_truth": int(bool(rules)),
            "nrf_source": "LIVE_NNRF_NFDISC_HTTP2",
            "nrf_authorized_udms": nrf["udm_ips"],
            "observed_targets": sorted(set(targets)),
            "unregistered_targets": unauthorized,
            "real_tcp_syn_to_pcf": targets.count(SINK),
            "real_tcp_syn_to_udm": sum(x in allowed for x in targets),
            "nrf_and_nf_probes_up": trusted_up,
            "ue_registration_ok": int(registered),
            "ue_pdu_tun": int(tunnel),
            "network_layer_route_error_detected": int(bool(unauthorized)),
            "capture_path": str(cap),
            "declared_mechanism": "AUSF netns Linux OUTPUT DNAT, not Open5GS AUSF cache",
        }
    finally:
        # Always restore kernel namespace on failure, too. Never leave a
        # deliberate redirect on the disposable lab's auth plane.
        for src in reversed(rules):
            firewall(pid, "-D", src)
            if firewall(pid, "-C", src).returncode == 0:
                raise RuntimeError("DNAT cleanup verification failed")


def collect(lab: Path, out: Path, cycles: int = 1) -> dict:
    if os.environ.get("CI_5GC_READONLY_AUTH_WITNESS") != "YES":
        raise RuntimeError("Explicit isolated-lab opt-in required")
    if lab.name != "open5gs-lab" or not (lab / "docker-compose.yml").is_file():
        raise RuntimeError("Only the pinned disposable Open5GS lab supported")
    if not 1 <= cycles <= 3:
        raise ValueError("Only 1–3 independently generated fault cycles are supported")
    command("which", "iptables")
    command("which", "tcpdump")
    command("which", "nsenter")
    if not server_up(SINK) or not server_up(UDM):
        raise RuntimeError("Genuine PCF and primary UDM must be listening")
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "kind": KIND, "source_sha": os.environ.get("GITHUB_SHA", "local"),
        "lab_scope": "Pinned disposable Open5GS 2.8.0 & UERANSIM",
        "intervention_type": "REAL_NETNS_TRANSPORT_REDIRECT_NOT_NF_CACHE_POISONING",
        "NFStatusNotify_forged": False,
        "prior_real_benign_controls": "results/legit_udm_switch.json",
        "trials": [],
    }
    for i in range(cycles):
        for label, expectation in (("injected", "misdirected_pcf"),
                                   ("restored", "authentic_udm")):
            row = live_sample(lab, out.parent, f"cycle{i}-{label}", expectation)
            report["trials"].append(row)
            out.write_text(json.dumps(report, indent=2), encoding="utf8")
            print(json.dumps({"sample": row["name"], "real_pcf_syn": row["real_tcp_syn_to_pcf"],
                              "real_udm_syn": row["real_tcp_syn_to_udm"],
                              "cross_view_alarm": row["network_layer_route_error_detected"],
                              "registration": row["ue_registration_ok"]}), flush=True)
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("results/real_route_fault.json"))
    p.add_argument("--cycles", type=int, default=1)
    a = p.parse_args()
    print(json.dumps({"sample_count": len(collect(a.lab, a.output, a.cycles)["trials"])},
                     indent=2))


if __name__ == "__main__":
    main()
