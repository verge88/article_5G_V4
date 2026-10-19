"""Prospective Phase 11 LIVE native Open5GS packet/NRF observer with abstention.

Two simultaneous host-side tcpdump processes capture headers from the actual
AUSF namespace. An independent audit witness is always complete. The policy
witness is deliberately blinded by a wrong BPF filter in one predeclared
cycle; the policy NRF observation is withheld in another. All real faults
are scoped, reversible Linux DNAT, NOT NF compromise or SBA cache poisoning.

An ephemeral HOST key signs canonical manifests and raw-file SHA256 digests.
This is NOT an Open5GS native signature or a trusted hardware attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from experiment.auth_witness import (
    AUSF, NRF, SBI, UDM, capture_one, command, nrf_udm_discovery,
    pid_ausf, tcp_syn_targets,
)
from experiment.collect import probe
from experiment.eval_auth_route import SINK
from experiment.eval_phase11 import KIND, MASKS, canonical_bytes, decide, digest
from experiment.legit_udm_switch import UDM_ALT, server_up
from experiment.route_fault import SOURCES, firewall, reboot_auth_path

SOURCE_KIND = "REAL_HOST_TCP_HEADERS_AND_LIVE_NRF"


def concurrent_capture(pid: str, audit_path: Path, policy_path: Path,
                       lab: Path, mask: str) -> tuple[bool, bool]:
    """Start the policy collector BEFORE the audited real UE registration."""
    # An intentionally wrong port filter is a REAL collector configuration
    # blind spot; it does not drop or rewrite packets on the network.
    port = 7778 if mask == "packet_blind" else SBI
    cmd = ["sudo", "nsenter", "-t", pid, "-n", "tcpdump", "-i", "eth0",
           "-Q", "out", "-nn", "-tt", "-l",
           f"src host {AUSF} and tcp dst port {port}"]
    with policy_path.open("w", encoding="utf8") as stream:
        p = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
        try:
            time.sleep(0.7)
            if p.poll() is not None:
                raise RuntimeError("Policy tcpdump could not start")
            # Reuse the already tested Phase 5-7 real AUSF TCP + UE capture.
            return capture_one(pid, audit_path, str(lab), 29)
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGINT)
                try:
                    p.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=6)
            if p.returncode not in (0, -signal.SIGINT):
                stderr = p.stderr.read() if p.stderr else ""
                raise RuntimeError("Policy tcpdump failed: " + stderr[-300:])
            if p.stderr:
                p.stderr.close()


def key_pair(folder: Path, secret: Path) -> tuple[Path, str]:
    command("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(secret))
    os.chmod(secret, 0o600)
    public = folder / "phase11_observer_pubkey.pem"
    command("openssl", "pkey", "-in", str(secret), "-pubout", "-out", str(public))
    fingerprint = digest(public.read_bytes())
    print(json.dumps({"phase11_host_observer_public_key_sha256": fingerprint,
                      "warning": "NOT Open5GS NF attestation or external PKI"}),
          flush=True)
    return public, fingerprint


def signed_record(folder: Path, secret: Path, record: dict) -> dict:
    stem = "phase11-" + record["id"]
    manifest = folder / (stem + ".manifest.json")
    signature = folder / (stem + ".sig")
    manifest.write_bytes(canonical_bytes(record))
    command("openssl", "pkeyutl", "-sign", "-rawin",
            "-inkey", str(secret), "-in", str(manifest),
            "-out", str(signature), timeout=15)
    return {"manifest": manifest.name, "signature": signature.name}


def acquire(lab: Path, folder: Path, secret: Path,
            cycle: int, mask: str, fault: bool) -> dict:
    phase = "injected" if fault else "restored"
    name = f"cycle{cycle}-{phase}"
    pid = reboot_auth_path(lab)
    raw_nrf = folder / f"phase11-{name}.nrf.json"
    # The audit NRF query is genuinely sent and its ORIGINAL raw JSON saved.
    nrf = nrf_udm_discovery(set(SOURCES), raw_path=raw_nrf)
    allowed = set(nrf["udm_ips"])
    if UDM not in allowed or SINK in allowed:
        raise RuntimeError("Unexpected live NRF UDM authority")
    audit_file = folder / f"phase11-{name}.audit.txt"
    policy_file = folder / f"phase11-{name}.policy.txt"
    installed = []
    try:
        if fault:
            for source in SOURCES:
                if firewall(pid, "-C", source).returncode == 0:
                    raise RuntimeError("Refusing preexisting AUSF namespace DNAT")
                firewall(pid, "-I", source)
                installed.append(source)
                if firewall(pid, "-C", source).returncode != 0:
                    raise RuntimeError("Scoped DNAT rule could not be verified")
        registered, tunnel = concurrent_capture(pid, audit_file, policy_file, lab, mask)
        audit_targets = sorted(set(tcp_syn_targets(audit_file.read_text(encoding="utf8"))))
        policy_targets = sorted(set(tcp_syn_targets(policy_file.read_text(encoding="utf8"))))
        audit_service = set(audit_targets) - {NRF}
        policy_service = set(policy_targets) - {NRF}
        probes = {nf: bool(probe(nf, 3)["up"]) for nf in ("nrf", "ausf", "udm", "pcf")}
        if not all(probes.values()):
            raise RuntimeError("Real NRF/AUSF/UDM/PCF listener unavailable")
        if fault:
            if audit_service != {SINK}:
                raise RuntimeError("Actual AUSF->PCF TCP SYN not audited under DNAT")
        else:
            if not audit_service or audit_service - allowed or not registered:
                raise RuntimeError("Real clean UDM egress and fresh UE registration absent")
        if mask == "packet_blind":
            if policy_service:
                raise RuntimeError("Intentionally blinded policy BPF captured service packets")
        elif policy_service != audit_service:
            raise RuntimeError("Concurrent audit and policy packet witnesses disagree")
        # Policy sees NO audit NRF data when the collection is withheld.
        policy_authorized = None if mask == "nrf_blind" else sorted(allowed)
        decision = decide(policy_authorized, policy_targets)
        expected = ("UNKNOWN" if mask != "complete" else
                    ("ALARM" if fault else "NORMAL"))
        if decision != expected:
            raise RuntimeError(f"Frozen Phase 11 decision {decision} != {expected}")
        paths = {"audit": audit_file, "policy": policy_file, "nrf": raw_nrf}
        record = {
            "kind": KIND, "source_kind": SOURCE_KIND, "id": name,
            "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "mask": mask, "ground_truth": int(fault),
            "intervention": "REAL_AUSF_NETNS_DNAT_TO_PCF" if fault else "NONE_RESTORED",
            "nrf_source": "LIVE_NNRF_NFDISC_HTTP2",
            "files": {k: p.name for k, p in paths.items()},
            "sha256": {k: digest(p.read_bytes()) for k, p in paths.items()},
            "audit_authorized_udms": sorted(allowed),
            "policy_authorized_udms": policy_authorized,
            "audit_targets": audit_targets,
            "policy_targets": policy_targets,
            "nf_probes_up": probes,
            "ue_registration_ok": bool(registered),
            "ue_pdu_tun": bool(tunnel),
            "policy_decision": decision,
            "sensor_note": ("policy tcpdump wrong BPF destination port 7778"
                            if mask == "packet_blind" else
                            "policy NRF observation intentionally not acquired"
                            if mask == "nrf_blind" else
                            "both policy witnesses enabled"),
        }
        item = signed_record(folder, secret, record)
        print(json.dumps({"live_episode": name, "mask": mask,
                          "actual_audit_service": sorted(audit_service),
                          "policy_decision": decision,
                          "ue_registration_ok": registered}), flush=True)
        return item
    finally:
        # Unconditionally remove the exact inserted namespace rules.
        for source in reversed(installed):
            firewall(pid, "-D", source)
            if firewall(pid, "-C", source).returncode == 0:
                raise RuntimeError("Scoped AUSF DNAT cleanup verification failed")


def collect(lab: Path, output: Path) -> dict:
    if os.environ.get("CI_5GC_READONLY_AUTH_WITNESS") != "YES":
        raise RuntimeError("Explicit disposable-lab opt-in required")
    if lab.name != "open5gs-lab" or not (lab / "docker-compose.yml").is_file():
        raise RuntimeError("Only pinned disposable Open5GS lab supported")
    for name in ("tcpdump", "nsenter", "openssl", "iptables"):
        command("which", name)
    if not server_up(UDM) or not server_up(SINK):
        raise RuntimeError("Real original UDM and PCF must be listening")
    folder = output.parent
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="phase11-host-key-") as temporary:
        secret = Path(temporary) / "observer-private.pem"
        public, fingerprint = key_pair(folder, secret)
        report = {
            "kind": KIND, "source_sha": os.environ.get("GITHUB_SHA", "local"),
            "lab_scope": "PINNED_DISPOSABLE_OPEN5GS_UERANSIM",
            "public_key": public.name, "public_key_sha256": fingerprint,
            "key_scope": "EPHEMERAL_HOST_OBSERVER_NOT_OPEN5GS_NF",
            "rows": [],
        }
        for cycle, mask in enumerate(MASKS):
            for fault in (True, False):
                report["rows"].append(acquire(lab, folder, secret, cycle, mask, fault))
                output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", type=Path, required=True)
    parser.add_argument("--output", type=Path,
                        default=Path("results/phase11_native_observability.json"))
    args = parser.parse_args()
    report = collect(args.lab, args.output)
    print(json.dumps({"signed_live_episodes": len(report["rows"]),
                      "observer_public_key_sha256": report["public_key_sha256"]},
                     indent=2))


if __name__ == "__main__":
    main()
