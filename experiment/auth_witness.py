"""Non-invasive real 5GC AUSF->UDM routing witness.

READ ONLY, except restarting disposable UE/AUSF lab containers to cause
a fresh real registration. No notification forgery, traffic redirection
or Open5GS NF-cache modification. TCP *headers* only, no packet payload.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from experiment.collect import probe
from experiment.features import IP

NRF = f"10.45.0.{IP['nrf']}"
AUSF = f"10.45.0.{IP['ausf']}"
UDM = f"10.45.0.{IP['udm']}"
SBI = 7777


def command(*args, cwd=None, timeout=40, check=True):
    r = subprocess.run(args, text=True, capture_output=True, cwd=cwd,
                       timeout=timeout, check=False)
    if check and r.returncode:
        raise RuntimeError(f"{args!r} failed: {r.stderr[-600:]}")
    return r


def nrf_udm_discovery(expected_udms: set[str] | None = None) -> dict:
    """Retrieve real UDM service endpoints from live NRF NFDiscovery.

    In the original single-UDM phase, require exactly the pinned UDM.
    During authorized dual-UDM failover, callers must explicitly supply
    their expected actual lab addresses; all NRF-reported UDM endpoints
    must be within this whitelist and no other NF type is trusted.
    """
    expected = {UDM} if expected_udms is None else set(expected_udms)
    if not expected:
        raise ValueError("Expected lab UDM allowlist is empty")
    r = command(
        "curl", "--noproxy", "*", "--http2-prior-knowledge", "-fSs",
        "--max-time", "5", "-G", f"http://{NRF}:{SBI}/nnrf-disc/v1/nf-instances",
        "--data-urlencode", "target-nf-type=UDM",
        "--data-urlencode", "requester-nf-type=AUSF", timeout=10)
    payload = json.loads(r.stdout)
    instances = payload.get("nfInstances")
    if not isinstance(instances, list) or not instances:
        raise RuntimeError("NRF did not return live UDM NF profiles")
    addresses = set()
    service_ids = []
    for nf in instances:
        if nf.get("nfType") != "UDM":
            continue
        services = nf.get("nfServices") or list(
            (nf.get("nfServiceList") or {}).values())
        for s in services:
            if s.get("serviceName") != "nudm-ueau":
                continue
            service_ids.append(nf.get("nfInstanceId", ""))
            for ep in s.get("ipEndPoints", []):
                if ep.get("ipv4Address"):
                    addresses.add(ep["ipv4Address"])
            if s.get("apiPrefix"):
                host = urlparse(s["apiPrefix"]).hostname
                if host and re.fullmatch(r"[\d.]+", host):
                    addresses.add(host)
            if not addresses:
                addresses.update(nf.get("ipv4Addresses") or [])
    # Lab contract: ensure we did not accidentally query a different network.
    if not addresses or not addresses.issubset(expected):
        raise RuntimeError(
            f"Unexpected live NRF UDM discovery: {sorted(addresses)} "
            f"(expected subset of {sorted(expected)})")
    return {"udm_ips": sorted(addresses),
            "nf_instance_ids": service_ids,
            "instance_count": len(instances),
            "source": "LIVE_NNRF_NFDISC_HTTP2"}


def tcp_syn_targets(text: str) -> list[str]:
    pattern = re.compile(
        r"\bIP\s+" + re.escape(AUSF) +
        r"\.\d+\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.7777:"
        r"\s+Flags\s+\[S\]")
    return [m.group(1) for line in text.splitlines()
            if (m := pattern.search(line))]


def pid_ausf() -> str:
    r = command("docker", "inspect", "-f", "{{.State.Pid}}",
                "open5gs-ausf").stdout.strip()
    if not r.isdecimal() or int(r) < 2:
        raise RuntimeError("Invalid AUSF netns PID")
    actual = command("sudo", "nsenter", "-t", r, "-n",
                     "ip", "-4", "addr", "show", "dev", "eth0").stdout
    if AUSF not in actual:
        raise RuntimeError("AUSF is not the expected pinned isolated test host")
    return r


def capture_one(pid: str, dest: Path, lab: str, seconds: int) -> bool:
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["sudo", "nsenter", "-t", pid, "-n",
           "tcpdump", "-i", "eth0", "-Q", "out", "-nn", "-tt", "-l",
           f"src host {AUSF} and tcp dst port {SBI}"]
    with dest.open("w") as out:
        p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
        try:
            time.sleep(1.5)
            if p.poll() is not None:
                raise RuntimeError("Read-only tcpdump unavailable")
            since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            command("docker", "compose", "--profile", "ran", "restart", "ue",
                    cwd=lab, timeout=70)
            tunnel = False
            registered = False
            for _ in range(seconds):
                logs = command("docker", "logs", "--since", since,
                               "ueransim-ue", timeout=7, check=False)
                # The result of 5G-AKA/registration, not PDU setup, is
                # the necessary ground truth for authentication routing.
                registered = registered or (
                    "Initial Registration is successful" in logs.stdout + logs.stderr)
                x = command("docker", "compose", "--profile", "ran",
                            "exec", "-T", "ue", "sh", "-lc",
                            "ip link show uesimtun0",
                            cwd=lab, timeout=7, check=False)
                tunnel = tunnel or x.returncode == 0
                if registered and tunnel:
                    break
                time.sleep(1)
            return registered, tunnel
        finally:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGINT)
                try:
                    p.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=6)


def collect(lab: Path, out: Path, trials: int = 2, seconds: int = 16) -> dict:
    if os.environ.get("CI_5GC_READONLY_AUTH_WITNESS") != "YES":
        raise RuntimeError("Explicit isolated-lab opt-in required")
    if lab.name != "open5gs-lab" or not (lab / "docker-compose.yml").is_file():
        raise RuntimeError("Only pinned disposable Open5GS lab supported")
    if trials < 2:
        raise ValueError("Two+ real acquisitions required")
    command("which", "tcpdump")
    command("which", "nsenter")
    result = {"kind": "LIVE_AUSF_NRF_PASSIVE_CONSISTENCY",
              "scope": "Passive TCP header witness, UE/AUSF restarts only",
              "not_exploit": "No NFStatusNotify payload or AUSF NF cache change",
              "source_commit": os.environ.get("GITHUB_SHA", "local"),
              "trials": []}
    out.parent.mkdir(parents=True, exist_ok=True)
    for trial in range(trials):
        # AMF may reuse UE's prior NAS security context after just an
        # AUSF/UE restart and never initiate 5G-AKA. Clean AMF + gNB
        # restarts in this DISPOSABLE testbed force a fresh registration
        # path; no source code, cache entries or endpoint routes are edited.
        command("docker", "compose", "restart", "amf", cwd=str(lab), timeout=65)
        command("docker", "compose", "--profile", "ran", "restart", "gnb",
                cwd=str(lab), timeout=65)
        time.sleep(4)
        command("docker", "compose", "restart", "ausf", cwd=str(lab), timeout=65)
        ready = False
        for _ in range(40):
            if probe("ausf", 2)["up"]:
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("AUSF not available after clean test restart")
        nrf = nrf_udm_discovery()
        text_path = out.parent / f"real-ausf-tcp-trial{trial}.txt"
        registered, tunnel = capture_one(pid_ausf(), text_path, str(lab), seconds)
        targets = tcp_syn_targets(text_path.read_text())
        if not targets:
            raise RuntimeError("No live AUSF TCP SYN observed; fail closed")
        authorized = set(nrf["udm_ips"])
        if not authorized.intersection(targets):
            raise RuntimeError("No observed genuine AUSF->UDM authentication socket")
        if not registered:
            raise RuntimeError("UERANSIM UE did not complete 5G-AKA registration")
        local = {n: probe(n, 3)["up"] for n in ("nrf", "ausf", "udm")}
        row = {
            "trial": trial, "time_utc": datetime.now(timezone.utc).isoformat(),
            "authorized_udm": sorted(authorized), "observed_targets": sorted(set(targets)),
            "observed_udm_tcp_syn": sum(x in authorized for x in targets),
            "ue_registration_ok": int(registered), "ue_pdu_tun": int(tunnel),
            "local_sba_up": local,
            "cross_view_unexpected": sorted(
                set(targets) - authorized - {NRF}),
            "source_kind": "REAL_PASSIVE_HEADER_OBSERVATION",
            "capture_path": str(text_path),
            "nrf_discovery": nrf,
        }
        result["trials"].append(row)
        out.write_text(json.dumps(result, indent=2), encoding="utf8")
        print(json.dumps({"trial": trial, "observed_targets": row["observed_targets"],
                          "auth_registered": row["ue_registration_ok"],
                          "pdu_tun": row["ue_pdu_tun"]}), flush=True)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("results/auth_witness.json"))
    p.add_argument("--trials", type=int, default=2)
    p.add_argument("--seconds", type=int, default=16)
    a = p.parse_args()
    collect(a.lab, a.output, a.trials, a.seconds)


if __name__ == "__main__":
    main()
