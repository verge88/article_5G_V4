"""Phase 11: verify host-signed REAL packet/NRF evidence before abstention scoring.

No NF attestation is claimed. The Ed25519 key belongs to the CI host observer,
not to stock Open5GS. Synthetic test fixtures are never live evidence.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from experiment.auth_witness import NRF, UDM, tcp_syn_targets
from experiment.eval_auth_route import SINK
from experiment.legit_udm_switch import UDM_ALT

KIND = "PHASE11_HOST_SIGNED_NATIVE_EGRESS_V1"
MASKS = ("complete", "packet_blind", "nrf_blind")
NORMAL, ALARM, UNKNOWN = "NORMAL", "ALARM", "UNKNOWN"
EXPECTED = tuple(
    (f"cycle{i}-{phase}", mask, int(phase == "injected"))
    for i, mask in enumerate(MASKS)
    for phase in ("injected", "restored")
)


def canonical_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("utf8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decide(authorized: list[str] | None, observed: list[str] | None) -> str:
    """Use ONLY the policy's NRF and packet observations, never audit/truth."""
    if authorized is None or observed is None:
        return UNKNOWN
    allowed = set(authorized)
    # NRF discovery connections are not AUSF->UDM service transactions.
    destinations = set(observed) - {NRF}
    if not allowed or not destinations:
        return UNKNOWN
    return ALARM if destinations - allowed else NORMAL


def raw_nrf_udm_addresses(raw: bytes) -> list[str]:
    """Independently reparse actual archived NRF NFDiscovery JSON."""
    payload = json.loads(raw)
    instances = payload.get("nfInstances")
    if not isinstance(instances, list) or not instances:
        raise ValueError("Missing raw NRF NFDiscovery NF profiles")
    addresses = set()
    for nf in instances:
        if nf.get("nfType") != "UDM":
            continue
        services = nf.get("nfServices") or list((nf.get("nfServiceList") or {}).values())
        for service in services:
            if service.get("serviceName") != "nudm-ueau":
                continue
            for endpoint in service.get("ipEndPoints", []):
                if endpoint.get("ipv4Address"):
                    addresses.add(endpoint["ipv4Address"])
            if service.get("apiPrefix"):
                host = urlparse(service["apiPrefix"]).hostname
                if host and re.fullmatch(r"[\\d.]+", host):
                    addresses.add(host)
            if not addresses:
                addresses.update(nf.get("ipv4Addresses") or [])
    if not addresses or not addresses.issubset({UDM, UDM_ALT}) or UDM not in addresses:
        raise ValueError(f"Unexpected raw NRF UDM authority: {sorted(addresses)}")
    return sorted(addresses)


def confined_file(folder: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("Manifest references must be local filenames")
    return folder / name


def verified_manifest(folder: Path, public_key: Path, item: dict) -> dict:
    manifest = confined_file(folder, item["manifest"])
    signature = confined_file(folder, item["signature"])
    if not manifest.is_file() or not signature.is_file():
        raise ValueError("Missing signed observer manifest or signature")
    check = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
         "-rawin", "-in", str(manifest), "-sigfile", str(signature)],
        capture_output=True, text=True, check=False, timeout=12)
    if check.returncode:
        raise ValueError("Observer Ed25519 signature invalid: " + check.stderr[-250:])
    raw = manifest.read_bytes()
    row = json.loads(raw)
    if raw != canonical_bytes(row):
        raise ValueError("Noncanonical observer manifest")
    if row.get("kind") != KIND or row.get("source_kind") != "REAL_HOST_TCP_HEADERS_AND_LIVE_NRF":
        raise ValueError("Invalid native-event provenance")
    for kind in ("audit", "policy", "nrf"):
        file = confined_file(folder, row["files"][kind])
        if not file.is_file() or digest(file.read_bytes()) != row["sha256"][kind]:
            raise ValueError(f"Missing or tampered raw {kind} observation")
    return row


def validate_real_row(folder: Path, row: dict, expected: tuple) -> dict:
    name, mask, truth = expected
    if (row.get("id"), row.get("mask"), row.get("ground_truth")) != expected:
        raise ValueError("Unregistered Phase 11 trial/mask/ground-truth order")
    if row.get("intervention") != (
            "REAL_AUSF_NETNS_DNAT_TO_PCF" if truth else "NONE_RESTORED"):
        raise ValueError("Invalid actual lab fault provenance")
    if row.get("nrf_source") != "LIVE_NNRF_NFDISC_HTTP2":
        raise ValueError("NRF was not measured from actual service discovery")
    audit_text = confined_file(folder, row["files"]["audit"]).read_text(encoding="utf8")
    policy_text = confined_file(folder, row["files"]["policy"]).read_text(encoding="utf8")
    nrf_bytes = confined_file(folder, row["files"]["nrf"]).read_bytes()
    audit = sorted(set(tcp_syn_targets(audit_text)))
    policy = sorted(set(tcp_syn_targets(policy_text)))
    allowed = raw_nrf_udm_addresses(nrf_bytes)
    if (audit != row.get("audit_targets") or policy != row.get("policy_targets")
            or allowed != row.get("audit_authorized_udms")):
        raise ValueError("Signed manifest contradicts independently reparsed raw evidence")
    if not set(audit) - {NRF}:
        raise ValueError("Missing REAL audit AUSF->service SYN")
    probes = row.get("nf_probes_up")
    if not isinstance(probes, dict) or set(probes) != {"nrf", "ausf", "udm", "pcf"} or not all(v is True for v in probes.values()):
        raise ValueError("Missing real NF availability evidence")
    if truth:
        if SINK not in audit or (set(audit) - {NRF}) != {SINK}:
            raise ValueError("No real audit SYN to non-UDM PCF under scoped DNAT")
    else:
        if not (set(audit) & set(allowed)) or SINK in audit or row.get("ue_registration_ok") is not True:
            raise ValueError("No real restored AUSF->UDM SYN and successful UE registration")
        if (set(audit) - {NRF}) - set(allowed):
            raise ValueError("Clean restoration has unexpected egress destination")
    if mask == "complete":
        if row.get("policy_authorized_udms") != allowed or not (set(policy) - {NRF}):
            raise ValueError("Complete policy view missing required live evidence")
        if set(policy) - {NRF} != set(audit) - {NRF}:
            raise ValueError("Concurrent policy and audit packet witnesses disagree")
    elif mask == "packet_blind":
        if row.get("policy_authorized_udms") != allowed or set(policy) - {NRF}:
            raise ValueError("Collector BPF blind-spot control did not take effect")
    elif mask == "nrf_blind":
        if row.get("policy_authorized_udms") is not None:
            raise ValueError("NRF was exposed to the intentionally blind policy")
        if set(policy) - {NRF} != set(audit) - {NRF}:
            raise ValueError("NRF-only blind policy did not capture genuine packet egress")
    observed_decision = decide(row["policy_authorized_udms"], policy)
    if row.get("policy_decision") != observed_decision:
        raise ValueError("Stored policy decision disagrees with frozen three-valued rule")
    return {
        "id": name, "mask": mask, "ground_truth": truth,
        "decision": observed_decision,
        "fail_open": NORMAL if observed_decision == UNKNOWN else observed_decision,
        "fail_closed": ALARM if observed_decision == UNKNOWN else observed_decision,
        "availability_only": NORMAL,
        "nrf_authorized": ";".join(allowed),
        "audit_targets": ";".join(audit),
        "policy_targets": ";".join(policy),
        "observer_signature_verified": 1,
    }


def stats(rows: list[dict], field: str) -> dict:
    decided = [r for r in rows if r[field] != UNKNOWN]
    tp = sum(r["ground_truth"] == 1 and r[field] == ALARM for r in decided)
    fn = sum(r["ground_truth"] == 1 and r[field] == NORMAL for r in decided)
    fp = sum(r["ground_truth"] == 0 and r[field] == ALARM for r in decided)
    tn = sum(r["ground_truth"] == 0 and r[field] == NORMAL for r in decided)
    unknown_faults = sum(r["ground_truth"] == 1 and r[field] == UNKNOWN for r in rows)
    unknown_clean = sum(r["ground_truth"] == 0 and r[field] == UNKNOWN for r in rows)
    return {
        "total_live_episodes": len(rows), "decided": len(decided),
        "coverage": len(decided) / len(rows),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "unresolved_faults": unknown_faults, "unresolved_clean": unknown_clean,
        "conditional_error_rate": (fp + fn) / len(decided) if decided else None,
        "all_faults_detected_fraction": tp / sum(r["ground_truth"] for r in rows),
        "all_clean_false_alarm_fraction": fp / sum(not r["ground_truth"] for r in rows),
    }


def evaluate(index: Path, output: Path) -> dict:
    data = json.loads(index.read_text(encoding="utf8"))
    if data.get("kind") != KIND or data.get("lab_scope") != "PINNED_DISPOSABLE_OPEN5GS_UERANSIM":
        raise ValueError("Not a Phase 11 isolated live lab index")
    folder = index.parent
    pub = confined_file(folder, data["public_key"])
    if not pub.is_file() or digest(pub.read_bytes()) != data.get("public_key_sha256"):
        raise ValueError("Observer public key or logged fingerprint invalid")
    items = data.get("rows")
    if not isinstance(items, list) or len(items) != len(EXPECTED):
        raise ValueError("Incomplete Phase 11 six-episode frozen protocol")
    rows = []
    for item, expected in zip(items, EXPECTED):
        signed = verified_manifest(folder, pub, item)
        rows.append(validate_real_row(folder, signed, expected))
    metrics = {
        "experiment": KIND,
        "source_sha": data.get("source_sha"),
        "observer_public_key_sha256": data["public_key_sha256"],
        "trust_boundary": "Ephemeral host observer Ed25519; NOT Open5GS NF signature/TEE/PKI attestation",
        "native_evidence": "Real AUSF egress TCP SYN headers + raw live NRF NFDiscovery; NOT SBA payload/NAS/PFCP",
        "actual_fault_episodes": 3,
        "actual_clean_recoveries": 3,
        "controlled_collector_failures": 4,
        "three_valued": stats(rows, "decision"),
        "fail_open": stats(rows, "fail_open"),
        "fail_closed": stats(rows, "fail_closed"),
        "availability_only": stats(rows, "availability_only"),
        "per_mask": {mask: {
            "episodes": sum(r["mask"] == mask for r in rows),
            "unknown": sum(r["mask"] == mask and r["decision"] == UNKNOWN for r in rows),
        } for mask in MASKS},
        "scientific_limitations": [
            "Only 3 fixed fault/restoration pairs; not independent attack families",
            "Audit and policy packet observers share the same host and Linux kernel",
            "BPF blind spot and withheld NRF query are controlled collector failures, not natural packet loss",
            "Signatures bind observer artifacts but do not attest truth under compromised host/kernel/NF",
            "No GNN/POMDP comparison: those models do not consume these native packet/NRF fields",
            "Unknown is not a successful fault detection; coverage and unresolved faults are reported",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metrics, indent=2, allow_nan=False) + "\n", encoding="utf8")
    with output.with_suffix(".csv").open("w", newline="", encoding="utf8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("results/phase11_native_observability.json"))
    parser.add_argument("--output", type=Path, default=Path("results/phase11_native_observability_metrics.json"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.input, args.output), indent=2))


if __name__ == "__main__":
    main()
