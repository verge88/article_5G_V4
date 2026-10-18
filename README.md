# Open5GS + UERANSIM: hierarchical 5G SBA anomaly experiment

This repository implements an **executable GitHub Actions lab experiment**:
real Open5GS 5G SA Core + UERANSIM gNB/UE, HTTP/2 active SBA probes
(KIE-equivalent), NF availability faults, local/hierarchical/graph-temporal
machine-learning baselines, normal-only ML-guided selective probing, held-out
trial evaluation, and uploaded raw evidence/metrics.

> **Evidence rule:** GitHub Actions must verify an NRF HTTP/2 request, UE
> registration/PDU session (TUN), and UE-to-DN traffic before ANY model
> output is treated as live 5G experimental data. It fails rather than
> silently replacing missing 5GC activity with simulated observations.
>
> **Scope:** this is an *active KIE-equivalent transport probe* rather than
> full cryptographically authenticated KIE. Stock Open5GS does not verify
> the nonce or sign a report. The injected faults are Docker container pauses,
> **not** demonstrated hostile NF compromise. The graph model is engineered
> context + ExtraTrees, **not** a GNN. See scientific limitations below.

## Run

Go to **Actions → Live 5G SA signaling experiment → Run workflow** and select
`smoke` (small) or `research` (longer). Automatic runs are configured for
pushes and pull requests. Wait for BOTH jobs to finish and download the
`5g-live-evidence-<run_id>` artifact from the Actions run.

Linux with Docker Compose v2, SCTP, TUN, Python 3.11 and curl HTTP/2 is
required for a local run:

```bash
python -m pip install -r requirements.txt
python -m pytest -q tests
bash scripts/run_live.sh
# longer experiment:
EXPERIMENT_MODE=research bash scripts/run_live.sh
```

Data are produced in `results/fixed.csv`, `results/adaptive.csv`;
`results/metrics.json` and `results/metrics.csv` contain measured
classification and detection-delay results. `results/open5gs-docker.log`,
`results/ue-traffic.txt` and `results/upstream-sha.txt` help audit the
runtime.

The lab is pinned to the third-party MIT-licensed
[Open5GS/UERANSIM testbed](https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab)
at `00fe2ef2cf9b93ffb185050671ba145fb6a4ef05`.

**Read the complete [experimental protocol and limitations](docs/PROTOCOL.md)
before using results in a scientific article.** This project does not contain
real result tables until the Actions workflow has successfully executed.
