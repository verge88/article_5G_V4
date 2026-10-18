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

## Phase 2: signed KIE and genuine PyTorch graph-temporal neural experiment

The live CI also launches HMAC-authenticated challenge/response reporting agents
co-located with **SMF and NRF** (separate HTTP/1.1 lab endpoints), models
signed but dishonest SMF agent reports, and trains a real graph-convolution +
GRU model on live measurement sequences. The new comparison includes GNN
without KIE, GNN without graph edges, local/hierarchical RF and signed-KIE RF.
Validation and testing use different complete acquisition trials.

See **[Phase 2 protocol](docs/SIGNED_KIE_GNN.md)**. Important distinction:
the agent signs *its own challenge receipt count*, not actual Open5GS NF
internals; its spoofing does not constitute compromise of the SMF process.
A PyTorch CPU package is installed only in the GitHub Actions live job.
Artifacts include `results/signed_kie.csv` and
`results/signed_gnn_metrics.json` after a successful run.

## Phase 3: adaptive signed-control budget evaluation

An additional LIVE experiment sends authentically signed KIEs to the two
instrumented NF test agents under **full**, **rotation** and
**normal-only ML-guided** policies. It randomized NRF/SMF signed-counter
falsification **without artificial response delay**, and checks a separately
benign 120-ms delay as a negative control. The scheduler never uses the
intervention labels. It measures actual signed transmissions, episode
detection time, false alarms and application-level byte estimates.

See **[Phase 3: scope and scientific design](docs/ADAPTIVE_SIGNED_BUDGET.md)**.
The graph-temporal GNN from Phase 2 is **not** the online scheduler in Phase 3;
Phase 3 uses IsolationForest ranking and a deterministic counter-disagreement
alarm. This phase is not evidence of compromised stock Open5GS NFs.

## Phase 4: end-to-end neural selection of signed KIE

The next verified experiment trains a PyTorch graph-convolution + temporal
GRU **scheduler** on earlier real full-signature observations, then uses its
risk estimates to choose which NRF/SMF test agent receives the next
**actual signed challenge**, subject to the same 1-of-2 budget used by
rotation and IsolationForest. The current tick's KIE response is never
available at scheduling time. GNN weights remain frozen for the entire
prospective campaign.

See [Phase 4 scientific protocol](docs/PHASE4_GNN_ACTIVE.md). Important:
the model prioritizes recipient polling; signed-count mismatch remains the
independent alarm and the agents are not native Open5GS NFs. Full/rotation/
IsolationForest/GNN data are stored in `results/phase4_signed.csv`;
`results/graph_scheduler.metadata.json` documents the previous-trial
training/validation split. Results are not asserted until live Actions pass.

## Phase 5: passive AUSF–NRF UDM-route consistency witness

The CI observes **real Open5GS AUSF outbound TCP header destinations**
during independently triggered UERANSIM registrations and compares them
against **live NRF NFDiscovery nudm-ueau** endpoints. It verifies that
normal actual UE routing is consistent and contrasts a local-availability
rule with the cross-view invariant on a **separate explicitly artificial
metadata-mismatch copy**. The live traces are never modified.

See [Phase 5 evidence protocol](docs/PHASE5_AUSF_ROUTE_WITNESS.md).
This phase **does not** exploit GHSA-fvpc-gmgr-qrg3, poison Open5GS
AUSF caches, redirect live traffic, or establish any gain for GNN on
a real compromised core. The advisory specifically evaluated Open5GS
2.7.7, whereas this pinned lab uses 2.8.0.

## Phase 6: genuine authorized UDM rotation as a security negative control

An additional isolated LIVE Open5GS/UERANSIM experiment starts a **second real
NRF-registered `open5gs-udmd` NF**. The lab first authenticates a new UE
through the second UDM after intentionally stopping the original, then
restores the original UDM and repeats the registration and passive AUSF
TCP SYN capture. Both transitions require real NRF NFDiscovery, an
observed outgoing AUSF connection and a successful fresh UE registration.

The legitimate alternate service must **not** be misclassified as attack
simply because it differs from a hard-coded single-UDM IP. Independent
NRF/AUSF cross-view comparison is evaluated against static IP pinning
and availability checks. Analytic route-forgery *metadata copies* remain
distinct from true network measurements; **no actual attack or GNN
superiority is claimed**. See
[Phase 6 legitimate UDM switch protocol](docs/PHASE6_LEGIT_UDM_SWITCH.md).

## Phase 7: independently witnessed **actual** transport misrouting (NOT NF-cache poisoning)

The isolated Open5GS + UERANSIM Actions job now applies a **reversible
iptables OUTPUT DNAT in the disposable AUSF Linux network namespace**,
diverting actual UDM-directed TCP SYNs to the real non-UDM PCF while
the independently queried live NRF retains UDM registrations. This is
a genuinely injected *network-layer* fault with real packet headers;
it does **not** invoke forged NFStatusNotify or change AUSF NF cache.
The rule is unconditionally removed and actual clean AUSF→UDM
connection and UE registration recovery are mandatory.

The evaluator compares NF availability, hardcoded singleton UDM
pinning and independently observed NRF↔AUSF route consistency on
the **actual recorded fault and restoration**, with Phase 6 genuine
benign UDM failovers retained as negative controls. The existing
Phase 4 GNN has no routing-destination features and is NOT credited
with detecting this scenario. See [Phase 7 protocol](docs/PHASE7_REAL_ROUTE_FAULT.md).

## Phase 8: harder 8-NF signed-probe scheduling test (pre-registered)

A separate real Open5GS + UERANSIM experiment has **eight independent
NF-co-located HMAC test agents**, rather than the two of Phase 4.
Budgeted strategies have exactly two signed KIE challenges per tick
(after an eight-agent initialization), and face precommitted cascades
of artificially dishonest test-agent reports across adjacent
NF-role nodes. Graph topology is also supplied to an explicit
non-neural graph-neighbor heuristic, alongside rotation, a local
heuristic, a no-edge temporal GRU and full polling.

Trained schedulers use only prior **genuine full-polling signed
observation** campaigns with artificial sparse-mask augmentation;
prospective held-out policy evaluations issue their own real
signed network requests, never use future labels, and record
actual bytes and episode first-alert delay.

These are deliberately graph-correlated LAB AGENT interventions,
not native Open5GS 5GC compromises. A neural advantage is **not
presumed**: primary gate is >=10 percentage points better episode
recall than rotation, graph-neighbor heuristic and no-edge GRU
at equal budget **without worse FPR**. Compare measured results
without retuning to achieve this outcome.

[Scientific Phase 8 design](docs/PHASE8_8NF_GRAPH_BUDGET.md).
