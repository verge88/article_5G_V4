# Protocol and scientific validity

## Intended research question

Does hierarchical and graph-context analysis of **live Open5GS 5G SA**
service-based signaling improve NF-availability anomaly detection compared
with local NF measurements, and can ML-prioritized challenge selection
reduce the number of extra HTTP/2 probe requests at a similar detection
quality? This **does not** establish detection of arbitrary cyber attacks
or of a fully compromised NF able to falsify all its outputs.

## Real system under test

The runner pins an independently developed, MIT-licensed Open5GS SA lab at
commit `00fe2ef2cf9b93ffb185050671ba145fb6a4ef05`:
<https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab>.
That upstream project defines Open5GS 2.8.0, UERANSIM 3.3.0, MongoDB,
NRF, AMF, SMF, AUSF, UDM, UDR, PCF, BSF, UPF, gNB, UE and DN target.
Its independent scripts provision the subscriber and validate UE registration,
PDU session and traffic to an internal DN.

The local workflow first performs a **hard gate**: NRF must answer an actual
HTTP/2 Nnrf API request and UERANSIM must establish a PDU session plus
successful UE tunnel traffic. If this fails, the job fails: there is no
fallback to generated traffic. Test fixtures are only used for unit tests.

## What is and is not a KIE

For this version, the instrument is a **KIE-equivalent active observation**:
a randomly generated nonce in a custom HTTP/2 header is sent over the NF's
actual SBA transport. RTT, HTTP/2 reachability, probe response state,
request size and ageing of last observation are captured. The request travels
on the live SBA network used by normal NF control-plane communication.

IMPORTANT: Unmodified Open5GS does NOT recognize, authenticate, or echo the
experimental nonce. No NF-side HMAC, responder-authenticated report, or 3GPP
extension has been implemented. A 404 response over HTTP/2 is **transport
reachability**, not proof of successful 5G service procedure. It is therefore
incorrect to call this a fully realized cryptographic KIE implementation.

The existing experimental probes can independently monitor transport availability
from outside the NF; they cannot validate falsified local NF application counters.
Adding instrumented NF agents and a signed report is distinct future engineering
work. This experiment tests the distributed active-probing and contextual ML
components of the dissertation method, not all its security properties.

## Controlled interventions

`baseline`: no intervention, actual UE user-plane traffic active in background.

`fault_smf` and `fault_nrf`: temporarily pause their respective Docker
containers, then unpause in `recovery_*`. This is an availability disruption
within an isolated laboratory; **NOT proof of malicious compromise**.
The ground truth marks the targeted paused NF only, never an entire zone.
Pausing a central NF may induce secondary response changes in neighbors; such
changes should be counted as possible collateral false alarms.

There is no artificial replacement of the actual HTTP/2 responses in the
published live dataset. The labels are supplied from recorded intervention
schedule, not inferred from model outputs.

## Hierarchy and ML

NRF is treated as the *logical leading reference point*, not changed into a
new normative 3GPP supervisor. The other NF form a zone. Neighbor edges
are hypotheses from known service relationships; no packet-derived GNN
topology is claimed.

Feature families:
- Local: independent live probe state, HTTP/2 RTT, observation age/selection.
- Temporal: lagged state and delay, causal rolling availability.
- Zone: other-NF mean status, RTT and deviation (exclude current NF).
- Graph: direct-neighbor state and RTT/deviation, static degree.

The study compares an unsupervised IsolationForest, local RandomForest,
local+temporal+zone RandomForest, and graph-temporal **engineered-feature
ExtraTrees**. The last model is NOT a Graph Neural Network. This avoids
claiming GNN results without implementing and validating one.

The adaptive control policy fits an IsolationForest **only on benign live
observations from earlier full-polling runs**. At each tick, its anomaly
score is combined with an age/exploration term to choose up to 3 of 8 NFs.
The first tick probes all NFs for initial state. The fixed campaign probes
all NFs; these are collected as independent campaigns and must not be called
paired trials. For apples-to-apples policy conclusions, independent repeated
network restarts and randomized run order are needed in follow-on research.

## Experimental protocol

1. Pinned upstream Open5GS/UERANSIM lab runs on Ubuntu 24.04 Actions runner.
2. Hard gate: HTTP/2 NRF NFM, subscriber provision, UE TUN and user-plane ping.
3. Collect `fixed.csv`: 3 repeats of baseline, SMF fault/recovery, NRF fault/recovery.
4. Fit normal-only scheduling model using actual baseline observations.
5. Collect `adaptive.csv` with a probe budget of three of eight NFs per tick.
6. Split fixed data by **entire collection trial** (final trial held out).
7. Fit four detectors; evaluate on held-out full and separately acquired
   adaptive data. No random row-wise split; future experiments must
   also separate topology and deployment conditions.
8. Report F1, PR-AUC, ROC-AUC, FPR, confusion counts, episode detection
   delay (ticks), actual request counts and application-level byte estimates.
9. Re-check UE data traffic and upload raw data, metadata, metrics,
   container state and runtime logs.

The `experiment/enrich.py` equivalent feature construction is implemented
in `experiment/features.py`; peer statistics never include the target NF.
Outputs are in the workflow's `5g-live-evidence-<run-id>` artifact.

## Running locally

Requires Docker Compose v2, Linux with SCTP and /dev/net/tun, privileges for
SCTP, TUN and container pause, curl with HTTP/2 support and Python 3.11.

```bash
python -m pip install -r requirements.txt
python -m pytest tests -q
bash scripts/run_live.sh
```

For a longer acquisition use `EXPERIMENT_MODE=research bash scripts/run_live.sh`,
or select **research** in Actions `workflow_dispatch`.

## Interpretation limitations

- Live means real Open5GS/UERANSIM activity; not a production operator trace.
- Application-level request/response-body bytes exclude TCP, HTTP/2 framing,
  response headers, retries and IP overhead. Never report them as total link
  utilization without packet capture.
- A valid HTTP/2 404 is reachability, not successful SBI service.
- Failed probes have unknown RTT; it is not zero.
- A few trials on one virtual host are not independent real deployments.
- NF availability faults are not covert compromise, report tampering, DoS
  traffic, or a general 5G security attack benchmark.
- Model scoring and query-count reduction establish only what observed
  evidence supports; no unmeasured improvements are implied.
- No source credentials, IMSIs, Mongo subscriber database contents or
  potentially sensitive operator data should be publicly uploaded for
  real-world deployments; this CI only uses published lab test credentials.

## Third party

The integration lab is referenced and fetched (not vendored) from
[omidrahimirad/open5gs-ueransim-5g-sa-lab](https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab)
(MIT license); upstream Open5GS and UERANSIM retain their respective licenses.
Verify image digests and third-party Git commit before a formal publication.
