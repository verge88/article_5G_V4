# Phase 8 — decisive eight-NF causal active-KIE hypothesis test

## Why this is a different, more demanding task

Phase 4 monitored only two HMAC lab signers with budget one; a round-robin
schedule re-queried both agents every two ticks. The attack-to-observation
interval was too easy, and the reported learned Graph-GRU did **NOT**
consistently outperform rotation.

This study changes **all three substantive experimental limitations**:

1. **Eight independent observation recipients, two challenges/tick**
   instead of two recipients, one challenge/tick. An honest fixed
   round-robin policy requires four ticks to visit all eight,
   potentially longer than a short intermittent episode.
2. **No single cheap local alarm shortcut before querying:** every
   real Open5GS NF listener remains available, while independently
   authenticated HMAC lab agent counters deliberately report stale,
   correctly MACed counts. A discrepancy is only observable
   *after* the costly signed challenge has been sent. Signed count
   consistency itself is still determined by a transparent rule.
   Cheap HTTP/2 SBA listener RTTs and previous KIE reports are the
   only pre-decision inputs.
3. **Predeclared graph-correlated follow-up:** two primary lab-agent
   counter-staleness interventions in each trial each last seven
   ticks; four ticks after onset, a neighboring NF's lab-agent
   counter-staleness lasts only **three ticks**. The neighboring role
   is drawn from the repository's existing fixed functional graph,
   independently of any trained weights or test model ranking.
   Four ticks of unobserved uncertainty create a meaningful
   short-horizon *where to probe next* problem rather than merely
   recognizing an already queried stale counter. Another agent is
   subjected to an unrelated benign 120-ms delay with no dishonest
   counter. The faults are artificially **orchestrated** graph
   cascades. Open5GS signaling is NOT compromised, poisoned,
   manipulated or claimed to suffer real malware propagation.

Both the signed challenge/response transport and the eight SBA
HTTP/2 listener measurements take place in a genuinely running
Open5GS 2.8.0 + UERANSIM 5G SA testbed with actual UE PDU session
and confirmed end-to-end user-plane traffic. Eight individual
co-located signers use ephemeral HMAC-SHA256 test keys and each reports
its OWN challenge receipt count. They do NOT claim access to the
native NF PFCP/SBA message counters or cryptographically trusted
root-of-hardware attestation.

## Strict causal time ordering

At tick t the scheduler may see only (a) previously probed genuine
signed KIE responses, (b) their explicitly maintained age/mask,
and (c) cheap eight-NF SBA reachability/RTT data **from earlier
ticks**. The neural network makes a decision and only then are
new actual NF SBA and HMAC challenge packets sent. Test episode
plan/labels never enter policy inputs.

Only **six previously completed FULL-polling live campaigns** train
models (the last of six is model selection/validation, the other
five fit the model). Training uses four sparse KIE mask
augmentations per FULL data sequence, explicitly recorded as
**artificial masking of genuinely observed historical responses**.
They are NOT prospectively sent sparse network queries.
No test campaign labels or actual test observations tune model
weights, thresholds or priority coefficients.

After training, a completely new schedule seed is used for **two
prospective trials per policy**, each re-running actual HMAC
challenges and real SBA probes. A shared precommitted attack schedule
within trial reduces one source of policy-comparison variance;
observed packets are **not** shared. Each GitHub Actions run uses
a separate clean Docker lab; repetitions are few and matched target
schedules must NOT be mistaken for statistically independent attacks.

## Pre-registered comparator policies

With exactly **2 of 8** signed checks per tick after all eight
nodes are initialized at tick 0:

- **Full** (reference): eight HMAC KIEs every tick.
- **Rotation**: deterministic two of eight per tick.
- **Local heuristic**: latest verified own counter gap, report age,
  bounded fairness.
- **Graph-neighbor heuristic**: latest verified *neighbor* KIE
  discrepancy, own discrepancy, age, bounded fairness.
- **No-edge temporal GRU**: identical trainable architecture,
  but identity graph (ablates topology).
- **Graph-GRU**: same feature set and training, fixed functional
  adjacency with neighbor aggregation.

All policies have the same **independent deterministic alarm
rule**, from verified signed-counter consistency. The neural model
only selects which recipient gets the next expensive signed
challenge. The previous observation/counter features are equal
across neural and rule-based recipients; neither model can read
future probes.

## Metrics fixed before viewing test results

Primary practical comparison: **fraction of whole injected episodes
detected before the fault ends**, at equal actual signed KIE
budget, together with episode first-alert delay and row-level FPR.

The *exploratory success gate* for this specific lab is demanding:
Graph-GRU must exceed ALL of rotation, the graph-neighbor heuristic,
and the no-edge temporal GRU by **at least 10 percentage points
absolute episode recall**, with **no higher FPR**. This is *not* a
statistical significance test. If the gate fails, the result is a
negative or inconclusive experiment; we **must not retune attacks,
seeds or thresholds on the test set** to force success.

Additional outputs: actual number of signed HMAC requests and
request/response application bytes, full row-level TP/FP/FN/TN,
episode detection by primary vs short neighbor cascade, signed
authentication validation, repeated full live NF grids. Fail
closed on missing NF probes, invalid HMAC, incomplete 8-node
ticks, broken query budget or inconsistent intervention labels.

The unit fixture samples test code invariants ONLY. They are not
security data and NEVER included in experimental results.

## Reproduction

In a GitHub Actions runner, the new separate `budget8` job
uses `scripts/run_budget8.sh` to clone the same pinned upstream
5GC lab (SHA `00fe2ef2cf9b93ffb185050671ba145fb6a4ef05`),
establish a real 5G SA UE session and user plane, attach eight
per-NF namespace agents via `experiment/kie8.compose.yml`, then
run:

1. `python -m experiment.budget8_campaign --policies full --trials 6 --seed 107 ...`
2. `python -m experiment.active8_graph --input results/eight_full_training.csv ...`
3. `python -m experiment.budget8_campaign --policies full rotation local_heuristic neighbor_heuristic no_graph_gru graph_gru --trials 2 --seed 81491 ...`
4. `python -m experiment.analyze_budget8 ...`

Outputs in the archived `results/eight-*` files:

- `eight_full_training.csv` and `.metadata.json` (actual historical FULL HMAC roundtrips)
- `eight_scheduler-graph_gru.pt` and `eight_scheduler-no_graph_gru.pt` (learned, fixed CPU networks)
- `eight_scheduler.metadata.json` (trial split, masked augmentation declaration, validation BCE)
- `eight_active.csv` and `.metadata.json` (prospective actual signature/bytes/budget rows, attack plans outside feature input)
- `eight_active_metrics.json` (all baselines, each detected episode, prespecified success gate)
- `eight-docker.log`, `eight-ue-traffic.txt` (raw real 5G SA evidence)

Never infer a GNN win from a green CI: CI validates genuine
collection and integrity, **NOT scientific superiority**.

## Essential limitations and scientific interpretation

- The *graph-correlated* faults are a deliberately designed
  intervention family among HMAC lab signers. They are NOT naturally
  spreading 5G attacks. This task is chosen because topology
  contains predictive information **by construction**. Generalizing
  to unknown attack propagation mechanisms remains untested.
- Exact same NF service graph is available to strong graph-neighbor
  heuristic, to avoid granting learned policy exclusive privileged
  knowledge of topology.
- No native NF message counters are signed. The malicious bit
  changes only the colocated test signer response, not stock Open5GS
  application logic. Any claimed advantage applies only to **active
  signed-report scheduling** on this lab counter scenario.
- Training masks full-polling snapshots to approximate sparse
  monitoring, introducing an imperfect pilot-to-deployment
  distribution shift.
- A deterministic counter inconsistency detector remains
  indispensable. GNN risks are not proofs of compromise.
- 8 nodes and a budget of 2 create a harder task than 2 nodes,
  but may STILL fail to produce a neural gain. That would be a
  genuine result, not a failure of the implementation.
- Two independent runs with a small number of target episodes
  cannot establish statistical significance or robustness to
  unknown attack classes. Larger independent held-out campaigns,
  varying propagation mechanisms, and actual service-function
  counters would be prerequisites for a dissertation superiority claim.

**Do not merge merely because a unit fixture predicts good numbers;
inspect the two independent real 5G SA CI artifacts and preserve
all unfavorable measurements.**
