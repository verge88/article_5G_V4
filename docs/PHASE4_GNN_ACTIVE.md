# Phase 4: prospective graph-temporal signed-KIE scheduling on live 5G SA

## Hypothesis

With the same one-of-two *authenticated laboratory KIE* budget, does a
supervised graph-convolution + GRU **next-tick risk scheduler** reduce
detection delay or missed anomalies compared with rotation and earlier
IsolationForest-guided selection?

This explicitly separates a **trained risk-ranking policy** from the
**deterministic signed-counter alarm**. The learned neural model influences
which actual KIE is transmitted; it does not authenticate the report and
does not replace the independent HMAC/nonce integrity checks.

## Training / prospective testing

First the workflow completes Phase 1, Phase 2 and Phase 3 against real
Open5GS 5GC and UERANSIM. Phase 3 collects an independent *FULL signed KIE*
dataset for two or more trials, including verified NRF and SMF challenge
reports, test-agent counter-only dishonesty, and benign response delays.

`active_gnn.py` uses **only the earlier Phase 3 full-control runs** to
train a PyTorch graph projection + GRU, with per-NF binary next-tick
anomaly targets. The full runs are split by trial: all but the last are
training, last is validation/early-stopping. No Phase 4 labels or
observations are used to tune the GNN weights or selection constants.

To prepare the model for missed KIE opportunities, training *masks*
some previously and genuinely measured KIE observations; these masks are
**artificial data augmentation**, not claimed new live packets.
The underlying measurements still originate from the lab.
Training windows are assembled from the state strictly before the target
tick; responses at tick t cannot influence selecting at tick t.

The trained `results/graph_scheduler.pt` checkpoint is loaded by the
live runner and its weights are fixed for the entirety of Phase 4.
At the start of each tick the trained GRU outputs risk estimates from
the last four lagged observation states for all eight NFs. Graph
adjacency is fixed by the declared service topology, **not** discovered.
Only two agents, NRF and SMF, can receive a signed KIE. An age
safeguard overrides model risk to avoid starvation; risk, age and last
verified discrepancy select the next live recipient.

## Prospective, equal-budget controls

Phase 4 separately re-runs, on the *same working but evolving Docker
5GC lab*, four policy campaigns with randomized policy order,
test-agent intervention order and fixed recorded random seed:

- `full`: both signers checked at every tick (reference, budget=2)
- `rotation`: one signer checked per tick (budget=1)
- `ml_adaptive`: historical normal-only IsolationForest novelty
  and age (budget=1)
- `gnn_guided`: prospective supervised graph-GRU risk and age
  (budget=1)

All policies probe both signers at the very first tick of a trial.
Every later tick transmits exactly one signed HTTP/1.1 KIE for each of
the three restricted-budget strategies. The eight ordinary Open5GS
SBA HTTP/2 reachability probes still operate each tick. Do not equate
signed-KIE savings with total 5G signaling savings.

Each policy tests both target agents using **counter-only** dishonest
but properly MACed reports, with no extra response latency, plus a
separate genuine signed-response delay without a false report.
The faults are NOT native 5G NF compromises.

All Phase 4 campaigns happen **after** the older Phase 3 full dataset
was collected. This is the prospective temporal separation needed
for an unbiased evaluation on *new packets*, but it is still the
same 5GC installation and type of injected misreport.

## Audit artifacts

- `results/graph_scheduler.pt` — CPU PyTorch trained checkpoint
- `results/graph_scheduler.metadata.json` — earlier trial split,
  mask-augmentation declaration, epochs, validation BCE
- `results/phase4_signed.csv` — eight real NF transport observations
  per tick; actual signed KIE request count, latest authenticated count
  discrepancy, age, alarm, preceding neural risk, actual selected signer
- `results/phase4_signed.metadata.json` — order and schedule, source,
  exact experiment budgets and counts
- `results/phase4_metrics.json` / `.csv` — accuracy, packet/byte
  overhead, first-alert delay, missed episodes and confidence intervals
- Original UE PDU and user-plane checks, upstream SHA, full container logs

The phase fails if all required real NF observations are not present,
every sent KIE is not verifiably authenticated, or a policy uses more
queries than permitted. Unit tests additionally verify that a response
from the current tick cannot affect the decision at that same tick.

## Critical limits for a scientific article

1. Only two signed **test-agent** recipients, no native Open5GS NF
   signaling counters. Real NF availability HTTP/2 is measured separately.
2. GNN learns from the same attack mechanism (falsified test-agent
   counter). This does **not** establish unseen-attack generalization.
3. Sparse KIE schedules in GNN *training* are artificially masked
   historical readings; prospective Phase 4 selection does issue real
   messages. This difference may cause deployment distribution shift.
4. Two trials per policy (smoke) is far too few for superiority claims,
   even if one row-level F1 is high.
5. Graph is a fixed NF-role topology; native NF internals not instrumented.
6. Unlike the experimental agent counter test, actual compromised
   5GC NFs could manipulate more fields, delay selectively, or evade probes.
7. Detection is by independent signed-counter consistency; graph-GRU
   steers *which* KIE is sent. GNN is not an authenticated report itself.

A next real-world step is instrumenting real Open5GS service-based
message counters or a native lab NF with signed, audited reports. Until
then the correct contribution is the **causal, budgeted neural
control strategy validated over real 5G SA transport, with a controlled
laboratory report-falsification intervention.**
