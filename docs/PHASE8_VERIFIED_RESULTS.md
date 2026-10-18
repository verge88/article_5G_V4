# Phase 8: VERIFIED NEGATIVE RESULT — 8 NF active signed KIEs, real 5G SA

## Frozen research hypothesis and conclusion

The predeclared objective was to show that a trainable graph-temporal
scheduler improves *whole-episode detection recall* over a **rotation
scheduler**, a **same-graph neighbor heuristic**, and an identically
trained **GRU without graph edges** by at least **10 absolute
percentage points**, with **no increase in row false-positive rate**,
at the *same actual signed KIE budget*.

**THIS OBJECTIVE WAS NOT MET.** In the verified complete-archive
confirmatory runs, the Graph-GRU detected **6/8 episodes** in each,
while rotation and graph-neighbor rules detected **8/8**. Do not
claim Graph-GRU outperforms these controls.

Training history, raw prospective packets, model checkpoint, episode
metrics and live 5G SA Docker logs are saved as GitHub Actions
artifacts in two distinct successful workflows:
- [Push run 39156946036](https://github.com/verge88/article_5G_V4/actions/runs/39156946036), [full archived evidence 12147129460](https://github.com/verge88/article_5G_V4/actions/runs/39156946036/artifacts/12147129460).
- [PR run 39156950360](https://github.com/verge88/article_5G_V4/actions/runs/39156950360), [full archived evidence 12147233496](https://github.com/verge88/article_5G_V4/actions/runs/39156950360/artifacts/12147233496).

Both are from exactly the same tested source commit
`52cd28582beabef9c51e284aa8bf17f236809412`.
The code was then squash-merged as
`f2af9ba08ea93ccc939086c52676a08120f2bfe3`.
All FOUR workflows/jobs in each source-commit run succeeded:
unit tests, legacy real Open5GS/UERANSIM GNN & KIE experiments,
independent real AUSF/UDM route validation and the new eight-NF
KIE benchmark.

## Real observed 5G metrics

Each complete-archive run:
- Actual FULL history: 6 separate real full-polling acquisition
  trials × 36 ticks × 8 NF = **1,728 genuine cryptographically
  authenticated agent challenge observations**, with 5 training
  and 1 prior validation trial; validation seeds never include
  prospective experiment rows.
- Prospective collection: 6 selection policies × 2 timed trials
  × 36 ticks × 8 NF = **3,456 real NF/tick observation rows**.
  All eight NF availability HTTP/2 probes occurred every tick.
- Actual HMAC signed queries across all six test policies: **1,356**.
  Full reference sends **576**, each restricted-budget policy
  **156** (8 initial + 35×2, repeated in 2 trials). Thus the
  per-policy signed-KIE request reduction vs full is **72.9167%**.
  The total 5G SBA traffic is NOT reduced 72.9167%.
- Attack family: coordinated laboratory falsification of each
  TEST AGENT's OWN signed challenge receipt counter; the
  underlying Open5GS NF remains intact, signaling routes
  unmodified. Follow-up effects use the fixed NF graph by
  experimental design and are 3 ticks long; harmless delayed
  signer responses serve as negative controls.
- All heldout episode labels come from the predeclared
  intervention plan, NEVER passed to online schedulers.
- Alarm itself is the same cryptographically verified signed
  counter mismatch for all policies; learned models only choose
  which signer receives the next challenge.
- No native Open5GS PFCP/SBA counter is authenticated by this
  agent. No real 5G NF compromise was performed.

### Episode-level results from ACTUAL independently acquired network messages

| Policy | Signed KIE per run | Run 39156946036: detected /8 | Run 39156950360: detected /8 | Row FPR per run |
|---|---:|---:|---:|---:|
| FULL | 576 | 8 | 8 | 0% |
| Rotation | 156 | 8 | 8 | 2.80% |
| Local age/gap | 156 | 5 | 5 | 0.19% |
| Neighbor-graph heuristic | 156 | **8** | **8** | 2.05% |
| No-edge temporal GRU | 156 | 6 | 6 | 0.56% |
| **Graph-GRU** | 156 | **6** | **6** | **0.37%** |

Graph-GRU has a lower observed row false-positive rate than
rotation or the graph heuristic, at the cost of missing **two
real lab intervention episodes** that those controls did detect.
This is a **sensitivity-specificity tradeoff**, not established
superiority. The comparator choices, 2/8 budget, model training
and intervention schedule were predeclared in
`docs/PHASE8_8NF_GRAPH_BUDGET.md` before seeing held-out outputs.

Median first-alert delay among **detected episodes only**:
- FULL 0 ticks; rotation 1 tick;
- neighbor heuristic 1.5 ticks; local heuristic 2 ticks;
- Graph-GRU 1 tick (push) and 0 ticks (PR); no-edge GRU
  1 tick (push) and 0.5 ticks (PR).

The **0 ticks median** for Graph-GRU in one run is calculated
on only its six detected episodes, not the other two it missed.
It is not an unconditional faster-detection claim.

### Validation evidence

GNN validation BCE in the separately acquired historical
validation trial was **higher** (worse) than the no-edge GRU:
- Push Graph-GRU 0.925304 vs no-edge 0.885508.
- PR Graph-GRU 0.931922 vs no-edge 0.873517.

The pilot model checkpoint, test raw CSV and all source counts
can be independently recomputed from the artifacts.

SHA256 of archived **unmodified bytes**:
- Push `eight_active.csv`:
  `c1032ecfdf97521d9375992ab98bd8bfba7eea54031ba84b661eb496b4e7e7d6`;
  `eight_active_metrics.json`:
  `036f62375e855ce6cd131aa2a87b1489fd475392f88aecf404f5c57d452edcd4`.
- PR `eight_active.csv`:
  `ef93352c56d07b6b2e2451d4cfb003692aa23f7098c757292bc9700329ec9fbd`;
  `eight_active_metrics.json`:
  `07475727bf27cbeadf68f7e3ee42b876c65c3ba98d1ad812fcf0bc72b8017ad3`.

The earlier successful pre-archive-repair runs
[39156074617](https://github.com/verge88/article_5G_V4/actions/runs/39156074617)
and [39156102807](https://github.com/verge88/article_5G_V4/actions/runs/39156102807)
also rejected the advantage criterion: Graph-GRU detected 4/8
and 7/8 episodes respectively, versus 8/8 for the same two
non-neural strong controls. The raw KIE CSVs from these initial
runs were **not archived due to a workflow glob mistake**;
their summary JSON appears in job stdout and those earlier
numbers are preserved in
`docs/PHASE8_INITIAL_NEGATIVE_RESULTS.md`. The defect was
repaired by changing only the archive matching pattern
(`results/eight*`); **no learned hyperparameter, fault schedule,
seed or policy comparison was changed**.

## Limits to avoid scientific overclaiming

1. The first root target is arbitrary and the follow-up
   affected NF is randomly selected among its functional
   neighbors. Once the root is detected, the graph restricts
   but does NOT uniquely identify which neighbor will be
   affected: the remaining choice contains intrinsic entropy
   unavailable to either learner or rule.
2. All repeat workflows use **identical attack schedule seeds**
   across different fresh 5G labs. Counts across the two runs
   are *not independent attack scenarios* or statistical
   validation of network-operator performance.
3. A simple graph-neighbor heuristic has the same functional
   graph knowledge as the Graph-GRU and is demonstrably strong.
4. The signer counters are not native Open5GS NF message counters;
   the graphs are model assumptions, not learned active NF
   call traces.
5. Training "selective" examples mask earlier genuine FULL
   signed responses instead of collecting live sparse training
   messages, an unavoidable pilot/deployment mismatch.
6. Attack patterns are deliberately staged and do not imply
   naturally propagating malware or real 5G NF compromise.
7. A real higher-complexity, causal *native NF signaling*
   dataset with numerous unpredictable service state changes
   is needed to determine whether GNN adds value beyond rules.
   Repeatedly adjusting the present seeded scenario until GNN
   wins would be **invalid test-set tuning**.

## Research decision

The predeclared Phase 8 superiority hypothesis is **falsified
for this tested lab task**. It is scientifically appropriate to
stop claiming neural superiority based on the existing
two-/eight-signer signed-counter experiments. Reframe the
possible contribution as independently verified, budgeted
cross-function signaling integrity and transparent uncertainty,
or design an entirely new prespecified study with native NF
causal traces and statistically adequate independently held-out
fault families. No additional attacks are needed merely to
search for a favorable Graph-GRU score.
