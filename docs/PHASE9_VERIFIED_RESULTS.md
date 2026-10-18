# Phase 9 verified results — Bayesian hidden states + approximate POMDP active KIE

## Status and scientific conclusion

**IMPLEMENTED, TESTED, MERGED.** The Phase 9 Bayesian controller
and its one-step approximate POMDP active signed-KIE policy were
squash-merged from [PR #9](https://github.com/verge88/article_5G_V4/pull/9)
as commit `f3455b0b1686792ee343f074947873f4be84d65b`.

**Meaningful secondary practical improvement observed:** in
**both independently executed Open5GS 2.8.0 + UERANSIM
GitHub Actions runner environments**, at the same 156
authenticated KIE requests per policy, the approximate Bayesian
POMDP policy detected **all eight staged signed-receipt
dishonesty episodes**, matching rotation and the graph-neighbor
heuristic. Its row-level false alarms were **1** compared
with **15** for rotation and **11** for the graph-neighbor
heuristic. Thus in this same controlled test task the
POMDP preserved episode-level recall while reducing the
number of stale signed-counter alarms in recovery.

**The predeclared primary success criterion nevertheless FAILED.**
It required *at least ten absolute percentage points greater
episode-level recall than every equal-budget competitor* and no
worse row FPR. Rotation and graph-neighbor each already detect
8/8. There is no room for higher episode recall in these eight
trials. Hence the Bayesian method's beneficial secondary false-
alarm result must NOT be portrayed as satisfying the primary
superiority hypothesis or establishing statistical significance.

### Source and archival evidence (original, unmodified bytes)

All four CI jobs (causal/unit tests, prior real 5GC ML regressions,
isolated AUSF↔NRF route experiments, and this real 8-NF signed
agent experiment) passed in **both** independently executed
source-commit runs:

1. [Push workflow 39160680305](https://github.com/verge88/article_5G_V4/actions/runs/39160680305),
   [complete 8-NF artifact 12149410034](https://github.com/verge88/article_5G_V4/actions/runs/39160680305/artifacts/12149410034).
2. [PR workflow 39160684489](https://github.com/verge88/article_5G_V4/actions/runs/39160684489),
   [complete 8-NF artifact 12148459374](https://github.com/verge88/article_5G_V4/actions/runs/39160684489/artifacts/12148459374).

**Source commit of both tested workflows**:
`e088dfcb03cb637f03fca0d8247ef00c748dd798`.

The actual ZIPs contain 16 auditable files each, including
historical FULL HMAC KIE CSV, Bayesian frozen prior JSON,
Graph-GRU checkpoints, previous Phase 8 CSV/metrics,
**new `eight_bayesian_active.csv` and `eight_bayesian_metrics.json`**,
actual KIE policy selection/bytes audit metadata, NF Docker
container logs, pinned upstream source SHA and real UE traffic.

Raw original ZIP member SHA-256:

| File | Push 39160680305 | PR 39160684489 |
|---|---|---|
| `eight_bayesian_active.csv` | `0dcd76f54cc841befb458086427de50c7ec6b284719ab8d979be90476dafa546` | `f74f706b161f353d95028149de50475a592e7af1da3e9246c8fe10bfc2344de1` |
| `eight_bayesian_metrics.json` | `87023cc631e5982b4470d3bd22559d4f3d4d0c390e77f98ab83b4407a28049dc` | `b8edbcdaff247565a3ed81c94366a1c203f369e2e6084cc0793cde6f5c952485` |
| `eight_bayes_frozen.json` | `533fac290b424eae0564c6acd65f44c83a8995d18968f86eb56cff1700115059` | `533fac290b424eae0564c6acd65f44c83a8995d18968f86eb56cff1700115059` |

### Experiment design and actual message counts

- A pinned, isolated real 5G SA testbed runs eight
  reachable Open5GS NF-role containers and UERANSIM
  with successful real UE PDU/TUN/user-plane traffic.
- Each NF role has a co-located, *separate* HMAC test
  signer; signed counters represent the test signer's
  OWN accepted challenge receipt count, **NOT**
  a stock Open5GS SBA/PFCP/NGAP signaling counter.
- Six separately acquired prior FULL-polling HMAC agent
  acquisition trials: 6 × 36 ticks × 8 NF =
  **1,728 authenticated real-network observations**.
  Only trials 0–4 fit Bayesian transition, emission and
  initial probabilities; trial 5 yields **untuned**
  predictive log-loss validation. The Graph-GRU control
  similarly trains solely on the prior trial family.
- Seven genuinely and prospectively acquired policy
  campaigns with 2 trials × 36 ticks × 8 NF each:
  **4,032 prospective NF/tick measurement rows**.
  Full policy issues **576** HMAC KIE; each of the six
  constrained policies **156** genuine signed HMAC
  KIEs. The exact total across all seven prospectively
  run policies is **1,512 HMAC requests per runner**.
  The constrained-policy reduction against full is
  **72.9167% in signed KIE count**; low-cost NF SBA
  HTTP/2 probes still occur for all eight NFs/tick.
- The lab attack labels are **staged false signed
  agent receipt reports**, with graph-neighbor followup
  selected by the precommitted task generator, NOT
  native NF exploitation or naturally spreading malware.
- Each constrained scheduler sees only its own
  already-verified past KIEs, last NF transport
  status/RTT and age. All policies use the same
  signed-count mismatch as the actual alarm. The
  Bayesian policy only changes WHICH signed KIEs
  are sent on the next tick.
- Both independent GitHub Actions runner instances
  use the **same target schedule seed 81491**;
  the eight episode identities repeat. The two
  runs are independent in live packet execution,
  but NOT sixteen independent random attack scenarios.

### Real prospective results

These values agree across both complete original
`eight_bayesian_metrics.json` archives except the
Graph-GRU's timing-dependent row-level counts shown
as a range.

| Scheduler | Signed KIE | Episodes detected /8 | TP NF/ticks /40 | FP NF/ticks /536 | FPR | Median first detection delay, detected episodes only |
|---|---:|---:|---:|---:|---:|---:|
| Full reference | 576 | 8 | 40 | 0 | 0% | 0 |
| Rotation | 156 | 8 | 33 | 15 | 2.799% | 1 |
| Graph-neighbor heuristic | 156 | 8 | 29 | 11 | 2.052% | 1.5 |
| Graph-GRU | 156 | 5 | 24–25 | 0–1 | 0–0.187% | 1 |
| Bayesian entropy-only | 156 | 8 | 36 | 4 | 0.746% | 0 |
| Bayesian no edges | 156 | 6 | 22 | 0 | 0% | 2 |
| **Bayesian approximate POMDP** | **156** | **8** | **34** | **1** | **0.187%** | **0.5** |

The approximate POMDP detected **all four staged root
episodes and all four short three-tick neighbor episodes**
in both runner environments.

Measured change versus rotation:
- Equal 8/8 episode detection at equal 156 KIE count;
- FP drops from 15 to 1 rows (**93.3% fewer counted
  NF-tick false alarms**, or 2.799% to 0.187% FPR);
- row TP increases 33→34, but repeated seeded
  episodes prohibit a generalization claim.

Measured change versus graph-neighbor:
- Equal 8/8 episodes at 156 KIE;
- FP 11→1 (**90.9% fewer counted NF-tick false
  alarms**, 2.052%→0.187% FPR);
- row TP 29→34;
- detected-episode median first delay 1.5→0.5
  ticks. The latter excludes any missed events.

Measured change versus Bayesian entropy-only:
- Same 8/8 episodes, FP 4→1;
- **row TP worsens from 36 to 34**, so
  POMDP is not unconditionally better on
  every classification measure.
- Bayesian no-edge predicts 6/8, supporting
  utility of the graph-coupled filter for
  this deliberately graph-correlated generator,
  not proving general transferability.

### Bayesian learned parameters (identical prior data and frozen weights)

From the five genuinely acquired historical
full KIE training trials:

| Parameter | Fitted value |
|---|---:|
| Quiet spontaneous onset probability | 0.010319 |
| Increased neighbor-related onset term | 0.029681 |
| Fault persistence probability | 0.798077 |
| Signed mismatch emission sensitivity | 0.980769 |
| Signed mismatch emission false-positive probability | 0.00072464 |
| Initial marginal fault probability | 0.068243 |
| Prior heldout trial 5 *untuned* predictive log loss | 0.108987 |

The controller implements binary Bayes updates only
after actual verified current signed KIEs, and
mean-field neighbor-dependent Markov forecasting.
The maximum age and information weights were
fixed BEFORE test evaluation, not optimized against
these results. The optimizer is greedy one-step
expected reward/entropy reduction: **NOT an exact
finite/infinite-horizon POMDP solver**.

### Limits and suggested next verification

1. **No claim of beating the preregistered primary
   episode-level recall criterion.** Strong baselines
   already achieved maximum episodic recall.
2. **False alarm counts are correlated NF-tick
   observations**; a few hundred normal rows from
   the same short recovery periods are not hundreds
   of independently generated clean attack-free
   networks. Statistical significance cannot be
   inferred from 1 vs 15 correlated alarms.
3. All faults are test-agent counter falsification,
   NOT genuine compromised NF message streams.
   A 5GC-native, service-event-specific KIE and
   trustworthy independent source would be
   a necessary step toward general attack claims.
4. The fault generator intentionally chooses
   secondary targets along the same fixed graph
   that the Bayesian controller models. Unknown
   propagation families and changed topologies
   were NOT used in this test.
5. The two Actions runs replay the same
   intervention schedule with genuine fresh packets.
   Independent test seeds and a larger number
   of genuinely different episode families are
   necessary for robust confidence intervals.
6. Prediction and optimal action are not equivalent.
   This controller optimizes a frozen *surrogate*
   risk/uncertainty reward over one step, not the
   exact multi-step operator cost.
7. Computational/runtime cost of the Bayesian
   scheduler has not yet been separately isolated
   from the network request time. The reported
   72.9% concerns the signed KIE count **only**.

**Next experiment must be predeclared again**:
independent unseen seeds, new attack families and
a fixed maximum row FPR operating point for each
policy, with episode recall/delay evaluated at
that same operating constraint. Changing the
previous Phase 9 definition after observing these
numbers would constitute test-set tuning.
