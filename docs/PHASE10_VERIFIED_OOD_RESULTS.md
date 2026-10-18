# Phase 10 — VERIFIED held-out generalization failure for frozen Bayesian POMDP

## Scientific answer, not a model-selection contest

**The Phase 9 Bayesian/POMDP performance did NOT generalize** to the
new precommitted fault families tested in Phase 10.
Its known-seed Phase 9 result, 8/8 staged test-signer dishonesty
episodes found with 1 NF-tick FP vs 15 under rotation and 11
under neighbor heuristic, was reproduced previously, but
was NOT evidence of universal performance.

Here Bayesian/POMDP detected **15/24 genuine LAB-AGENT
receipt-counter intervention episodes** in EACH of two
separately recreated, real Open5GS 2.8.0 + UERANSIM
5G SA GitHub Actions runners. With identical prospective
signed KIE budget, Graph-GRU found **19/24**, rotation
**17/24**, graph-neighbor **16/24**, entropy-only
Bayes **16/24**, Bayes without graph **15/24**.
Bayes/POMDP registered **zero** row-level false alarms
but missed nine of 24 staged episodes.

**The pre-registered primary generalization criterion
FAILED in BOTH runs.** Do not claim that changing
the architecture from Graph-GRU to Bayesian/POMDP
delivered a consistent neural/active-sensing
superiority on previously unseen faults.

This is a *negative scientific result with reproducible
source data*, not an implementation failure: all
unit tests, genuine Open5GS/UERANSIM and NF-route
regression jobs, and four-family 8-NF signed
acquisition jobs succeeded twice.

## Pre-registration, commits and independently archived original data

- Pre-registered experiment
  [protocol](PHASE10_FROZEN_OOD_PROTOCOL.md):
  *four fixed seed/family pairs committed before CI*,
  unchanged Bayesian prior and utility, unchanged
  Graph-GRU baseline, seven equal-budget policies,
  strict 10pp improvement and ≤1% measured NF-tick
  FPR gate.
- Source [PR #10](https://github.com/verge88/article_5G_V4/pull/10),
  source commit **`66ac7d858ea1dd33b988f890978b04d50cec06f5`**,
  squash merge commit
  **`8e243b6114a78d9137276486bdb50c30bc8d8a21`**.
- [Independent PR Actions 39162838315](https://github.com/verge88/article_5G_V4/actions/runs/39162838315):
  [full real 8-NF evidence, artifact 12149324963](https://github.com/verge88/article_5G_V4/actions/runs/39162838315/artifacts/12149324963).
- [Independent push Actions 39162834441](https://github.com/verge88/article_5G_V4/actions/runs/39162834441):
  [full real 8-NF evidence, artifact 12150265397](https://github.com/verge88/article_5G_V4/actions/runs/39162834441/artifacts/12150265397).

Each original ZIP has **25 genuine CI files**, including
four independently acquired new cohort signed-report
CSVs, four corresponding intervention/budget audit
JSON files, frozen Bayes priors and Graph-GRU model
checkpoints, the independent final auditor JSON,
previous Phase 8/9 controls, real Open5GS Docker
logs, source SHA and UE user-plane traffic report.

The following are verified by a second audit of
the actual archived CSVs using an independent
ZIP/Pandas reader — not inferred merely from green
CI or trusting the scoring script:

- Per NEW cohort: **4,032 prospective
  NF/tick observation rows** and **1,512 real
  signed KIE HTTP/1.1 interactions** over seven
  policies.
- Four cohorts per runner: **16,128 NF/tick
  rows** and **6,048 signed agent KIEs**.
- The full 8/8 reference uses **2,304** signed
  KIEs across all four cohorts; EACH six
  budgeted methods uses **624**. This is
  **72.9167% fewer signed KIE requests** than
  full polling, not 72.9% fewer total NF SBA
  probes.
- All actual queried KIEs have verified signatures
  in the prospective source data. A falsified
  counter remains MAC-signed by the *dishonest
  experimental test agent*, not attested by
  stock Open5GS.
- The **frozen Bayesian model SHA-256 was identical
  across BOTH independent 5G runner instances and
  Phase 9**:
  `533fac290b424eae0564c6acd65f44c83a8995d18968f86eb56cff1700115059`.
  Frozen Graph-GRU weights remained fixed within
  each run, but their run-specific checkpoint hashes
  differed due to real pilot/training stochasticity.
- All four GitHub Actions jobs in each of the
  two tested runs finished successfully:
  units, previous native-core ML experiment,
  real AUSF→UDM route witnesses, and the new
  eight-NF signed-cohort job.

### Aggregate new-test results, per independent lab runner

| Policy | Authentic KIE | Detected episodes /24 | NF/tick FP, PR runner / push runner | Measured row FPR | All-episode censored mean delay (ticks) |
|---|---:|---:|---:|---:|---:|
| Full | 2304 | 24 | 0 / 0 | 0% | 0 |
| Rotation | 624 | 17 | 29 / 29 | 1.31% | 1.708 |
| Graph-neighbor heuristic | 624 | 16 | 41 / 41 | 1.85% | 1.417 |
| Graph-GRU | 624 | **19** | **7 / 10** | 0.32% / 0.45% | 1.333 / 1.208 |
| Bayesian entropy-only | 624 | 16 | 0 / 0 | 0% | 1.792 |
| Bayesian without graph | 624 | 15 | 0 / 0 | 0% | 1.667 |
| **Bayesian approx-POMDP** | **624** | **15** | **0 / 0** | **0%** | **1.917** |

The censored-mean delay measure penalizes **missed**
events by their entire active duration, rather than
reporting merely conditional delay among detected
episodes. It is a transparent proxy for delayed/missed
verification, not a wall-clock breach time.

Bayesian/POMDP remains an appealing way to suppress
false alarms from persisted past signed-counter gaps,
but **its 15/24 recall is weaker than Graph-GRU's
19/24 and rotation's 17/24 on these new
families**. Lower FP is a recall/false-alarm
tradeoff and cannot be promoted to universal model
superiority. Graph-GRU is the recall leader *for this
OOD generator*, while Phase 8/9 documented
its limitations on the original generator: no
single approach won reliably across families.

### Mandatory per-family breakdown

Each positive family has 2 trial IDs ×4 staged
counter dishonesty episodes =8 positive episodes
per policy. The benign-only family has NO positive
episode, so its episode recall is **undefined**.

| Family (fixed test seed) | Rotation | Graph-neighbor | Graph-GRU | Bayes entropy | Bayes no-edges | **Bayes POMDP** |
|---|---:|---:|---:|---:|---:|---:|
| Shifted neighbor, 52937 | 7/8 | 8/8 | 7/8 | 7/8 | 4/8 | **7/8** |
| **Off-graph**, 73417 | 7/8 | 6/8 | 7/8 | 4/8 | 6/8 | **4/8** |
| Independent two-tick, 90371 | 3/8 | 2/8 | 5/8 | 5/8 | 5/8 | **4/8** |
| Benign delayed-only, 118901 | FP 0 | FP 0 | FP 0 | FP 0 | FP 0 | **FP 0** |

The Bayesian/POMDP assumption that an early
root intervention increases near-neighbor risk
was **misleading on the deliberately off-graph
generator**. In independent two-tick incidents,
none of the budgeted methods fully detected
all events: the 2/8 active monitoring schedule
sometimes never probes the affected signer's
receipt state during the short window.
Graph-GRU happens to find 5/8 of these short
episodes, POMDP 4/8, and rotation 3/8.
These patterns are analytically intelligible,
but the evidence is too narrow to claim any
method generally detects these classes better.

### Real raw data fingerprints (unmodified ZIP bytes)

| File | PR runner SHA256 | Push runner SHA256 |
|---|---|---|
| `eight_ood_generalization_metrics.json` | `c71db88cee09259bbe38459addec57fc4429aa15b473bb2dd778b7f04d7019b2` | `016c81f757663700a7b81c71e87849c56c5bff50d31aa92aaeb3fed22cb8a16e` |
| `eight_ood_off_graph.csv` | `d568cf4510dddcc1b6d4646bb8b0331ef6b00c242d151e9979d0e782e3916e2a` | `27fedd306f659e9d8a457addf7f81e4a1f858b517d2b0724e830e483bf6b0d41` |
| `eight_ood_independent_short.csv` | `47d2570ce33e2e851fe02eef9e2645cf73b202e85b11dd5ae3774b5ed0b30cc2` | `f84b2f5b1a3cdb6ae98ef3caea967180c5484253c72dc8e3ebe54156a8c27e8f` |
| `eight_bayes_frozen.json` | `533fac290b424eae0564c6acd65f44c83a8995d18968f86eb56cff1700115059` | SAME |

## Limits and research direction

1. This is a **test-agent counter-reporting study**.
   Each co-located signer signs its own challenge
   receipt count; NO native Open5GS NF SBA/PFCP
   transaction counter is authenticated. No actual
   NF compromise, NFStatusNotify exploit, malicious
   registration or naturally spreading attack was
   performed.
2. The two independent CI runners use **the SAME**
   four fixed family seeds and each family's two
   trial indices. Their real network HMAC exchanges
   were independently executed, but there are only
   **six distinct positive family/trial clusters**,
   not 48 independent new attack families.
3. NF/tick rows are strongly temporally correlated.
   Measured FPR 0% on short observations is NOT a
   guarantee of zero false positives in production.
   Further independent benign state transitions and
   genuinely different attack mechanisms are needed
   before deriving trustworthy confidence intervals.
4. Graph-GRU checkpoints were fit on genuinely
   acquired full-signer pilot reports and kept
   fixed for all four prospective cohorts of each
   runner. The Bayesian prior retained **exact**
   previously documented checksum.
5. The entire controlled cohort keeps all eight
   true NF listener transport probes always running.
   Reducing signed-KIE count by 72.9% does NOT
   reduce overall monitoring traffic or runtime by
   the same amount.
6. **Do not change the test seeds, Bayes utility
   weights or selection criteria after seeing
   this result.** Phase 10 is complete as a
   falsifying generalization experiment; any new
   model must receive a new train/validation/test
   split with independent production-like traces.

**Research decision:** neither GNN nor Bayesian-POMDP
has established consistent superiority across
the different tested (staged) signed-agent
reporting fault families. The robust contribution
supported by evidence remains the signed,
independently verified, budget-limited KIE
monitoring mechanism, together with clearly
measured sensitivity/false-alarm tradeoffs.
A defensible dissertation claim must acknowledge
the model-generalization failure and would
require new *native NF event* evidence before
generalizing to genuine 5G SF compromise.
