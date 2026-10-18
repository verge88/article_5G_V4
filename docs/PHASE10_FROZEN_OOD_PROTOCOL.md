# Phase 10 — prospective out-of-distribution Bayesian KIE sensing

## Pre-registration (before this code's FIRST CI evaluation)

The already-merged Phase 9 implementation is **frozen**: Bayesian
Markov transition/emission fit, binary entropy reward, 2/8 signed
budget, maximum-age fairness, Graph-GRU checkpoints and all existing
strong baselines are unchanged. Historical HMAC training still uses
FULL pilot seed **107**; prior heldout baseline uses **81491**.

Phase 9 showed a promising secondary effect: all eight staged
test-signer counter faults detected with just **1 NF/tick
false-alarm row** using Bayesian-POMDP, versus 15 under rotation
and 11 under a same-graph neighbor heuristic. BUT the
preregistered improvement-in-episode-recall gate **failed**:
both simple baselines already found all eight. Reusing the old
test generator or post-hoc tuning would not establish
generalization.

This Phase 10 explicitly requires **four different, new,
precommitted test families** that have not been fit into the
Bayesian model or used to tune its utilities.

| Predeclared family | Fixed NEW random seed | Laboratory intervention |
|---|---:|---|
| `shifted_neighbor` | 52937 | root lasts five ticks, graph-neighbor followup after two ticks |
| `off_graph` | 73417 | seven-tick root, 3-tick followup at a **non-neighbor** NF |
| `independent_short` | 90371 | four independent 2-tick false lab-signer receipt counts |
| `benign_only` | 118901 | no dishonest counter; only two genuine 120ms signer delays |

Each family has **two separately timed trial IDs** with
four positive event instances per positive-family trial.
The positive-family total is thus **24 staged signer fault
episodes per policy** (3×2×4), plus two fully benign
validation trials of 36 ticks each. Four families × two trials
× 36 ticks × eight real NF per-tick results yields
**2304 NF rows per policy**, **16128 prospectively
acquired NF/tick rows per GitHub Actions runner** for seven
policies. Real HTTP/2 Open5GS SBA listener probes still
occur at all eight NF addresses every tick.

The following **seven unchanged policies** run on all four
precommitted families: FULL signed KIE (8/8 upper reference);
rotation; same-graph neighbor heuristic; old frozen Graph-GRU;
Bayesian entropy-only; Bayesian without inter-NF edges;
and the **frozen Bayesian-POMDP active controller**. Every
budgeted policy has initial all-8 authentication followed
by 2/8 signed queries, exactly **156 actual HMAC KIE per
family per policy** (8 at tick 0 ×2 trials, plus 2×35×2).
FULL sends **576** KIE per family.

All attacks in this test are deliberately staged modifications
to each NF-colocated **test signer's OWN signed receipt-counter
reports**. These are NOT Open5GS native NF counters, native
PFCP/SBA/NAS signaling manipulations, NF compromise,
real 5G attacks, or exploitation of NFStatusNotify. Real
Open5GS + UERANSIM 5G SA session and user-plane traffic
must still succeed, all eight NF HTTP/2 ports must remain
accessible, and all real KIE HMAC responses are checked.

## No information leakage

The model fitting is complete before any Phase 10
prospective KIE acquisition. No test/future labels,
exact targets, new seeds, scenario family identifiers
or current signed reports enter the model's online
action features. The only use of the fault plan is
controlled test-signers' intervention flags and the
**separate, after-the-fact evaluator**.

The evaluator `experiment/eval_holdout8.py` refuses to
score incomplete NF/tick grids, unexpected scenario
seeds, manipulated intervention provenance/labels,
unsigned KIE, claimed bytes from unqueried recipients,
missing authenticated messages, non-available genuine
5GC NF probes and unfair KIE budgets. It independently
rebuilds the frozen plan from the published constants
in `experiment/holdout8_scenarios.py`. The unit test
fixtures are NOT live experimental evidence.

The same frozen models are fingerprinted by SHA256.
Runner repeats use the SAME predeclared intervention
seeds in independently re-created live 5G SA Docker
labs; this gives independent packet execution but NOT
different scenario identities across runs. Do not
incorrectly treat all 24×2 repeated events as distinct
attack families.

## Locked primary decision rule

At the identical 2-of-8 signed query cost, Bayesian
POMDP must **improve aggregate whole-episode recall by
at least ten absolute percentage points** against the
**BEST** of all five equal-budget competitors,
while retaining a **measured NF/tick false-positive
rate ≤1%**, and not losing more than 10 percentage
points episode recall against the best competitor in
**any** of the three positive families. A clean-only
family has **undefined recall**; its false alarms
are counted.

This is a STRICT postulated generalization criterion,
NOT a model optimization objective and NOT a
guarantee of Bayesian superiority. No test-seed or
scenario substitution, training changes or utility
parameter revisions after observing results.

Secondary and descriptive outputs:
- per-family total true episodes, detected episodes,
  episode-first signed KIE detection delay;
- **censored average detection delay** counting a
  missed episode as its entire duration, to avoid
  survivor bias from only detected events;
- per-family and aggregate row-level TP, FP, FN, TN,
  FPR, and Bayesian ablation comparisons;
- authenticated application bytes and KIE query
  counts, report ages and risk scores; full
  calm-state delay-only control;
- whether each policy stays within a **fixed
  measured 1% FPR operating constraint**.
  A threshold is NOT tuned at test time: this
  is a descriptive acceptability check at the
  policies' existing fixed alarm thresholds.

The FPR threshold is not a statistically calibrated
population guarantee from short, temporally
correlated NF/tick rows.

## Executable protocol and artifact names

`scripts/run_budget8.sh` reuses the *same* pristine
pinned Open5GS lab and historically fitted frozen
model from Phase 9 in one independent GitHub Actions
budget8 job. It first independently reruns Phase 8/9
historical controls, then (WITHOUT refitting) runs:

```sh
python -m experiment.budget8_campaign \
  --output results/eight_ood_off_graph.csv \
  --policies full rotation neighbor_heuristic graph_gru \
      bayes_entropy bayes_no_edges bayes_pomdp \
  --model-root results/eight_scheduler.pt \
  --bayes-model results/eight_bayes_frozen.json \
  --seed 73417 --scenario-family off_graph --trials 2
python -m experiment.eval_holdout8 --folder results \
  --output results/eight_ood_generalization_metrics.json
```

The actual script does this for all FOUR families,
each with the correct registered seed. Raw
`results/eight_ood_*.csv` and `.metadata.json`,
Bayesian and Graph-GRU model files, the independent
auditor output, NF Docker logs, pinned Open5GS
source hash, and real UE traffic output are uploaded
using the preexisting workflow's `results/eight*`
glob.

## Known limits and falsifiable interpretation

1. This is a harder **out-of-generator test**, not
   an unknown real 5G cyberattack. The signer
   corruption mechanism remains counter-only.
2. In the non-neighbor and independent-short
   families, the historic graph can be
   **misleading**. A Bayesian model trained on
   neighbor propagation may systematically over-
   prioritize neighbors and therefore MISS
   off-graph early detection. This negative
   result is valid and must be preserved.
3. Test-signers' own receipt counters do NOT
   constitute native NF cryptographic
   attestation. The attack-episode labels
   belong to lab interventions.
4. A 36-tick observation window, six positive
   family/trial clusters and 24 episodes still
   cannot establish network-wide confidence
   intervals or external validity. Three fault
   families remain a narrow taxonomy.
5. If the Bayes model loses its advantage
   outside the earlier seeded distribution,
   report that without reselecting scenarios
   or hyperparameters. Any new utility
   would require a NEW, prospectively
   separated train/validation/test study.
