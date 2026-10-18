# Phase 9 — Bayesian hidden states and approximate POMDP active signed-KIE acquisition

## Research hypothesis, registered before collecting new prospective trials

Our Phase 8 8-NF Graph-GRU failed the declared sensitivity criterion:
Graph-GRU found 6/8 episodes twice, while rotation and graph-neighbor
heuristics found 8/8 at the same 2-of-8 verified KIE budget.
Phase 9 tests a *different inductive bias*:

**A Bayesian belief-state active sensor policy might use verification
uncertainty and the forecast information value of correlated
network-function states better than a static order or a learned
next-tick classification ranking.**

This is an explicitly **falsifiable** hypothesis, not a promised
advantage. A known correct answer from a signed KIE cannot make
the Bayes controller universally superior: unpredictably sampled
future neighbors still carry irreducible uncertainty.

## What is implemented

`experiment/bayes_active.py` provides three distinct layers:

1. **Hierarchical NF latent state estimation**:
   for each of eight core NF roles, hidden binary state
   (X_{i,t} \in \{0,1\}) means honest/dishonest **lab-agent
   signed challenge-receipt counter**, NOT compromised Open5GS
   software. Each NF is associated with its static lab service
   adjacency, and uncertainty is represented by the marginal
   belief (b_{i,t} = P(X_{i,t}=1\mid\mathcal H_{t-1})).
2. **Trained Markov prior and signed-emission likelihood**:
   previous FULL-polling real authenticated eight-NF KIE records
   from six preexisting genuine training campaigns are divided
   into five fitting trials and one untuned validation trial.
   The training-only intervention labels estimate a
   Beta-smoothed spontaneous onset probability, neighbor-active
   incremental onset probability, fault persistence and
   binary signed-gap emission sensitivity/false-positive
   probability. Parameters are saved in
   `results/eight_bayes_frozen.json`.
   Training targets are historically staged *test-agent
   counter-mode interventions*, not native 5GC faults.
3. **One-step approximate POMDP active sensing**:
   each budgeted verification has an expected observation
   utility based on hidden-state posterior and signed-report
   reliability. The Bayesian `pomdp` policy values:
      - immediately verified current anomaly likelihood,
      - own NF Shannon entropy reduction on receiving
        an authenticated KIE,
      - expected entropy reduction in next-tick **neighbor
        hidden state forecast** caused by updating the
        queried NF's belief.
   Greedy selection chooses **two KIE recipients from eight**
   after initial full state initialization. A frozen
   maximum-age safety rule prevents indefinite ignorance.
   Signed bytes and actual challenge counts are measured.

The filter is **factorized / mean-field** and uses a greedy
one-step lookahead; this is NOT an exact POMDP solution and
does NOT offer globally optimal action selection. A purely
entropy-driven `bayes_entropy` ablation, and a
`bayes_no_edges` ablation with Markov neighbor coupling
disabled, distinguish contributions of belief estimation,
information gain and network topology.

Previous Graph-GRU, full, rotation, and graph-neighbor heuristic
implementations remain unchanged.

## Decision sequence and observation boundaries

At online tick `t` the controller:

- predicts each NF hidden state solely from previous posterior
  and the frozen transition probabilities;
- picks the same 2-of-8 challenge recipients without ever seeing
  current data, labels or future intervention schedules;
- THEN performs eight real Open5GS HTTP/2 SBA transport probes,
  and genuinely issues/validates the two HMAC HTTP/1.1
  challenges to NF-co-located laboratory agents;
- updates the posterior only for actually queried nodes
  whose HMAC replies were verified. Unqueried nodes retain
  predicted marginal belief, not invented measurements.

An initial tick authenticates all eight recipients for
all policies, matching Phase 8. The environment additionally
reports challenge count mismatch via the exact same
deterministic integrity predicate for every policy, and
records full receipts, ages, bytes and unknown states.

## Frozen independent test protocol

The same pinned, disposable Open5GS 2.8.0 + UERANSIM
real UE bearer / user-plane lab as Phase 8:

1. Acquire **six historical FULL 8NF KIE live campaigns** using
   `seed=107`; fit the previously implemented Graph-GRU
   on five trials and validate on the sixth; calibrate the
   separate Bayesian Markov/emission parameters using
   ONLY those five prior trials, with the sixth used
   strictly for predictive log-loss reporting, not
   tuning action weights.
2. Complete the previous six-policy real Phase 8 experiment
   independently, preserving known negative results.
3. Freeze both trained models before any new Phase 9 test
   campaigns. Run exactly **seven** prospective policies
   with `seed=81491`, two trials each, 36 ticks per
   trial, eight NF observations per tick:
    - full (8/8) upper-bound reference;
    - rotation (2/8);
    - graph-neighbor heuristic (2/8);
    - Graph-GRU (2/8);
    - Bayesian entropy-only (2/8);
    - Bayesian Markov with **no edges** (2/8);
    - Bayesian **approximate POMDP** with neighbor
      expected future information value (2/8).
4. Each policy sends fresh independent HMAC-verified
   challenges and real NF HTTP/2 probes; policies
   follow the same prior intervention *schedule*
   within test trial to reduce extraneous noise.
   The actual messages are NOT replayed. True target
   identities are not supplied to any policy.
5. Archive BOTH complete real test CSVs and frozen
   model files, model-fit metadata, per-episode JSON,
   all Docker logs and UE user-plane witness.
   CI fails on incomplete 8NF grid, wrong signed
   budget, invalid authentic response, metadata
   origin mismatch or changed target labels.

Predeclared principal criterion: **Bayesian POMDP must exceed
each equal-budget competitor** (rotation, graph-neighbor
heuristic, graph-GRU, entropy-only Bayes, no-edge Bayes)
by **at least ten percentage points absolute episode
recall**, *and* have no higher row-level FPR.
The threshold is locked before observing Phase 9 test
runs. No model tuning on these test observations is
allowed. Also report per-episode first signed-KIE
detection delay, all TP/FP/FN/TN, real authenticated
message counts, KIE bytes and heldout historic
predictive log-loss. A negative result is to be
preserved unchanged.

Two clean GitHub Actions runners repeat the entire
workflow, with the same specified target seed on
different genuine Docker labs; this does NOT generate
independently sampled attack families. CI green means
valid execution, never scientific superiority.
No statistical superiority is asserted from two
short lab test repetitions.

## Non-negotiable limitations

- The signed KIE is from an HTTP/1.1 **TEST AGENT**
  co-located with each NF network namespace. It signs
  its OWN challenge receipt count, not Open5GS's
  native SBA/PFCP/NGAP transactions.
- The future fault graph structure is deliberately
  **orchestrated in the experiment**. It is not
  naturally spreading malware or native 5G network
  compromise; no NFStatusNotify spoofing is used.
- The posterior Markov probabilities are fitted to
  this limited attack generator. Their reliability
  under different service/fault families or changing
  NF topology is not established.
- Mean-field filtering loses higher-order state
  correlations, and the one-step lookahead is
  computationally efficient but not exact.
- If the future affected neighbor is sampled randomly
  among equivalent neighbors, no observer can
  determine its hidden choice before independent
  evidence becomes available.
- An unqueried NF's latent state is never a cryptographic
  fact: only a signed observation supports detection;
  probabilities only prioritize those observations.
- The low-cost SBA HTTP/2 probes are still sent to all
  eight NFs at every tick. The reduction in KIE
  count does not mean identical reduction of total
  transport or CPU resources.
- Strict scientific advancement to native NF counters,
  heterogeneous test seeds, meaningful independent
  attacks and enough repeats is a separate study.

## Expected archived results

- `results/eight_full_training.csv` — real full-polling pilot
- `results/eight_bayes_frozen.json` — prior-only transition,
  signed-emission likelihood and locked selection utility
- `results/eight_scheduler-graph_gru.pt` — prior Graph-GRU control
- `results/eight_bayesian_active.csv` — new prospective HMAC
  and HTTP/2 measurements
- `results/eight_bayesian_active.metadata.json` — actual
  signed counts and intervention schedule (metadata only)
- `results/eight_bayesian_metrics.json` — independent
  per-episode comparison and fixed success criterion
- `results/eight-docker.log` and `eight-ue-traffic.txt`
  — actual 5G SA lab and successful user-plane traffic

The budgeted Bayes model is an evaluation of *active sensing*
using only actual NF-co-located signer receipts; no superiority
can be inferred from analytically derived Bayesian weights.
