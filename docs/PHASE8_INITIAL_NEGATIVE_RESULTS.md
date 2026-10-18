# Phase 8 preliminary real-network results — BEFORE artifact-path repair

This audit record preserves the **unfavorable** results of the
unmodified pre-registered eight-NF experiment (GitHub source SHA
`7ed6965a126fcd853cf01b5e3ca481dbe240ed90`) from two
independent clean Open5GS 2.8.0 + UERANSIM workflows:

- [Actions push 39156074617](https://github.com/verge88/article_5G_V4/actions/runs/39156074617), live eight-NF job `117759784725`.
- [Actions PR 39156102807](https://github.com/verge88/article_5G_V4/actions/runs/39156102807), live eight-NF job `117759816710`.

The complete **actual 8-NF run and model training executed successfully**
in both, and the runner logs contain the printed JSON with every
per-episode decision and classifier confusion count. HOWEVER the
workflow upload pattern `results/eight-*` initially matched only
`eight-docker.log`, `eight-containers.txt`, `eight-ue-traffic.txt`
and `eight-upstream-sha.txt` — not the CSV, model checkpoint or
JSON analysis named with `eight_`. Thus these initial runs **lack
the independently downloadable raw KIE CSVs**, despite green CI.
The workflow must be repaired to archive `results/eight*`, and
re-run **without changing policy, seeds, graph, epochs or faults**.
Initial results remain preserved here to prevent selection bias.

## Actual measurements reported by live CI stdout

Each run completed 2 prospective trials per policy, 36 ticks each,
8 NF observations each tick (576 rows per policy); initial 8 signed
KIE per campaign followed by a 2-of-8 signed-KIE budget for the five
selective policies. The FULL comparator transmitted 576 KIEs
per run per policy, each constrained comparator transmitted 156
actual authenticated KIEs, giving **72.9167%** query savings.

| Strategy | Ep. detected /8, push | Ep. detected /8, PR | FP rows, push / PR |
|---|---:|---:|---:|
| FULL authenticated (8/8) | 8 | 8 | 0 / 0 |
| Rotation (2/8) | 8 | 8 | 15 / 15 |
| Local age+own-gap heuristic (2/8) | 5 | 5 | 1 / 1 |
| Graph-neighbor heuristic (2/8) | 8 | 8 | 11 / 11 |
| Temporal GRU, no graph (2/8) | 5 | 5 | 2 / 1 |
| Graph-GRU (2/8) | **4** | **7** | **0 / 1** |

For all policies a false-positive row is a lingering last verified
signed-counter gap during recovery (a known conservative persistent
alarm mechanism), not proof of a malicious network function.

**Pre-registered success criterion: FAILED on both independent
runners.** The full and simple rotation/graph-neighbor policies
detected 8/8; Graph-GRU detected fewer (4/8 or 7/8).
Graph-GRU did have fewer false-positive rows than rotation and
neighbor heuristics, which is a *potential sensitivity/false-alarm
tradeoff*, not the prespecified detection advantage.

The two GitHub runs replayed the **same precommitted attack plans**
on separate genuine 5G SA Docker labs. Therefore 8 + 8 measured
episodes are NOT 16 distinct random attack mechanisms. These are
artificially orchestrated lab-agent receipt counter falsifications,
not natural 5G malware cascades or native compromised NFs.

## Interpretation

This experiment deliberately made graph dependencies predictive in
principle, introduced eight test signer endpoints, a tight budget,
a three-tick cascade and non-GNN graph-neighbor controls.
**Still no advantage was demonstrated for the trained graph
model.** The short secondary fault chooses one neighbor randomly
from the fixed graph, and an early observation of a root problem
does not uniquely identify which neighbor will be affected.
A graph neural architecture cannot infer unpredictable hidden
random choices from past observations. Its learned policy may
therefore prioritize already anomalous objects or overfit previous
episodes and miss short unseen targets.

We must not alter the test seed or select a different reported
metric post hoc in order to manufacture a positive result.
A controlled GNN benchmark with live agent traffic is a valuable
negative result; no attack generalization or dissertation
superiority claim is justified.

Once the artifact pattern is repaired, compare the fresh,
fully archived new runs against these recorded numbers. The
predeclared scientific criterion and method MUST remain unchanged.
