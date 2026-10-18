# Phase 3 results: signed-KIE budget on real Open5GS/UERANSIM

**Verified October 18, 2026; frozen source commit:** `28fd7b9580ca1af0c1bf99436a80aa65b7b48f0a`.

Two GitHub Actions runs passed all jobs (unit tests, live Open5GS
5G SA + UERANSIM, signed-agent validation, signed-KIE study, and the
end-of-run UE tunnel traffic test):

- [Push run 39133155807](https://github.com/verge88/article_5G_V4/actions/runs/39133155807)
- [PR run 39133176743](https://github.com/verge88/article_5G_V4/actions/runs/39133176743)

Their raw CSV measurements differ (independent hosted-runner execution);
the deterministic seed, intervention schedules and aggregate results match.
GitHub artifact retention is 14 days, so download raw data while available.
The summary below is preserved here to avoid relying on ephemeral artifacts.

## Evidence and design

Per run, **2,016 rows** were actually collected: three policies × two
collection trials × 42 ticks/trial × eight Open5GS NF HTTP/2 reachability
observations. Each policy includes **four attack episodes** (counter-only
falsified reports by NRF and SMF test agents across two trials) and a
120-ms **benign-delay** control. In every measured attack row, the stock
NF's separate HTTP/2 listener remained reachable; this is not a claim of
malicious compromise of actual Open5GS NF software.

For signed KIE, **340 verified replies** were measured in each run:
168 + 86 + 86. No signed agent reply failed verification. The
counter-only falsification was performed **without added response delay**;
benign delay was performed with truthful signed counts. The reported
control RTT median was approximately 1 ms for honest baseline and spoof
(no delay), while the 120-ms negative-control phase showed elevated
latencies for whichever signer was selected.

The source of data is actual live Docker/NF networking, not synthetic
samples. However **the misreporting behavior itself is intentionally
injected into an instrumented lab signer**, and the main HTTP/2 probe
continues for all eight NF on all policies. Only the two signed test-agent
HTTP/1.1 queries are budgeted.

## Main results (per successful Actions run)

| Metric | Full signed polling | Rotation | ML-adaptive |
| --- | ---: | ---: | ---: |
| Signed KIE requests, actual | 168 | 86 | 86 |
| Query savings relative to full | 0% | 48.81% | 48.81% |
| Episode detection | 4 / 4 | 4 / 4 | 4 / 4 |
| Row-level true positives / 36 | 36 | 34 | 35 |
| Row-level false negatives | 0 | 2 | 1 |
| Row-level false positives | 0 | 2 | 1 |
| Row-level recall | 100% | 94.44% | 97.22% |
| Row-level FPR | 0% | 1.515% | 0.758% |
| Median first-alert delay in ticks (detected episodes only) | 0 | 0.5 | 0 |
| False alarms in benign-delay control | 0 | 0 | 0 |
| Signed-agent request + response-body application bytes | 72,154 | 36,937 | 36,940 |

All tick-level results include explicit detection delay and potential
stale alarms after a fault is cleared. They must NOT be interpreted as
independent trials: tick rows are autocorrelated and share a fixed
physical topology. Only four attack episodes per policy are represented
in a run. The 95% Wilson lower bound for 4/4 episode detection is
approximately **0.51**, indicating high uncertainty despite 100% observed
episode recall.

The ML-adaptive policy prioritized signers using a normal-only
IsolationForest score, last signed discrepancy and the age of the last
observation. **Anomaly alarms were determined by a verified discrepancy
test, not by the GNN classifier.** The trained GNN comparison was
performed separately in Phase 2.

## Narrow conclusion appropriate for a paper

**Supported:** signed challenge-based testing can detect a deliberately
stale but cryptographically valid laboratory agent report while stock
5G NF HTTP/2 remains available. A one-of-two active signed-probe budget
reduces signed query transmissions by about 48.8% while all four
modeled misreport episodes remain detectable. In this test the ML-guided
scheduler required one fewer anomalous-tick miss and one fewer false
alarm than the round-robin strategy, at identical signed-query budget.

**Not supported:** universal GNN superiority, statistically significant
ML scheduling gains, real operator-scale overhead savings, native
5G NF compromise detection, independence of full/rotation/ML campaigns,
or generalization to previously unknown attacks. The same seed and
scenarios were used on two independent runners. To claim a new
generally superior ML scheduling method, run independent **research**
campaigns with more intervention episodes, variation in network
workload/topology, randomized seeds, and ultimately native NF telemetry.

## Raw-data integrity references

From push run 39133155807:

- `adaptive_signed.csv` SHA-256:
  `eb9b2c49fd36016bf5c29db9a1567b747887ac8418b0e9baf4e3badbe0299c72`
- `adaptive_signed_metrics.json` SHA-256:
  `dc06f3551267b065fa92fa498ec430704d936c1e2e9ae49b9292a3a8daa64a3b`

From PR run 39133176743:

- `adaptive_signed.csv` SHA-256:
  `ff2e2a4de89db28dd65a3681bec9713e0dd7378a8944c2daaebedc280885e3ab`
- `adaptive_signed_metrics.json` SHA-256:
  `dac118456795a1e81a344d3ca862597dfcc9ae4ca35c08f29dea10facef4435c`

See [methodology](ADAPTIVE_SIGNED_BUDGET.md) and [trust boundary](SIGNED_KIE_GNN.md).
