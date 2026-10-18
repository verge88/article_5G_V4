# Phase 6: legitimate, NRF-authorized UDM switch — live hard negative control

## Research question

When AUSF changes its UDM destination **legitimately**, will a
cross-NF consistency invariant alarm erroneously? A detector tied to
one hardcoded UDM address can report a *false positive* when the
authorized service registration changes. The defensible KIE comparison
is instead **AUSF-observed egress destination vs. independently obtained
current authorized NRF NFDiscovery service endpoints**.

This is a **benign service-redundancy experiment**, not a 5G attack or
a demonstration of GHSA-fvpc-gmgr-qrg3. Phase 5 already collected
real, single-UDM observations. Phase 6 asks a DIFFERENT question:
can cross-view validation tolerate legitimate change?

## Actual network topology and safety

All network functions run inside the pinned, disposable Docker
Open5GS 2.8.0 + UERANSIM 5G SA lab:

- NRF = `10.45.0.11:7777`
- AUSF = `10.45.0.22:7777`
- Original real UDM = `10.45.0.23:7777`
- Newly started **genuine Open5GS UDM** = `10.45.0.33:7777`

The second UDM executes `open5gs-udmd` with ordinary Open5GS SBI
configuration against the **same real NRF**, using a Docker Compose
overlay and the previously pinned container image. This is NOT an
attacker-controlled imitation. No NFStatusNotify forgery, false UDM
registration, source-code patch, subscriber-key interception, HTTP/2
response modification or route poisoning occurs.

The program first insists NRF independently advertises both UDM
instances. It then performs real authorized service transitions:

1. Stop the original UDM; keep alternative genuine registered UDM
   alive; restart only lab AMF, gNB and AUSF to get fresh
   authentication; passively capture AUSF's outgoing TCP SYNs.
2. Start the original real UDM; stop the alternate; repeat independent
   NRF NFDiscovery and fresh AUSF→UDM observation.
3. A smoke run executes one full switch-and-return pair; manually
   selected research mode executes two pairs.

The call to `capture_one` restarts the simulated UE **after starting
tcpdump** in the AUSF Linux network namespace; only TCP SYN metadata is
collected, not bearer payloads or subscriber identifiers. Both
per-transition NRF discovery and the target service TCP listener must
be valid; a failed new UE registration fails the run.

We do not infer success from docker container startup or probe
reachability alone. **The selected UDM must be observed as an actual
AUSF egress TCP SYN destination and authorized in real NRF
NFDiscovery**, even if the former UDM's NRF record is stale during
retirement. NRF/AUSF must remain available; a stopped former UDM is
not a malicious outage.

## Comparators

Three alternative detectors, applied to recorded REAL benign switches
and distinctly labeled, OFFLINE artificial metadata mismatch copies:

1. **Singleton pin**: permits only old `10.45.0.23`. This is
   intentionally an inappropriate, nonadaptive baseline: it can
   falsely flag an authorized switch.
2. **Current NRF/AUSF cross-view**: permits whichever genuine UDM
   destinations the live NRF advertises for `nudm-ueau`.
3. **NRF/AUSF availability only**: alarms on a failed infrastructure
   probe, not on routing inconsistency.

For the positive code-path exercise, the evaluation makes a **separate
offline copy** of each genuine record and replaces its destination
metadata with the PCF's known address. The copy is marked
`ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK`. No such traffic was
actually sent. The original TCP captures and JSON remain unmodified.

The report must always say **`real_positive_attacks: 0`** and report
real benign false alarms separately from artificial mismatch recall.
It must not combine those rows as if they were real NF attacks.
No GNN is trained or assessed in Phase 6.

## Gate and evidence

The same isolated `auth-route` GitHub Actions job already confirms
Phase 5 clean registrations, before collecting Phase 6:

- `results/legit_udm_switch.json`: actual new and restored NRF service
  instance sets, independent AUSF SYN targets and UE registrations
- `results/real-authorized-switch-*.txt`: packet HEADER ONLY,
  from genuine outgoing AUSF sockets
- `results/legit_udm_switch_metrics.json` and `.csv`: negative
  control false alarms by detector and separate artificial positives
- `results/auth_witness.json`: Phase 5 normal live baseline
- `results/auth-route-docker.log`: full reproducible Docker run
- `results/auth-route-upstream-sha.txt`: pinned upstream source SHA

A result must be dropped if the second UDM does not register,
the alternative cannot authenticate the UE, the old NF still listens
after a commanded stop, or TCP packet evidence is missing. There is no
synthetic success fallback.

The source has unit tests for explicit NRF allowlists, unknown real
endpoints, absence of UE registration, unexpected AUSF destinations
and separation of real negatives from artificial positives.

## Important limitations

- `tcpdump` establishes real *TCP connections*, not a semantic proof
  that each `Nudm_UEAuthentication` HTTP/2 transaction succeeded.
  Successful UE registration adds indirect functional evidence.
- A fixed, static allowlist failure is a weak, expected baseline.
  Proving this negative control does NOT prove superiority of a GNN
  over a properly implemented rule comparing NRF vs AUSF destinations.
- Stop/start convergence and NRF stale cache windows may affect
  replayability; report whether each time-specific NRF observation
  permitted the selected destination.
- One Docker lab and two to four switches cannot estimate production
  FPR. Live *attack* recall remains undefined without a real,
  authorized network attack with verified ground truth.
- Trust in NRF is assumed. If NRF itself is compromised, an independent
  administrative signing/attestation authority is needed.
- Neither Phase 5 nor Phase 6 provides a native signed counter/KIE
  service in the unmodified Open5GS NFs. Signing experimental
  reports (Phase 2–4) is a distinct capability and trust boundary.

**Do not assert numeric gains or merge on the basis of fixture unit
tests; CI must verify real alternate UDM use and successful UE
registrations.**
