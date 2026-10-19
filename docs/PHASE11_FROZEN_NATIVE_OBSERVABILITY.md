# Phase 11 — preregistered native egress evidence, collector loss and three-valued verification

**Status at commit:** PROTOCOL ONLY. No Phase 11 live observations, effect sizes, CI passes or publication claims exist until this exact source has been run and independently audited. This is a bounded proof-of-mechanism pilot, not an ML superiority test.

## Research question and explicit limitations

Can a host-side, cryptographically integrity-protected observation of **actual Open5GS AUSF outgoing TCP SYN headers** and **real NRF NFDiscovery UDM service metadata** support a three-valued cross-view monitor that returns `UNKNOWN`, rather than fabricating `NORMAL` or `ALARM`, when either required witness is not observed?

This addresses the proposed research direction of evidence quality and selective diagnosis, **not** native Open5GS KIE attestation. The witness signs collected evidence with a newly generated **host-held Ed25519 key**. Neither AUSF nor NRF signs these records. The signature authenticates the observer's manifest under its key; it does **not** prove that a compromised kernel, host, tcpdump, or NRF told the truth. The ephemeral public key is archived and its SHA256 fingerprint printed in CI logs, but **there is no external PKI/TEE hardware root or independently trusted key enrollment**. Signatures are tamper evidence under the explicitly assumed honest observer, not a defense against a hostile CI runner.

Only SYN **headers**, not HTTP/2/NAS/PFCP payloads, are observed. The captured TCP destination can reflect namespace DNAT, not the AUSF application's originally selected target. Do not claim SBA semantic consistency, cross-plane causality, NF compromise, adversarial exfiltration or GNN superiority.

## Locked experimental design (before first live CI)

The same pinned disposable Open5GS 2.8.0 + UERANSIM 5G SA testbed and the Phase 7 controlled Linux AUSF-netns OUTPUT DNAT fault are reused. The real non-UDM PCF `10.45.0.25:7777` receives redirected AUSF SYNs; the independent NRF continues to advertise genuine UDM service endpoints `10.45.0.23` (possibly also the stopped alternate `10.45.0.33`). Every fault phase is followed by exact DNAT removal, fresh AUSF/AMF/gNB/UE registration, real AUSF→UDM SYN and successful UE registration. All NRF/AUSF/UDM/PCF listeners must remain reachable. No forged NFStatusNotify, application cache poisoning or payload interception.

Six prospectively collected live episodes in **fixed, precommitted** order:

| Cycle | Fault episode | Clean recovery | Policy visibility |
|---|---|---|---|
| 0 | actual DNAT | restored real registration | `complete`: NRF + AUSF egress TCP |
| 1 | actual DNAT | restored real registration | `packet_blind`: a **separate policy tcpdump process** is intentionally configured with a wrong destination-port BPF filter (`7778` instead of `7777`), while an independently started **audit tcpdump** sees real TCP port 7777 |
| 2 | actual DNAT | restored real registration | `nrf_blind`: the policy's NRF acquisition is deliberately skipped, while the audit observer obtains a real NRF HTTP/2 response |

These are **controlled observation/collector failures**, not claims of natural packet loss or hostile compromise. The audit and policy packet captures share one host/kernel/netns and are not independent trust domains. The audit NRF response is collected for scientific validation but is strictly unavailable to the policy under `nrf_blind`. The audit egress capture is unavailable to the policy under `packet_blind`. Mask mode and intervention truth are evaluator-only labels; no scheduler or alarm may use them. The sample order is fixed and confounded with cycle/time; no statistical inference over diverse conditions is permitted.

Each episode archives (1) raw audit TCP SYN-header capture, (2) separate raw policy capture, (3) raw real NRF NFDiscovery JSON, (4) a canonical manifest with per-file SHA256, independent real observations, source and intervention metadata, and (5) an Ed25519 signature. The private signing key is stored outside uploaded `results/` and deleted with the disposable runtime; the public key and fingerprint are archived. The evaluator MUST verify all signatures and raw hashes, reparse TCP SYN destinations and NRF UDM services independently, check actual fault/restoration/UE evidence and reject missing/tampered files **before** computing any metric.

## Frozen decision rule

Let `A_t` be the policy-visible set of NRF-authorized `nudm-ueau` UDM addresses, and `D_t` the policy-visible AUSF egress TCP SYN destinations to service port 7777 **excluding NRF discovery connections**.

- `UNKNOWN` if `A_t` is absent/empty or `D_t` is absent/empty. **Absence of packets is not evidence of normal routing.**
- `ALARM` if both are present and `D_t \\ A_t` is nonempty.
- `NORMAL` otherwise.

Comparators: `fail_open` maps UNKNOWN→NORMAL, `fail_closed` maps UNKNOWN→ALARM, `availability_only` alarms only on NF listener failures, and the simple fully observed deterministic cross-view rule. No neural/POMDP comparator is appropriate: those frozen Phase 10 models only observe unrelated signed **lab-agent counters**, not these packet/NRF fields. Giving them different evidence would be an invalid model comparison.

## Predeclared primary gates and expected interpretation

1. Six distinct fresh **live** fault/restoration samples, including **3 actual injected DNAT faults** and **3 actual clean recovery samples**, with auditable real SYN evidence, real NRF records, all required NF listeners up and clean UE registration. Missing evidence aborts CI.
2. All six manifests are verifiable under the run's observer public key; any modified raw capture, NRF response, manifest or signature must cause evaluator failure. Signatures **do not** attest stock Open5GS.
3. Both complete observations must yield the correct ALARM/NORMAL decision. All four deliberately incomplete policy observations must yield **UNKNOWN**, never a forced diagnosis. Count UNKNOWN as abstention, not as a correct positive detection.
4. Report coverage, conditional error rate **and** unconditional missed-fault/false-alarm rates, including unknown rates by truth and collector-failure type. A fail-open method will miss fault episodes when witnesses are withheld; fail-closed will alarm on clean episodes when witnesses are withheld. These are **logical consequences of the predeclared masks**, not statistical novelty.
5. The new result must not be presented as evidence of real-world recall/FPR, network overhead improvement, native 5GC attestation, cross-plane SBA–NGAP–PFCP invariants or superior learned scheduling. It is the first bounded native **network-event** integrity/observability control, preparatory to multi-source/multi-fault experiments.

**Fail criterion:** any absent actual audit packet, unexpected NRF service, failed clean registration, incomplete signature/hash verification, non-UNKNOWN decision under masked required evidence, or failure to remove a DNAT rule. A failing run is reported as failed, not silently replaced by synthetic data.

**Statistical unit:** a fault/recovery episode pair, n=3 fixed pairs, not six independent random attacks. No confidence interval or hypothesis-test p-value is justified from this pilot. Repeated GitHub Actions with the same fixed masks are independent live executions but **not** new failure families.

## Planned evidence

`results/phase11_native_observability.json`, `results/phase11_native_observability_metrics.json`, `results/phase11_native_observability_metrics.csv`, `results/phase11_observer_pubkey.pem`, `results/phase11-cycle*-*.{manifest.json,sig,audit.txt,policy.txt,nrf.json}`, existing `auth-route-docker.log`, and upstream/source SHA. Unit-test fixtures are never live evidence.
