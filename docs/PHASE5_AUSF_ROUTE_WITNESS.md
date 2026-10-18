# Phase 5: AUSF ↔ NRF/UDM independent routing-evidence experiment

## Origin and research hypothesis

The [Open5GS security advisory GHSA-fvpc-gmgr-qrg3](https://github.com/open5gs/open5gs/security/advisories/GHSA-fvpc-gmgr-qrg3)
reports that **Open5GS 2.7.7** AUSF may accept an untrusted
`NFStatusNotify` notification, use an unauthorized UDM NF profile in
its internal routing cache, and misroute `Nudm_UEAuthentication`
requests while the real NRF record remains intact.

**This repository's pinned lab uses Open5GS 2.8.0, not the advisory's
verified version.** The study does NOT exploit the vulnerability,
forge any callback, modify NF caches or redirect real traffic.
It tests the **independent observational capability** needed to
recognize a divergence if one occurs.

## Two genuinely independent observational views

For each real UERANSIM UE registration in the running Docker lab:

1. **NRF authority view:** request Open5GS `Nnrf_NFDiscovery` using real
   HTTP/2, with target NF type UDM and requester type AUSF.
   Parse the advertised `nudm-ueau` IPv4 service endpoints and
   reject absent, ambiguous or unexpected NRF data.
2. **AUSF egress view:** restart **only the lab AUSF process** to
   establish a fresh connection, start a temporary read-only
   `tcpdump` in the AUSF Linux network namespace, and restart the
   simulated UERANSIM UE to generate a genuine registration.
   Record outgoing TCP SYN **header metadata only**, without packet
   payload, subscriber identities or encryption keys.
3. **Local NF availability view:** separately test NRF, AUSF and UDM
   HTTP/2 listeners. Verify the UE successfully establishes a TUN
   PDU session. The later standalone traffic-test checks recovery.

The consistency criterion is:

`unregistered_route = observed_AUSF_service_destination - NRF_authorized_UDM - known_NRF_endpoint`

The detector alarms when that set is non-empty. A failed NRF discovery
or absence of actual AUSF→UDM traffic **aborts** the experiment
instead of assigning convenient values. Only an independently captured
SYN is accepted as evidence of a newly connected destination.

This test is deliberately small (two separate live registrations in CI
smoke, four in research). A successfully reconnected UE is the only
positive source for normal-operation evidence. A restarted AUSF is **not
legitimate UDM failover**; this is only a clean restart control.

## Two VERY DIFFERENT evidence sets

- **Live real baseline:** `results/auth_witness.json` contains actual
  NRF discovery, independent AUSF TCP SYN destination metadata, NF
  reachability, successful UERANSIM attach, and links to raw text
  `results/real-ausf-tcp-trial*.txt`. All observed baseline rows
  should be consistent and have **ground-truth label normal**.
- **Offline deliberate discrepancy:** `experiment/eval_auth_route.py`
  copies the observed destination metadata into a SEPARATE analytic
  counterfactual and substitutes the expected UDM destination with the
  already-known PCF service address. **No packet or NF state is
  changed.** The resulting rows are explicitly marked
  `ARTIFICIAL_COUNTERFACTUAL_NOT_NETWORK_ATTACK`. Original live
  captures/JSON remain unchanged.

The counterfactual is a **unit/integration test of the cross-view
invariant**, not a measured real NF poisoning attack.

## Comparison and what it means

The evaluator contrasts:

- *Availability-only baseline*: alarm if NRF, AUSF or UDM listener is
  unreachable via its actual HTTP/2 endpoint.
- *Independent cross-view consistency*: alarm if actual AUSF outbound
  destination would not belong to NRF's registered UDM address set.

On an explicitly constructed mismatched metadata row, the latter must
succeed and the former must remain negative when all NF endpoints are
accessible. That is a logical result of which inputs each rule sees;
**it is not a claim of higher GNN F1 on real security attacks**.

No graph neural network is fitted or evaluated in Phase 5. The
previously trained Phase 4 GNN ranks two signed lab challenge agents;
the present evidence tests a DIFFERENT and missing signal: real
NRF-advertised UDM profiles and real AUSF egress connections.

## GitHub Actions evidence and fail-closed gates

The pinned GitHub Actions smoke mode should upload:

- `auth_witness.json`: genuinely observed clean routing evidence
- `real-ausf-tcp-trial*.txt`: header-only live tcpdump traces
- `auth_route_metrics.json`: comparison with explicit
  `live_positive_attack_samples: 0`
- `auth_route_metrics.csv`: each REAL clean control versus its
  SEPARATE ARTIFICIAL metadata-mismatch copy
- `open5gs-docker.log`, `ue-traffic.txt`, previous phase evidence

The workflow fails if the lab cannot register UE and observe AUSF→UDM
transport after the clean restart, if NFDiscovery has no valid
`nudm-ueau` profile, or if the final traffic test fails.

## Next steps before claiming a 5G cache-poisoning result

A genuinely experimental security paper would next require an
authorized, isolated, version-matched test image, a separately
verified reproducible cache-state change, packet and application
telemetry from the actual changed route, a legitimate-Udm-switch
negative control, and multiple independent physical deployments.
The user should not treat the proposed vulnerability exploit as
demonstrated merely because the read-only routing witness works.

References: Open5GS `GHSA-fvpc-gmgr-qrg3`, 3GPP TS 29.510 NFDiscovery.
