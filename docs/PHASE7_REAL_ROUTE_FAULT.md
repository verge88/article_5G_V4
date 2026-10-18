# Phase 7: real, reversible AUSF egress-route fault under live NRF authority

## What is actually changed

This is a **real Linux network-layer fault**, not a fabricated CSV and
not exploitation of the Open5GS NFStatusNotify vulnerability.

The isolated GitHub Actions `auth-route` job already builds a separate
fully functional Open5GS 2.8.0 + UERANSIM 5G SA network. Prior phases
verify independent real clean AUSF→UDM TCP SYNs, successful UE 5G
registration and a legitimate switch between two NRF-registered real
UDMs.

Phase 7 temporarily inserts a restricted Linux `iptables -t nat
OUTPUT` DNAT **inside the real running AUSF process's own Docker
network namespace**, translating only outbound TCP `*:7777` packets
whose original destination was one of the two declared lab UDM
addresses `10.45.0.23` / `10.45.0.33` to the genuine (but not
authorized as a UDM) PCF listener `10.45.0.25:7777`.

This is intentionally **not an AUSF internal routing-cache change**.
The application's originally selected destination is still an
NRF-advertised UDM; the kernel's egress packet destination is modified
*after* that selection. The PCF is a real NF, NOT a fake UDM or an
attacker-controlled receiver.

No NFStatusNotify, NF-registration forgery, application proxy,
credential changes, source-code patch, subscriber-key extraction,
payload capture or packet replay is involved. It is a controlled,
self-contained fault injection **only** against the ephemeral lab
network namespace.

## Real evidence gates

For each independent injected-and-recovered trial pair:

1. In a separate prior negative-control experiment, verify the
   dual-UDM legitimate transition and successful UE registrations.
   At the start of Phase 7, verify that the real PCF and original
   real UDM are actually listening.
2. Independently query real NRF `Nnrf_NFDiscovery` for UDM service
   endpoints (HTTP/2), and restart lab AMF/gNB/AUSF to force new
   authentication and prevent reuse of old AUSF sockets.
3. Install and verify exact `iptables OUTPUT DNAT` rules in
   the live AUSF Linux network namespace. **A preexisting matching
   rule aborts** the experiment. A Python `finally` block deletes
   every installed rule and verifies absence, even on failure.
4. Start **host-privileged passive tcpdump in the AUSF network
   namespace** before restarting the lab UE. Record only TCP SYN
   header destinations, never application payloads.
5. **Positive network fault evidence:** the actual outgoing AUSF
   TCP SYN targets `10.45.0.25:7777` (a real, non-UDM PCF);
   the independent real NRF UDM service list contains original
   UDM and possibly stale alternate UDM, but never PCF.
   NRF/AUSF/UDM/PCF ordinary probes remain accessible.
   The UE may be unable to authenticate; unlike clean restoration,
   successful UE registration is **not** required during fault.
6. **Real restoration negative control:** after removing both
   namespace rules, reboot AMF/gNB/AUSF and recapture. Require
   a new TCP SYN to a genuine NRF-authorized UDM, no TCP SYN to
   PCF, and successful new UE registration.
7. Persist source-provenance-tagged JSON, separate raw header capture
   files, baseline and recovery metrics, and full Docker logs.
   The experiment fails if positive packet evidence or restoration
   confirmation is missing.

Smoke mode runs **one injected/recovered pair** per independently
timed GitHub runner; research mode runs two pairs. This is a small
controlled network test, not an accuracy estimate over attack
families.

## Predeclared comparator inputs

Three detectors receive the same real observation row:

- `availability_only`: alarms when a required NF listener is
  unreachable. This has no visibility into namespace egress NAT.
- `static_udm_pin`: compares actual AUSF destination to one fixed
  original UDM. Correctly diagnoses injected PCF, but generated
  false alarms on benign real alt-UDM transitions in Phase 6.
- `live_nrf_consistency`: compares **observed actual egress
  destination** against an independently captured, current
  real NRF-advertised set of `nudm-ueau` service destinations.
  Allows actual legitimate UDM failover; flags PCF transport.

Phase 7 positive observations are **genuinely captured packets
during an intentionally injected network-layer fault**, rather than
the artificial metadata copies of Phases 5 and 6. This difference
is recorded as `REAL_NETNS_TRANSPORT_REDIRECT_NOT_NF_CACHE_POISONING`
throughout all artifacts.

No Graph-GRU is compared in Phase 7: the preexisting Phase 4 network
is trained to rank authenticated lab counters from NRF and SMF and
has no actual AUSF→UDM destination feature. Passing the route
destination to an oracle deterministic rule without equipping the
GNN with the same observed information would be an unfair comparison;
retraining on one tiny positive episode would leak attack mechanism
rather than establishing generalization. A later study can add
independent AUSF egress KIE measurements, collect multiple fault
families and train a held-out route-aware graph model.

## Evidence files

- `results/real_route_fault.json`: real packet/NRF observations,
  exact declared kernel intervention and recovered UE registration
- `results/real-ausf-route-*.txt`: passive actual AUSF TCP SYN headers
- `results/real_route_fault_metrics.json` and `.csv`: real-only
  confusion counts for the three detectors
- `results/legit_udm_switch.json`: real benign alternation negative control
- `results/auth-route-docker.log`: independently run Docker logs
- `results/auth-route-upstream-sha.txt`: pinned lab commit

All generated artifact scores must be inspected before merging to
`main`. **Do not present unit fixture scores or prior offline
counterfactuals as measured live route attacks.**

## Cautions

A Linux DNAT intervention at network egress **is not the NFStatusNotify
cache poisoning attack** described in the published Open5GS 2.7.7
advisory. This lab pins Open5GS 2.8.0. The fact that actual TCP SYNs
go to a non-UDM proves transport redirection, NOT that an AUSF
application selected the incorrect NF, completed an incorrect 5G
authentication exchange, or revealed subscriber identity.

The rule succeeds only because independent packet and NRF witnesses
are observed. Local availability alone is a deliberately information-
limited comparator; its failure to see a transparent routing rewrite
does not demonstrate superiority to a well-engineered observer.
A small two- or four-episode same-lab campaign cannot establish
statistical generalization, unknown-attack detection, or the
superiority of graph-temporal learning.

Cleanup is part of the experiment, not an optional step. Failure to
remove a rule and verify real recovered UE registration invalidates
the result.
