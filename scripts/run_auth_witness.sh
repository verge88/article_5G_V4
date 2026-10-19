#!/usr/bin/env bash
# Standalone, READ-ONLY AUSF-to-UDM authentication-route witness.
# Uses a disposable, freshly started Open5GS 2.8.0 + UERANSIM test lab.
# No NFStatusNotify forgery, no NF cache manipulation, no route redirection.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/.runtime/auth-route/open5gs-lab"
UPSTREAM="https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab.git"
UPSTREAM_SHA="00fe2ef2cf9b93ffb185050671ba145fb6a4ef05"
mkdir -p "$ROOT/.runtime/auth-route" "$ROOT/results"
export PYTHONPATH="$ROOT"

cleanup() {
  code=$?
  trap - EXIT
  if [[ -d "$LAB" ]]; then
    (
      cd "$LAB"
      docker compose --profile ran --profile tools logs --no-color --timestamps \
        >"$ROOT/results/auth-route-docker.log" 2>&1 || true
      docker compose --profile ran --profile tools ps \
        >"$ROOT/results/auth-route-containers.txt" 2>&1 || true
      if [[ -f runtime/traffic_test_result.txt ]]; then
        cp runtime/traffic_test_result.txt "$ROOT/results/auth-route-ue-traffic.txt"
      fi
      docker compose --profile ran --profile tools down -v --remove-orphans || true
    )
  fi
  exit "$code"
}
trap cleanup EXIT

[[ "$(uname -s)" == Linux ]] || { echo "Linux required" >&2; exit 2; }
if [[ ! -c /dev/net/tun ]]; then
  sudo mkdir -p /dev/net
  sudo mknod /dev/net/tun c 10 200
fi
sudo chmod 666 /dev/net/tun
sudo modprobe sctp
sudo modprobe tun || true
docker info >/dev/null
docker compose version
curl -V | grep -Eq 'HTTP2|HTTP/2' || {
  echo "Real HTTP/2 curl required" >&2; exit 2;
}
which tcpdump
which nsenter
git clone --quiet "$UPSTREAM" "$LAB"
git -C "$LAB" checkout --quiet "$UPSTREAM_SHA"
echo "$UPSTREAM_SHA" >"$ROOT/results/auth-route-upstream-sha.txt"

cd "$LAB"
docker compose config --quiet
docker compose up -d mongodb nrf ausf udm udr bsf pcf amf upf smf dn-server
for attempt in $(seq 1 90); do
  if curl --noproxy '*' -fsS --http2-prior-knowledge --max-time 2 \
       http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl --noproxy '*' -fsS --http2-prior-knowledge --max-time 5 \
  http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances \
  >"$ROOT/results/auth-route-nrf-baseline.json"
./scripts/add_subscriber.sh >"$ROOT/results/auth-route-subscriber.txt"
docker compose --profile ran up -d gnb
sleep 10
docker compose --profile ran up -d ue
ready=0
for attempt in $(seq 1 90); do
  if docker compose --profile ran exec -T ue sh -lc 'ip link show uesimtun0' \
     >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
(( ready )) || { echo "No real initial PDU/UE TUN" >&2; exit 3; }
./scripts/traffic_test.sh

# Only the baseline proves UE PDU/user-plane. Subsequent restarts are
# for real new authentication, which can temporarily lose PDU continuity.
cd "$ROOT"
export CI_5GC_READONLY_AUTH_WITNESS=YES
if [[ "${EXPERIMENT_MODE:-smoke}" == research ]]; then
  AUTH_TRIALS=4
else
  AUTH_TRIALS=2
fi
python -m experiment.auth_witness --lab "$LAB" \
  --output results/auth_witness.json --trials "$AUTH_TRIALS" --seconds 24
python -m experiment.eval_auth_route \
  --input results/auth_witness.json \
  --output results/auth_route_metrics.json

# Phase 6: a genuine SECOND Open5GS UDM instance, advertised by REAL NRF.
# This is a benign authorization/failover negative control, NOT cache poisoning.
# The alt UDM configuration is deployed ONLY to this pinned disposable lab.
cp "$ROOT/experiment/udm-alt.yaml" "$LAB/configs/open5gs/udm-alt.yaml"
if [[ "${EXPERIMENT_MODE:-smoke}" == research ]]; then
  UDM_SWITCH_CYCLES=2
else
  UDM_SWITCH_CYCLES=1
fi
python -m experiment.legit_udm_switch --lab "$LAB" \
  --overlay "$ROOT/experiment/udm_switch.compose.yml" \
  --output results/legit_udm_switch.json \
  --cycles "$UDM_SWITCH_CYCLES" --seconds 28
python -m experiment.eval_legit_switch \
  --input results/legit_udm_switch.json \
  --output results/legit_udm_switch_metrics.json
echo "PASS: live registered and independently observed AUSF UDM failover; no attack performed"

# Phase 7: REAL, reversible packet-level routing inconsistency in ONLY
# this disposable AUSF network namespace, never an Open5GS NF cache exploit.
# Require live unauthorized PCF destination SYN with NRF still advertising UDM;
# then remove the exact scoped DNAT rules and prove UE registration recovery.
if [[ "${EXPERIMENT_MODE:-smoke}" == research ]]; then
  ROUTE_FAULT_CYCLES=2
else
  ROUTE_FAULT_CYCLES=1
fi
python -m experiment.route_fault --lab "$LAB" \
  --output results/real_route_fault.json \
  --cycles "$ROUTE_FAULT_CYCLES"
python -m experiment.eval_route_fault \
  --input results/real_route_fault.json \
  --output results/real_route_fault_metrics.json
echo "PASS: REAL transport misroute to non-UDM PCF and verified clean restoration"

# Phase 11: NEW live, two-sensor native AUSF TCP witness with controlled
# collector blind spots, host-signed raw packet/NRF evidence, and explicit
# UNKNOWN diagnoses when a necessary witness is unavailable.
# This is NOT stock Open5GS NF attestation or a native SBA counter signature.
python -m experiment.phase11_witness --lab "$LAB" \
  --output results/phase11_native_observability.json
python -m experiment.eval_phase11 \
  --input results/phase11_native_observability.json \
  --output results/phase11_native_observability_metrics.json
echo "PASS: Phase 11 live host-signed native packet/NRF observer + abstention pilot"

