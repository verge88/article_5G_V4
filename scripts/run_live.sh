#!/usr/bin/env bash
# Live integration runner: no synthetic fallback, every failure aborts the CI job.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/.runtime/open5gs-lab"
UPSTREAM="https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab.git"
UPSTREAM_SHA="00fe2ef2cf9b93ffb185050671ba145fb6a4ef05"
mkdir -p "$ROOT/results" "$ROOT/.runtime"
export PYTHONPATH="$ROOT"
cleanup() {
  code=$?
  trap - EXIT
  if [[ -d "$LAB" ]]; then
    (
      cd "$LAB"
      docker unpause open5gs-nrf open5gs-smf 2>/dev/null || true
      local_overlay=()
      if [[ -n "${KIE_TEST_KEY:-}" ]]; then
        local_overlay=(-f docker-compose.yml -f "$ROOT/experiment/kie.compose.yml")
      fi
      docker compose "${local_overlay[@]}" --profile ran --profile tools logs --no-color --timestamps >"$ROOT/results/open5gs-docker.log" 2>&1 || true
      docker compose "${local_overlay[@]}" --profile ran --profile tools ps >"$ROOT/results/containers.txt" 2>&1 || true
      if [[ -f runtime/traffic_test_result.txt ]]; then
        cp runtime/traffic_test_result.txt "$ROOT/results/ue-traffic.txt"
      fi
      docker compose "${local_overlay[@]}" --profile ran --profile tools down -v --remove-orphans || true
    )
  fi
  exit "$code"
}
trap cleanup EXIT

if [[ "$(uname -s)" != Linux ]]; then
  echo "Requires real Linux, not simulated fixtures" >&2; exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  sudo mkdir -p /dev/net
  sudo mknod /dev/net/tun c 10 200
fi
sudo chmod 666 /dev/net/tun
sudo modprobe sctp
sudo modprobe tun || true
docker info >/dev/null
docker compose version
curl -V | grep -Eq 'HTTP2|HTTP/2' || { echo "curl HTTP2 required" >&2; exit 1; }

git clone --quiet "$UPSTREAM" "$LAB"
git -C "$LAB" checkout --quiet "$UPSTREAM_SHA"
echo "$UPSTREAM_SHA" >"$ROOT/results/upstream-sha.txt"
cd "$LAB"
docker compose config --quiet
docker compose up -d mongodb nrf ausf udm udr bsf pcf amf upf smf dn-server
echo "Waiting for NRF HTTP/2..."
for attempt in $(seq 1 90); do
  if curl --noproxy '*' -fsS --http2-prior-knowledge --max-time 2        http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl --noproxy '*' -fsS --http2-prior-knowledge --max-time 5   http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances   >"$ROOT/results/nrf-instances.json"

./scripts/add_subscriber.sh >"$ROOT/results/subscriber-provisioning.txt"
docker compose --profile ran up -d gnb
sleep 10
docker compose --profile ran up -d ue
echo "Waiting for UERANSIM IPv4 PDU TUN session..."
ready=0
for attempt in $(seq 1 90); do
  if docker compose --profile ran exec -T ue sh -lc 'ip link show uesimtun0'      >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if (( ! ready )); then echo "No UE TUN/PDU session" >&2; exit 2; fi
./scripts/traffic_test.sh

# Generate user-plane packets during active signaling monitoring.
docker compose --profile ran exec -T -d ue sh -lc   'ping -I uesimtun0 -i 0.5 -c 800 10.46.0.100 >/tmp/monitoring-ping.log 2>&1' || true
cd "$ROOT"

MODE="${EXPERIMENT_MODE:-smoke}"
if [[ "$MODE" == research ]]; then
  TRIALS=4; BASE=30; FAULT=16; RECOVERY=16; INTERVAL=1
else
  TRIALS=3; BASE=10; FAULT=8; RECOVERY=8; INTERVAL=0.25
fi
python -m experiment.collect --output results/fixed.csv --policy full   --trials "$TRIALS" --baseline "$BASE" --fault "$FAULT"   --recovery "$RECOVERY" --interval "$INTERVAL" --faults smf nrf --seed 51
python -m experiment.train_policy results/fixed.csv --output results/policy.joblib
python -m experiment.collect --output results/adaptive.csv --policy adaptive   --policy-model results/policy.joblib --budget 3 --trials 2   --baseline "$BASE" --fault "$FAULT" --recovery "$RECOVERY"   --interval "$INTERVAL" --faults smf nrf --seed 98
python -m experiment.evaluate --fixed results/fixed.csv   --adaptive results/adaptive.csv --output results/metrics.json

# Extended study: authenticated KIE challenge/response in two NF-colocated
# laboratory agents. Generated test key remains ephemeral (never uploaded).
export KIE_SOURCE_DIR="$ROOT"
export KIE_TEST_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::add-mask::$KIE_TEST_KEY"; fi
cd "$LAB"
docker compose -f docker-compose.yml -f "$ROOT/experiment/kie.compose.yml" up -d kie-nrf kie-smf
for endpoint in 10.45.0.11 10.45.0.21; do
  signed_ready=0
  for attempt in $(seq 1 45); do
    response="$(curl --noproxy '*' -sS --max-time 2 -o /dev/null -w '%{http_code}' "http://$endpoint:18080/ready" 2>/dev/null || true)"
    if [[ "$response" == "200" ]]; then signed_ready=1; break; fi
    sleep 1
  done
  if (( ! signed_ready )); then echo "KIE agent unavailable at $endpoint" >&2; exit 3; fi
done
cd "$ROOT"
if [[ "$MODE" == research ]]; then
  SIGNED_BASE=18; SIGNED_SPOOF=14; SIGNED_RECOVERY=14; EPOCHS=100
else
  SIGNED_BASE=12; SIGNED_SPOOF=10; SIGNED_RECOVERY=10; EPOCHS=65
fi
python -m experiment.secure_collect --output results/signed_kie.csv --trials 4 \
  --baseline "$SIGNED_BASE" --spoof "$SIGNED_SPOOF" \
  --recovery "$SIGNED_RECOVERY" --interval "$INTERVAL"
python -m experiment.temporal_gnn --input results/signed_kie.csv \
  --output results/signed_gnn_metrics.json --epochs "$EPOCHS"

# Phase 3: three independent campaigns of ACTUALLY SENT signed KIEs,
# with randomized NRF/SMF counter-only misreports and benign delays.
# The prior is fitted only to baseline LIVE signed observations from
# the earlier full-control study; it never sees Phase 3 attack labels.
if [[ "$MODE" == research ]]; then
  POLICY_TRIALS=4; POLICY_BASE=12; POLICY_ATTACK=14
  POLICY_RECOVERY=10; POLICY_NUISANCE=10
else
  POLICY_TRIALS=2; POLICY_BASE=6; POLICY_ATTACK=9
  POLICY_RECOVERY=6; POLICY_NUISANCE=6
fi
python -m experiment.adaptive_signed \
  --pilot results/signed_kie.csv --output results/adaptive_signed.csv \
  --trials "$POLICY_TRIALS" --baseline "$POLICY_BASE" \
  --attack "$POLICY_ATTACK" --recovery "$POLICY_RECOVERY" \
  --nuisance "$POLICY_NUISANCE" --signed-budget 1 --max-age 3 \
  --interval "$INTERVAL"
python -m experiment.analyze_adaptive \
  --input results/adaptive_signed.csv \
  --output results/adaptive_signed_metrics.json

# Phase 4: Train graph-temporal ranking weights solely from the previously
# acquired Phase 3 FULL-polling live dataset; split its full trials into
# training and validation. Sparse masks are TRAINING augmentation only.
python -m experiment.active_gnn \
  --input results/adaptive_signed.csv \
  --output results/graph_scheduler.pt --epochs "$EPOCHS"

# Prospective online measurements: the graph-GRU ranks signers BEFORE each
# tick's real SBA/KIE probes. No model updates from Phase 4 labels.
# All policies operate on independent campaigns at an identical signed
# one-out-of-two post-initialization budget.
python -m experiment.adaptive_signed \
  --pilot results/signed_kie.csv \
  --gnn-model results/graph_scheduler.pt \
  --policies full rotation ml_adaptive gnn_guided \
  --output results/phase4_signed.csv \
  --trials "$POLICY_TRIALS" --baseline "$POLICY_BASE" \
  --attack "$POLICY_ATTACK" --recovery "$POLICY_RECOVERY" \
  --nuisance "$POLICY_NUISANCE" --signed-budget 1 --max-age 3 \
  --seed 8417 --interval "$INTERVAL"
python -m experiment.analyze_adaptive \
  --input results/phase4_signed.csv \
  --output results/phase4_metrics.json

cd "$LAB"
./scripts/traffic_test.sh

# Phase 5: observational (non-exploit) route-consistency witness.
# Discover authorized UDM from live NRF via HTTP/2, and independently
# record real AUSF network-namespace outbound TCP SYNs during new UE attach.
# Never send forged notifications or modify NF's state/routing here.
cd "$ROOT"
export CI_5GC_READONLY_AUTH_WITNESS=YES
if [[ "$MODE" == research ]]; then AUTH_ROUTE_TRIALS=4
else AUTH_ROUTE_TRIALS=2; fi
python -m experiment.auth_witness --lab "$LAB" \
  --output results/auth_witness.json --trials "$AUTH_ROUTE_TRIALS"
python -m experiment.eval_auth_route \
  --input results/auth_witness.json \
  --output results/auth_route_metrics.json
# Do not require a new PDU session after deliberately restarting AUSF:
# the endpoint attestation tests authentication routing, not session continuity.
# Earlier live UE PDU/user-plane checks have already passed and are archived.
echo "LIVE Open5GS / UERANSIM and read-only AUSF routing witness completed."
