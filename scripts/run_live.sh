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
      docker compose --profile ran --profile tools logs --no-color --timestamps         >"$ROOT/results/open5gs-docker.log" 2>&1 || true
      docker compose --profile ran --profile tools ps         >"$ROOT/results/containers.txt" 2>&1 || true
      if [[ -f runtime/traffic_test_result.txt ]]; then
        cp runtime/traffic_test_result.txt "$ROOT/results/ue-traffic.txt"
      fi
      docker compose --profile ran --profile tools down -v --remove-orphans || true
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
cd "$LAB"
./scripts/traffic_test.sh
echo "LIVE Open5GS / UERANSIM experiment completed and validated."
