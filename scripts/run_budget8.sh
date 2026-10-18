#!/usr/bin/env bash
# Separate, disposable Open5GS SA 8-agent KIE scheduling experiment.
# Genuine eight NF SBA listeners, eight independently signed lab agents.
# NO modifications to native Open5GS counters or 3GPP authentication.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="$ROOT/.runtime/budget8/open5gs-lab"
UPSTREAM="https://github.com/omidrahimirad/open5gs-ueransim-5g-sa-lab.git"
UPSTREAM_SHA="00fe2ef2cf9b93ffb185050671ba145fb6a4ef05"
mkdir -p "$ROOT/.runtime/budget8" "$ROOT/results"
export PYTHONPATH="$ROOT"
export KIE_SOURCE_DIR="$ROOT"
export KIE_TEST_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then echo "::add-mask::$KIE_TEST_KEY"; fi
cleanup() {
  code=$?
  trap - EXIT
  if [[ -d "$LAB" ]]; then
    (
      cd "$LAB"
      docker compose -f docker-compose.yml -f "$ROOT/experiment/kie8.compose.yml" \
        --profile ran --profile tools logs --no-color --timestamps \
        >"$ROOT/results/eight-docker.log" 2>&1 || true
      docker compose -f docker-compose.yml -f "$ROOT/experiment/kie8.compose.yml" \
        --profile ran --profile tools ps >"$ROOT/results/eight-containers.txt" 2>&1 || true
      if [[ -f runtime/traffic_test_result.txt ]]; then
        cp runtime/traffic_test_result.txt "$ROOT/results/eight-ue-traffic.txt"
      fi
      docker compose -f docker-compose.yml -f "$ROOT/experiment/kie8.compose.yml" \
        --profile ran --profile tools down -v --remove-orphans || true
    )
  fi
  exit "$code"
}
trap cleanup EXIT
[[ "$(uname -s)" == Linux ]] || { echo "Linux required" >&2; exit 1; }
if [[ ! -c /dev/net/tun ]]; then
  sudo mkdir -p /dev/net
  sudo mknod /dev/net/tun c 10 200
fi
sudo chmod 666 /dev/net/tun
sudo modprobe sctp
sudo modprobe tun || true
docker info >/dev/null
git clone --quiet "$UPSTREAM" "$LAB"
git -C "$LAB" checkout --quiet "$UPSTREAM_SHA"
echo "$UPSTREAM_SHA" >"$ROOT/results/eight-upstream-sha.txt"
cd "$LAB"
docker compose -f docker-compose.yml -f "$ROOT/experiment/kie8.compose.yml" \
  config --quiet
docker compose up -d mongodb nrf ausf udm udr bsf pcf amf upf smf dn-server
ready=0
for _ in $(seq 1 90); do
  if curl --noproxy '*' --http2-prior-knowledge -fsS --max-time 2 \
     http://127.0.0.1:7777/nnrf-nfm/v1/nf-instances >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
(( ready )) || { echo "Actual 5GC NRF unavailable" >&2; exit 2; }
./scripts/add_subscriber.sh
docker compose --profile ran up -d gnb
sleep 10
docker compose --profile ran up -d ue
ready=0
for _ in $(seq 1 90); do
  if docker compose --profile ran exec -T ue sh -lc 'ip link show uesimtun0' \
    >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
(( ready )) || { echo "UERANSIM UE PDU TUN unavailable" >&2; exit 3; }
./scripts/traffic_test.sh
docker compose -f docker-compose.yml -f "$ROOT/experiment/kie8.compose.yml" \
  up -d kie8-nrf kie8-amf kie8-smf kie8-ausf kie8-udm kie8-udr kie8-pcf kie8-bsf
for ip in 11 20 21 22 23 24 25 26; do
  ready=0
  for _ in $(seq 1 45); do
    code="$(curl --noproxy '*' --max-time 2 -sS \
      -o /dev/null -w '%{http_code}' "http://10.45.0.$ip:18080/ready" 2>/dev/null || true)"
    if [[ "$code" == 200 ]]; then ready=1; break; fi
    sleep 1
  done
  (( ready )) || { echo "Signer at NF IP $ip unavailable" >&2; exit 4; }
done
cd "$ROOT"
# Train ONLY on historical full KIE pilot. Six separately timed trials:
# 6*36*8=1728 genuinely transmitted/signed KIEs; no artificial packets.
python -m experiment.budget8_campaign \
  --output results/eight_full_training.csv --policies full \
  --trials 6 --seed 107 --interval .08
python -m experiment.active8_graph \
  --input results/eight_full_training.csv --output results/eight_scheduler.pt --seed 28
# Prospective and frozen: target schedules are shared by seed between
# policies to reduce one source of variance; all network packets are NEW.
# Budget 2/8 after initialization; compare all strong baselines.
python -m experiment.budget8_campaign \
  --output results/eight_active.csv \
  --policies full rotation local_heuristic neighbor_heuristic no_graph_gru graph_gru \
  --model-root results/eight_scheduler.pt \
  --trials 2 --seed 81491 --interval .08
python -m experiment.analyze_budget8 \
  --input results/eight_active.csv \
  --metadata results/eight_active.metadata.json \
  --output results/eight_active_metrics.json --seed 81491
echo "8-NF signed probe budget experiment completed with live Open5GS and UERANSIM."

# Phase 9: frozen Bayesian two-state NF filter with one-step approximate
# POMDP active KIE acquisition. Fit only on PRIOR honest full-observation
# pilot; no heldout labels/targets/current responses in the action chooser.
python -m experiment.bayes_active \
  --input results/eight_full_training.csv \
  --output results/eight_bayes_frozen.json
python -m experiment.budget8_campaign \
  --output results/eight_bayesian_active.csv \
  --policies full rotation neighbor_heuristic graph_gru \
             bayes_entropy bayes_no_edges bayes_pomdp \
  --model-root results/eight_scheduler.pt \
  --bayes-model results/eight_bayes_frozen.json \
  --trials 2 --seed 81491 --interval .08
python -m experiment.analyze_budget8 \
  --input results/eight_bayesian_active.csv \
  --metadata results/eight_bayesian_active.metadata.json \
  --output results/eight_bayesian_metrics.json --seed 81491 \
  --policies full rotation neighbor_heuristic graph_gru \
             bayes_entropy bayes_no_edges bayes_pomdp
echo "Frozen Bayesian active KIE benchmark and seven real 5GC policy campaigns completed."
