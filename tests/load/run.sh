#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOAD_DIR="${ROOT_DIR}/tests/load"
RESULTS_DIR="${LOAD_DIR}/results"
mkdir -p "${RESULTS_DIR}"

SCENARIO="${1:-${SCENARIO:-login_steady}}"
case "${SCENARIO}" in
  login_steady|refresh_steady|signup_burst|mixed_workload) ;;
  *)
    echo "unknown scenario: ${SCENARIO}" >&2
    echo "expected one of: login_steady refresh_steady signup_burst mixed_workload" >&2
    exit 1
    ;;
esac

STAMP="${STAMP:-$(date -u +%Y-%m-%dT%H-%M-%SZ)}"
PREFIX="${RESULT_PREFIX:-local}"
SUMMARY_BASENAME="${PREFIX}-${SCENARIO}-${STAMP}"
SUMMARY_JSON="${RESULTS_DIR}/${SUMMARY_BASENAME}.json"
SUMMARY_TXT="${RESULTS_DIR}/${SUMMARY_BASENAME}.txt"

IMAGE="${K6_IMAGE:-grafana/k6:0.49.0}"
BASE_URL="${BASE_URL:-http://host.docker.internal:18080}"
SCRIPT="/work/k6/${SCENARIO}.js"

echo "Running ${SCENARIO}"
echo "Writing k6 output to:"
echo "  ${SUMMARY_TXT}"
echo "  ${SUMMARY_JSON}"

docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "${LOAD_DIR}:/work" \
  -w /work \
  -e BASE_URL="${BASE_URL}" \
  -e USERS="${USERS:-}" \
  -e TARGET_QPS="${TARGET_QPS:-}" \
  -e DURATION="${DURATION:-}" \
  -e PREALLOCATED_VUS="${PREALLOCATED_VUS:-}" \
  -e MAX_VUS="${MAX_VUS:-}" \
  -e VUS="${VUS:-}" \
  -e SLEEP_SECONDS="${SLEEP_SECONDS:-}" \
  -e CLEANUP_LOGOUT="${CLEANUP_LOGOUT:-}" \
  -e BATCH_SIZE="${BATCH_SIZE:-}" \
  -e SIGNUP_WEIGHT="${SIGNUP_WEIGHT:-}" \
  -e LOGIN_WEIGHT="${LOGIN_WEIGHT:-}" \
  -e REFRESH_WEIGHT="${REFRESH_WEIGHT:-}" \
  -e LOGOUT_WEIGHT="${LOGOUT_WEIGHT:-}" \
  "${IMAGE}" run "${SCRIPT}" \
  --summary-export "/work/results/$(basename "${SUMMARY_JSON}")" | tee "${SUMMARY_TXT}"
