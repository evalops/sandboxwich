#!/usr/bin/env sh
set -eu

NAMESPACE="${SANDBOXWICH_NAMESPACE:-sandboxwich}"
LOCAL_PORT="${SANDBOXWICH_SMOKE_PORT:-32170}"
TIMEOUT="${SANDBOXWICH_SMOKE_TIMEOUT:-120s}"
API_URL="http://127.0.0.1:${LOCAL_PORT}"

log() {
  printf '%s\n' "$*"
}

curl_api() {
  if [ -n "${SANDBOXWICH_API_TOKEN:-}" ] && [ -n "${SANDBOXWICH_TENANT:-}" ]; then
    curl -fsS \
      -H "Authorization: Bearer ${SANDBOXWICH_API_TOKEN}" \
      -H "x-sandboxwich-tenant: ${SANDBOXWICH_TENANT}" \
      "$@"
  elif [ -n "${SANDBOXWICH_API_TOKEN:-}" ]; then
    curl -fsS -H "Authorization: Bearer ${SANDBOXWICH_API_TOKEN}" "$@"
  elif [ -n "${SANDBOXWICH_TENANT:-}" ]; then
    curl -fsS -H "x-sandboxwich-tenant: ${SANDBOXWICH_TENANT}" "$@"
  else
    curl -fsS "$@"
  fi
}

log "Checking Sandboxwich deployments in namespace ${NAMESPACE}"
kubectl -n "${NAMESPACE}" rollout status deployment/sandboxwich-api --timeout="${TIMEOUT}"
kubectl -n "${NAMESPACE}" rollout status deployment/sandboxwich-worker --timeout="${TIMEOUT}"
kubectl -n "${NAMESPACE}" get pods -l app.kubernetes.io/part-of=sandboxwich

port_forward_log="$(mktemp)"
kubectl -n "${NAMESPACE}" port-forward svc/sandboxwich-api "${LOCAL_PORT}:3217" >"${port_forward_log}" 2>&1 &
port_forward_pid="$!"
trap 'kill "${port_forward_pid}" >/dev/null 2>&1 || true; rm -f "${port_forward_log}"' EXIT

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if curl -fsS "${API_URL}/readyz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [ "${ready}" != "1" ]; then
  log "API did not become ready through port-forward. Last port-forward output:"
  cat "${port_forward_log}"
  exit 1
fi

log "Readiness:"
curl -fsS "${API_URL}/readyz"
printf '\n'

log "Metrics sample:"
metrics_output="$(curl_api "${API_URL}/metrics")"
printf '%s\n' "${metrics_output}" | sed -n '1,24p'

log "Tenant-scoped sandbox list:"
curl_api "${API_URL}/sandboxes"
printf '\n'

log "Homelab smoke passed"
