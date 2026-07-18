#!/usr/bin/env bash
set -euo pipefail

# Apply schema changes before the API Deployment. The API runs with
# SANDBOXWICH_AUTO_MIGRATE=false, so rolling it out first would make new pods
# fail schema validation or, worse, leave old pods serving an incompatible API.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KUBECTL=(kubectl)
if [[ -n "${SANDBOXWICH_KUBE_CONTEXT:-}" ]]; then
  KUBECTL+=(--context "${SANDBOXWICH_KUBE_CONTEXT}")
fi
MIGRATION_TIMEOUT="${SANDBOXWICH_MIGRATION_TIMEOUT:-5m}"

"${KUBECTL[@]}" apply -f "${ROOT_DIR}/namespace.yaml"
# The resident-bootstrap broker is process-local and the schema contract is
# exact-versioned, so no old API replica may remain serving during migration.
if "${KUBECTL[@]}" -n sandboxwich get deployment/sandboxwich-api >/dev/null 2>&1; then
  "${KUBECTL[@]}" -n sandboxwich scale deployment/sandboxwich-api --replicas=0
  "${KUBECTL[@]}" -n sandboxwich rollout status deployment/sandboxwich-api \
    --timeout="${MIGRATION_TIMEOUT}"
fi
"${KUBECTL[@]}" apply -f "${ROOT_DIR}/api-migrate.yaml"
MIGRATION_JOB="$("${KUBECTL[@]}" -n sandboxwich get -f "${ROOT_DIR}/api-migrate.yaml" -o name)"
if ! "${KUBECTL[@]}" -n sandboxwich wait --for=condition=complete \
  "${MIGRATION_JOB}" --timeout="${MIGRATION_TIMEOUT}"; then
  "${KUBECTL[@]}" -n sandboxwich describe "${MIGRATION_JOB}" || true
  "${KUBECTL[@]}" -n sandboxwich logs "${MIGRATION_JOB}" --all-containers=true || true
  exit 1
fi

"${KUBECTL[@]}" apply -f "${ROOT_DIR}/api.yaml"
"${KUBECTL[@]}" -n sandboxwich rollout status deployment/sandboxwich-api \
  --timeout="${MIGRATION_TIMEOUT}"
"${KUBECTL[@]}" apply -f "${ROOT_DIR}/worker.yaml"
"${KUBECTL[@]}" -n sandboxwich rollout status deployment/sandboxwich-worker \
  --timeout="${MIGRATION_TIMEOUT}"
