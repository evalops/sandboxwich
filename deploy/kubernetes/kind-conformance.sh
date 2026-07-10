#!/usr/bin/env bash
set -euo pipefail

# Destructive only to the explicitly named disposable kind cluster.
CLUSTER_NAME="${SANDBOXWICH_KIND_CLUSTER:-sandboxwich-conformance}"
API_IMAGE="${SANDBOXWICH_API_IMAGE:-sandboxwich-api:conformance}"
WORKER_IMAGE="${SANDBOXWICH_WORKER_IMAGE:-sandboxwich-worker:conformance}"
RUNTIME_IMAGE="${SANDBOXWICH_RUNTIME_IMAGE:-sandboxwich-runtime:conformance}"
POSTGRES_IMAGE="${SANDBOXWICH_POSTGRES_IMAGE:-postgres:conformance}"
API_TOKEN="sandboxwich-kind-conformance-token"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
TMP_DIR="$(mktemp -d)"
PORT_FORWARD_PID=""
CURL_CONFIG="${TMP_DIR}/curl.conf"

cleanup() {
  if [[ -n "${PORT_FORWARD_PID}" ]]; then
    kill "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

fail() {
  echo "conformance failure: $*" >&2
  kubectl --context "${KUBE_CONTEXT}" get pods -A -o wide >&2 || true
  kubectl --context "${KUBE_CONTEXT}" -n sandboxwich logs deployment/sandboxwich-worker --tail=100 >&2 || true
  exit 1
}

for command in kind kubectl curl jq sed; do
  command -v "${command}" >/dev/null || fail "${command} is required"
done
kind get clusters | grep -Fxq "${CLUSTER_NAME}" || fail "kind cluster ${CLUSTER_NAME} does not exist"
kubectl --context "${KUBE_CONTEXT}" -n kube-system rollout status deployment/coredns --timeout=120s

kind load docker-image --name "${CLUSTER_NAME}" \
  "${API_IMAGE}" "${WORKER_IMAGE}" "${RUNTIME_IMAGE}" "${POSTGRES_IMAGE}"
kubectl config use-context "${KUBE_CONTEXT}" >/dev/null

kubectl create namespace sandboxwich
kubectl create namespace sandboxwich-sandboxes
printf '%s' 'postgres://postgres:postgres@postgres:5432/sandboxwich' >"${TMP_DIR}/database-url"
printf '%s' "${API_TOKEN}" >"${TMP_DIR}/api-token"
chmod 0600 "${TMP_DIR}/database-url" "${TMP_DIR}/api-token"
kubectl -n sandboxwich create secret generic sandboxwich-secrets \
  --from-file="database-url=${TMP_DIR}/database-url" \
  --from-file="api-token=${TMP_DIR}/api-token"
kubectl -n sandboxwich create deployment postgres --image="${POSTGRES_IMAGE}" --dry-run=client -o yaml | \
  kubectl set env --local -f - POSTGRES_DB=sandboxwich POSTGRES_USER=postgres \
    POSTGRES_PASSWORD=postgres -o yaml | kubectl apply -f -
kubectl -n sandboxwich expose deployment postgres --port=5432
kubectl -n sandboxwich rollout status deployment/postgres --timeout=120s

sed \
  -e "s#ghcr.io/evalops/sandboxwich-api:latest#${API_IMAGE}#g" \
  -e 's/imagePullPolicy: Always/imagePullPolicy: IfNotPresent/g' \
  -e 's/replicas: 2/replicas: 1/' \
  "${ROOT_DIR}/deploy/kubernetes/api.yaml" >"${TMP_DIR}/api.yaml"
sed \
  -e "s#ghcr.io/evalops/sandboxwich-worker:latest#${WORKER_IMAGE}#g" \
  -e 's/imagePullPolicy: Always/imagePullPolicy: IfNotPresent/g' \
  -e 's/value: k3s-dev/value: kind-conformance/' \
  -e 's/value: local-path/value: standard/' \
  "${ROOT_DIR}/deploy/kubernetes/worker.yaml" >"${TMP_DIR}/worker.yaml"

kubectl apply -f "${TMP_DIR}/api.yaml"
kubectl -n sandboxwich wait --for=condition=complete job/sandboxwich-api-migrate --timeout=120s
kubectl -n sandboxwich rollout status deployment/sandboxwich-api --timeout=120s
kubectl apply -f "${TMP_DIR}/worker.yaml"
kubectl -n sandboxwich set env deployment/sandboxwich-worker \
  "SANDBOXWICH_RUNTIME_IMAGE=${RUNTIME_IMAGE}"
kubectl -n sandboxwich rollout status deployment/sandboxwich-worker --timeout=120s

printf 'header = "Authorization: Bearer %s"\nheader = "content-type: application/json"\n' \
  "${API_TOKEN}" >"${CURL_CONFIG}"
chmod 0600 "${CURL_CONFIG}"

start_port_forward() {
  if [[ -n "${PORT_FORWARD_PID}" ]]; then
    kill "${PORT_FORWARD_PID}" >/dev/null 2>&1 || true
  fi
  kubectl -n sandboxwich port-forward service/sandboxwich-api 32170:3217 \
    >"${TMP_DIR}/port-forward.log" 2>&1 &
  PORT_FORWARD_PID=$!
  for _ in $(seq 1 40); do
    curl -fsS http://127.0.0.1:32170/readyz >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "API port-forward did not become ready"
}
start_port_forward

api() {
  curl -fsS --config "${CURL_CONFIG}" "$@"
}

wait_json() {
  local url="$1" expression="$2" expected="$3"
  for _ in $(seq 1 90); do
    local response value
    response="$(api "${url}")" || true
    value="$(jq -r "${expression}" <<<"${response:-{}}" 2>/dev/null || true)"
    [[ "${value}" == "${expected}" ]] && return 0
    [[ "${value}" == "failed" || "${value}" == "dead" ]] && fail "terminal failure from ${url}: ${response}"
    sleep 1
  done
  fail "timed out waiting for ${expression}=${expected} from ${url}"
}

create_sandbox() {
  local name="$1" network_egress="$2" response sandbox_id
  response="$(api -X POST http://127.0.0.1:32170/sandboxes \
    --data "$(jq -cn --arg name "${name}" --arg egress "${network_egress}" \
      '{name:$name,network_egress:{mode:$egress},ttl_seconds:600}')")"
  sandbox_id="$(jq -r .sandbox.id <<<"${response}")"
  wait_json "http://127.0.0.1:32170/sandboxes/${sandbox_id}" '.sandbox.state' ready
  kubectl -n sandboxwich-sandboxes wait --for=condition=Ready \
    "pod/sandboxwich-${sandbox_id}" --timeout=120s >/dev/null
  printf '%s' "${sandbox_id}"
}

run_command() {
  local sandbox_id="$1" argv_json="$2" response command_id
  response="$(api -X POST "http://127.0.0.1:32170/sandboxes/${sandbox_id}/commands" \
    --data "$(jq -cn --argjson argv "${argv_json}" '{argv:$argv}')")"
  command_id="$(jq -r .command.id <<<"${response}")"
  wait_json "http://127.0.0.1:32170/commands/${command_id}" '.command.status' finished
  api "http://127.0.0.1:32170/commands/${command_id}"
}

stop_sandbox() {
  local sandbox_id="$1"
  api -X POST "http://127.0.0.1:32170/sandboxes/${sandbox_id}/stop" --data '{}' >/dev/null
  wait_json "http://127.0.0.1:32170/sandboxes/${sandbox_id}" '.sandbox.state' archived
}

deny_id="$(create_sandbox conformance-deny deny_all)"
command_response="$(run_command "${deny_id}" '["sh","-c","printf sandboxwich-live-exec"]')"
[[ "$(jq -r .command.stdout <<<"${command_response}")" == "sandboxwich-live-exec" ]] || fail "exec output mismatch"

# Product-rendered pod hardening and NetworkPolicies are checked against live objects.
kubectl -n sandboxwich-sandboxes exec "sandboxwich-${deny_id}" -- \
  sh -c 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token'
api_service_ip="$(kubectl -n sandboxwich get service sandboxwich-api -o jsonpath='{.spec.clusterIP}')"
if kubectl -n sandboxwich-sandboxes exec "sandboxwich-${deny_id}" -- nc -z -w 3 "${api_service_ip}" 3217; then
  fail "deny-all sandbox reached the API service"
fi
stop_sandbox "${deny_id}"

source_id="$(create_sandbox conformance-source allow_all)"
target_id="$(create_sandbox conformance-target allow_all)"
target_ip="$(kubectl -n sandboxwich-sandboxes get pod "sandboxwich-${target_id}" -o jsonpath='{.status.podIP}')"
if kubectl -n sandboxwich-sandboxes exec "sandboxwich-${source_id}" -- nc -z -w 3 "${target_ip}" 2222; then
  fail "one sandbox reached another sandbox's SSH port"
fi

# A client that sends a complete request and disconnects without reading still
# exercises the lost-response path. The unique job must be durably visible.
lost_marker="lost-response-${source_id}"
lost_body="$(jq -cn --arg id "${source_id}" --arg marker "${lost_marker}" \
  '{kind:"provision_sandbox",payload:{sandboxId:$id,marker:$marker},required_capability:"provision_sandbox"}')"
{
  printf 'POST /jobs HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' \
    "${API_TOKEN}" "${#lost_body}" "${lost_body}"
} >/dev/tcp/127.0.0.1/32170
for _ in $(seq 1 30); do
  api http://127.0.0.1:32170/jobs | jq -e --arg marker "${lost_marker}" \
    '.jobs[] | select(.payload.marker == $marker)' >/dev/null && break
  sleep 1
done
api http://127.0.0.1:32170/jobs | jq -e --arg marker "${lost_marker}" \
  '.jobs[] | select(.payload.marker == $marker)' >/dev/null || fail "lost-response request was not durable"

# Control-plane and worker restarts must recover against durable Postgres state.
kubectl -n sandboxwich rollout restart deployment/sandboxwich-api
kubectl -n sandboxwich rollout status deployment/sandboxwich-api --timeout=120s
start_port_forward
api "http://127.0.0.1:32170/sandboxes/${source_id}" >/dev/null || fail "API restart lost durable state"
kubectl -n sandboxwich delete pod -l app.kubernetes.io/name=sandboxwich-worker --wait=true
kubectl -n sandboxwich rollout status deployment/sandboxwich-worker --timeout=120s
run_command "${source_id}" '["true"]' >/dev/null

stop_sandbox "${source_id}"
stop_sandbox "${target_id}"

# A configured-but-missing runtime handler must fail closed: the pod may be
# created, but it must never become Ready or execute guest code.
SANDBOXWICH_K8S_ENABLE_MUTATION=0 "${ROOT_DIR}/target/debug/sandboxwich-worker" \
  provider-apply-plan --cluster kind-conformance --namespace sandboxwich-sandboxes \
  --storage-class standard --runtime-image "${RUNTIME_IMAGE}" \
  --runtime-class-name sandboxwich-missing-handler >"${TMP_DIR}/runtimeclass-plan.json"
jq '[.apply_manifests[] | select(.kind == "PersistentVolumeClaim")][0]' \
  "${TMP_DIR}/runtimeclass-plan.json" >"${TMP_DIR}/runtimeclass-pvc.json"
jq '[.apply_manifests[] | select(.kind == "Pod")][0]' \
  "${TMP_DIR}/runtimeclass-plan.json" >"${TMP_DIR}/runtimeclass-pod.json"
runtimeclass_pod="$(jq -r '.metadata.name' "${TMP_DIR}/runtimeclass-pod.json")"
[[ "$(jq -r '.spec.runtimeClassName' "${TMP_DIR}/runtimeclass-pod.json")" == "sandboxwich-missing-handler" ]] \
  || fail "runtimeClassName was dropped from the rendered pod"
kubectl apply -f "${TMP_DIR}/runtimeclass-pvc.json"
if kubectl apply -f "${TMP_DIR}/runtimeclass-pod.json" 2>"${TMP_DIR}/runtimeclass-error.log"; then
  fail "pod admission accepted a missing RuntimeClass"
fi
grep -F 'RuntimeClass "sandboxwich-missing-handler" not found' \
  "${TMP_DIR}/runtimeclass-error.log" >/dev/null || fail "missing RuntimeClass did not fail closed"
if kubectl -n sandboxwich-sandboxes get pod "${runtimeclass_pod}" >/dev/null 2>&1; then
  fail "a pod exists despite missing RuntimeClass admission failure"
fi
kubectl delete -f "${TMP_DIR}/runtimeclass-pvc.json" --wait=true

for sandbox_id in "${deny_id}" "${source_id}" "${target_id}"; do
  remaining="$(kubectl -n sandboxwich-sandboxes get pod,pvc,service,networkpolicy \
    -l "sandboxwich.dev/sandbox-id=${sandbox_id}" -o name)"
  [[ -z "${remaining}" ]] || fail "resources leaked for ${sandbox_id}: ${remaining}"
done

echo "kind conformance passed"
