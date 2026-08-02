#!/usr/bin/env bash
set -euo pipefail

# SW-3 live conformance for the `virtual_machine` execution class.
#
# Unlike kind-conformance.sh this script does NOT create its own cluster: a
# Kata RuntimeClass needs a runtime handler on the node, which in turn needs
# hardware virtualization (or nested virtualization) that no GitHub-hosted
# runner exposes. Point it at a disposable cluster whose nodes already run a
# Kata handler (see docs/kubernetes.md, "Kata / virtual_machine conformance")
# and it will deploy the control plane, drive a real `virtual_machine`
# sandbox through the API, and assert the VM boundary and lifecycle recovery
# gates from ROADMAP.md.
#
# Every check fails closed. There is deliberately no "Kata unavailable, skip"
# path: a green run of this script is the only evidence that certifies the
# class, so it must never be satisfiable by a cluster that cannot run VMs.
#
# Destructive to the `sandboxwich` and `sandboxwich-sandboxes` namespaces of
# the target cluster. Use a disposable cluster.

KUBE_CONTEXT="${SANDBOXWICH_KUBE_CONTEXT:-}"
CLUSTER_NAME="${SANDBOXWICH_CLUSTER_NAME:-${KUBE_CONTEXT}}"
RUNTIME_CLASS="${SANDBOXWICH_KATA_RUNTIME_CLASS:-kata-qemu}"
STORAGE_CLASS="${SANDBOXWICH_STORAGE_CLASS:-standard}"
API_IMAGE="${SANDBOXWICH_API_IMAGE:-}"
WORKER_IMAGE="${SANDBOXWICH_WORKER_IMAGE:-}"
GATEWAY_IMAGE="${SANDBOXWICH_GATEWAY_IMAGE:-}"
RUNTIME_IMAGE="${SANDBOXWICH_RUNTIME_IMAGE:-}"
POSTGRES_IMAGE="${SANDBOXWICH_POSTGRES_IMAGE:-postgres:16}"
API_TOKEN="sandboxwich-kata-conformance-token"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
  echo "kata conformance failure: $*" >&2
  kubectl get pods -A -o wide >&2 || true
  kubectl -n sandboxwich logs deployment/sandboxwich-worker --tail=-1 --prefix >&2 || true
  kubectl -n sandboxwich logs deployment/sandboxwich-api --tail=-1 --prefix >&2 || true
  exit 1
}

for command in kubectl curl jq sed; do
  command -v "${command}" >/dev/null || fail "${command} is required"
done
[[ -n "${KUBE_CONTEXT}" ]] || fail "SANDBOXWICH_KUBE_CONTEXT must name the disposable cluster's context"
[[ "${API_IMAGE}" == *@sha256:* ]] || fail "SANDBOXWICH_API_IMAGE must be digest-pinned"
[[ "${WORKER_IMAGE}" == *@sha256:* ]] || fail "SANDBOXWICH_WORKER_IMAGE must be digest-pinned"
[[ "${GATEWAY_IMAGE}" == *@sha256:* ]] || fail "SANDBOXWICH_GATEWAY_IMAGE must be digest-pinned"
[[ "${RUNTIME_IMAGE}" == *@sha256:* ]] || fail "SANDBOXWICH_RUNTIME_IMAGE must be digest-pinned"
kubectl config use-context "${KUBE_CONTEXT}" >/dev/null

# ---------------------------------------------------------------------------
# Gate 0: the cluster really can run VMs.
# ---------------------------------------------------------------------------
kubectl get runtimeclass "${RUNTIME_CLASS}" >/dev/null 2>&1 || \
  fail "RuntimeClass ${RUNTIME_CLASS} does not exist; this cluster cannot certify the VM class"
runtime_handler="$(kubectl get runtimeclass "${RUNTIME_CLASS}" -o jsonpath='{.handler}')"
[[ -n "${runtime_handler}" ]] || fail "RuntimeClass ${RUNTIME_CLASS} declares no handler"

kubectl create namespace sandboxwich
kubectl create namespace sandboxwich-sandboxes

# A probe Pod under the RuntimeClass must boot a kernel that is not the node's.
# A shared-kernel runtime (runc, gVisor's KVM-less platform, a silently
# ignored handler) cannot produce a different `uname -r`, so this is the
# cheapest positive evidence that a guest kernel exists at all.
kubectl -n sandboxwich-sandboxes run kata-probe \
  --image="${RUNTIME_IMAGE}" --restart=Never \
  --overrides="$(jq -cn --arg class "${RUNTIME_CLASS}" --arg image "${RUNTIME_IMAGE}" \
    '{spec:{runtimeClassName:$class,containers:[{name:"probe",image:$image,command:["sleep","300"]}]}}')" \
  >/dev/null
kubectl -n sandboxwich-sandboxes wait --for=condition=Ready pod/kata-probe --timeout=180s >/dev/null || \
  fail "the ${RUNTIME_CLASS} probe pod never became ready"
probe_node="$(kubectl -n sandboxwich-sandboxes get pod kata-probe -o jsonpath='{.spec.nodeName}')"
node_kernel="$(kubectl get node "${probe_node}" -o jsonpath='{.status.nodeInfo.kernelVersion}')"
guest_kernel="$(kubectl -n sandboxwich-sandboxes exec kata-probe -- uname -r)"
[[ -n "${guest_kernel}" ]] || fail "could not read the guest kernel version"
[[ "${guest_kernel}" != "${node_kernel}" ]] || \
  fail "guest kernel ${guest_kernel} equals node kernel ${node_kernel}: the workload shares the host kernel"
kubectl -n sandboxwich-sandboxes delete pod kata-probe --wait=true >/dev/null
echo "kata-runtime-verified guest_kernel=${guest_kernel} node_kernel=${node_kernel}"

# ---------------------------------------------------------------------------
# Control plane, configured for the VM class.
# ---------------------------------------------------------------------------
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
kubectl -n sandboxwich rollout status deployment/postgres --timeout=180s

sed \
  -e "s#ghcr.io/evalops/sandboxwich-api@sha256:[0-9a-f]\{64\}#${API_IMAGE}#g" \
  -e 's/replicas: 2/replicas: 1/' \
  "${ROOT_DIR}/deploy/kubernetes/api.yaml" >"${TMP_DIR}/api.yaml"
sed \
  -e "s#ghcr.io/evalops/sandboxwich-api@sha256:[0-9a-f]\{64\}#${API_IMAGE}#g" \
  "${ROOT_DIR}/deploy/kubernetes/api-migrate.yaml" >"${TMP_DIR}/api-migrate.yaml"
# The worker only advertises the `virtual_machine` capability when it runs the
# kata isolation profile with a nonempty RuntimeClass, so the deployed manifest
# is rewritten to exactly that operator configuration.
sed \
  -e "s#ghcr.io/evalops/sandboxwich-worker@sha256:[0-9a-f]\{64\}#${WORKER_IMAGE}#g" \
  -e "s#ghcr.io/evalops/sandboxwich-ubuntu-dev@sha256:[a-f0-9]\{64\}#${RUNTIME_IMAGE}#g" \
  -e "s/value: k3s-dev/value: ${CLUSTER_NAME}/" \
  -e "s/value: local-path/value: ${STORAGE_CLASS}/" \
  "${ROOT_DIR}/deploy/kubernetes/worker.yaml" >"${TMP_DIR}/worker.yaml"
sed -i "/name: SANDBOXWICH_EGRESS_GATEWAY_IMAGE/{n;s#value: .*#value: ${GATEWAY_IMAGE}#;}" \
  "${TMP_DIR}/worker.yaml"
sed -i "/name: SANDBOXWICH_RUNTIME_CLASS_NAME/{n;s#value: .*#value: ${RUNTIME_CLASS}#;}" \
  "${TMP_DIR}/worker.yaml"
sed -i "/name: SANDBOXWICH_ISOLATION_PROFILE/{n;s#value: .*#value: kata#;}" \
  "${TMP_DIR}/worker.yaml"
grep -Fq "value: ${RUNTIME_CLASS}" "${TMP_DIR}/worker.yaml" || \
  fail "worker manifest missing RuntimeClass value ${RUNTIME_CLASS}"
grep -Fq "value: kata" "${TMP_DIR}/worker.yaml" || \
  fail "worker manifest missing the kata isolation profile"

kubectl apply -f "${TMP_DIR}/api-migrate.yaml"
kubectl -n sandboxwich wait --for=condition=complete -f "${TMP_DIR}/api-migrate.yaml" --timeout=180s
kubectl apply -f "${TMP_DIR}/api.yaml"
kubectl -n sandboxwich rollout status deployment/sandboxwich-api --timeout=180s
kubectl apply -f "${TMP_DIR}/worker.yaml"
kubectl -n sandboxwich rollout status deployment/sandboxwich-worker --timeout=180s

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
  for _ in $(seq 1 180); do
    local response value
    response="$(api "${url}")" || true
    value="$(jq -r "${expression}" <<<"${response:-{}}" 2>/dev/null || true)"
    [[ "${value}" == "${expected}" ]] && return 0
    [[ "${value}" == "failed" || "${value}" == "dead" ]] && fail "terminal failure from ${url}: ${response}"
    sleep 1
  done
  fail "timed out waiting for ${expression}=${expected} from ${url}"
}

wait_command_terminal() {
  local url="$1"
  for _ in $(seq 1 180); do
    local response status
    response="$(api "${url}")" || true
    status="$(jq -r '.command.status' <<<"${response:-{}}" 2>/dev/null || true)"
    [[ "${status}" == "finished" || "${status}" == "failed" ]] && return 0
    [[ "${status}" == "dead" ]] && fail "terminal failure from ${url}: ${response}"
    sleep 1
  done
  fail "timed out waiting for a terminal command status from ${url}"
}

create_vm_sandbox() {
  local name="$1" response sandbox_id
  response="$(api -X POST http://127.0.0.1:32170/sandboxes \
    --data "$(jq -cn --arg name "${name}" \
      '{name:$name,execution_class:"virtual_machine",network_egress:{mode:"deny_all"},ttl_seconds:900}')")"
  sandbox_id="$(jq -r .sandbox.id <<<"${response}")"
  [[ "$(jq -r .sandbox.execution_class <<<"${response}")" == "virtual_machine" ]] || \
    fail "API did not record the requested execution class: ${response}"
  wait_json "http://127.0.0.1:32170/sandboxes/${sandbox_id}" '.sandbox.state' ready
  kubectl -n sandboxwich-sandboxes wait --for=condition=Ready \
    "pod/sandboxwich-${sandbox_id}" --timeout=300s >/dev/null
  printf '%s' "${sandbox_id}"
}

run_command() {
  local sandbox_id="$1" argv_json="$2" response command_id
  response="$(api -X POST "http://127.0.0.1:32170/sandboxes/${sandbox_id}/commands" \
    --data "$(jq -cn --argjson argv "${argv_json}" '{argv:$argv}')")"
  command_id="$(jq -r .command.id <<<"${response}")"
  wait_command_terminal "http://127.0.0.1:32170/commands/${command_id}"
  api "http://127.0.0.1:32170/commands/${command_id}"
}

stop_sandbox() {
  local sandbox_id="$1"
  api -X POST "http://127.0.0.1:32170/sandboxes/${sandbox_id}/stop" --data '{}' >/dev/null
  wait_json "http://127.0.0.1:32170/sandboxes/${sandbox_id}" '.sandbox.state' archived
}

# ---------------------------------------------------------------------------
# Gate 1: isolation. The product's own provisioning path must put the guest
# behind the VM boundary, not just render a manifest that says so.
# ---------------------------------------------------------------------------
vm_id="$(create_vm_sandbox kata-conformance-vm)"
[[ "$(kubectl -n sandboxwich-sandboxes get pod "sandboxwich-${vm_id}" \
  -o jsonpath='{.spec.runtimeClassName}')" == "${RUNTIME_CLASS}" ]] || \
  fail "the provisioned VM-class pod does not carry RuntimeClass ${RUNTIME_CLASS}"
vm_node="$(kubectl -n sandboxwich-sandboxes get pod "sandboxwich-${vm_id}" -o jsonpath='{.spec.nodeName}')"
vm_node_kernel="$(kubectl get node "${vm_node}" -o jsonpath='{.status.nodeInfo.kernelVersion}')"

# Guest evidence is collected through the product's command API (the path Dex
# actually uses), not through `kubectl exec`, so the boundary is proven for
# real tenant work.
kernel_response="$(run_command "${vm_id}" '["uname","-r"]')"
vm_guest_kernel="$(jq -r .command.stdout <<<"${kernel_response}" | tr -d '\n')"
[[ "$(jq -r .command.exit_code <<<"${kernel_response}")" == "0" ]] || \
  fail "could not read the guest kernel through the command API: ${kernel_response}"
[[ "${vm_guest_kernel}" != "${vm_node_kernel}" ]] || \
  fail "VM-class guest shares the node kernel ${vm_node_kernel}"

# The guest must not see the node's PID namespace, filesystem, or kubelet
# credentials. Each assertion is a distinct escape route.
host_procs="$(run_command "${vm_id}" '["sh","-c","ps -eo comm | grep -c kubelet || true"]')"
[[ "$(jq -r .command.stdout <<<"${host_procs}" | tr -d '\n')" == "0" ]] || \
  fail "the guest can see host processes: ${host_procs}"
token_probe="$(run_command "${vm_id}" '["sh","-c","test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token"]')"
[[ "$(jq -r .command.exit_code <<<"${token_probe}")" == "0" ]] || \
  fail "a service account token is mounted in the VM guest"
echo "vm-isolation-verified guest_kernel=${vm_guest_kernel} node_kernel=${vm_node_kernel}"

# ---------------------------------------------------------------------------
# Gate 2: lifecycle recovery. Killing the worker mid-command must not lose the
# VM sandbox's work, and out-of-band deletion must not wedge the stop path.
# ---------------------------------------------------------------------------
lease_response="$(api -X POST "http://127.0.0.1:32170/sandboxes/${vm_id}/commands" \
  --data '{"argv":["sh","-c","sleep 20; printf vm-lease-recovered"]}')"
lease_command_id="$(jq -r .command.id <<<"${lease_response}")"
wait_json "http://127.0.0.1:32170/commands/${lease_command_id}" '.command.status' running
kubectl -n sandboxwich delete pod -l app.kubernetes.io/name=sandboxwich-worker --wait=true
kubectl -n sandboxwich rollout status deployment/sandboxwich-worker --timeout=180s
wait_json "http://127.0.0.1:32170/commands/${lease_command_id}" '.command.status' finished
lease_command="$(api "http://127.0.0.1:32170/commands/${lease_command_id}")"
[[ "$(jq -r .command.stdout <<<"${lease_command}")" == "vm-lease-recovered" ]] || \
  fail "reclaimed VM-class command output mismatch: ${lease_command}"
echo "vm-lease-recovered"

kubectl -n sandboxwich rollout restart deployment/sandboxwich-api
kubectl -n sandboxwich rollout status deployment/sandboxwich-api --timeout=180s
start_port_forward
[[ "$(api "http://127.0.0.1:32170/sandboxes/${vm_id}" | jq -r .sandbox.execution_class)" == "virtual_machine" ]] || \
  fail "API restart lost the durable execution class"
echo "vm-api-restart-recovered"

orphan_id="$(create_vm_sandbox kata-conformance-orphan)"
kubectl -n sandboxwich-sandboxes delete pod "sandboxwich-${orphan_id}" --wait=true
stop_sandbox "${orphan_id}"
echo "vm-out-of-band-deletion-recovered"

stop_sandbox "${vm_id}"
for sandbox_id in "${vm_id}" "${orphan_id}"; do
  remaining="$(kubectl -n sandboxwich-sandboxes get pod,pvc,service,networkpolicy \
    -l "sandboxwich.dev/sandbox-id=${sandbox_id}" -o name)"
  [[ -z "${remaining}" ]] || fail "resources leaked for ${sandbox_id}: ${remaining}"
done
echo "vm-cleanup-verified"

# ---------------------------------------------------------------------------
# Gate 3: fail closed. A worker without the kata profile must never satisfy
# VM-class work, even on a cluster where the RuntimeClass exists.
# ---------------------------------------------------------------------------
# The worker stays deployed and healthy on a cluster that has the Kata
# RuntimeClass; only its typed isolation profile changes. VM-class work must
# still find no capable worker.
sed -i "/name: SANDBOXWICH_ISOLATION_PROFILE/{n;s#value: .*#value: development#;}" \
  "${TMP_DIR}/worker.yaml"
kubectl apply -f "${TMP_DIR}/worker.yaml"
kubectl -n sandboxwich rollout status deployment/sandboxwich-worker --timeout=180s

pending_response="$(api -X POST http://127.0.0.1:32170/sandboxes \
  --data '{"name":"kata-conformance-fail-closed","execution_class":"virtual_machine","network_egress":{"mode":"deny_all"},"ttl_seconds":300}')"
pending_id="$(jq -r .sandbox.id <<<"${pending_response}")"
for _ in $(seq 1 30); do
  state="$(api "http://127.0.0.1:32170/sandboxes/${pending_id}" | jq -r .sandbox.state)"
  [[ "${state}" == "ready" ]] && fail "VM-class work became ready with no VM-capable worker"
  sleep 1
done
if kubectl -n sandboxwich-sandboxes get pod "sandboxwich-${pending_id}" >/dev/null 2>&1; then
  fail "a pod was created for VM-class work with no VM-capable worker"
fi
echo "vm-fail-closed-verified"

echo "kata conformance passed"
