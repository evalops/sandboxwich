#!/usr/bin/env bash
# Live Cilium FQDN egress conformance.
#
# Proves that a host allow rule rendered by the shipped provider
# (SANDBOXWICH_CILIUM_FQDN_EGRESS=true) is an enforcement boundary rather than
# an additive hint, by exercising it against a real Cilium data path:
#
#   allowed-fqdn-ipv4    an allowlisted name is reachable over IPv4
#   allowed-fqdn-ipv6    the same name is reachable over IPv6 (AAAA answers)
#   denied-fqdn-ipv4     a resolvable, non-allowlisted name is not reachable
#   denied-fqdn-ipv6     the same over IPv6
#   dns-failure          a name that does not resolve fails closed
#   redirect-chain       a 302 from an allowlisted origin to a denied name is
#                        blocked, and one to an allowlisted name is not
#   metadata-denied      link-local cloud metadata stays denied
#   apiserver-denied     the Kubernetes API server stays denied
#
# The policy under test is rendered by `sandboxwich-worker render-egress-policy`
# -- the same code path `provision` uses -- so this suite fails when the shipped
# rendering regresses, which a hand-maintained copy of the policy would not.
#
# The allow/deny targets are two HTTP origins run on the kind Docker network
# with distinct IPv4 and IPv6 addresses and resolved through CoreDNS, so the
# suite is hermetic: no public DNS, no public egress, and the deny case can be
# distinguished from an unreachable internet.
set -euo pipefail

namespace=sandboxwich-cilium-proof
sandbox_id="${SANDBOXWICH_CONFORMANCE_SANDBOX_ID:-00000000-0000-7000-8000-00000000c111}"
allowed_host=allowed.sandboxwich.test
denied_host=denied.sandboxwich.test
unresolvable_host=does-not-exist.sandboxwich.test
docker_network="${SANDBOXWICH_CONFORMANCE_DOCKER_NETWORK:-kind}"
origin_image="${SANDBOXWICH_CONFORMANCE_ORIGIN_IMAGE:-mirror.gcr.io/library/nginx:1.29-alpine}"
probe_image="${SANDBOXWICH_CONFORMANCE_PROBE_IMAGE:-mirror.gcr.io/curlimages/curl:8.12.1}"
worker_bin="${SANDBOXWICH_WORKER_BIN:-}"
# The IPv6 cases need a dual-stack cluster whose CNI enforces IPv6. Skipping
# them leaves the suite short of the promotion gate; it exists only so the
# suite can run on hosts without ip6tables, and CI never sets it.
skip_ipv6="${SANDBOXWICH_CONFORMANCE_SKIP_IPV6:-false}"

workdir="$(mktemp -d)"
allowed_container=sandboxwich-conformance-allowed
denied_container=sandboxwich-conformance-denied

# Leaves the cluster reusable: a namespace still Terminating fails the next
# run's `create namespace`, and a restored Corefile is only served after
# CoreDNS reloads.
cleanup() {
  kubectl delete namespace "${namespace}" --wait=true --timeout=120s >/dev/null 2>&1 || true
  docker rm -f "${allowed_container}" "${denied_container}" >/dev/null 2>&1 || true
  if kubectl -n kube-system get configmap coredns -o json >/dev/null 2>&1 &&
    kubectl -n kube-system patch configmap coredns --type merge \
      --patch-file "${workdir}/coredns-original.json" >/dev/null 2>&1; then
    kubectl -n kube-system rollout restart deployment/coredns >/dev/null 2>&1 || true
  fi
  rm -rf "${workdir}"
}
trap cleanup EXIT

if [[ -z "${worker_bin}" ]]; then
  cargo build -p sandboxwich-worker
  worker_bin="$(cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/debug/sandboxwich-worker"
fi
[[ -x "${worker_bin}" ]] || {
  echo "sandboxwich-worker binary not found at ${worker_bin}" >&2
  exit 1
}

# --- world endpoints -------------------------------------------------------
# Two origins with distinct addresses: FQDN policy resolves to IPs, so an
# allow/deny pair sharing one address would prove nothing.
cat >"${workdir}/allowed.conf" <<NGINX
server {
  listen 80;
  listen [::]:80;
  location / { return 200 "allowed-origin\n"; }
  location /redirect-to-denied { return 302 http://${denied_host}/; }
  location /redirect-to-allowed { return 302 http://${allowed_host}/; }
}
# The allowlisted origin also serves a port the rendered policy does not name,
# so the port-scoping case fails on a missing deny rather than passing on a
# refused connection.
server {
  listen 8080;
  listen [::]:8080;
  location / { return 200 "allowed-origin-8080\n"; }
}
NGINX
cat >"${workdir}/denied.conf" <<'NGINX'
server {
  listen 80;
  listen [::]:80;
  location / { return 200 "denied-origin\n"; }
}
NGINX

start_origin() {
  local name="$1" conf="$2"
  docker rm -f "${name}" >/dev/null 2>&1 || true
  docker run -d --name "${name}" --network "${docker_network}" \
    -v "${workdir}/${conf}:/etc/nginx/conf.d/default.conf:ro" \
    "${origin_image}" >/dev/null
}
start_origin "${allowed_container}" allowed.conf
start_origin "${denied_container}" denied.conf

container_address() {
  docker inspect "$1" \
    --format "{{(index .NetworkSettings.Networks \"${docker_network}\").$2}}"
}
allowed_ipv4="$(container_address "${allowed_container}" IPAddress)"
denied_ipv4="$(container_address "${denied_container}" IPAddress)"
allowed_ipv6="$(container_address "${allowed_container}" GlobalIPv6Address)"
denied_ipv6="$(container_address "${denied_container}" GlobalIPv6Address)"
[[ -n "${allowed_ipv4}" && -n "${denied_ipv4}" ]] || {
  echo "conformance origins did not receive IPv4 addresses on the ${docker_network} network" >&2
  exit 1
}
if [[ "${skip_ipv6}" != true && ( -z "${allowed_ipv6}" || -z "${denied_ipv6}" ) ]]; then
  echo "conformance origins did not receive IPv6 addresses; the cluster is not dual-stack" >&2
  exit 1
fi
# Off-policy control for allowed-fqdn-other-port: prove 8080 answers when no
# CiliumNetworkPolicy is in the way, so the later deny measures the policy.
docker run --rm --network "${docker_network}" "${probe_image}" \
  curl -fsS --retry 5 --retry-connrefused --max-time 20 \
  "http://${allowed_ipv4}:8080/" >/dev/null

# --- DNS -------------------------------------------------------------------
kubectl -n kube-system get configmap coredns -o json |
  python3 -c 'import json,sys; print(json.dumps({"data": json.load(sys.stdin)["data"]}))' \
    >"${workdir}/coredns-original.json"
hosts_block="        ${allowed_ipv4} ${allowed_host}
        ${denied_ipv4} ${denied_host}"
if [[ -n "${allowed_ipv6}" ]]; then
  hosts_block="${hosts_block}
        ${allowed_ipv6} ${allowed_host}
        ${denied_ipv6} ${denied_host}"
fi
python3 - "${workdir}/coredns-patch.json" <<PY
import json, subprocess, sys

corefile = json.loads(
    subprocess.run(
        ["kubectl", "-n", "kube-system", "get", "configmap", "coredns", "-o", "json"],
        check=True, capture_output=True, text=True,
    ).stdout
)["data"]["Corefile"]
hosts = """    hosts {
${hosts_block}
        fallthrough
    }
"""
marker = "    kubernetes cluster.local"
assert marker in corefile, corefile
patched = corefile.replace(marker, hosts + marker, 1)
with open(sys.argv[1], "w") as handle:
    json.dump({"data": {"Corefile": patched}}, handle)
PY
kubectl -n kube-system patch configmap coredns --type merge \
  --patch-file "${workdir}/coredns-patch.json"
kubectl -n kube-system rollout restart deployment/coredns
kubectl -n kube-system rollout status deployment/coredns --timeout=180s

# --- probe -----------------------------------------------------------------
kubectl create namespace "${namespace}"
kubectl -n "${namespace}" run fqdn-probe \
  --image="${probe_image}" \
  --labels="app=fqdn-probe,sandboxwich.dev/sandbox-id=${sandbox_id},sandboxwich.dev/component=runtime" \
  --command -- sh -c 'sleep 3600'
kubectl -n "${namespace}" wait --for=condition=Ready pod/fqdn-probe --timeout=180s

SANDBOXWICH_CILIUM_FQDN_EGRESS=true "${worker_bin}" render-egress-policy \
  --namespace "${namespace}" \
  --sandbox-id "${sandbox_id}" \
  --allow-host "${allowed_host}" >"${workdir}/policy.json"
python3 -c '
import json, sys

policy = json.load(open(sys.argv[1]))
assert policy["kind"] == "CiliumNetworkPolicy", policy
egress = policy["spec"]["egress"]
# Without an L7 DNS rule Cilium never populates the toFQDNs cache and this
# suite would be testing a policy that denies everything.
assert any(
    "dns" in port.get("rules", {}) for rule in egress for port in rule.get("toPorts", [])
), policy
' "${workdir}/policy.json"
kubectl apply -f "${workdir}/policy.json"
kubectl -n "${namespace}" wait \
  --for=condition=Valid ciliumnetworkpolicy/"sandboxwich-egress-${sandbox_id}" --timeout=120s

exec_probe() { kubectl -n "${namespace}" exec fqdn-probe -- "$@"; }
reachable() { exec_probe curl -fsS --max-time 8 "$@" >/dev/null 2>&1; }

# Endpoint policy application is asynchronous: wait for the allow *and* deny
# sides to both hold before asserting anything, so a pass can never come from
# a policy that has not landed yet.
policy_ready=false
for _ in $(seq 1 90); do
  if reachable -4 "http://${allowed_host}/" && ! reachable -4 "http://${denied_host}/"; then
    policy_ready=true
    break
  fi
  sleep 1
done
[[ "${policy_ready}" == true ]] || {
  echo "Cilium policy did not reach the expected allow/deny behavior" >&2
  kubectl -n "${namespace}" get ciliumendpoints.cilium.io fqdn-probe -o yaml >&2 || true
  exit 1
}

expect_allowed() {
  local marker="$1"
  shift
  exec_probe curl -fsS --retry 3 --max-time 20 "$@" >/dev/null
  echo "${marker}: pass"
}
expect_denied() {
  local marker="$1"
  shift
  if exec_probe curl -fsS --max-time 8 "$@" >/dev/null 2>&1; then
    echo "${marker}: unexpectedly reachable" >&2
    exit 1
  fi
  echo "${marker}: pass"
}

expect_allowed allowed-fqdn-ipv4 -4 "http://${allowed_host}/"
expect_denied denied-fqdn-ipv4 -4 "http://${denied_host}/"
# A denied name resolving to an allowed IP would pass the deny case for the
# wrong reason; assert the two origins really are distinct destinations.
[[ "${allowed_ipv4}" != "${denied_ipv4}" ]]

if [[ "${skip_ipv6}" == true ]]; then
  echo "allowed-fqdn-ipv6: SKIPPED (SANDBOXWICH_CONFORMANCE_SKIP_IPV6)" >&2
  echo "denied-fqdn-ipv6: SKIPPED (SANDBOXWICH_CONFORMANCE_SKIP_IPV6)" >&2
else
  expect_allowed allowed-fqdn-ipv6 -6 "http://${allowed_host}/"
  expect_denied denied-fqdn-ipv6 -6 "http://${denied_host}/"
  [[ "${allowed_ipv6}" != "${denied_ipv6}" ]]
fi

expect_denied dns-failure "http://${unresolvable_host}/"
# The redirect target is resolved and connected to inside the sandbox, so an
# allowlist that only inspected the first request would leak here.
expect_denied redirect-chain -4 -L "http://${allowed_host}/redirect-to-denied"
expect_allowed redirect-chain-allowed -4 -L "http://${allowed_host}/redirect-to-allowed"
expect_denied metadata-denied http://169.254.169.254
expect_denied apiserver-denied -k https://kubernetes.default.svc
# The allowlisted name is reachable only on the ports the rendered policy
# names; any other port on the same address stays denied.
expect_denied allowed-fqdn-other-port -4 "http://${allowed_host}:8080/"

echo "cilium FQDN conformance passed"
