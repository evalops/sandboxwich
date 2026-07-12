#!/usr/bin/env bash
set -euo pipefail

namespace=sandboxwich-cilium-proof
kubectl create namespace "${namespace}"
kubectl -n "${namespace}" run fqdn-probe \
  --image=curlimages/curl:8.12.1 --labels=app=fqdn-probe \
  --command -- sh -c 'sleep 3600'
kubectl -n "${namespace}" wait --for=condition=Ready pod/fqdn-probe --timeout=120s

cat <<'YAML' | kubectl apply -f -
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: sandboxwich-fqdn-proof
  namespace: sandboxwich-cilium-proof
spec:
  endpointSelector:
    matchLabels:
      app: fqdn-probe
  egress:
    - toEndpoints:
        - matchLabels:
            k8s:io.kubernetes.pod.namespace: kube-system
            k8s:k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: ANY
          rules:
            dns:
              - matchPattern: "*"
    - toFQDNs:
        - matchName: example.com
        - matchName: httpbingo.org
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
YAML

kubectl -n "${namespace}" wait \
  --for=condition=Valid ciliumnetworkpolicy/sandboxwich-fqdn-proof --timeout=120s
for _ in $(seq 1 60); do
  desired="$(kubectl -n "${namespace}" get ciliumendpoint fqdn-probe \
    -o jsonpath='{.status.policy.spec.policy-revision}' 2>/dev/null || true)"
  realized="$(kubectl -n "${namespace}" get ciliumendpoint fqdn-probe \
    -o jsonpath='{.status.policy.realized.policy-revision}' 2>/dev/null || true)"
  [[ -n "${desired}" && "${desired}" == "${realized}" ]] && break
  sleep 1
done
[[ -n "${desired:-}" && "${desired}" == "${realized:-}" ]] || {
  echo "Cilium endpoint policy did not realize: desired=${desired:-} realized=${realized:-}" >&2
  exit 1
}

exec_probe() { kubectl -n "${namespace}" exec fqdn-probe -- "$@"; }
expect_denied() {
  marker="$1"
  shift
  if exec_probe "$@"; then
    echo "${marker}: unexpectedly reachable" >&2
    exit 1
  fi
  echo "${marker}: pass"
}

exec_probe curl -fsSI --retry 3 --max-time 20 https://example.com >/dev/null
echo "allowed-fqdn: pass"
echo "ipv4-allowed: pass"
expect_denied denied-fqdn curl -fsSI --max-time 8 https://www.wikipedia.org
expect_denied dns-failure curl -fsSI --max-time 8 https://does-not-exist.invalid
exec_probe curl -fsSL --retry 3 --max-time 20 \
  'https://httpbingo.org/redirect-to?url=https://example.com' >/dev/null
echo "redirect-chain: pass"
expect_denied metadata-denied curl -fsS --max-time 5 http://169.254.169.254
expect_denied apiserver-denied curl -kfsS --max-time 5 https://kubernetes.default.svc
expect_denied ipv6-denied curl -gfsS --max-time 5 'http://[fd00::1]'

kubectl -n "${namespace}" delete pod fqdn-probe --wait=true
kubectl delete namespace "${namespace}" --wait=true
echo "cilium FQDN conformance passed"
