# Kubernetes

The checked-in API and worker manifests use OCI image-index digests. The API
migration job and Deployment intentionally use the same digest. After a
successful `containers` workflow, download its `*-image-digest` artifacts and
update both API references together in a reviewed pull request. Run
`python3 scripts/test-deployment-images.py` before applying the manifests.

Host egress allowlists require an enforceable FQDN boundary. Set
`SANDBOXWICH_EGRESS_GATEWAY_IMAGE` to a digest-pinned `sandboxwich-worker`
image. Each host-bearing Sandbox then gets a dedicated HTTP proxy, Service,
and NetworkPolicy. The Sandbox can reach cluster DNS and its gateway but cannot
connect directly to public IP addresses. The gateway resolves a requested host
once, rejects every result set containing a private, link-local, metadata,
cluster, or operator-excluded address, and connects to the validated address
without resolving again. Gateway loss therefore fails closed. Workers reject
host rules when the gateway image is absent or mutable.

`SANDBOXWICH_CILIUM_FQDN_EGRESS=true` remains available on namespaces managed
by Cilium DNS proxy enforcement. Native GKE `FQDNNetworkPolicy` is not used:
its allows are additive with Kubernetes NetworkPolicy and cannot preserve CIDR
denies when an allowed hostname resolves to a protected address.

`sandboxwich` is being shaped to run comfortably on k3s and Kubernetes. The control plane is stateless except for Postgres, and workers register themselves with typed capabilities before they claim any work.

## Current Shape

- Run `sandboxwich-api` as a Deployment.
- Run `sandboxwich-api migrate` as a Job before or during rollouts.
- Store state in Postgres through `SANDBOXWICH_DATABASE_URL`.
- Expose the API with a ClusterIP Service.
- Register workers with typed provider labels such as `provider=kubernetes` and capabilities such as `k8s_pod`, `run_command`, and, when configured through an isolation profile, `sandboxed_container` or `virtual_machine`.
- Persist provider-created Pods, PVCs, Services, NetworkPolicies, and VolumeSnapshots in the `runtime_resources` table for controller cleanup and capacity accounting.

The worker binary can register and heartbeat today:

```sh
sandboxwich-worker --api http://sandboxwich-api:3217 register \
  --name k3s-worker-a \
  --provider kubernetes \
  --capability k8s-pod \
  --capability run-command \
  --label cluster=k3s-dev

sandboxwich-worker --api http://sandboxwich-api:3217 heartbeat <worker-id> \
  --label node=k3s-node-1
```

Workers can process one lease or run continuously:

```sh
sandboxwich-worker --api http://sandboxwich-api:3217 run \
  --name k3s-worker-a \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --label cluster=k3s-dev

sandboxwich-worker --api http://sandboxwich-api:3217 work-once <worker-id> \
  --cluster k3s-dev \
  --namespace sandboxwich

sandboxwich-worker --api http://sandboxwich-api:3217 work-loop <worker-id> \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --idle-sleep-ms 1000
```

Use `run` in Kubernetes Deployments so the worker registers itself before entering the loop. Use `--max-iterations` for CI or non-production smoke runs. The worker dispatches by typed `JobKind` contracts and reports every lease through the API; it does not infer behavior from user-visible text.

For a real in-cluster Kubernetes worker, opt into apply mode explicitly:

```sh
SANDBOXWICH_K8S_ENABLE_MUTATION=1 sandboxwich-worker --api http://sandboxwich-api:3217 run \
  --name "$POD_NAME" \
  --provider kubernetes \
  --provider-mode apply \
  --confirm-apply \
  --kubectl-context in-cluster \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --sandbox-namespace sandboxwich-sandboxes \
  --storage-class local-path \
  --isolation-profile gvisor \
  --runtime-class-name gvisor \
  --workspace-storage 2Gi \
  --label cluster=k3s-dev
```

Apply mode uses the pod ServiceAccount and `kubectl` to create the sandbox PVC, Pod, NetworkPolicy, and Services in the dedicated sandbox namespace (`--sandbox-namespace`, falling back to `--namespace` when unset), waits for the sandbox Pod to become Ready, records the runtime resources through the API, and executes command jobs with `kubectl exec` against the sandbox container. The worker's RBAC in `deploy/kubernetes/worker.yaml` is scoped to the sandbox namespace only — it has no Role in the control-plane namespace where the API and its secrets live (GH-76).

### Provider-isolated resident sidecars

Set `SANDBOXWICH_ISOLATED_RESIDENT_PROCESS_IMAGE` to an immutable image digest
and configure a nonempty `--runtime-class-name` to enable
`provider_isolated_resident_process_v1`. The capability is never advertised in
dry-run mode or when either setting is absent. The authoritative worker then
runs `orb-sidecar` in a dedicated Pod rather than inside the guest Pod. The
sidecar has separate mount, PID, and network namespaces, no service-account
token, a read-only root filesystem, dropped capabilities, non-root identity,
seccomp, and resource bounds. Its bootstrap is mounted from an immutable
transient Secret; worker cleanup attempts to delete both resources on every
terminal path.

`SANDBOXWICH_MAX_RESIDENT_PROCESSES` (default `8`, minimum effective value `1`)
bounds concurrent sidecar supervisors per worker. At the bound, the worker
continues claiming non-resident work but leaves additional sidecars queued.

This boundary prevents a compromised guest Pod from directly reading or
tracing the sidecar, but its host-level strength is only that of the selected
RuntimeClass and cluster configuration. The two Pods do not share localhost,
so integrations must provide an explicit network endpoint or relay. Bootstrap
bytes remain API-process-local and are retryable only for the same
generation/lease/digest fence until the exact process reports `Starting`; an
API restart or replica failover cannot replay them. Once a sandbox has a
sidecar record, executor bootstrap fails closed unless that sidecar is observed
`Running` under a live lease. Operators can alert on
`sandboxwich_sidecar_bootstrap_block_total{reason=...}` and inspect
`sandboxwich_resident_process_count{state=...}` plus the bounded
`sidecar_bootstrap_blocked` and `resident_process_terminal_failure` events.

The double opt-in (`--confirm-apply` plus `SANDBOXWICH_K8S_ENABLE_MUTATION=1`) exists so a worker cannot mutate Kubernetes resources by accident in local runs, CI, and smoke tests. Be aware of its limits in production: the checked-in worker Deployment sets both halves unconditionally, because an apply-mode worker with the gate closed cannot process any work. In that deployment the gate is documentation, not a control — the Role scoping to the sandbox namespace is what bounds a compromised worker's blast radius. The worker logs a startup warning whenever both halves are force-enabled so the state is visible in pod logs.

### Orphan reconciliation

Apply-mode workers compare labeled Pods, PVCs, Services, Secrets, and NetworkPolicies with `GET /workers/{worker_id}/runtime-resource-inventory`. The loop runs every 60 seconds in the checked-in Deployment, scans at most 200 resources, spends at most 10 seconds, and permits at most 20 deletes per pass. Inventory, discovery, scope, UID, pagination, or deadline uncertainty produces no deletes. Resources for a live sandbox that have not yet been acknowledged are also indeterminate and survive the pass.

Reconciliation is dry-run unless both `--orphan-reconciliation-apply` and `SANDBOXWICH_ORPHAN_RECONCILIATION_APPLY=1` are set. Apply mode sends a Kubernetes `DeleteOptions` request with the observed UID as a precondition. Roll back immediately by removing either opt-in; use `--orphan-reconciliation-interval-secs`, `--orphan-reconciliation-max-scanned`, `--orphan-reconciliation-max-deleted`, and `--orphan-reconciliation-max-elapsed-secs` to tune the bounded loop.

Sandbox creation carries a typed provision spec: memory tier (`1g`, `4g`, `16g`, `64g`), network egress (`deny_all`, `allow_all`, or `allowlist`), and execution class (`development_container`, `sandboxed_container`, or `virtual_machine`). The Kubernetes provider maps tiers to CPU/memory requests and PVC size, renders deny-by-default egress with explicit CIDR allow rules, sets `runAsNonRoot`, drops all container capabilities, and uses `RuntimeDefault` seccomp.

### Execution class and isolation ownership

The caller's `execution_class` HTTP field is a provider-neutral workload
requirement. The operator decides how a worker satisfies it with
`--isolation-profile development|gvisor|kata` (or
`SANDBOXWICH_ISOLATION_PROFILE`) and the independently supplied
`--runtime-class-name`. The mapping is exact: `development` advertises no
hostile-workload capability, `gvisor` advertises `sandboxed_container`, and
`kata` advertises `virtual_machine`. gVisor and Kata profiles require a
nonempty RuntimeClass name; a RuntimeClass name by itself does not select or
imply an isolation profile.

Sandboxwich does not create or discover RuntimeClasses, install runtime
handlers, inspect node compatibility, or schedule supporting node labels. The
cluster operator must provision compatible nodes and runtime handlers and set
any required affinity, taints, or tolerations outside this contract. The
operator is likewise responsible for an enforceable CNI configuration, the
selected `StorageClass` and CSI `VolumeSnapshotClass`, and live conformance of
provision, command, snapshot, fork, and cleanup paths.

Worker registration and provider dry-run output report configured capability;
they do not certify that the cluster can execute it. VM-class
(`virtual_machine`/Kata) execution remains experimental until SW-3 live
conformance certification passes. Do not route production hostile workloads to
that class based only on registration or rendered manifests.

Inspect the persisted runtime view with:

```sh
sandboxwich-cli --api http://sandboxwich-api:3217 resources <sandbox-id>
```

## Provider Adapter Dry Run

The first provider adapter is a Kubernetes-shaped dry run. It reports the same typed capabilities and provider metadata that a k3s worker will use, but it does not call the Kubernetes API or mutate Pods, PVCs, NetworkPolicies, VolumeSnapshots, Services, or Secrets.

```sh
sandboxwich-worker provider-capabilities \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --storage-class local-path

sandboxwich-worker provider-health \
  --cluster k3s-dev \
  --namespace sandboxwich

sandboxwich-worker provider-smoke \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --ssh-authorized-keys-secret sandboxwich-authorized-keys
```

Use the dry-run output to validate control-plane wiring before granting a worker ServiceAccount any Kubernetes permissions. The smoke output includes Pod, PVC, NetworkPolicy, Service, and VolumeSnapshot-shaped manifests as diagnostics, while lease completion sends typed runtime-resource records to the API.

## Guest Runtime Image

The starter guest runtime lives in `deploy/runtime/ubuntu-dev/`. It is an Ubuntu image contract for sandbox Pods:

- SSH daemon on port `2222`.
- noVNC desktop bridge on port `6080`, backed by `x11vnc` bound to `localhost:5900` only (not reachable from other pods) and requiring a password: either read from the file at `SANDBOXWICH_VNC_PASSWORD_FILE` (wire a Secret with `--vnc-password-secret`, mounted read-only rather than exposed as a plain env var) or a random one generated per container start. The noVNC web client prompts for this password.
- Persistent workspace mounted at `/workspace`.
- Optional authorized keys file mounted from a caller-owned Secret.
- Development tooling installed from package repositories, including Git, Rust, Node/npm, GitHub CLI, Docker CLI/daemon packages, Python, tmux, and shell utilities.
- The image runs as the unprivileged `sandbox` user by default, with no sudoers grant (no passwordless-root escape hatch).
- Docker daemon startup is opt-in with `SANDBOXWICH_DOCKERD=1`, and is ignored in non-root pods because most clusters require explicit runtime policy for that.

Build it locally or in your own registry pipeline:

```sh
docker build -t ghcr.io/evalops/sandboxwich-ubuntu-dev:latest \
  deploy/runtime/ubuntu-dev
```

Do not bake user keys into the image. Create the key Secret outside git, in whichever namespace the provider is configured to deploy sandboxes into (see Sandbox Namespace Isolation below; `sandboxwich-sandboxes` for the shipped `worker.yaml`):

```sh
kubectl -n sandboxwich-sandboxes create secret generic sandboxwich-authorized-keys \
  --from-file=authorized_keys=$HOME/.ssh/authorized_keys
```

The provider manifest only references the Secret by name. It expects the key `authorized_keys` and mounts it read-only at `/run/sandboxwich/ssh/authorized_keys`.

The desktop VNC server requires a password (see Guest Runtime Image notes above). Optionally provide one explicitly instead of the per-container random default:

```sh
kubectl -n sandboxwich-sandboxes create secret generic sandboxwich-vnc-password \
  --from-literal=vnc-password='replace-with-a-strong-password'
```

Pass `--vnc-password-secret sandboxwich-vnc-password` (or set `SANDBOXWICH_VNC_PASSWORD_SECRET`) so the worker mounts it read-only at `/run/sandboxwich/vnc/vnc-password` in the sandbox container (exposed via `SANDBOXWICH_VNC_PASSWORD_FILE`), the same way the SSH authorized-keys Secret is mounted rather than injected as a plain env var.

## Sandbox Namespace Isolation

Sandbox Pods, Services, PVCs, NetworkPolicies, and optional GKE FQDNNetworkPolicies render into a dedicated namespace, separate from the control-plane namespace running `sandboxwich-api` and the `sandboxwich-secrets` Secret (`SANDBOXWICH_DATABASE_URL`, `api-token`). Configure it with `--sandbox-namespace` / `SANDBOXWICH_SANDBOX_NAMESPACE`; unset falls back to `--namespace` (the control-plane namespace), preserving older single-namespace deployments. `deploy/kubernetes/worker.yaml` creates a `sandboxwich-sandboxes` Namespace and scopes the worker's Role/RoleBinding to it exclusively, so a compromised worker cannot reach control-plane pods or the database credential.

The rendered per-sandbox NetworkPolicy also:

- Always allows DNS egress to `kube-dns` (scoped with `--dns-namespace` / `SANDBOXWICH_DNS_NAMESPACE`, default `kube-system`) regardless of egress mode, so an `allowlist` policy no longer silently breaks name resolution.
- Carves the control-plane/link-local/cluster CIDRs (`--egress-excluded-cidr` / `SANDBOXWICH_EGRESS_EXCLUDED_CIDRS`, default `169.254.0.0/16,10.42.0.0/16,10.43.0.0/16`, merged with any operator-supplied CIDRs unless `--egress-excluded-cidrs-replace` is set) out of *every* egress allow rule that overlaps them, not just `0.0.0.0/0` -- an allowlist entry as broad as `10.0.0.0/8` also gets the overlapping ranges carved out -- so sandboxes can never reach the apiserver or cloud metadata endpoints regardless of egress mode.
- Adds an ingress policy restricting the sandbox's ssh/desktop/vnc ports (2222/6080/5900) to pods matching `--ingress-namespace`/`--ingress-selector-label` (default: the control-plane namespace, pods labeled `app.kubernetes.io/part-of=sandboxwich`), closing the previous cross-tenant path where any pod on the cluster network could reach another tenant's sandbox desktop directly.

## Guarded Provider Apply Smoke

The standalone provider apply smoke can render the exact `kubectl` plan for a non-production provider drill. It covers provision, exec handoff metadata, snapshot, fork from a `VolumeSnapshot`, and cleanup manifests. Planning never mutates a cluster.

```sh
sandboxwich-worker provider-apply-plan \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --storage-class local-path \
  --snapshot-class local-path-snapshot \
  --ssh-authorized-keys-secret sandboxwich-authorized-keys
```

Applying is guarded by two switches:

```sh
SANDBOXWICH_K8S_ENABLE_MUTATION=1 sandboxwich-worker provider-apply-smoke \
  --cluster k3s-dev \
  --namespace sandboxwich \
  --storage-class local-path \
  --snapshot-class local-path-snapshot \
  --ssh-authorized-keys-secret sandboxwich-authorized-keys \
  --confirm-apply
```

By default the smoke command deletes the resources it created with `kubectl delete --ignore-not-found -f -`. Use `--keep-resources` only when debugging a disposable namespace. Do not run the apply smoke against production-like namespaces. Grant the worker only namespace-scoped permissions for Pods, PVCs, Services, NetworkPolicies, and VolumeSnapshots, scoped to the dedicated sandbox namespace rather than the control-plane namespace (see Sandbox Namespace Isolation above). `deploy/kubernetes/worker.yaml` includes a ServiceAccount, Role, RoleBinding, and worker Deployment example. Secret creation should stay in your existing secret-management path.

Clusters without a CSI `VolumeSnapshotClass` should use the long-running apply-mode worker for pod/exec smoke and skip the standalone full apply smoke, or pass a real snapshot class. The command execution path does not require snapshots.

## Health, Metrics, And Smoke

The API exposes:

- `/healthz` for lightweight liveness.
- `/readyz` for database-backed readiness.
- `/metrics` for Prometheus text metrics. If `SANDBOXWICH_API_TOKEN` is configured, scrape clients must send the bearer token.

The control-plane NetworkPolicy permits in-cluster scrapes from pods in the
`sandboxwich` namespace carrying the label
`sandboxwich.dev/metrics-access: "true"`. Add that label to the Prometheus pod
template (or the pod selected by your ServiceMonitor) and configure the bearer
token there. Scrapers in another namespace require a deployment-specific
companion NetworkPolicy with both namespace and pod selectors; the shipped
policy does not grant cross-namespace ingress.

Latency SLO series are derived from durable database timestamps, so API
restarts or archived-sandbox deletion do not reset them. Terminal observations
are append-only so Prometheus counters and histogram buckets remain monotonic.
`sandboxwich_sandbox_creation_seconds` and
`sandboxwich_sandbox_creation_total` are labeled by bounded `workspace_mode`,
`outcome`, and `start_type` values. A start is `warm` when the first worker
lease is acquired within 30 seconds of scheduling and `cold` otherwise; this
definition measures whether ready capacity was available without exposing node
or tenant identity. Command, cleanup, worker-claim, and provisioning-stage
histograms likewise use only bounded status, job-kind, stage, storage-mode, and
error-class labels. Tenant, sandbox, job, command, hostname, and arbitrary
provider values are never metric labels.

`sandboxwich_worker_capacity_slots` reports configured online concurrency;
`sandboxwich_worker_available_slots` subtracts active leases and clamps the
result at zero. The initial production rollout should keep SLO alerting in
measurement mode until at least 14 days of cardinality and traffic evidence is
available.

Run the read-only homelab smoke through a port-forward after GitOps applies the manifests:

```sh
SANDBOXWICH_API_TOKEN="$(kubectl -n sandboxwich get secret sandboxwich-secrets -o jsonpath='{.data.api-token}' | base64 -d)" \
SANDBOXWICH_TENANT=default \
deploy/kubernetes/homelab-smoke.sh
```

The smoke checks API and worker rollouts, `/readyz`, `/metrics`, and a tenant-scoped sandbox list. It does not apply manifests or mutate sandbox resources.

## Migrations And Startup

The API binary has three operational modes:

```sh
sandboxwich-api migrate
sandboxwich-api check-schema
sandboxwich-api serve
```

`migrate` applies SQL migrations and reconciles typed database constraints. The
constraint reconciler stores a deterministic fingerprint in the database, so a
normal restart skips constraint DDL when the typed Rust variant contract has not
changed. `check-schema` verifies that migrations and the constraint fingerprint
are current without mutating the database.

For k3s and Kubernetes, prefer a migration Job plus API pods with automatic
migration disabled:

```yaml
env:
  - name: SANDBOXWICH_AUTO_MIGRATE
    value: "false"
  - name: SANDBOXWICH_DATABASE_MAX_CONNECTIONS
    value: "10"
```

This avoids multiple replicas racing to run migrations or rewrite constraints.
Pods that start before the Job completes fail fast until the Deployment restarts
them against a ready schema.

## Apply The API Manifests

The starter manifests in `deploy/kubernetes/` expect a Secret named `sandboxwich-secrets` with `database-url`. Add `api-token` through your existing secret-management path when the API should require bearer auth.

```sh
kubectl create namespace sandboxwich
kubectl -n sandboxwich create secret generic sandboxwich-secrets \
  --from-literal=database-url='postgres://user:password@postgres.example:5432/sandboxwich' \
  --from-literal=api-token='replace-through-secret-management'
kubectl apply -f deploy/kubernetes/
```

Do not commit the real database URL or API token. Use your existing secret-management path for shared clusters.

## Benchmarking

`sandboxwich-bench` provides a repeatable local harness that does not require
`ab`, `wrk`, or `hyperfine`:

```sh
cargo build -p sandboxwich-api -p sandboxwich-bench
cargo run -p sandboxwich-bench -- all \
  --api-bin target/debug/sandboxwich-api \
  --runs 5 \
  --requests 300 \
  --seed-sandboxes 250
```

Use `sandboxwich-bench seed --database-url ...` to load larger Postgres datasets
before measuring query plans or k3s service latency. CI uploads a benchmark
report artifact on every PR and push; treat it as a trend report until the
project has dedicated, quiet benchmark runners.

## Next Kubernetes Work

- Add Helm or Kustomize overlays for k3s, staging, and production.
- Add cluster-specific RuntimeClass examples for gVisor, runsc, and Kata.
# Instance-affine APEX callbacks

The checked-in API Deployment derives `SANDBOXWICH_APEX_CALLBACK_BASE_URL`
from each pod's own `status.podIP`. Do not replace it with the
`sandboxwich-api` Service URL: instruction bytes are delivered to an in-memory
waiter owned by exactly one API process, while the database stores only request,
lease, digest, and byte-count lineage. A callback routed to another replica is
acknowledged as `outputUnavailable`, and a caller must reacquire with a fresh
claim-scoped idempotency key.

For a single-process local API, set the variable to that process's reachable
origin, for example `http://127.0.0.1:3217`. The API rejects credentials, paths,
queries, fragments, and non-HTTP schemes at startup.
