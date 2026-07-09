# Kubernetes

`sandboxwich` is being shaped to run comfortably on k3s and Kubernetes. The control plane is stateless except for Postgres, and workers register themselves with typed capabilities before they claim any work.

## Current Shape

- Run `sandboxwich-api` as a Deployment.
- Run `sandboxwich-api migrate` as a Job before or during rollouts.
- Store state in Postgres through `SANDBOXWICH_DATABASE_URL`.
- Expose the API with a ClusterIP Service.
- Register workers with typed provider labels such as `provider=kubernetes` and capabilities such as `k8s_pod`, `run_command`, and, when configured, `gvisor_sandbox`.
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
  --runtime-class-name gvisor \
  --workspace-storage 2Gi \
  --label cluster=k3s-dev
```

Apply mode uses the pod ServiceAccount and `kubectl` to create the sandbox PVC, Pod, NetworkPolicy, and Services in the dedicated sandbox namespace (`--sandbox-namespace`, falling back to `--namespace` when unset), waits for the sandbox Pod to become Ready, records the runtime resources through the API, and executes command jobs with `kubectl exec` against the sandbox container. The worker's RBAC in `deploy/kubernetes/worker.yaml` is scoped to the sandbox namespace only — it has no Role in the control-plane namespace where the API and its secrets live (GH-76).

The double opt-in (`--confirm-apply` plus `SANDBOXWICH_K8S_ENABLE_MUTATION=1`) exists so a worker cannot mutate Kubernetes resources by accident in local runs, CI, and smoke tests. Be aware of its limits in production: the checked-in worker Deployment sets both halves unconditionally, because an apply-mode worker with the gate closed cannot process any work. In that deployment the gate is documentation, not a control — the Role scoping to the sandbox namespace is what bounds a compromised worker's blast radius. The worker logs a startup warning whenever both halves are force-enabled so the state is visible in pod logs.

Sandbox creation carries a typed provision spec: memory tier (`1g`, `4g`, `16g`, `64g`) and network egress (`deny_all`, `allow_all`, or `allowlist`). The Kubernetes provider maps tiers to CPU/memory requests and PVC size, renders deny-by-default egress with explicit CIDR allow rules, sets `runAsNonRoot`, drops all container capabilities, and uses `RuntimeDefault` seccomp. `--runtime-class-name gvisor` or `--runtime-class-name kata` enables a RuntimeClass-backed isolation backend when the cluster supports it.

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
- noVNC desktop bridge on port `6080`, backed by `x11vnc` bound to `localhost:5900` only (not reachable from other pods) and requiring a password: either `SANDBOXWICH_VNC_PASSWORD` (wire it from a Secret with `--vnc-password-secret`) or a random one generated per container start. The noVNC web client prompts for this password.
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

Pass `--vnc-password-secret sandboxwich-vnc-password` (or set `SANDBOXWICH_VNC_PASSWORD_SECRET`) so the worker injects it as `SANDBOXWICH_VNC_PASSWORD` in the sandbox container.

## Sandbox Namespace Isolation

Sandbox Pods, Services, PVCs, and NetworkPolicies render into a dedicated namespace, separate from the control-plane namespace running `sandboxwich-api` and the `sandboxwich-secrets` Secret (`SANDBOXWICH_DATABASE_URL`, `api-token`). Configure it with `--sandbox-namespace` / `SANDBOXWICH_SANDBOX_NAMESPACE`; unset falls back to `--namespace` (the control-plane namespace), preserving older single-namespace deployments. `deploy/kubernetes/worker.yaml` creates a `sandboxwich-sandboxes` Namespace and scopes the worker's Role/RoleBinding to it exclusively, so a compromised worker cannot reach control-plane pods or the database credential.

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
