# Kubernetes

`sandboxwich` is being shaped to run comfortably on k3s and Kubernetes. The control plane is stateless except for Postgres, and workers register themselves with typed capabilities before they claim any work.

## Current Shape

- Run `sandboxwich-api` as a Deployment.
- Store state in Postgres through `SANDBOXWICH_DATABASE_URL`.
- Expose the API with a ClusterIP Service.
- Register workers with provider metadata such as `provider=kubernetes` and capabilities such as `k8s_pod` and `run_command`.

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

## Provider Adapter Dry Run

The first provider adapter is a Kubernetes-shaped dry run. It reports the same typed capabilities and provider metadata that a k3s worker will use, but it does not call the Kubernetes API or mutate Pods, PVCs, VolumeSnapshots, Services, or Secrets.

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

Use the dry-run output to validate control-plane wiring before granting a worker ServiceAccount any Kubernetes permissions. The smoke output includes Pod, PVC, Service, and VolumeSnapshot-shaped manifests under provider metadata, but the worker does not apply them.

## Guest Runtime Image

The starter guest runtime lives in `deploy/runtime/ubuntu-dev/`. It is an Ubuntu image contract for sandbox Pods:

- SSH daemon on port `22`.
- noVNC desktop bridge on port `6080`.
- Persistent workspace mounted at `/workspace`.
- Optional authorized keys file mounted from a caller-owned Secret.
- Development tooling installed from package repositories, including Git, Rust, Node/npm, GitHub CLI, Docker CLI/daemon packages, Python, tmux, and shell utilities.
- Docker daemon startup is opt-in with `SANDBOXWICH_DOCKERD=1` because most clusters require explicit runtime policy for that.

Build it locally or in your own registry pipeline:

```sh
docker build -t ghcr.io/evalops/sandboxwich-ubuntu-dev:latest \
  deploy/runtime/ubuntu-dev
```

Do not bake user keys into the image. Create the key Secret outside git:

```sh
kubectl -n sandboxwich create secret generic sandboxwich-authorized-keys \
  --from-file=authorized_keys=$HOME/.ssh/authorized_keys
```

The provider manifest only references the Secret by name. It expects the key `authorized_keys` and mounts it read-only at `/run/sandboxwich/ssh/authorized_keys`.

## Guarded Provider Apply

The next provider path can render the exact `kubectl` plan for a non-production smoke run. It covers provision, exec handoff metadata, snapshot, fork from a `VolumeSnapshot`, and cleanup manifests. Planning never mutates a cluster.

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

By default the smoke command deletes the resources it created with `kubectl delete --ignore-not-found -f -`. Use `--keep-resources` only when debugging a disposable namespace. Do not run the apply smoke against production-like namespaces. Grant the worker only namespace-scoped permissions for Pods, PVCs, Services, and VolumeSnapshots. `deploy/kubernetes/worker.yaml` includes a ServiceAccount, Role, RoleBinding, and worker Deployment example. Secret creation should stay in your existing secret-management path.

## Apply The API Manifests

The starter manifests in `deploy/kubernetes/` expect a Secret named `sandboxwich-secrets` with `database-url`.

```sh
kubectl create namespace sandboxwich
kubectl -n sandboxwich create secret generic sandboxwich-secrets \
  --from-literal=database-url='postgres://user:password@postgres.example:5432/sandboxwich'
kubectl apply -f deploy/kubernetes/
```

Do not commit the real database URL. Use your existing secret-management path for shared clusters.

## Next Kubernetes Work

- Add NetworkPolicy examples for sandbox egress control.
- Add Helm or Kustomize overlays for k3s, staging, and production.
- Add service accounts and RBAC once the provider adapter needs Kubernetes API access.
