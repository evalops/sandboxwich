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
  --namespace sandboxwich
```

Use the dry-run output to validate control-plane wiring before granting a worker ServiceAccount any Kubernetes permissions.

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

- Add a long-running worker lease loop.
- Turn the dry-run Kubernetes adapter into a real adapter that creates per-sandbox Pods or Jobs.
- Add NetworkPolicy examples for sandbox egress control.
- Add Helm or Kustomize overlays for k3s, staging, and production.
- Add service accounts and RBAC once the provider adapter needs Kubernetes API access.
