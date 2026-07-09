# sandboxwich

A tiny, typed Rust control plane for disposable development sandboxes. It is intentionally early: the first slice gives us an API, CLI, durable event model, worker boundary, and guest-agent boundary that can grow into real VM orchestration.

The name is dumb on purpose. The contracts should not be.

## What exists now

- `sandboxwich-api`: HTTP control plane backed by SQLite for local dev or Postgres for shared deployments.
- `sandboxwich-cli`: CLI for creating, listing, stopping, resuming, forking, copying files, running commands, reading events, and inspecting runtime resources.
- `sandboxwich-core`: shared typed request/response/event contracts.
- `sandboxwich-worker`: host-side worker registration and heartbeat CLI.
- `sandboxwich-agent`: guest-side daemon/CLI for guest health, streaming exec, and file read/write operations.

## Quick start

Run the API:

```sh
cargo run -p sandboxwich-api
```

Prepare or repair the database schema without starting the server:

```sh
cargo run -p sandboxwich-api -- migrate
```

Shared deployments can run `migrate` as a one-shot job and start API pods with
`SANDBOXWICH_AUTO_MIGRATE=false`; startup then only verifies that migrations and
typed database constraints are current.

In another shell:

```sh
cargo run -p sandboxwich-cli -- new --name demo --memory-limit 4g
cargo run -p sandboxwich-cli -- list
cargo run -p sandboxwich-cli -- cp <sandbox-id> ./local.txt /workspace/local.txt
cargo run -p sandboxwich-cli -- cp <sandbox-id> /workspace/local.txt ./downloaded.txt --download
cargo run -p sandboxwich-cli -- exec <sandbox-id> -- echo hello
cargo run -p sandboxwich-cli -- ssh <sandbox-id>
cargo run -p sandboxwich-cli -- prompt <sandbox-id> "inspect the repo"
cargo run -p sandboxwich-cli -- events <sandbox-id>
cargo run -p sandboxwich-cli -- resources <sandbox-id>
cargo run -p sandboxwich-worker -- register --name k3s-worker-a --provider kubernetes
cargo run -p sandboxwich-worker -- provider-smoke --cluster k3s-dev --namespace sandboxwich
cargo run -p sandboxwich-worker -- provider-apply-plan --cluster k3s-dev --namespace sandboxwich --ssh-authorized-keys-secret sandboxwich-authorized-keys
cargo run -p sandboxwich-worker -- run --name k3s-worker-a --max-iterations 1
cargo run -p sandboxwich-worker -- work-loop <worker-id> --max-iterations 1
cargo run -p sandboxwich-cli -- workers
```

By default the CLI talks to `http://127.0.0.1:3217`. Override it with `SANDBOXWICH_API`.

By default the API writes to `sqlite://sandboxwich.db`. Override it with `SANDBOXWICH_DATABASE_URL`, for example `postgres://sandboxwich:secret@localhost:5432/sandboxwich`.
Tune the API pool with `SANDBOXWICH_DATABASE_MAX_CONNECTIONS`.

The API exposes `/healthz`, `/readyz`, and `/metrics`. `/healthz` and `/readyz` remain probe-friendly for Kubernetes; every other route requires authentication.

Configure exactly one of:

- `SANDBOXWICH_API_TOKEN` — a single shared bearer token. **This is single-tenant only**: every request that presents the token is treated as `SANDBOXWICH_DEFAULT_TENANT` (`default` unless overridden), regardless of any `x-sandboxwich-tenant` header a client sends. Do not run more than one tenant's data through a shared-token deployment.
- `SANDBOXWICH_TENANT_TOKENS` — a comma-separated `tenant_id=token` list (e.g. `acme=abc123,globex=def456`) for real multi-tenant isolation. Tenant identity is derived from which bearer token matched, never from a client-supplied header.

If neither is set, the API fails closed: it refuses every non-probe request with an error rather than trusting a client-supplied `x-sandboxwich-tenant` header. There is no way to run sandboxwich-api unauthenticated.

`POST /snapshots/cleanup` performs cross-tenant maintenance (expiring snapshots and deleting archived sandboxes for every tenant) and is gated by a separate `SANDBOXWICH_OPERATOR_TOKEN` credential, checked via the `x-sandboxwich-operator-token` header. This token is intentionally distinct from tenant/shared tokens: a valid tenant credential is never sufficient to run cleanup, and cleanup is disabled (rejected) until an operator token is configured.

Sandbox create accepts typed memory tiers (`1g`, `4g`, `16g`, `64g`) and typed network egress policy. File upload/list/download state is persisted in SQL and command output chunks can carry typed file-citation annotations.

Worker completions use typed result variants. Provider-created Pods, PVCs, Services, NetworkPolicies, and VolumeSnapshots are persisted as `runtime_resources` rows with constrained kind, purpose, and status columns; provider metadata is diagnostic compatibility data, not the durable source of runtime state. Runtime resources marked `deleted` were reconciled as missing or removed outside the cleanup path; resources marked `destroyed` were explicitly torn down by archived-sandbox cleanup. Kubernetes providers render deny-by-default egress, pod/container security contexts, resource requests/limits, and optional RuntimeClass isolation such as gVisor or Kata.

## Public API contract

The stable HTTP surface is versioned under `/v1`. Unversioned routes remain as
temporary compatibility aliases and will be removed in a future major release.
Every response includes `x-request-id`; callers may supply that header to carry
their own correlation ID. Errors use a stable `{ "ok": false, "code", "message" }`
envelope, so clients should branch on `code`, never message text.

The runtime-generated OpenAPI document is served at `/v1/openapi.json`. It is
compiled from Rust handler and schema types rather than a checked-in JSON file.

Asynchronous command acceptance returns HTTP `202` and an `operation` resource.
Poll `GET /v1/operations/{id}`, reconnect to
`GET /v1/operations/{id}/events` with SSE `Last-Event-ID`, or cancel a queued
command with `POST /v1/operations/{id}/cancel`. Cancellation is rejected once
work is leased and for operation kinds that cannot be safely rolled back.

Sandbox creation currently completes synchronously and returns HTTP `201`.
Stop/resume are also synchronous today; they will expose Operations when the
provider-backed lifecycle reconciler becomes authoritative. The prompt endpoint
returns typed `501 agent_prompt_unavailable`, and workers do not advertise the
prompt capability.

## Design principles

- Typed state over text scraping.
- Durable events over inferred readiness.
- Worker and guest-agent boundaries from day one.
- Real isolation before real users.
- No committed runtime secrets.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current milestones.

For k3s and Kubernetes deployment notes, see [docs/kubernetes.md](docs/kubernetes.md).

For API compatibility notes, see [CHANGELOG.md](CHANGELOG.md).

## Benchmarks

Run the local benchmark harness after building the API, worker, and bench binaries:

```sh
cargo build -p sandboxwich-api -p sandboxwich-worker -p sandboxwich-bench
cargo run -p sandboxwich-bench -- all \
  --api-bin target/debug/sandboxwich-api \
  --worker-bin target/debug/sandboxwich-worker \
  --runs 5 \
  --ttft-runs 10 \
  --requests 300 \
  --seed-sandboxes 250
```

The harness runs a warm-start benchmark, seeds realistic sandboxes, commands,
events, workers, jobs, and runtime resources, then measures common HTTP paths.
It also measures sandbox TTFT as create sandbox request start to the first
persisted command-output chunk through a live API and live dry-run Kubernetes
worker. The TTFT phase uses a fresh temporary SQLite database so seeded jobs do
not pollute worker-claim timing. CI uploads the same style of report as
`sandboxwich-benchmark-report`.

Run just the sandbox TTFT path with:

```sh
cargo build -p sandboxwich-api -p sandboxwich-worker -p sandboxwich-bench
cargo run -p sandboxwich-bench -- sandbox-ttft \
  --api-bin target/debug/sandboxwich-api \
  --worker-bin target/debug/sandboxwich-worker \
  --runs 20
```
