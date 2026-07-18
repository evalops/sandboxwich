# sandboxwich

A typed Rust control plane for self-hosted, policy-controlled development and
agent-evaluation sandboxes. The project is pre-1.0: Kubernetes apply mode is
experimental, and simulated capabilities are identified explicitly.

The name is dumb on purpose. The contracts should not be.

## What exists now

- `sandboxwich-api`: HTTP control plane backed by SQLite for local dev or Postgres for shared deployments.
- `sandboxwich-cli`: CLI for creating, listing, stopping, resuming, forking, copying files, running commands, reading events, and inspecting runtime resources.
- `sandboxwich-core`: shared typed request/response/event contracts.
- `sandboxwich-worker`: host-side worker registration and heartbeat CLI.
- `sandboxwich-agent`: experimental guest-side daemon/CLI. It is not included
  in the starter Ubuntu runtime image yet.
- [`sdks/python`](sdks/python): a handwritten, typed Python client (`httpx` +
  pydantic v2) covering the core sandbox/command/file/snapshot flows.

See the [capability maturity matrix](docs/capabilities.md) before selecting a
provider or relying on an isolation claim.

## Quick start

If you have [`just`](https://github.com/casey/just) installed, `just dev`
runs the API and a dry-run worker together (Ctrl-C stops both), and `just pg`
starts a dockerized Postgres for the contract tests below. See the
`justfile` for details; the manual steps follow.

Set a local-only token and run the API:

```sh
export SANDBOXWICH_API_TOKEN="local-development-token"
cargo run -p sandboxwich-api -- serve
```

Prepare or repair the database schema without starting the server:

```sh
cargo run -p sandboxwich-api -- migrate
```

Shared deployments can run `migrate` as a one-shot job and start API pods with
`SANDBOXWICH_AUTO_MIGRATE=false`; startup then only verifies that migrations and
typed database constraints are current.

In a second shell, export the same token and start a dry-run worker. Dry-run
mode validates the control-plane flow but does not create an isolated runtime:

```sh
export SANDBOXWICH_API_TOKEN="local-development-token"
cargo run -p sandboxwich-worker -- run \
  --name local-dry-run \
  --provider kubernetes \
  --provider-mode dry-run
```

In a third shell, create a sandbox and execute the typed dry-run path:

```sh
export SANDBOXWICH_API_TOKEN="local-development-token"
cargo run -p sandboxwich-cli -- new --name demo --memory-limit 4g
cargo run -p sandboxwich-cli -- list
# Copy the sandbox id from the previous output.
cargo run -p sandboxwich-cli -- exec <sandbox-id> --wait -- echo hello
cargo run -p sandboxwich-cli -- events <sandbox-id>
```

For a real disposable-cluster workflow, follow
[the Kubernetes apply-mode guide](docs/kubernetes.md). It requires explicit
mutation opt-in, a sandbox namespace, and an appropriate RuntimeClass for
hostile workloads.

By default the CLI talks to `http://127.0.0.1:3217`. Override it with `SANDBOXWICH_API`.

By default the API writes to `sqlite://sandboxwich.db`. Override it with `SANDBOXWICH_DATABASE_URL`, for example `postgres://sandboxwich:secret@localhost:5432/sandboxwich`.
Tune the API pool with `SANDBOXWICH_DATABASE_MAX_CONNECTIONS`.

The API exposes `/healthz`, `/readyz`, and `/metrics`. `/healthz` and `/readyz` remain probe-friendly for Kubernetes; every other route requires authentication.

Configure exactly one of:

- `SANDBOXWICH_API_TOKEN` — a single shared bearer token. **This is single-tenant only**: every request that presents the token is treated as `SANDBOXWICH_DEFAULT_TENANT` (`default` unless overridden), regardless of any `x-sandboxwich-tenant` header a client sends. Do not run more than one tenant's data through a shared-token deployment.
- `SANDBOXWICH_TENANT_TOKENS` — a comma-separated `tenant_id=token` list (e.g. `acme=abc123,globex=def456`) for real multi-tenant isolation. Tenant identity is derived from which bearer token matched, never from a client-supplied header.

If neither is set, the API fails closed: it refuses every non-probe request with an error rather than trusting a client-supplied `x-sandboxwich-tenant` header. There is no way to run sandboxwich-api unauthenticated.

`POST /snapshots/cleanup` performs cross-tenant maintenance (expiring snapshots and deleting archived sandboxes for every tenant) and is gated by a separate `SANDBOXWICH_OPERATOR_TOKEN` credential, checked via the `x-sandboxwich-operator-token` header. This token is intentionally distinct from tenant/shared tokens: a valid tenant credential is never sufficient to run cleanup, and cleanup is disabled (rejected) until an operator token is configured.

### Sandbox lifetime: three separate knobs

Sandboxes carry three independent, easy-to-conflate timing fields. Do not assume they're the same thing:

- **`ttl_seconds`** — retention for an *already-`archived`* sandbox's record. It does not run until the sandbox has already been stopped (by a user, or by one of the two knobs below), and it only controls how long the row (and dependent rows) stay queryable before `POST /snapshots/cleanup` deletes them.
- **`max_lifetime_seconds`** — a hard cap on how long a *live* sandbox may run at all, measured from creation. Once this passes, the background sweeper stops the sandbox through the same path `POST /sandboxes/{id}/stop` uses, regardless of activity.
- **`idle_ttl_seconds`** — stops a live sandbox after a period of no observed activity, via the same path. "Activity" is the most recent of: the sandbox's last lifecycle-state transition, its most recently queued guest command, and `last_activity_at` -- a server-maintained timestamp bumped (throttled to once per 60s per sandbox) by SSH access, desktop access, and resident-process observation requests (see [capabilities.md](docs/capabilities.md)).

All three are optional and independent of each other; a sandbox can have any combination set (or none). `max_lifetime_seconds` and `idle_ttl_seconds` are what actually reap idle or forgotten sandboxes to free host disk — `ttl_seconds` alone does not, since it never fires until something else has already stopped the sandbox.

Set `--max-lifetime-seconds`/`--idle-ttl-seconds` on `sandboxwich new`/`sandboxwich fork`, or configure operator-wide policy:

- `SANDBOXWICH_DEFAULT_MAX_LIFETIME_SECONDS` / `SANDBOXWICH_MAX_MAX_LIFETIME_SECONDS` — default and ceiling (clamp, never reject) for `max_lifetime_seconds`.
- `SANDBOXWICH_DEFAULT_IDLE_TTL_SECONDS` / `SANDBOXWICH_MAX_IDLE_TTL_SECONDS` — same, for `idle_ttl_seconds`.

All four are unset by default: with no operator configuration, a caller that omits both fields gets a sandbox with no active-lifetime cap at all, identical to behavior before these knobs existed. In particular, `workspace_mode: persistent` sandboxes get no default lifetime unless the operator explicitly configures one or the caller explicitly opts in — this is deliberate, not an oversight; a persistent workspace an operator hasn't opted into capping should not start expiring the day this ships. The reaping sweep itself runs inside the same background task as the lease/snapshot/desktop-session sweeps, so `SANDBOXWICH_DISABLE_EXPIRY_SWEEPER=true` also disables active-lifetime reaping.

Sandbox create accepts typed memory tiers (`1g`, `4g`, `16g`, `64g`) and typed network egress policy. File upload/list/download state is persisted in SQL and command output chunks can carry typed file-citation annotations.

Worker completions use typed result variants. Provider-created Pods, PVCs, Services, NetworkPolicies, and VolumeSnapshots are persisted as `runtime_resources` rows with constrained kind, purpose, and status columns; provider metadata is diagnostic compatibility data, not the durable source of runtime state. Runtime resources marked `deleted` were reconciled as missing or removed outside the cleanup path; resources marked `destroyed` were explicitly torn down by archived-sandbox cleanup. Kubernetes providers render deny-by-default egress, pod/container security contexts, resource requests/limits, and optional RuntimeClass isolation such as gVisor or Kata.

Guest agents must use a sandbox-bound token minted by the owning worker through
`POST /v1/workers/{worker_id}/sandboxes/{sandbox_id}/guest-token`. Do not copy a
worker token into a guest. Minting a replacement revokes the previous token;
stopping or deleting the sandbox also revokes it. Guest tokens can claim only
`run_command` work for their bound sandbox and cannot call worker administration
routes.

## Public API contract

The stable HTTP surface is versioned under `/v1`. Unversioned routes remain as
temporary compatibility aliases and will be removed in a future major release.
Every response includes `x-request-id`; callers may supply that header to carry
their own correlation ID. Errors use a stable `{ "ok": false, "code", "message" }`
envelope, so clients should branch on `code`, never message text.

The runtime-generated OpenAPI document is served at `/v1/openapi.json`. It is
compiled from Rust handler and schema types rather than a checked-in JSON file.

All mutating `/v1` routes accept an optional `Idempotency-Key`. Keys are scoped
to the authenticated tenant and retained for 24 hours. Repeating the same
method, URI, query, and body replays the original status, selected response
headers, and body. Reusing a key for a different request returns
`409 idempotency_key_reused`; a duplicate that is still executing returns
`409 idempotency_in_progress` with `Retry-After: 1`. Idempotent request bodies
follow the normal 1 MiB API limit, so larger multipart uploads must omit the key or be split.

Asynchronous command acceptance returns HTTP `202` and an `operation` resource.
Poll `GET /v1/operations/{id}`, reconnect to
`GET /v1/operations/{id}/events` with SSE `Last-Event-ID`, or cancel a queued
command with `POST /v1/operations/{id}/cancel`. Cancellation is rejected once
work is leased and for operation kinds that cannot be safely rolled back.

Operators can configure durable fixed-window tenant limits with
`PUT /v1/operator/tenant-policies/{tenant_id}` using `requestLimit`,
`mutationLimit`, and `windowSeconds`. The endpoint requires both normal tenant
authentication and `x-sandboxwich-operator-token`. Limits cover tenant and
worker `/v1` traffic, use atomic database counters on SQLite and PostgreSQL,
and survive API restarts. Exhausted request or mutation budgets return `429`
with `Retry-After` and the stable codes `tenant_rate_limit_exceeded` or
`tenant_mutation_quota_exceeded`; tenants without a policy remain unlimited.

Sandbox creation and stop are asynchronous and return HTTP `202` with an
Operation. Resource-only creation endpoints return `201`. Resume is explicitly
unsupported until a provider can restore durable state. The prompt endpoint
returns typed `501 agent_prompt_unavailable`, and workers do not advertise the
prompt capability.

## Design principles

- Typed state over text scraping.
- Durable events over inferred readiness.
- Worker and guest-agent boundaries from day one.
- Fail-closed isolation requirements before shared or hostile workloads.
- No committed runtime secrets.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the current milestones.

For k3s and Kubernetes deployment notes, see [docs/kubernetes.md](docs/kubernetes.md).

For API compatibility notes, see [CHANGELOG.md](CHANGELOG.md). For security
reporting and deployment boundaries, see [SECURITY.md](SECURITY.md).

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
