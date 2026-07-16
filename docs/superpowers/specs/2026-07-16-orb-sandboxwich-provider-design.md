# Orb Sandboxwich Provider Design

## Summary

Orb will gain an optional `sandboxwich` provisioner. The existing local,
Docker, and Kubernetes provisioners remain available.

Sandboxwich will gain a tenant-scoped resident-process resource for long-lived
guest processes. Orb will use that resource to run `orb-executor` inside a
Sandboxwich sandbox. Agent and task events will continue to flow between
`orb-executor` and the Orb control plane.

The integration lands in two repositories:

1. Sandboxwich adds the resident-process API and guest execution contract.
2. Orb adds the Sandboxwich client provisioner after the Sandboxwich contract
   is available on `main`.

## Existing Contracts

Orb already provides:

- `ProvisionerKind` with local, Docker, and Kubernetes variants;
- durable executor generation and runtime-instance identities;
- executor grants, authenticated handshakes, retries, and cleanup;
- a `Provisioner` trait that returns `SpawnResponse`;
- task, approval, controller, and evidence state.

Sandboxwich already provides:

- asynchronous sandbox creation with idempotent operations;
- tenant isolation, execution classes, runtime profiles, and placement proof;
- worker-scoped guest credentials;
- bounded commands, snapshots, stop, resume, and lifecycle events;
- live-only delivery patterns for secret instruction bytes;
- provider reconciliation and lease fencing.

Sandboxwich commands have a terminal status and bounded timeout. They cannot
represent an Orb executor, which may remain connected for the lifetime of a
thread.

## Goals

- Allow an Orb thread to select `provisioner=sandboxwich`.
- Provision a digest-pinned runtime image through Sandboxwich.
- Start one authenticated `orb-executor` process in the sandbox.
- Preserve Orb's executor generation, runtime instance, admission, retry, and
  cleanup semantics.
- Keep task and approval state in Orb.
- Keep sandbox placement, resource enforcement, and guest process lifecycle in
  Sandboxwich.
- Prevent executor grants and other secret bytes from entering database rows,
  API responses, logs, provider metadata, or command arguments.
- Provide deterministic unit, contract, and fake-control-plane tests.

## Non-goals

- Replacing Orb's current provisioners.
- Adding model execution to Sandboxwich.
- Moving Orb task scheduling or approvals into Sandboxwich.
- Letting Orb call Kubernetes directly after Sandboxwich provisioning.
- Providing arbitrary init systems or multi-service composition.
- Requiring a live Kubernetes cluster for the default test suite.
- Deploying the integration to a production environment in this change.

## Approaches Considered

### Bounded Sandboxwich command

Orb could queue `orb-executor` through the existing command API. The command
API clamps execution time, expects a terminal result, and stores bounded
output. Extending the timeout would leave restart, readiness, and cleanup
undefined.

### Orb-managed pod attachment

Orb could provision through Sandboxwich and then use `kubectl exec` or pod
metadata to start the executor. This would expose provider details to Orb and
bypass Sandboxwich's worker credentials and reconciliation.

### Resident process

Sandboxwich stores the desired state and public metadata for one long-lived
process, delivers bootstrap secret bytes through a live-only path, and assigns
execution to the sandbox's worker or guest agent. Orb consumes this API through
its existing provisioner boundary.

The resident-process approach is selected.

## Sandboxwich Resident-Process Contract

### Resource

The API adds a `ResidentProcess` resource:

```text
ResidentProcess
  id
  sandbox_id
  tenant_id
  name
  argv
  cwd
  environment
  bootstrap_digest
  bootstrap_byte_count
  restart_policy
  desired_state
  observed_state
  generation
  active_lease_id
  pid
  started_at
  ready_at
  exited_at
  exit_code
  last_error
  created_at
  updated_at
```

Supported values:

- `restart_policy`: `never` or `on_failure`;
- `desired_state`: `running` or `stopped`;
- `observed_state`: `pending`, `starting`, `running`, `failed`, `stopped`, or
  `lost`.

The first release allows one resident process named `orb-executor` per
sandbox. The database uniqueness key is `(sandbox_id, name)`.

### API

Tenant routes:

```text
PUT  /v1/sandboxes/{sandbox_id}/resident-processes/{name}
GET  /v1/sandboxes/{sandbox_id}/resident-processes/{name}
POST /v1/sandboxes/{sandbox_id}/resident-processes/{name}/stop
GET  /v1/sandboxes/{sandbox_id}/resident-processes/{name}/events
```

`PUT` is idempotent. The caller supplies an idempotency key and an expected
generation. Repeating the same request returns the existing resource.
Changing the process specification increments the generation and fences prior
leases.

The create request contains:

```json
{
  "argv": ["/usr/local/bin/orb-executor"],
  "cwd": "/workspace",
  "environment": {
    "ORB_THREAD_ID": "uuid",
    "ORB_WS_URL": "wss://orb.example/executor/uuid",
    "ORB_EXECUTOR_GENERATION": "4",
    "ORB_RUNTIME_INSTANCE_ID": "uuid",
    "ORB_EXECUTOR_TYPE": "sandbox",
    "ORB_TOKEN_FILE": "/run/sandboxwich/bootstrap/orb-executor-token"
  },
  "restartPolicy": "on_failure",
  "bootstrap": {
    "contentBase64": "...",
    "targetFile": "/run/sandboxwich/bootstrap/orb-executor-token",
    "mode": "0600"
  }
}
```

`contentBase64` is accepted by the API handler and forwarded through a
live-only handoff. Durable records contain its SHA-256 digest and byte count.
The request type uses a redacted `Debug` implementation.

`targetFile` must be an absolute path under `/run/sandboxwich/bootstrap/` or an
operator-configured equivalent. The worker writes the file with the requested
mode through a capability-safe path and passes the resulting path through
non-secret environment metadata.

### Worker and guest behavior

The worker claims a resident-process lease scoped to:

- tenant;
- worker;
- sandbox;
- resident-process ID;
- generation;
- lease expiry.

The guest agent receives the process specification and bootstrap bytes. It
writes the bootstrap file, spawns the process without a shell, closes inherited
file descriptors, and reports the PID.

Readiness is satisfied when the process remains alive for the configured
stability interval. Orb's authenticated executor handshake remains the
authoritative application-level readiness signal.

The guest agent renews the lease while the process is alive. A lost lease
causes the guest agent to terminate the matching process generation. A sandbox
stop marks resident processes stopped before provider teardown.

For `on_failure`, Sandboxwich applies bounded exponential backoff and preserves
the resource generation. It stops retrying after the configured attempt limit
and reports `failed`.

### Persistence and secret handling

Bootstrap bytes are excluded from:

- job payloads;
- resident-process rows;
- event payloads;
- logs and traces;
- provider handle metadata;
- list and get responses.

The API stores:

- SHA-256 digest;
- byte count;
- target-file path;
- mode;
- creation and consumption timestamps.

The API rejects bootstrap content larger than 64 KiB, target paths outside the
allowed directory, NUL bytes in arguments or environment values, duplicate
environment keys after normalization, and mutable image references when the
requested runtime profile requires a digest.

## Orb Provisioner Contract

### Configuration

Orb adds:

```text
ProvisionerKind::Sandboxwich

ORB_SANDBOXWICH_API_URL
ORB_SANDBOXWICH_API_TOKEN_FILE
ORB_SANDBOXWICH_TENANT
ORB_SANDBOXWICH_TEMPLATE
ORB_SANDBOXWICH_EXECUTION_CLASS
ORB_SANDBOXWICH_RUNTIME_PROFILE
ORB_SANDBOXWICH_TTL_SECONDS
ORB_SANDBOXWICH_PROVISION_TIMEOUT_SECONDS
```

The API token must come from a file. Orb rejects token values supplied directly
through an environment variable or CLI argument.

`ORB_SANDBOXWICH_TEMPLATE` must be a digest-pinned image reference. The image
must contain `orb-executor` at the configured executable path.

### Provisioning sequence

`SandboxwichProvisioner::provision` performs these steps:

1. Resolve the Orb repository checkout and runtime request.
2. Mint the existing Orb executor grant for the thread generation and runtime
   instance.
3. Create a Sandboxwich sandbox with an idempotency key derived from the Orb
   runtime identity.
4. Poll the returned operation until the sandbox is ready or terminal.
5. Verify placement proof uses `provider_mode=apply`.
6. Create the `orb-executor` resident process with the same runtime identity.
7. Deliver the executor grant as bootstrap bytes.
8. Poll until the resident process reports `running`.
9. Return a `SpawnResponse` whose runtime key contains the Sandboxwich sandbox
   ID, process ID, process generation, and Orb runtime identity.

Orb still waits for the executor's authenticated WebSocket handshake before
marking the runtime ready.

### Runtime identity

Orb adds a versioned `SandboxwichRuntimeResources` encoding:

```text
sandboxwich:v1:{
  sandbox_id,
  process_id,
  process_generation,
  thread_id,
  executor_generation,
  runtime_instance_id
}
```

Cleanup parses this key and sends an idempotent sandbox stop request. A delayed
cleanup request verifies the stored Orb generation and runtime instance before
stopping the sandbox.

### Retry behavior

Orb's current runtime supervisor remains responsible for retrying failed
executor provisioning. Each retry creates a new Orb runtime instance and
therefore a new Sandboxwich idempotency key.

Within one provisioning attempt:

- network and `5xx` responses use bounded retry with jitter;
- `409` generation conflicts fail the attempt;
- `401` and `403` fail without retry;
- terminal Sandboxwich operation and resident-process failures are returned
  with their public error code;
- timeout triggers sandbox cleanup before returning an error.

Sandboxwich handles provider retries and resident-process restarts inside the
same sandbox. Orb handles replacement after Sandboxwich reports a terminal
failure or the executor handshake expires.

## Event Boundaries

Sandboxwich events describe:

- sandbox planning, provisioning, readiness, stop, and failure;
- resident-process starting, running, exit, restart, stop, and lease loss;
- provider and resource failure codes.

Orb events describe:

- executor connection and disconnection;
- agent turns, tool activity, approvals, evidence, and task outcomes.

Orb may project selected Sandboxwich lifecycle events into its runtime status.
Sandboxwich does not receive Orb task transcripts, approval payloads, model
requests, or task-controller state.

## Testing

### Sandboxwich

Tests are written before implementation for:

- resident-process request validation;
- tenant isolation and hidden cross-tenant resources;
- idempotent create and generation fencing;
- live-only bootstrap delivery;
- absence of bootstrap bytes from database rows, events, logs, and responses;
- lease renewal, lease loss, restart, and stop behavior;
- sandbox stop cascading to resident processes;
- process spawn without shell interpretation;
- readiness, terminal exit, and retry exhaustion;
- OpenAPI contract generation.

The standard gates are:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Postgres contract tests run when `SANDBOXWICH_TEST_POSTGRES_URL` is available.
The live Kubernetes test remains environment-gated.

### Orb

Tests are written before implementation for:

- `sandboxwich` CLI and API enum parsing;
- configuration validation and token-file loading;
- exact sandbox and resident-process request translation;
- idempotency-key construction;
- operation polling and status classification;
- apply-mode placement proof enforcement;
- bootstrap token redaction;
- runtime-resource encoding and delayed-cleanup fencing;
- cleanup after partial provisioning;
- supervisor retry behavior;
- fake Sandboxwich API flow through an authenticated executor handshake.

The standard gates are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Landing Sequence

1. Land Sandboxwich API, storage, worker, guest-agent, tests, and OpenAPI
   changes.
2. Rebase the Orb integration on current Orb `main`.
3. Land the Orb provisioner, configuration, lifecycle cleanup, tests, and
   documentation.
4. Run each repository's full required gates after its final merge with current
   `main`.

Production deployment and live-cluster enablement require a separate explicit
request.
