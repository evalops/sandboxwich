# Sandboxwich control-plane hardening design

**Status:** Approved for implementation on 2026-08-15.

## Problem

Sandboxwich has a broad typed surface, but its support state remains Experimental because lifecycle authority is still coupled to callback delivery and provider-specific code paths. The current live Kubernetes conformance lane demonstrates the failure mode: a provider operation can progress while the API is restarting, then the worker can fail the job because it could not persist an intermediate stage callback. That converts an unknown outcome into a terminal outcome.

The next release must improve the trustworthiness of the existing computer path before adding another provider, execution class, or product-specific runtime feature.

## Goals

1. Never convert an ambiguous provider outcome into a terminal failure merely because the API, worker, or network was unavailable.
2. Make provider effects convergent through durable operation generations and observation.
3. Require exact-commit live conformance before publishing a release.
4. Make Buildkite the authoritative core CI implementation with PostgreSQL contract parity.
5. Separate generic computer authority from EvalOps-specific runtime integrations.
6. Declare PostgreSQL as the production database contract and SQLite as local single-process development.
7. Reserve capacity atomically rather than treating admission as a non-binding estimate.
8. Keep the roadmap and issue tracker synchronized with code that has already landed.

## Non-goals

- A new microVM provider.
- A browser UI.
- Billing.
- A model or prompt execution loop inside Sandboxwich.
- Replacing Maestro as the model-execution authority.
- Hiding meaningful PostgreSQL semantics behind a lowest-common-denominator ORM.

## Core invariants

- A transport failure after a provider request may have been accepted produces `outcome_unknown`, never `failed`.
- An operation reaches `succeeded` only from provider-confirmed observation or a replayed authoritative receipt.
- An operation reaches `failed` only from an explicit terminal provider rejection, an invalid immutable contract, or a policy/security rejection.
- Desired state, observed provider state, and callback-delivery state are independent.
- Every mutation carries a stable sandbox generation and idempotency key.
- Reconciliation is safe to repeat after API restart, worker restart, lease loss, and response loss.
- Stop and cancellation retain reserved control capacity.
- Production releases refer to one exact Git commit and one exact successful conformance run for that commit.

## Durable lifecycle operation

Introduce one durable row per logical lifecycle attempt:

```text
LifecycleOperation
  id
  tenant_id
  sandbox_id
  sandbox_generation
  kind                  provision | stop | restore | snapshot | fork
  idempotency_key
  phase                 planned | applying | outcome_unknown | observing | succeeded | failed
  provider
  provider_ref
  desired_state
  observed_state
  terminal_reason_code
  last_report_error
  attempt
  deadline_at
  cancel_requested_at
  created_at
  updated_at
  observed_at
```

`provider_ref` is provider-owned identity needed to observe or delete the effect. It may be absent while an operation is `planned`, but an operation whose request was transmitted and whose outcome cannot be proven enters `outcome_unknown`.

### Legal phase transitions

```text
planned -> applying
planned -> failed
applying -> observing
applying -> outcome_unknown
applying -> failed
outcome_unknown -> observing
outcome_unknown -> succeeded
outcome_unknown -> failed
observing -> succeeded
observing -> outcome_unknown
observing -> failed
```

No phase transitions back to `planned`. A retry retains the operation identity and increments `attempt`; a new sandbox generation creates a new operation.

## Provider contract

Provider adapters expose desired-state operations and observations. They do not directly own API lifecycle transitions.

```rust
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    async fn ensure(
        &self,
        desired: &DesiredSandbox,
        previous: Option<&ProviderRef>,
        cancellation: &CancelSignal,
    ) -> Result<ProviderObservation, ProviderError>;

    async fn observe(
        &self,
        provider_ref: &ProviderRef,
        cancellation: &CancelSignal,
    ) -> Result<ProviderObservation, ProviderError>;

    async fn delete(
        &self,
        provider_ref: &ProviderRef,
        cancellation: &CancelSignal,
    ) -> Result<ProviderObservation, ProviderError>;
}
```

Provider errors use three dispositions:

```text
retryable
  connection failure before request transmission
  429
  temporary Kubernetes conflict
  observation temporarily unavailable

outcome_unknown
  timeout after request transmission
  worker death after mutation
  callback delivery loss
  provider accepted request but response was lost

terminal
  invalid immutable specification
  unsupported capability
  explicit provider rejection
  policy or security denial
```

## Durable reporting

Provider mutation and callback delivery must not share one failure result.

The worker persists an operation update through an idempotent operation endpoint. If delivery fails, it retains the update in a bounded local reporting queue and continues only where the operation contract permits. The API reconciler can recover independently by observing `provider_ref` or resources carrying the operation idempotency label.

A callback-delivery failure records `last_report_error`; it does not rewrite the provider observation into a provider failure.

## Reconciliation

The reconciler scans nonterminal operations by `(phase, updated_at)` and performs bounded observation:

1. Load the authoritative sandbox generation and desired state.
2. Reject stale generations without mutating the current sandbox.
3. Observe the provider using `provider_ref` or the stable operation label.
4. Persist the observation and advance the operation atomically.
5. Enqueue or confirm cleanup when desired state is stopped.
6. Emit bounded-label metrics and an operator-readable event.

The reconciler must recover:

- API restart before and after every callback.
- Worker restart before and after provider mutation.
- Lease loss during provider polling.
- Duplicate provider requests.
- Provider resource creation with a lost response.
- Out-of-band provider deletion.
- Cleanup retries.

## Release certification

The release workflow resolves the tag to an exact commit SHA and requires a successful `kubernetes-conformance` workflow run whose `head_sha` is exactly that SHA. A successful run means both the `kind` lifecycle/chaos job and the Cilium FQDN job passed.

The release publishes a machine-readable attestation containing:

```json
{
  "schema": "sandboxwich.release-conformance.v1",
  "commit": "<40-hex commit>",
  "workflow": "kubernetes-conformance.yml",
  "workflowRunId": 0,
  "workflowRunUrl": "https://github.com/evalops/sandboxwich/actions/runs/0",
  "conclusion": "success",
  "verifiedAt": "RFC3339 timestamp"
}
```

No release job builds or publishes artifacts until this gate passes.

## CI authority

Buildkite owns:

- format and repository contracts;
- the complete Rust workspace test suite;
- PostgreSQL-backed HTTP and lifecycle contracts;
- Clippy;
- dependency audit;
- MSRV.

GitHub Actions continues to own:

- service and runtime image builds;
- image provenance and signatures;
- disposable Kubernetes conformance;
- Cilium and Kata conformance;
- releases.

The Buildkite test lane starts a digest-pinned PostgreSQL 17 container, waits for its health check, exports `SANDBOXWICH_TEST_POSTGRES_URL`, and fails if PostgreSQL-backed tests are skipped.

## Protocol compatibility

Worker registration advertises protocol support separately from provider capabilities:

```json
{
  "protocolVersion": 3,
  "supportedProtocolVersions": [2, 3],
  "providerAdapterVersion": "kubernetes/v1",
  "capabilities": {
    "liveCancellation": "v2",
    "persistentWorkspace": "v1",
    "snapshot": "v1"
  }
}
```

Continuous compatibility tests cover:

- old API with new worker;
- new API with old worker;
- old client with new API;
- new client with old API.

Legacy headers remain ownership-only. Provider routing uses its dedicated typed header and credential.

## Extension boundary

The stable core owns:

- sandbox lifecycle;
- commands and resident processes;
- files and artifacts;
- network authority;
- workload identity;
- workspace attachment;
- provider observations;
- attestations and receipts.

Foam, APEX, Orb, Maestro, Agent Sandbox, and future product integrations live behind versioned extension payloads and adapter crates. Adding an extension must not require a new product-specific enum variant in every scheduler, provider, cleanup, and API layer.

## Database support

PostgreSQL is the production database contract. SQLite remains supported only for local, single-process development and deterministic unit tests.

Distributed guarantees may be unavailable in SQLite when they require PostgreSQL locking, partial indexes, transaction isolation, or concurrent claim semantics. Release certification runs PostgreSQL. Documentation and `sandboxwich doctor` reject SQLite in production mode.

Repository interfaces are grouped by invariant and aggregate. Backend-specific SQL remains explicit where the semantics genuinely differ.

## Capacity reservations

Capacity becomes a typed resource vector:

```text
provider
execution_class
cpu_millicores
memory_bytes
ephemeral_storage_bytes
persistent_storage_bytes
network_mode
required_capabilities
provider_quota
observation_timestamp
```

Create-time admission may reject a request that no online worker can satisfy, but it is not a reservation. Claiming a provision operation atomically reserves capacity against one worker envelope. The reservation is released on terminal completion, cancellation, or lease expiry.

Stable outcomes:

- `capacity_unavailable`: fresh trustworthy evidence says no placement fits.
- `capacity_unknown`: evidence is missing or stale.
- `capability_unavailable`: no compatible provider exists.
- `quota_exhausted`: provider or tenant quota is exhausted.

## Rollout order

1. Fix the current API-restart/lost-callback conformance failure without weakening the test.
2. Gate releases on exact-SHA conformance.
3. Add PostgreSQL parity to Buildkite and make its aggregate status authoritative.
4. Introduce lifecycle operation generations and `outcome_unknown`.
5. Refactor worker orchestration away from provider adapters.
6. Add protocol compatibility tests and remove legacy routing ambiguity.
7. Make PostgreSQL production-only in configuration and doctor checks.
8. Add atomic capacity reservations.
9. Extract product-specific extensions incrementally.

## Promotion criteria

Before expanding providers:

- 30 consecutive successful full conformance runs on `main`.
- Zero false terminal lifecycle failures across 10,000 fault-injected operations.
- Every unknown operation converges within two reconciliation intervals.
- No provider resource remains orphaned beyond twice the reconciliation interval.
- N/N-1 API-worker compatibility is continuously green.
- Every published release contains an exact-SHA conformance attestation.
