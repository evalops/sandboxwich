# Sandboxwich Control-Plane Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing Sandboxwich computer path convergent under failure and make exact-commit runtime evidence a release prerequisite.

**Architecture:** Introduce durable lifecycle operations whose provider outcome is independent from callback delivery, then converge desired and observed state through provider observation. Keep Buildkite authoritative for core Rust and PostgreSQL contracts while GitHub Actions owns images, live conformance, and releases.

**Tech Stack:** Rust 1.95+, Tokio, Axum, sqlx, PostgreSQL 17, SQLite development mode, Kubernetes, Buildkite, GitHub Actions, Python 3 standard library.

## Global Constraints

- Do not weaken or delete the existing lost-response, API-restart, worker-restart, lease-loss, out-of-band-deletion, or cleanup conformance assertions.
- A transmitted provider request with an unprovable outcome must never become a terminal failure solely because callback delivery failed.
- PostgreSQL is the production correctness contract; SQLite remains local single-process development.
- No new provider, execution class, browser UI, billing surface, or model execution loop is part of this plan.
- Every new error outcome uses a stable code; clients never branch on message text.
- Every code task follows red-green-refactor and ends with focused plus workspace verification.

---

### Task 1: Exact-SHA release conformance gate

**Files:**
- Create: `scripts/verify-release-conformance.py`
- Modify: `.github/workflows/release.yml`
- Modify: `scripts/test-release-readiness.py`

**Interfaces:**
- Consumes: GitHub Actions environment variables `GITHUB_API_URL`, `GITHUB_REPOSITORY`, `GITHUB_SHA`, and `GITHUB_TOKEN`.
- Produces: `release-conformance-attestation.json` with schema `sandboxwich.release-conformance.v1`.

- [ ] **Step 1: Write the failing repository contract**

Add a test that requires the release workflow to have `actions: read`, a `conformance` job, the exact-SHA verifier invocation, and `needs: conformance` on build jobs.

```python
def test_release_waits_for_exact_sha_live_conformance(self) -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    self.assertIn("actions: read", workflow)
    self.assertIn("conformance:\n", workflow)
    self.assertIn("scripts/verify-release-conformance.py", workflow)
    self.assertIn('--sha "${GITHUB_SHA}"', workflow)
    self.assertIn("release-conformance-attestation.json", workflow)
    self.assertIn("needs: conformance", workflow)
```

- [ ] **Step 2: Run the contract and verify red**

Run:

```bash
python3 scripts/test-release-readiness.py
```

Expected: failure because the release workflow has no exact-SHA conformance job.

- [ ] **Step 3: Implement the verifier**

The verifier must:

- validate a 40-character lowercase hexadecimal SHA;
- query `GET /repos/{repo}/actions/workflows/kubernetes-conformance.yml/runs?head_sha={sha}&per_page=100`;
- pass only when a run for the exact SHA has `status=completed` and `conclusion=success`;
- fail immediately when the latest run is completed with a non-success conclusion and no newer active run exists;
- poll until a bounded deadline when the run is queued, in progress, or not yet visible;
- write the attestation atomically.

- [ ] **Step 4: Wire the release workflow**

Add `actions: read`, run the verifier before `openapi` and `cli`, upload the attestation, and make both build jobs depend on `conformance`.

- [ ] **Step 5: Verify green**

Run:

```bash
python3 scripts/test-release-readiness.py
python3 scripts/test-repository-rules.py
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/verify-release-conformance.py .github/workflows/release.yml scripts/test-release-readiness.py
git commit -m "ci: gate releases on exact-SHA conformance"
```

### Task 2: Buildkite PostgreSQL parity and CI authority

**Files:**
- Modify: `.buildkite/pipeline.yml`
- Modify: `.github/rulesets/main.json`
- Modify: `scripts/test-repository-rules.py`

**Interfaces:**
- Consumes: Docker on the hosted Buildkite Linux workers and the pinned PostgreSQL digest from `deploy/kubernetes/postgres.Dockerfile`.
- Produces: `SANDBOXWICH_TEST_POSTGRES_URL` for the full workspace test lane and one authoritative `buildkite/sandboxwich-ci` status.

- [ ] **Step 1: Write failing repository contracts**

Require the Buildkite pipeline to contain the pinned PostgreSQL image, a health check, dynamic host port discovery, and `SANDBOXWICH_TEST_POSTGRES_URL`. Require the ruleset to use `buildkite/sandboxwich-ci` plus the three image checks.

- [ ] **Step 2: Verify red**

Run:

```bash
python3 scripts/test-repository-rules.py
```

Expected: failure because Buildkite currently runs optional PostgreSQL cases without a database URL and the ruleset still treats four GitHub Rust jobs as authoritative.

- [ ] **Step 3: Add a digest-pinned PostgreSQL container to the Buildkite test step**

Use the same run-scoped Docker pattern as `evalops/platform`:

```bash
container_name="sandboxwich-buildkite-postgres-${BUILDKITE_JOB_ID//-/}"
postgres_image="mirror.gcr.io/library/postgres:17@sha256:0af65001d05296a2ead57ac4a6412433d8913d1bb5d0c88435a7d1e1ee5cb04b"
docker run --detach --rm \
  --name "${container_name}" \
  --env POSTGRES_USER=postgres \
  --env POSTGRES_PASSWORD=postgres \
  --env POSTGRES_DB=sandboxwich \
  --publish 127.0.0.1::5432 \
  --health-cmd "pg_isready -U postgres -d sandboxwich" \
  --health-interval 2s \
  --health-timeout 5s \
  --health-retries 30 \
  "${postgres_image}"
```

Export the dynamically discovered port as:

```bash
export SANDBOXWICH_TEST_POSTGRES_URL="postgres://postgres:postgres@127.0.0.1:${host_port}/sandboxwich"
```

- [ ] **Step 4: Change the checked-in desired ruleset**

Required contexts become:

```text
buildkite/sandboxwich-ci
service image (sandboxwich-api)
service image (sandboxwich-worker)
runtime image (ubuntu-dev)
```

- [ ] **Step 5: Verify green**

Run:

```bash
python3 scripts/test-repository-rules.py
python3 -c 'import yaml; yaml.safe_load(open(".buildkite/pipeline.yml"))'
```

Expected: all repository contracts pass and the Buildkite YAML parses.

- [ ] **Step 6: Commit**

```bash
git add .buildkite/pipeline.yml .github/rulesets/main.json scripts/test-repository-rules.py
git commit -m "ci: make Buildkite PostgreSQL-complete"
```

### Task 3: Durable lifecycle-operation schema and contract

**Files:**
- Create: `crates/sandboxwich-api/migrations/20260815000200_lifecycle_operations.sql`
- Create: `crates/sandboxwich-api/src/lifecycle_operations.rs`
- Modify: `crates/sandboxwich-api/src/main.rs`
- Modify: `crates/sandboxwich-api/src/state.rs`
- Modify: `crates/sandboxwich-api/src/rows.rs`
- Modify: `crates/sandboxwich-core/src/lifecycle_contract.rs`
- Modify: `contracts/lifecycle.v1.json`
- Test: `crates/sandboxwich-api/tests/http_contract/jobs.rs`

**Interfaces:**
- Produces: `LifecycleOperation`, `LifecycleOperationPhase`, and stable outcome code `provider_outcome_unknown`.
- Consumes: existing sandbox generations, jobs, leases, provisioning operations, and provider identity fields.

- [ ] **Step 1: Add a failing SQLite and PostgreSQL contract test**

The test creates one operation, advances `planned -> applying -> outcome_unknown`, replays the same observation idempotently, and rejects a stale sandbox generation.

- [ ] **Step 2: Verify red on both backends**

Run:

```bash
cargo test -p sandboxwich-api --test http_contract lifecycle_operation_unknown_outcome_is_durable -- --exact --nocapture
SANDBOXWICH_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/sandboxwich \
  cargo test -p sandboxwich-api --test http_contract lifecycle_operation_unknown_outcome_is_durable -- --exact --nocapture
```

Expected: failure because the table and types do not exist.

- [ ] **Step 3: Add the migration**

Use constrained text values, a unique `(tenant_id, sandbox_id, sandbox_generation, kind, idempotency_key)` key, and indexes on `(phase, updated_at)` and `(sandbox_id, sandbox_generation)`.

- [ ] **Step 4: Implement typed phase transitions**

Expose one function that performs a compare-and-set transition and validates the legal edge table. Replaying the current phase is idempotent only when the observation fingerprint matches.

- [ ] **Step 5: Export the machine lifecycle contract**

Add `provider_outcome_unknown` with disposition `observe_same_generation` to Rust and `contracts/lifecycle.v1.json`.

- [ ] **Step 6: Verify green**

Run focused SQLite and PostgreSQL tests, then:

```bash
cargo test -p sandboxwich-api --locked
cargo test -p sandboxwich-core --locked
cargo clippy -p sandboxwich-api -p sandboxwich-core --all-targets --locked -- -D warnings
```

- [ ] **Step 7: Commit**

```bash
git add crates/sandboxwich-api/migrations/20260815000200_lifecycle_operations.sql \
  crates/sandboxwich-api/src/lifecycle_operations.rs \
  crates/sandboxwich-api/src/main.rs crates/sandboxwich-api/src/state.rs \
  crates/sandboxwich-api/src/rows.rs crates/sandboxwich-core/src/lifecycle_contract.rs \
  contracts/lifecycle.v1.json crates/sandboxwich-api/tests/http_contract/jobs.rs
git commit -m "feat(lifecycle): persist ambiguous provider outcomes"
```

### Task 4: Separate provider outcome from callback delivery

**Files:**
- Create: `crates/sandboxwich-worker/src/operation_reporter.rs`
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Modify: `crates/sandboxwich-worker/src/provider.rs`
- Test: `crates/sandboxwich-worker/src/worker_tests.rs`
- Test: `deploy/kubernetes/kind-conformance.sh`

**Interfaces:**
- Consumes: `LifecycleOperation` API and existing `CancelSignal`.
- Produces: `OperationReporter::record_observation` and `ProviderErrorDisposition::OutcomeUnknown`.

- [ ] **Step 1: Write the failing worker test**

Simulate a provider effect that succeeds while the API rejects two callback attempts. Assert that the worker records `outcome_unknown`, does not call the terminal failure endpoint, and retains the provider reference for observation.

- [ ] **Step 2: Verify red**

Run:

```bash
cargo test -p sandboxwich-worker callback_loss_records_unknown_outcome_without_failing_provider_work -- --exact --nocapture
```

Expected: failure because callback delivery is currently part of staged provisioning progress.

- [ ] **Step 3: Implement `OperationReporter`**

The reporter owns callback retry and translates an exhausted delivery attempt into a durable unknown-outcome update. Provider code returns observations; it never fabricates a provider failure from a reporting failure.

- [ ] **Step 4: Preserve fail-closed stage ordering**

A stage whose observation cannot be durably recorded may not begin the next irreversible stage. It enters `outcome_unknown`, releases the lease safely, and lets reconciliation observe the already-applied resource.

- [ ] **Step 5: Keep the chaos test strict**

Do not remove the existing lost-response job or terminal-job assertion. Add an explicit assertion that the synthetic operation leaves no failed/dead job and reaches a provider-observed terminal state after API restart.

- [ ] **Step 6: Verify green**

Run:

```bash
cargo test -p sandboxwich-worker --locked
cargo clippy -p sandboxwich-worker --all-targets --locked -- -D warnings
deploy/kubernetes/kind-conformance.sh
```

- [ ] **Step 7: Commit**

```bash
git add crates/sandboxwich-worker/src/operation_reporter.rs \
  crates/sandboxwich-worker/src/main.rs crates/sandboxwich-worker/src/provider.rs \
  crates/sandboxwich-worker/src/worker_tests.rs deploy/kubernetes/kind-conformance.sh
git commit -m "fix(lifecycle): decouple provider outcome from callback delivery"
```

### Task 5: Provider observation and reconciliation

**Files:**
- Create: `crates/sandboxwich-worker/src/provider/observation.rs`
- Create: `crates/sandboxwich-api/src/operation_reconcile.rs`
- Modify: `crates/sandboxwich-worker/src/provider.rs`
- Modify: `crates/sandboxwich-api/src/main.rs`
- Modify: `crates/sandboxwich-api/src/config.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/jobs.rs`
- Test: `crates/sandboxwich-worker/src/provider/tests.rs`

**Interfaces:**
- Produces: `ProviderObservation`, `SandboxProvider::observe`, and a bounded API reconciliation sweep.
- Consumes: `provider_ref`, sandbox generation, desired state, and runtime-resource inventory.

- [ ] **Step 1: Write failing observation tests**

Cover an existing ready pod, a missing pod, a deleting pod, and a same-name different-UID pod. Assertions must distinguish confirmed absence from ambiguous observation.

- [ ] **Step 2: Verify red**

Run the focused provider and API tests and confirm the missing interfaces.

- [ ] **Step 3: Implement observation without mutation**

`observe` performs only provider reads. It returns typed resources, provider identity, readiness, deletion state, and evidence timestamp.

- [ ] **Step 4: Implement the bounded reconciler**

Scan only nonterminal lifecycle operations, enforce generation authority, advance from `outcome_unknown` through `observing`, and enqueue cleanup when desired state is stopped.

- [ ] **Step 5: Add metrics**

Expose bounded-label gauges and counters for operation phase, unknown-outcome age, reconciliation result, and convergence latency.

- [ ] **Step 6: Verify green**

Run focused tests, workspace tests, Clippy, and the live kind conformance lane.

- [ ] **Step 7: Commit**

```bash
git add crates/sandboxwich-worker/src/provider/observation.rs \
  crates/sandboxwich-api/src/operation_reconcile.rs \
  crates/sandboxwich-worker/src/provider.rs crates/sandboxwich-api/src/main.rs \
  crates/sandboxwich-api/src/config.rs crates/sandboxwich-api/tests/http_contract/jobs.rs \
  crates/sandboxwich-worker/src/provider/tests.rs
git commit -m "feat(lifecycle): reconcile provider observations"
```

### Task 6: Worker/provider module boundary and protocol negotiation

**Files:**
- Create: `crates/sandboxwich-worker/src/work_loop.rs`
- Create: `crates/sandboxwich-worker/src/lease_execution.rs`
- Create: `crates/sandboxwich-worker/src/cancellation.rs`
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Create: `crates/sandboxwich-core/src/protocol.rs`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Test: `crates/sandboxwich-worker/src/worker_tests.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/workers.rs`

**Interfaces:**
- Produces: `ProtocolSupport`, thin worker entrypoint, and isolated work-loop/cancellation modules.
- Consumes: existing worker registration and capability reports.

- [ ] **Step 1: Add failing protocol compatibility tests**

Test overlapping protocol ranges, no-overlap rejection, and omission by a legacy worker resolving to protocol v2 during the migration window.

- [ ] **Step 2: Verify red**

Run focused core/API tests and confirm the protocol contract is absent.

- [ ] **Step 3: Implement protocol negotiation**

Keep protocol version separate from provider capability strings. Return stable `worker_protocol_incompatible` when no overlap exists.

- [ ] **Step 4: Pure-move the worker loop**

Move code without behavioral edits, keeping tests green after each file extraction. `main.rs` retains CLI parsing and wiring only.

- [ ] **Step 5: Add N/N-1 fixtures**

Commit serialized registration fixtures for v2 and v3 and exercise both directions in API contracts.

- [ ] **Step 6: Verify green and commit**

Run worker, core, API contract, workspace, and Clippy gates, then commit as a pure structural/protocol change.

### Task 7: Production database mode and extension boundary

**Files:**
- Create: `crates/sandboxwich-core/src/extensions.rs`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Modify: `crates/sandboxwich-api/src/config.rs`
- Modify: `README.md`
- Modify: `docs/capabilities.md`
- Modify: `ROADMAP.md`
- Test: `crates/sandboxwich-api/src/tests.rs`

**Interfaces:**
- Produces: production-mode database validation and versioned extension envelopes.
- Consumes: current product-specific payloads during a compatibility migration.

- [ ] **Step 1: Add failing production-mode test**

Assert `SANDBOXWICH_PRODUCTION_MODE=1` rejects SQLite with stable code `production_mode_sqlite_unsupported` and accepts PostgreSQL configuration.

- [ ] **Step 2: Add failing extension-envelope tests**

Round-trip an unknown extension without losing bytes, reject duplicate extension keys, and enforce a bounded payload size.

- [ ] **Step 3: Implement minimal contracts**

Do not migrate every product payload in this task. Add the stable envelope and move one low-risk integration as the reference path.

- [ ] **Step 4: Update documentation**

State that PostgreSQL is production-supported, SQLite is local single-process development, and Maestro remains model-execution authority.

- [ ] **Step 5: Verify and commit**

Run focused API/core tests, workspace tests, Clippy, OpenAPI export checks, and repository contracts.

### Task 8: Atomic capacity reservations and tracker reconciliation

**Files:**
- Create: `crates/sandboxwich-api/migrations/20260815000300_capacity_reservations.sql`
- Create: `crates/sandboxwich-api/src/capacity_reservations.rs`
- Modify: `crates/sandboxwich-api/src/handlers/leases.rs`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Modify: `ROADMAP.md`
- Test: `crates/sandboxwich-api/tests/http_contract/jobs.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/workers.rs`

**Interfaces:**
- Produces: `CapacityVector`, `CapacityReservation`, and stable capacity outcomes.
- Consumes: fresh worker resource envelopes and lease claim transactions.

- [ ] **Step 1: Write the concurrent failing test**

Register one worker with capacity for one 4 GiB sandbox, queue two 4 GiB provisions, race two claims, and assert exactly one reservation succeeds.

- [ ] **Step 2: Verify red on PostgreSQL**

Run the concurrent contract with `SANDBOXWICH_TEST_POSTGRES_URL`; it must demonstrate overcommit before implementation.

- [ ] **Step 3: Add reservations**

Reserve capacity inside the same transaction that claims the lease. Release it on terminal completion, cancellation, and guarded lease expiry.

- [ ] **Step 4: Add typed outcomes**

Implement `capacity_unavailable`, `capacity_unknown`, `capability_unavailable`, and `quota_exhausted` without message parsing.

- [ ] **Step 5: Reconcile roadmap and issues**

Mark the already-landed baseline work complete, leave only live-probe, deadline propagation, and atomic reservation residuals open, and link every release blocker to a required test or conformance marker.

- [ ] **Step 6: Verify and commit**

Run PostgreSQL concurrent contracts, full workspace tests, Clippy, repository contracts, and live conformance.

## Final verification

After all tasks:

```bash
cargo fmt --all -- --check
SANDBOXWICH_TEST_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/sandboxwich \
  cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 scripts/test-repository-rules.py
python3 scripts/test-deployment-images.py
python3 scripts/test-release-readiness.py
python3 scripts/test-authz-proof.py
deploy/kubernetes/kind-conformance.sh
```

The implementation is complete only when the exact commit has a successful Buildkite core status, successful image checks, and a successful `kubernetes-conformance` run.
