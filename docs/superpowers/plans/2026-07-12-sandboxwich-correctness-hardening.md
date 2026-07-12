# Sandboxwich Correctness Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist fenced provisioning progress and let `sandboxwich-worker` adopt or remove labeled Kubernetes resources after interrupted work.

**Architecture:** The API stores one provisioning operation per sandbox and accepts monotonic stage updates only from the active lease attempt. The worker applies one Kubernetes resource stage at a time, records the observed UID before advancing, and runs a bounded periodic inventory comparison against the API's live runtime-resource view. Reconciliation defaults to dry-run and deletes only labeled resources classified as orphaned or expired.

**Tech Stack:** Rust, Axum, SQLx with SQLite and PostgreSQL, `kubectl`, Prometheus text metrics, Cargo tests, kind conformance.

## Global Constraints

- `unsafe_code = "forbid"` remains enabled.
- Provider metadata must not contain secret bytes.
- Database read failure and Kubernetes discovery failure produce zero deletions.
- Reconciliation apply mode requires `SANDBOXWICH_ORPHAN_RECONCILIATION_APPLY=1`.
- Every Kubernetes delete uses namespace, kind, name, UID, and `sandboxwich.dev/sandbox-id` preconditions.
- Reconciliation limits resources scanned, resources deleted, elapsed time, and retry backoff.
- Sandboxwich PRs use merge commits and merge current `main` before their final local and CI gates.

---

### Task 1: Persist fenced provisioning operations

**Files:**
- Create: `crates/sandboxwich-api/migrations/20260712000100_provisioning_operations.sql`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Modify: `crates/sandboxwich-api/src/db.rs`
- Modify: `crates/sandboxwich-api/src/handlers/leases.rs`
- Modify: `crates/sandboxwich-api/src/routes.rs`
- Test: `crates/sandboxwich-api/src/tests.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/jobs.rs`

**Interfaces:**
- Produces: `ProvisioningStage`, `ProvisioningErrorClass`, `ProvisioningStageUpdateRequest`, and `ProvisioningOperation` in `sandboxwich_core`.
- Produces: `PUT /leases/{lease_id}/provisioning`, authenticated with the lease's worker token.
- Consumes: the existing active `JobLease.id`, `JobLease.attempt`, and `ProvisionSandbox` payload sandbox ID.

- [ ] **Step 1: Write failing enum and migration-upgrade tests**

Add round-trip cases for all seven stages and four error classes to `crates/sandboxwich-api/src/tests.rs`. Add schema assertions for `provisioning_operations(sandbox_id, lease_id, lease_attempt, stage, resource_kind, resource_namespace, resource_name, resource_uid, observed_generation, attempt_count, last_error_class, last_error, updated_at)` and the unique `sandbox_id` key.

- [ ] **Step 2: Run the focused tests and confirm the missing types and table fail**

Run: `cargo test -p sandboxwich-api provisioning_operation -- --nocapture`

Expected: compilation fails because the four core types and migration table do not exist.

- [ ] **Step 3: Add the typed contract and migration**

Define database variants with these exact wire values:

```rust
db_variant_enum! {
    pub enum ProvisioningStage {
        WorkspacePlanned => "workspace_planned",
        WorkspaceReady => "workspace_ready",
        NetworkPolicyReady => "network_policy_ready",
        CredentialsReady => "credentials_ready",
        PodReady => "pod_ready",
        ServiceReady => "service_ready",
        SandboxReady => "sandbox_ready",
    }
}

db_variant_enum! {
    pub enum ProvisioningErrorClass {
        RetryableProvider => "retryable_provider",
        RetryableCapacity => "retryable_capacity",
        TerminalContract => "terminal_contract",
        TerminalSecurity => "terminal_security",
    }
}
```

`ProvisioningStageUpdateRequest` carries `stage`, optional resource identity fields, `attempt_count`, optional typed error class, and a bounded error message. `ProvisioningOperation` returns those fields plus `sandbox_id`, `lease_id`, `lease_attempt`, and `updated_at`.

- [ ] **Step 4: Add the fenced update transaction**

Implement `update_provisioning_stage_in_transaction`. Lock or conditionally update the active lease, require `lease.status = active`, require its job kind to be `provision_sandbox`, derive the sandbox ID from the job payload, reject stage regression, and upsert only when the submitted lease ID and attempt match the active lease. Return stable errors `lease_not_active`, `provisioning_stage_regression`, and `provisioning_operation_fenced`.

- [ ] **Step 5: Test stale-holder fencing and monotonic replay**

Create an expired first lease, reclaim the job, update through the second lease, then assert the first lease cannot change the stage or resource UID. Replay the same stage and UID and assert the operation remains unchanged.

- [ ] **Step 6: Run API gates and commit**

Run:

```bash
cargo fmt --check
cargo clippy -p sandboxwich-api --all-targets -- -D warnings
cargo test -p sandboxwich-api
```

Expected: all commands exit 0.

Commit: `feat(api): persist fenced provisioning stages`

### Task 2: Apply Kubernetes provisioning as resumable stages

**Files:**
- Modify: `crates/sandboxwich-worker/src/provider.rs`
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Test: `crates/sandboxwich-worker/src/provider.rs`
- Test: `crates/sandboxwich-worker/src/main.rs`

**Interfaces:**
- Consumes: `PUT /leases/{lease_id}/provisioning` and the typed stage contract from Task 1.
- Produces: `KubernetesApplyProvider::provision_staged`, which reports one `ProvisioningStageUpdateRequest` after each observed resource identity is verified.

- [ ] **Step 1: Write failing plan-order and adoption tests**

Use a fake kubectl executable to return resource JSON with fixed UIDs. Assert the call order is PVC get/apply/get, NetworkPolicy get/apply/get, Secret get/apply/get when configured, Pod get/apply/get/wait, then Service get/apply/get. Add a replay fixture where every matching labeled resource already exists and assert no create call occurs.

- [ ] **Step 2: Run the worker tests and confirm the staged method is missing**

Run: `cargo test -p sandboxwich-worker provision_staged -- --nocapture`

Expected: compilation fails because `provision_staged` is absent.

- [ ] **Step 3: Implement resource identity checks**

Add `KubernetesResourceIdentity { kind, namespace, name, uid, observed_generation }`. Before applying a stage, read the named resource as JSON and verify the sandbox-ID label and immutable fields from the desired manifest. Adopt matches, return `terminal_contract` for conflicts, and apply only on `NotFound`.

- [ ] **Step 4: Report each durable stage**

Pass a reporter closure from `handle_lease` into job execution. After Kubernetes returns the created or adopted UID, synchronously send the exact stage update before starting the next stage. If reporting fails or the lease renewal cancellation signal fires, stop without applying another resource.

- [ ] **Step 5: Classify provider errors without string parsing**

Extend `ProviderError` to carry `ProvisioningErrorClass` and a stable reason code. Map API timeouts and transient Kubernetes failures to `retryable_provider`, unschedulable and unbound-volume waits to `retryable_capacity`, manifest conflicts to `terminal_contract`, and admission or credential denials to `terminal_security`.

- [ ] **Step 6: Verify death-and-replay behavior**

Stop the fake provider after each successful Kubernetes stage and before its API acknowledgement. On replay, assert the matching resource is adopted and the final state contains one resource per kind.

- [ ] **Step 7: Run worker gates and commit**

Run:

```bash
cargo fmt --check
cargo clippy -p sandboxwich-worker --all-targets -- -D warnings
cargo test -p sandboxwich-worker
```

Expected: all commands exit 0.

Commit: `feat(worker): resume staged sandbox provisioning`

### Task 3: Add bounded product-owned orphan reconciliation

**Files:**
- Modify: `crates/sandboxwich-worker/src/main.rs`
- Modify: `crates/sandboxwich-worker/src/provider.rs`
- Modify: `crates/sandboxwich-api/src/routes.rs`
- Modify: `crates/sandboxwich-api/src/handlers/workers.rs`
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Test: `crates/sandboxwich-worker/src/provider.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/workers.rs`
- Modify: `deploy/kubernetes/kind-conformance.sh`

**Interfaces:**
- Produces: worker-authenticated `GET /workers/{worker_id}/runtime-resource-inventory` with live sandbox IDs, expected resource identities, and expiry deadlines.
- Produces: `KubernetesApplyProvider::reconcile_orphans(inventory, limits, apply)` returning typed decisions and outcomes.

- [ ] **Step 1: Write failing classification tests**

Cover `expected`, `missing`, `orphaned`, `expired`, and `indeterminate`. Assert a database error, kubectl discovery error, unlabeled resource, mismatched UID, or exceeded scan deadline produces zero deletes.

- [ ] **Step 2: Run focused tests and confirm inventory/reconciler interfaces are missing**

Run: `cargo test -p sandboxwich-worker orphan_reconciliation -- --nocapture`

Expected: compilation fails because the interfaces are absent.

- [ ] **Step 3: Implement the bounded inventory endpoint**

Return only the requesting worker's provider, cluster, and namespace scope. Include active or cleanup-pending sandboxes, runtime resource kind/name/UID, sandbox expiry, and cleanup deadline. Bound the response with a server-side maximum and pagination cursor.

- [ ] **Step 4: Implement dry-run reconciliation**

List `pod,persistentvolumeclaim,service,secret,networkpolicy` with `sandboxwich.dev/sandbox-id`. Compare by sandbox ID, kind, namespace, name, and UID. Record reason, UID, outcome, and duration for every decision. Stop at `max_scanned` or `max_elapsed`.

- [ ] **Step 5: Add guarded delete mode and backoff**

Enable deletion only when both the CLI flag and `SANDBOXWICH_ORPHAN_RECONCILIATION_APPLY=1` are present. Delete at most `max_deleted` orphaned or expired resources, passing the observed UID precondition. Retry transient failures with bounded exponential delays and retain failed decisions for metrics.

- [ ] **Step 6: Add the periodic worker loop and metrics**

Run reconciliation independently from lease claims. Emit bounded labels for classification, kind, outcome, and error class; exclude tenant and sandbox IDs. Default production configuration remains dry-run.

- [ ] **Step 7: Add kind failure injection**

Terminate a worker after PVC, NetworkPolicy, Secret, Pod, and Service creation. Assert the next worker adopts expected resources and removes resources for database rows deleted by the fixture. Assert a foreign unlabeled ConfigMap survives.

- [ ] **Step 8: Run full repository gates and commit**

Run:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash deploy/kubernetes/kind-conformance.sh
```

Expected: all commands exit 0; the kind script reports the staged replay and orphan cleanup cases as passed.

Commit: `feat(worker): reconcile orphaned sandbox resources`

### Task 4: Land and enable the correctness lane

**Files:**
- Modify: `docs/kubernetes.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: a merged Sandboxwich PR with reconciliation dry-run enabled and apply mode documented but disabled.

- [ ] **Step 1: Document settings and rollback**

List interval, scan/delete/time limits, dry-run default, apply environment gate, error classes, metrics, and the command that disables the loop.

- [ ] **Step 2: Run the prose audit**

Read each changed documentation sentence and delete any sentence without a concrete setting, command, result, or rollback instruction. Search for placeholder markers with `rg -n 'TB[D]|TO[DO]' docs/kubernetes.md CHANGELOG.md docs/superpowers/plans/2026-07-12-sandboxwich-correctness-hardening.md` and remove every match.

- [ ] **Step 3: Merge current main and rerun gates**

Run:

```bash
git fetch origin
git merge --no-edit origin/main
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: merge succeeds and all gates exit 0.

- [ ] **Step 4: Push, open the PR, monitor CI, resolve review threads, and merge with a merge commit**

The PR body must list exact local tests and state whether PostgreSQL contract tests and kind conformance ran. After CI passes, query GraphQL `reviewThreads(first:100)`, resolve actionable findings with new commits, merge current main again if it moved, and merge using `gh pr merge --merge --delete-branch`.
