# SW-1 Typed Execution Class Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable typed execution-class contract so callers request a security boundary while operators retain control of concrete providers and RuntimeClasses.

**Architecture:** `CreateSandboxRequest` selects `ExecutionClass`, which is persisted on `sandboxes`, copied into every `SandboxProvisionSpec`, and converted to a provider-neutral required worker capability. Existing callers default to `DevelopmentContainer`. RuntimeClass configuration reports an explicit isolation capability and never labels every RuntimeClass as gVisor.

**Tech Stack:** Rust 1.95, Axum, Serde, utoipa, SQLx Any/SQLite/PostgreSQL, Cargo tests.

## Global Constraints

- Do not classify behavior from user-visible strings; use typed enums and durable fields.
- Do not add JSON catalogs or descriptor files.
- Preserve tenant-scoped idempotency and parent/fork inheritance.
- RuntimeClass/provider selection remains operator-owned; callers request only an execution class.
- `unsafe_code` remains forbidden.
- Secret values must never enter argv, provider metadata, logs, or response bodies.
- Every change must pass `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.

---

### Task 1: Define the typed contract

**Files:**
- Modify: `crates/sandboxwich-core/src/lib.rs:780-920`
- Test: `crates/sandboxwich-core/src/lib.rs` (`db_variant_values_match_expected_database_strings` and new serde tests)

**Interfaces:**
- Produces: `ExecutionClass::{DevelopmentContainer,SandboxedContainer,VirtualMachine}` with DB values `development_container`, `sandboxed_container`, `virtual_machine`.
- Produces: `SandboxProvisionSpec.execution_class: ExecutionClass`.
- Produces: `CreateSandboxRequest.execution_class: Option<ExecutionClass>`.
- Produces: `Sandbox.execution_class: ExecutionClass`.

- [ ] **Step 1: Write failing enum and serde contract tests**

Add tests that require:

```rust
assert_eq!(ExecutionClass::VALUES, &["development_container", "sandboxed_container", "virtual_machine"]);
assert_eq!(serde_json::to_string(&ExecutionClass::VirtualMachine).unwrap(), "\"virtual_machine\"");
assert_eq!(ExecutionClass::default(), ExecutionClass::DevelopmentContainer);
```

Run: `cargo test -p sandboxwich-core execution_class -- --nocapture`

Expected: FAIL because `ExecutionClass` does not exist.

- [ ] **Step 2: Implement the enum and fields**

Use the existing database enum macro:

```rust
db_variant_enum! {
pub enum ExecutionClass {
    DevelopmentContainer => "development_container",
    SandboxedContainer => "sandboxed_container",
    VirtualMachine => "virtual_machine",
}
}

impl Default for ExecutionClass {
    fn default() -> Self { Self::DevelopmentContainer }
}
```

Add `#[serde(default)] pub execution_class: ExecutionClass` to `SandboxProvisionSpec` and `Sandbox`; add `pub execution_class: Option<ExecutionClass>` to `CreateSandboxRequest`.

- [ ] **Step 3: Run the core contract tests**

Run: `cargo test -p sandboxwich-core execution_class -- --nocapture`

Expected: PASS.

- [ ] **Step 4: Commit the typed contract**

```bash
git add crates/sandboxwich-core/src/lib.rs
git commit -m "feat(core): add typed sandbox execution class"
```

### Task 2: Persist execution class and preserve inheritance

**Files:**
- Create: `crates/sandboxwich-api/migrations/20260713000300_execution_classes.sql`
- Modify: `crates/sandboxwich-api/src/handlers/sandboxes.rs:20-50`
- Modify: `crates/sandboxwich-api/src/rows.rs` sandbox row decoder
- Modify: every sandbox `SELECT`, `INSERT`, and `RETURNING` list under `crates/sandboxwich-api/src/handlers/`
- Modify: `crates/sandboxwich-api/src/db.rs` constraint registry
- Test: `crates/sandboxwich-api/tests/http_contract/sandboxes.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/types.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/idempotency.rs`

**Interfaces:**
- Consumes: `ExecutionClass` from Task 1.
- Produces: non-null `sandboxes.execution_class` with a database check constraint.
- Produces: `provision_spec_from_request` inheritance `request -> parent -> default`.

- [ ] **Step 1: Add failing HTTP inheritance and replay tests**

Cover three cases through the real HTTP server:

```rust
// omitted field defaults
assert_eq!(created.sandbox.execution_class, ExecutionClass::DevelopmentContainer);
// explicit field persists
assert_eq!(vm.sandbox.execution_class, ExecutionClass::VirtualMachine);
// fork with omitted field inherits parent
assert_eq!(child.sandbox.execution_class, ExecutionClass::VirtualMachine);
```

Also replay an identical idempotency key and reject the same key with a changed execution class.

Run: `cargo test -p sandboxwich-api --test http_contract sandboxes:: -- --nocapture`

Expected: FAIL because the HTTP/store contract does not persist the field.

- [ ] **Step 2: Add the migration and row mappings**

The migration must be portable SQL accepted by the repository's SQLite/PostgreSQL migration harness:

```sql
ALTER TABLE sandboxes ADD COLUMN execution_class TEXT NOT NULL DEFAULT 'development_container'
  CHECK (execution_class IN ('development_container','sandboxed_container','virtual_machine'));

ALTER TABLE jobs ADD COLUMN required_execution_class TEXT NOT NULL DEFAULT 'development_container'
  CHECK (required_execution_class IN ('development_container','sandboxed_container','virtual_machine'));
```

Update the constraint registry and all typed row projections. Do not place execution class inside provider metadata JSON.

- [ ] **Step 3: Implement request/parent/default resolution**

Extend `provision_spec_from_request`:

```rust
let execution_class = request.execution_class.clone()
    .or_else(|| parent.map(|sandbox| sandbox.execution_class.clone()))
    .unwrap_or_default();
```

Include it in every provision/fork/command payload that constructs `SandboxProvisionSpec`.

- [ ] **Step 4: Prove SQL constraints on both supported backends**

Run: `cargo test -p sandboxwich-api --test http_contract types:: -- --nocapture`

Expected: PASS for SQLite. If `SANDBOXWICH_TEST_POSTGRES_URL` is configured, the same command must execute the PostgreSQL branch; record whether it ran.

- [ ] **Step 5: Run API contract tests**

Run: `cargo test -p sandboxwich-api --test http_contract -- --nocapture`

Expected: PASS.

- [ ] **Step 6: Commit persistence**

```bash
git add crates/sandboxwich-api crates/sandboxwich-core/src/lib.rs
git commit -m "feat(api): persist sandbox execution class"
```

### Task 3: Route by provider-neutral capability

**Files:**
- Modify: `crates/sandboxwich-core/src/lib.rs:1498-1510`
- Modify: `crates/sandboxwich-core/src/lib.rs:1360-1380,1668-1710` job and lease contracts
- Modify: `crates/sandboxwich-api/src/handlers/sandboxes.rs:105-130`
- Modify: `crates/sandboxwich-api/src/handlers/snapshots.rs`
- Modify: `crates/sandboxwich-api/src/handlers/jobs.rs`
- Modify: `crates/sandboxwich-api/src/handlers/leases.rs`
- Modify: `crates/sandboxwich-api/src/rows.rs:458-540`
- Modify: `crates/sandboxwich-api/src/db.rs:300-320`
- Test: `crates/sandboxwich-api/tests/http_contract/workers.rs`
- Test: `crates/sandboxwich-api/tests/http_contract/jobs.rs`

**Interfaces:**
- Produces: `WorkerCapability::{SandboxedContainer,VirtualMachine}` with DB values `sandboxed_container`, `virtual_machine`.
- Produces: `execution_capability(&ExecutionClass) -> WorkerCapability`.
- Produces: durable `jobs.required_execution_class` independent of the job's
  functional `required_capability` such as `FqdnEgress` or `Snapshot`.
- Produces: `Job.required_execution_class` and `JobLease.required_execution_class`.

- [ ] **Step 1: Write failing placement tests**

Register workers with `ProvisionSandbox`, `SandboxedContainer`, and
`VirtualMachine`. Assert that a VM request is claimed only by the VM worker and
a sandboxed request only by the sandboxed worker. Existing development requests
continue to require `ProvisionSandbox`. Add a host-allowlist VM request and
prove it requires both functional `FqdnEgress` and VM execution support.

Run: `cargo test -p sandboxwich-api --test http_contract workers:: -- --nocapture`

Expected: FAIL because the capabilities and routing do not exist.

- [ ] **Step 2: Add provider-neutral capabilities and selection**

Add:

```rust
fn execution_capability(class: &ExecutionClass) -> WorkerCapability {
    match class {
        ExecutionClass::DevelopmentContainer => WorkerCapability::ProvisionSandbox,
        ExecutionClass::SandboxedContainer => WorkerCapability::SandboxedContainer,
        ExecutionClass::VirtualMachine => WorkerCapability::VirtualMachine,
    }
}
```

Keep `jobs.required_capability` as the functional capability selected by the
existing provision/fork rules. Persist the execution requirement separately in
`jobs.required_execution_class`. At claim time, derive the execution classes a
worker may claim from its typed capability set and require both predicates:

```rust
fn worker_execution_classes(capabilities: &[WorkerCapability]) -> Vec<ExecutionClass> {
    let mut classes = vec![ExecutionClass::DevelopmentContainer];
    if capabilities.contains(&WorkerCapability::SandboxedContainer) {
        classes.push(ExecutionClass::SandboxedContainer);
    }
    if capabilities.contains(&WorkerCapability::VirtualMachine) {
        classes.push(ExecutionClass::VirtualMachine);
    }
    classes
}
```

This preserves `FqdnEgress`, `Snapshot`, or `ProvisionSandbox` as an independent
functional requirement and avoids encoding a capability set in JSON.

- [ ] **Step 3: Update DB variants and parsers**

Update enum parsers, the `jobs.required_execution_class` row mapping, claim SQL,
check constraints, fixtures, and invalid-value tests. Preserve `GvisorSandbox`
as a readable legacy value until a later migration can remove it.

- [ ] **Step 4: Run placement and database tests**

Run: `cargo test -p sandboxwich-api --test http_contract workers:: -- --nocapture`

Run: `cargo test -p sandboxwich-api --test http_contract jobs:: -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit routing**

```bash
git add crates/sandboxwich-core crates/sandboxwich-api
git commit -m "feat(scheduler): route sandboxes by execution class"
```

### Task 4: Correct RuntimeClass capability reporting

**Files:**
- Modify: `crates/sandboxwich-worker/src/main.rs:240-280,2045-2105`
- Modify: `crates/sandboxwich-worker/src/provider.rs:250-390,3497-3520`
- Test: `crates/sandboxwich-worker/src/worker_tests.rs:590-625`
- Test: `crates/sandboxwich-worker/src/provider/tests.rs:390-440`

**Interfaces:**
- Produces: typed CLI `--isolation-profile development|gvisor|kata`.
- Produces: exact mapping `gvisor -> SandboxedContainer`, `kata -> VirtualMachine`.
- Keeps `--runtime-class-name` operator-owned and requires it for gVisor/Kata profiles.

- [ ] **Step 1: Replace the permissive capability test with failing exact-profile tests**

Require these outcomes:

```rust
assert!(!capabilities(None, None).contains(&WorkerCapability::SandboxedContainer));
assert!(capabilities(Some(Gvisor), Some("gvisor")).contains(&WorkerCapability::SandboxedContainer));
assert!(capabilities(Some(Kata), Some("kata")).contains(&WorkerCapability::VirtualMachine));
assert!(capabilities(Some(Development), Some("arbitrary")).iter().all(|c| !matches!(c, WorkerCapability::SandboxedContainer | WorkerCapability::VirtualMachine)));
```

Run: `cargo test -p sandboxwich-worker capabilities_from_args -- --nocapture`

Expected: FAIL against current any-RuntimeClass-is-gVisor behavior.

- [ ] **Step 2: Add the typed CLI enum and validation**

Reject gVisor/Kata without a non-empty RuntimeClass. Reject development with a hostile-workload capability override. Provider labels may include bounded profile identifiers but no secrets.

- [ ] **Step 3: Make provider capability reports exact**

Pass the typed profile into `KubernetesDryRunProvider`; emit only the matching provider-neutral capability. Remove the branch that adds `GvisorSandbox` for every `runtime_class_name.is_some()`.

- [ ] **Step 4: Run worker tests**

Run: `cargo test -p sandboxwich-worker -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit worker reporting**

```bash
git add crates/sandboxwich-worker
git commit -m "fix(worker): report exact isolation capabilities"
```

### Task 5: Run the complete SW-1 gate and document the contract

**Files:**
- Modify: `docs/capabilities.md`
- Modify: `docs/kubernetes.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Document caller versus operator responsibility**

State that callers request the `execution_class` HTTP field; operators configure
profile, RuntimeClass, nodes, CNI, storage, and conformance. Mark VM-class
execution experimental until SW-3 live conformance passes.

- [ ] **Step 2: Run formatting and lint**

Run: `cargo fmt --check`

Run: `cargo clippy --workspace --all-targets -- -D warnings`

Expected: PASS.

- [ ] **Step 3: Run the full suite**

Run: `cargo test --workspace`

Expected: PASS, with the test count reported. State explicitly whether PostgreSQL conditional tests ran.

- [ ] **Step 4: Commit documentation**

```bash
git add docs CHANGELOG.md
git commit -m "docs: define execution class ownership"
```
