# Orb Resident Process Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tenant-scoped, lease-fenced resident-process API that can run `orb-executor` for the lifetime of a Sandboxwich sandbox without persisting bootstrap secrets.

**Architecture:** A resident process is a durable desired-state resource backed by one long-lived job. The sandbox guest agent claims the job with a sandbox-scoped token, receives bootstrap bytes through a live-only read, supervises the child process, and reports bounded observations to the API. Sandbox stop revokes the active lease and changes the desired state before provider teardown.

**Tech Stack:** Rust, Axum, SQLx Any/SQLite/Postgres, Tokio, Utoipa/OpenAPI, Reqwest.

## Global Constraints

- `unsafe_code = "forbid"` remains enabled.
- Bootstrap content is limited to 64 KiB.
- Bootstrap bytes may exist in request memory and the live-read cache only.
- Bootstrap bytes must not enter SQL rows, job payloads, API responses, logs, traces, provider metadata, or command arguments.
- Guest processes are spawned directly from `argv`; no shell is inserted.
- Cross-tenant reads return `404`.
- Default gates: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- Postgres tests run only when `SANDBOXWICH_TEST_POSTGRES_URL` is set.

---

## File Map

- `crates/sandboxwich-core/src/lib.rs`: public resident-process, bootstrap, job-kind, and observation types.
- `crates/sandboxwich-api/migrations/20260716000200_resident_processes.sql`: durable public metadata and generation state.
- `crates/sandboxwich-api/src/handlers/resident_processes.rs`: tenant and guest routes plus live bootstrap cache.
- `crates/sandboxwich-api/src/handlers.rs`: handler module registration.
- `crates/sandboxwich-api/src/routes.rs`: route registration and auth boundaries.
- `crates/sandboxwich-api/src/api_contract.rs`: OpenAPI paths and schemas.
- `crates/sandboxwich-api/src/handlers/jobs.rs`: resident-process job validation and persistence.
- `crates/sandboxwich-api/src/handlers/leases.rs`: sandbox-scoped resident-process claim and completion rules.
- `crates/sandboxwich-api/src/handlers/sandboxes.rs`: stop cascade.
- `crates/sandboxwich-api/src/rows.rs`: SQL row conversion.
- `crates/sandboxwich-api/src/state.rs`: bounded live bootstrap cache.
- `crates/sandboxwich-api/tests/http_contract/resident_processes.rs`: tenant HTTP contract.
- `crates/sandboxwich-api/tests/http_contract/jobs.rs`: guest claim and fencing contract.
- `crates/sandboxwich-api/tests/http_contract/common.rs`: resident-process test helpers.
- `crates/sandboxwich-api/tests/http_contract.rs`: test module registration.
- `crates/sandboxwich-agent/src/main.rs`: resident child supervision and lease renewal.
- `docs/capabilities.md`: experimental capability statement.

### Task 1: Public resident-process types and validation

**Files:**
- Modify: `crates/sandboxwich-core/src/lib.rs`

**Interfaces:**
- Produces: `ResidentProcessId`, `ResidentProcess`, `ResidentProcessRequest`,
  `ResidentProcessResponse`, `ResidentProcessDesiredState`,
  `ResidentProcessObservedState`, `ResidentProcessRestartPolicy`,
  `ResidentProcessBootstrap`, `ResidentProcessObservationRequest`, and
  `JobKind::RunResidentProcess`.

- [ ] **Step 1: Write failing serialization and validation tests**

Add tests that construct:

```rust
let request = ResidentProcessRequest {
    argv: vec!["/usr/local/bin/orb-executor".into()],
    cwd: Some("/workspace".into()),
    env: BTreeMap::from([(
        "ORB_TOKEN_FILE".into(),
        "/run/sandboxwich/bootstrap/orb-token".into(),
    )]),
    restart_policy: ResidentProcessRestartPolicy::OnFailure,
    expected_generation: 0,
    bootstrap: Some(ResidentProcessBootstrap {
        content: b"secret".to_vec(),
        target_file: "/run/sandboxwich/bootstrap/orb-token".into(),
        mode: 0o600,
    }),
};
```

Assert exact snake-case enum serialization, redacted `Debug`, a 64 KiB content
limit, non-empty `argv`, NUL rejection, absolute `cwd`, allowed bootstrap path,
and mode restricted to `0o400..=0o700`.

- [ ] **Step 2: Run the core tests and verify RED**

Run:

```sh
cargo test -p sandboxwich-core resident_process -- --nocapture
```

Expected: compile failure because resident-process types do not exist.

- [ ] **Step 3: Add minimal public types and validator**

Add:

```rust
pub const MAX_RESIDENT_PROCESS_BOOTSTRAP_BYTES: usize = 64 * 1024;
pub const RESIDENT_PROCESS_BOOTSTRAP_PREFIX: &str = "/run/sandboxwich/bootstrap/";

pub fn validate_resident_process_request(
    request: &ResidentProcessRequest,
) -> Result<(), ResidentProcessRequestError>;
```

Implement validation without reading environment state.

- [ ] **Step 4: Run the core tests and verify GREEN**

Run the Task 1 command. Expected: resident-process tests pass.

- [ ] **Step 5: Commit**

```sh
git add crates/sandboxwich-core/src/lib.rs
git commit -m "feat(core): define resident process contract"
```

### Task 2: Durable resident-process storage

**Files:**
- Create: `crates/sandboxwich-api/migrations/20260716000200_resident_processes.sql`
- Modify: `crates/sandboxwich-api/src/rows.rs`
- Modify: `crates/sandboxwich-api/src/db.rs`
- Modify: `crates/sandboxwich-api/src/tests.rs`

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `insert_resident_process_on_connection`,
  `fetch_resident_process`, `update_resident_process_generation`, and
  `row_to_resident_process`.

- [ ] **Step 1: Write failing SQLite storage tests**

Test insert/fetch round-trip, `(sandbox_id, name)` uniqueness, tenant ownership,
generation compare-and-swap, and absence of bootstrap content from every text
and blob column.

- [ ] **Step 2: Run storage tests and verify RED**

```sh
cargo test -p sandboxwich-api resident_process_storage -- --nocapture
```

Expected: failure because the table and helpers do not exist.

- [ ] **Step 3: Add migration and focused row helpers**

Create columns for public metadata, digest, byte count, desired/observed state,
generation, active lease, PID, timestamps, exit code, and last error. Store
`argv` and environment as JSON. Do not add a bootstrap-content column.

- [ ] **Step 4: Run storage tests and verify GREEN**

Run the Task 2 command. Expected: storage tests pass on SQLite.

- [ ] **Step 5: Commit**

```sh
git add crates/sandboxwich-api/migrations/20260716000200_resident_processes.sql crates/sandboxwich-api/src/rows.rs crates/sandboxwich-api/src/db.rs crates/sandboxwich-api/src/tests.rs
git commit -m "feat(api): persist resident process state"
```

### Task 3: Tenant API and live-only bootstrap handoff

**Files:**
- Create: `crates/sandboxwich-api/src/handlers/resident_processes.rs`
- Modify: `crates/sandboxwich-api/src/handlers.rs`
- Modify: `crates/sandboxwich-api/src/routes.rs`
- Modify: `crates/sandboxwich-api/src/state.rs`
- Modify: `crates/sandboxwich-api/src/handlers/jobs.rs`
- Modify: `crates/sandboxwich-api/src/handlers/operations.rs`
- Create: `crates/sandboxwich-api/tests/http_contract/resident_processes.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/common.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract.rs`

**Interfaces:**
- Produces:

```rust
pub(crate) async fn put_resident_process(...);
pub(crate) async fn get_resident_process(...);
pub(crate) async fn stop_resident_process(...);
pub(crate) async fn resident_process_events(...);
pub(crate) async fn read_resident_process_bootstrap(...);
```

- [ ] **Step 1: Write failing HTTP contract tests**

Cover:

- create returns `202` with a queued operation;
- repeated `Idempotency-Key` plus identical body returns the same IDs;
- stale `expectedGeneration` returns `409`;
- another tenant receives `404`;
- GET omits `contentBase64`;
- stop changes desired state and is idempotent;
- bootstrap read succeeds once for the scoped guest token and then returns
  `410`;
- database, event, operation, and debug projections contain no canary secret.

- [ ] **Step 2: Run HTTP tests and verify RED**

```sh
cargo test -p sandboxwich-api --test http_contract resident_processes -- --nocapture
```

Expected: route-not-found or missing-type failures.

- [ ] **Step 3: Add bounded live bootstrap state**

Add to `AppState`:

```rust
pub(crate) resident_bootstraps:
    Arc<Mutex<HashMap<ResidentProcessId, LiveResidentBootstrap>>>,
```

`LiveResidentBootstrap` contains bytes, digest, target path, mode, expiry, and
one consumed flag. It implements a redacted `Debug`.

- [ ] **Step 4: Implement tenant routes and queued job**

Use one database transaction for resource creation and the
`RunResidentProcess` job. Put only resident-process ID, sandbox ID, generation,
and bootstrap digest in the job payload.

- [ ] **Step 5: Implement scoped single-read bootstrap route**

Require the guest token to match tenant, worker, sandbox, resident-process ID,
and active generation. Remove bytes from the live cache after the successful
read.

- [ ] **Step 6: Run HTTP tests and verify GREEN**

Run the Task 3 command. Expected: all resident-process HTTP tests pass.

- [ ] **Step 7: Commit**

```sh
git add crates/sandboxwich-api/src/handlers/resident_processes.rs crates/sandboxwich-api/src/handlers.rs crates/sandboxwich-api/src/routes.rs crates/sandboxwich-api/src/state.rs crates/sandboxwich-api/src/handlers/jobs.rs crates/sandboxwich-api/src/handlers/operations.rs crates/sandboxwich-api/tests/http_contract/resident_processes.rs crates/sandboxwich-api/tests/http_contract/common.rs crates/sandboxwich-api/tests/http_contract.rs
git commit -m "feat(api): expose resident process lifecycle"
```

### Task 4: Guest claim, observation, and generation fencing

**Files:**
- Modify: `crates/sandboxwich-core/src/lib.rs`
- Modify: `crates/sandboxwich-api/src/handlers/workers.rs`
- Modify: `crates/sandboxwich-api/src/handlers/leases.rs`
- Modify: `crates/sandboxwich-api/src/handlers/resident_processes.rs`
- Modify: `crates/sandboxwich-api/src/routes.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/jobs.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/resident_processes.rs`

**Interfaces:**
- Produces a guest-token scope for `RunResidentProcess` and:

```rust
POST /v1/resident-processes/{id}/observations
```

- [ ] **Step 1: Write failing fencing tests**

Test that guest claims require their sandbox ID and resident-process kind,
tenant tokens cannot claim, another sandbox cannot claim, stale generations
cannot observe or complete, and lease loss changes the process to `lost`.

- [ ] **Step 2: Run lease tests and verify RED**

```sh
cargo test -p sandboxwich-api --test http_contract resident_process -- --nocapture
```

- [ ] **Step 3: Extend guest-token and lease scopes**

Mint a token with explicit allowed job kinds:

```rust
allowed_job_kinds: BTreeSet::from([
    JobKind::RunCommand,
    JobKind::RunResidentProcess,
])
```

Keep sandbox, worker, tenant, expiry, and revocation checks.

- [ ] **Step 4: Add observation compare-and-swap**

Accept `starting`, `running`, `failed`, `stopped`, and `lost` observations only
when lease ID and generation match the active row. Store bounded public error
codes and messages.

- [ ] **Step 5: Run lease tests and verify GREEN**

Run the Task 4 command.

- [ ] **Step 6: Commit**

```sh
git add crates/sandboxwich-core/src/lib.rs crates/sandboxwich-api/src/handlers/workers.rs crates/sandboxwich-api/src/handlers/leases.rs crates/sandboxwich-api/src/handlers/resident_processes.rs crates/sandboxwich-api/src/routes.rs crates/sandboxwich-api/tests/http_contract/jobs.rs crates/sandboxwich-api/tests/http_contract/resident_processes.rs
git commit -m "feat(api): fence resident process leases"
```

### Task 5: Guest-agent process supervision

**Files:**
- Modify: `crates/sandboxwich-agent/src/main.rs`

**Interfaces:**
- Consumes: resident-process lease payload and live bootstrap route.
- Produces:

```rust
async fn supervise_resident_process(
    client: &ApiClient,
    lease: ClaimedLease,
    cancelled: CancellationSignal,
) -> anyhow::Result<LeaseCompletion>;
```

- [ ] **Step 1: Write failing process tests**

Use temporary executable scripts to prove:

- arguments are passed without shell expansion;
- bootstrap bytes are written with `0600`;
- bootstrap bytes do not appear in `Debug` output;
- readiness is reported after the stability interval;
- lease loss kills the exact child;
- `on_failure` restarts with bounded backoff;
- retry exhaustion returns a terminal failure;
- stop returns a stopped observation.

- [ ] **Step 2: Run agent tests and verify RED**

```sh
cargo test -p sandboxwich-agent resident_process -- --nocapture
```

- [ ] **Step 3: Implement direct child supervision**

Build `tokio::process::Command` from `argv[0]` and `argv[1..]`, set `cwd` and
environment, set stdin to null, pipe bounded logs, and use `kill_on_drop(true)`.
Create the bootstrap file with `OpenOptions::create_new(true)` and Unix mode
before spawning.

- [ ] **Step 4: Integrate lease renewal and observation calls**

Use the existing renewal task. Stop the child when cancellation or renewal
loss wins the `tokio::select!`.

- [ ] **Step 5: Run agent tests and verify GREEN**

Run the Task 5 command.

- [ ] **Step 6: Commit**

```sh
git add crates/sandboxwich-agent/src/main.rs
git commit -m "feat(agent): supervise resident guest processes"
```

### Task 6: Sandbox stop cascade and public contract

**Files:**
- Modify: `crates/sandboxwich-api/src/handlers/sandboxes.rs`
- Modify: `crates/sandboxwich-api/src/api_contract.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/sandboxes.rs`
- Modify: `crates/sandboxwich-api/tests/http_contract/public_api.rs`
- Modify: `docs/capabilities.md`

**Interfaces:**
- Consumes: resident-process desired state and active lease.
- Produces: generated OpenAPI paths and stop ordering.

- [ ] **Step 1: Write failing cascade and schema tests**

Assert sandbox stop changes resident processes to desired `stopped`, revokes
their leases before queueing provider teardown, and publishes the four tenant
routes plus guest observation/read routes in OpenAPI.

- [ ] **Step 2: Run tests and verify RED**

```sh
cargo test -p sandboxwich-api --test http_contract stop_cascades_to_resident_processes -- --nocapture
cargo test -p sandboxwich-api openapi -- --nocapture
```

- [ ] **Step 3: Implement stop ordering and OpenAPI registration**

Perform resident-process state changes in the same transaction that queues the
stop job. Add Utoipa schemas and paths.

- [ ] **Step 4: Run tests and verify GREEN**

Run both Task 6 commands.

- [ ] **Step 5: Update the capability matrix**

Document the experimental resident-process boundary, apply-mode evidence
requirement, live-only bootstrap, and restart limitation.

- [ ] **Step 6: Commit**

```sh
git add crates/sandboxwich-api/src/handlers/sandboxes.rs crates/sandboxwich-api/src/api_contract.rs crates/sandboxwich-api/tests/http_contract/sandboxes.rs crates/sandboxwich-api/tests/http_contract/public_api.rs docs/capabilities.md
git commit -m "feat: complete resident process contract"
```

### Task 7: Full verification and main integration

**Files:**
- Verify all changed files.

- [ ] **Step 1: Merge current main into the branch**

```sh
git fetch origin main
git merge origin/main
```

- [ ] **Step 2: Audit shared call sites and conflict markers**

```sh
rg -n '<<<<<<<|=======|>>>>>>>' .
git diff --check
rg -n 'RunResidentProcess|resident_process' crates
```

- [ ] **Step 3: Run required gates**

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: every command exits zero.

- [ ] **Step 4: Run optional Postgres and Kubernetes checks when configured**

```sh
test -z "${SANDBOXWICH_TEST_POSTGRES_URL:-}" || cargo test --workspace
test -z "${SANDBOXWICH_KUBERNETES_CONFORMANCE:-}" || bash deploy/kubernetes/kind-conformance.sh
```

- [ ] **Step 5: Push, wait for required checks, and merge with a merge commit**

Do not squash and do not force-push.
