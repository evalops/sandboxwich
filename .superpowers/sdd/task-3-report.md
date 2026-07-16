# Task 3 report: typed Sandboxwich staging evidence

Base: `ff9ad3048c848e40ca90ba0559b34b22ffec8854`

## Causal path

The control plane verified `expectedSha256` against the staged file when it
created a `materialize_file` job, but the provider returned `()` after import.
The worker then copied `expectedSha256` from the job into
`MaterializeFileReceipt.sha256`. Consequently the receipt contained no digest
observed at the selected destination. The API deleted the staged file after a
terminal completion, but the receipt did not identify the component that owned
that cleanup.

## RED evidence

Before production changes, the focused API contract was extended to require a
destination digest and closed cleanup owner. On `developer@dev-desktop`
(`rustc 1.97.0`), this failed to compile with:

- `MaterializeFileReceipt has no field named destination_sha256`
- `MaterializeFileReceipt has no field named cleanup_owner`
- `use of undeclared type MaterializeFileCleanupOwner`

The local machine stopped earlier because its `rustc 1.93.0` is below the
workspace's required `1.95`, so all Rust RED/GREEN and full verification ran on
`dev-desktop`.

## GREEN implementation

- Added `MaterializeFileObservation`, returned from the provider only after the
  materialization boundary succeeds.
- The live Kubernetes provider performs a second fixed, argument-safe
  `/usr/bin/sha256sum` read of the closed destination path, strictly parses the
  result, and rejects a mismatch with the expected source digest.
- Retained `MaterializeFileReceipt.sha256` as the verified staged-source digest
  and added `destination_sha256` as the provider observation.
- Added the closed `MaterializeFileCleanupOwner::ControlPlane` value. The API
  validates it before deleting the staged file and records it in the
  `file_materialized` event.
- The completion contract rejects a forged destination observation, accepts an
  identical replay idempotently, and emits exactly one cleanup/materialization
  event.

## Files changed

- `crates/sandboxwich-core/src/lib.rs`
- `crates/sandboxwich-api/src/handlers/leases.rs`
- `crates/sandboxwich-api/src/tests.rs`
- `crates/sandboxwich-api/tests/http_contract/jobs.rs`
- `crates/sandboxwich-worker/src/provider.rs`
- `crates/sandboxwich-worker/src/main.rs`
- `crates/sandboxwich-worker/src/worker_tests.rs`

`sandboxwich-worker/src/main.rs` is the existing receipt-construction point and
therefore part of the causal path even though the brief's inspection list did
not name it explicitly.

## Verification

Focused GREEN checks on `dev-desktop`:

- `cargo test -p sandboxwich-api materialization_job_input_is_ref_only_and_exact`
- `cargo test -p sandboxwich-api --test http_contract materialization_bytes_are_worker_fenced_ref_only_and_consumed_only_when_terminal`
- `cargo test -p sandboxwich-worker materialization_dispatches_fetched_bytes_and_returns_only_safe_receipt`
- `cargo test -p sandboxwich-api --test http_contract idempotency_is_concurrent_safe_and_tenant_scoped_on_sqlite`

Full requested checks on `dev-desktop`:

- `cargo test -p sandboxwich-core -p sandboxwich-api -p sandboxwich-worker`:
  244 tests passed (56 API unit, 44 API contract, 16 core, 128 worker).
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.

## Self-review

- The receipt contains typed IDs, a closed destination, digests, byte count,
  and a closed cleanup owner only. It contains no path supplied by a caller,
  URL, token, staged content, instruction content, or provider credential.
- The provider observation is produced after import from the selected
  destination, not copied from the request.
- Existing tenant-scoped idempotency and changed-payload conflict coverage is
  green; this task also proves a forged destination digest is rejected and an
  identical completion replay has exactly one durable effect.
- Traversal through the destination selector is rejected by the existing
  closed enum and now has an explicit regression assertion.

## Concern

The live observation depends on the pinned APEX runtime image providing
`/usr/bin/sha256sum`. The code path is compiled and contract-tested here, but no
authorized live Kubernetes sandbox was available for an end-to-end provider
observation in this task.
