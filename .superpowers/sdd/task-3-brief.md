# Task 3: Prove and, if necessary, add typed Sandboxwich staging evidence

Exact base: `ff9ad3048c848e40ca90ba0559b34b22ffec8854`

## Goal

Make the existing `materialize_file` result provide safe, typed evidence that the staged source bytes reached the selected destination and that cleanup ownership is explicit. Do not add a new staging system.

## Scope

Inspect and, only where the current receipt is proven insufficient, modify:

- `crates/sandboxwich-core/src/lib.rs`
- `crates/sandboxwich-api/src/handlers/jobs.rs`
- `crates/sandboxwich-api/tests/http_contract/jobs.rs`
- `crates/sandboxwich-worker/src/provider.rs`
- `crates/sandboxwich-worker/src/worker_tests.rs`

The current receipt already exposes `sandbox_id`, `file_id`, destination enum, one `sha256`, and `size_bytes`. It does not visibly distinguish expected source digest from an observed destination digest or make cleanup ownership explicit. Establish the exact causal path before changing it.

## Required behavior

- First add an integration/contract test against the current `materialize_file` path. If it proves the required receipt already exists, record the evidence and make no production change.
- If missing, extend the existing typed operation result with the smallest fields needed to distinguish source digest, observed destination digest, byte count, and cleanup ownership.
- The observed destination digest must be produced from the destination/materialization boundary, not copied blindly from the request.
- Cleanup ownership must be a closed typed value or equally strict typed contract; do not accept or emit arbitrary paths, URLs, tokens, instruction content, or provider secrets.
- Preserve existing API contracts where possible; if retaining the existing `sha256` field for compatibility, define unambiguously what it represents and add the destination observation separately.
- Prove tenant-scoped idempotency, changed-payload conflict, traversal rejection, exactly-once materialization, and cleanup receipt generation using the existing operation path.
- Do not make Sandboxwich the dataset client. It must never receive or store a Hugging Face token.
- No broad refactor, new storage subsystem, credential handling, or APEX task content.

## Verification

Use TDD. Run the focused tests first, then:

```text
cargo test -p sandboxwich-core -p sandboxwich-api -p sandboxwich-worker
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Run heavy Rust verification on `developer@dev-desktop` when practical. Commit as `feat(apex): attest staged input materialization`. Do not push, open a PR, or merge. Write `.superpowers/sdd/task-3-report.md` with exact RED/GREEN evidence, files changed, tests, self-review, and concerns.
