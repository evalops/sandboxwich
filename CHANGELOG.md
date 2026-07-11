# Changelog

## Unreleased

## 0.1.0 - 2026-07-11

- The CLI executable is now named `sandboxwich`. Structured output supports
  `--output json|jsonl|table` while preserving JSON as the compatibility default;
  `--quiet` suppresses successful structured output.
- The CLI now supports `new --wait`, command working directories and environment
  variables, plus real SSH and SCP handoff. The misleading prompt command was
  removed because no production prompt runtime exists yet.
- `HealthResponse` includes `checked_at` and optional `database` fields. Clients built
  against older responses can still deserialize cached or pre-upgrade payloads because
  these fields have serde defaults in `sandboxwich-core`.
- `SnapshotCleanupResponse` includes cleanup-run metadata plus archived-sandbox and
  runtime-resource cleanup details. These are additive JSON response fields; clients
  that construct the Rust struct directly need to populate the new fields.
- `Worker.max_concurrent_jobs` defaults to `1` during deserialization so older worker
  payloads remain accepted.
- Sandboxes now include typed `memory_limit` and `network_egress` fields. JSON clients
  can omit them and receive safe defaults; Rust code that constructs
  `CreateSandboxRequest` directly must populate the new optional fields.
- File upload/list/download endpoints and command-output file citation annotations were
  added. Download endpoints return raw bytes, while metadata is exposed through typed
  response structs.
- Kubernetes provider manifests now include NetworkPolicies, resource requests/limits,
  pod/container security contexts, and optional RuntimeClass isolation.
- Runtime resource cleanup distinguishes `deleted` resources reconciled as missing
  from `destroyed` resources explicitly torn down during archived-sandbox cleanup.
- The guest agent preserves split multi-byte UTF-8 characters in streamed command
  output chunks and exits its heartbeat task after 12 consecutive failed heartbeat
  posts by default. Operators can tune that circuit breaker with
  `SANDBOXWICH_HEARTBEAT_FAILURE_THRESHOLD`.
- Benchmark reports now include sandbox TTFT measured through a live API and
  dry-run Kubernetes worker, split into create, provision, command queue, and
  first-output phases.
- Jobs can now be fetched directly with `GET /jobs/{job_id}`.
- Command queue responses now include a typed `queued_job` reference so clients
  can verify worker handoff without exposing the full job payload.
