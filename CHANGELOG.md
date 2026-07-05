# Changelog

## Unreleased

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
