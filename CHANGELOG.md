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
