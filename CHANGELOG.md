# Changelog

## Unreleased

## 0.1.15 - 2026-08-09
### Added

- *(api)* Replace fenced terminal residents ([#340](https://github.com/evalops/sandboxwich/pull/340))
- *(runtime)* Add one-shot sterile cell pool
- *(api)* Make sterile cell claims recoverable
- *(api)* Add one-shot sterile cell leases ([#336](https://github.com/evalops/sandboxwich/pull/336))
- *(api)* Deterministic home identity via external_key + mount visibility
- Add native Cloudflare sandbox provider

### Fixed

- Stabilize Cloudflare body bounds and defaults

### Other

- Merge sterile cell pool with resident activation
- *(activation)* Combine identity validation and proof

## 0.1.14 - 2026-08-06
### Other

- Add authoritative Maestro activation proof
- Add authoritative Maestro activation validation
- Define hosted runner activation lifecycle contract ([#312](https://github.com/evalops/sandboxwich/pull/312))

## 0.1.13 - 2026-08-05
### Fixed

- *(worker)* Secure Maestro gateway bootstrap
- *(lifecycle)* Publish one sandbox runtime contract
- *(api)* Fence Maestro resident model cohort
- *(api)* Accept current Maestro resident contract ([#303](https://github.com/evalops/sandboxwich/pull/303))
- *(api)* Cast postgres metrics aggregates to bigint
- *(api)* Enforce Maestro bootstrap boundary
- *(api)* Admit managed EvalOps gateway env on Maestro residents
- *(metrics)* Widen SLO rollup counters
- *(worker)* Retain resident lease through capacity pressure
- *(worker)* Allow Maestro residents egress to llm-gateway

### Other

- Expose typed resident materialization failures
- Update Cargo.lock dependencies
- Merge branch 'main' into fix/maestro-resident-contract-trace-codes
- *(maestro)* Overlap binding with resident startup
- Merge branch 'main' into agent/maestro-runtime-bootstrap-boundary
- Rustfmt allowlist fix
- *(worker)* Run residents beside sandbox provision
- *(worker)* Poll resident observations every 50ms ([#302](https://github.com/evalops/sandboxwich/pull/302))

## 0.1.12 - 2026-08-05
### Fixed

- *(worker)* Secure Maestro gateway bootstrap
- *(lifecycle)* Publish one sandbox runtime contract
- *(api)* Fence Maestro resident model cohort
- *(api)* Accept current Maestro resident contract ([#303](https://github.com/evalops/sandboxwich/pull/303))
- *(api)* Cast postgres metrics aggregates to bigint
- *(api)* Enforce Maestro bootstrap boundary
- *(api)* Admit managed EvalOps gateway env on Maestro residents
- *(metrics)* Widen SLO rollup counters
- *(worker)* Retain resident lease through capacity pressure
- *(worker)* Allow Maestro residents egress to llm-gateway

### Other

- Expose typed resident materialization failures
- Merge branch 'main' into fix/maestro-resident-contract-trace-codes
- *(maestro)* Overlap binding with resident startup
- Merge branch 'main' into agent/maestro-runtime-bootstrap-boundary
- Rustfmt allowlist fix
- *(worker)* Run residents beside sandbox provision
- *(worker)* Poll resident observations every 50ms ([#302](https://github.com/evalops/sandboxwich/pull/302))

## 0.1.11 - 2026-08-04
### Other

- Claim wait_ms long-poll, hourly SLO rollups, nightly gate
- Rustfmt allowlist rules json helpers
- *(api)* Embed allowlist rules JSON on sandboxes for list
- Add scenario A/B harness and allowlist seed support
- Main
- Main into lifecycle v2
- Lifecycle completion upsert, set-based stop retire, claim/sweep

## 0.1.10 - 2026-08-04
### Other

- *(api)* Cut lifecycle spin-up and tear-down round trips

## 0.1.9 - 2026-08-04
### Fixed

- Make isolation, capacity, and lifecycle guarantees hold under failure
- *(api)* Scope reconciliation to relevant workers

### Other

- *(api)* Short-circuit claim when the worker has no free slots
- *(api)* Cut claim write amplification and move hot reads off the writer
- Merge branch 'main' into perf/generalize-read-pool
- *(api)* Route all keyset lists through the query-only read pool
- *(api)* Serve pure-read point lookups from the query-only pool
- Merge origin/main into fix/p0-lifecycle-isolation-guarantees
- Merge origin/main into fix/p0-lifecycle-isolation-guarantees
- *(api)* Cut list-path String copies and pre-size JSON
- Merge remote-tracking branch 'origin/main' into fix/out-of-band-reconciler
- Merge remote-tracking branch 'origin/main' into fix/out-of-band-reconciler
- Merge branch 'main' of https://github.com/evalops/sandboxwich into perf/deep-hot-paths
- Bound database hot paths

### Security

- Reject hardlinked cache sources and bind tenant identity

## 0.1.8 - 2026-08-04
### Fixed

- *(identity)* Separate API tenant from Maestro binding
- *(identity)* Allow fenced Maestro startup exchange
- *(worker)* Bound orphan discovery at production scale
- *(worker)* Publish resident pod identity before startup

### Other

- *(worker)* Bound idle heartbeat logs
- *(worker)* Stabilize sidecar deadline coverage

## 0.1.7 - 2026-08-04
### Added

- *(observability)* Correlate sandbox lifecycle traces
- *(api)* Export the OpenAPI document so downstream mirrors can be validated

### Fixed

- *(api)* Classify concurrent sandbox stops as idempotent
- Speed inventory reconciliation and trace stale placements
- *(api)* Distinguish pending resident placement
- *(api)* Reconcile recreated provisioning resources
- *(sandboxwich)* Close archived cleanup race paths
- *(sandboxwich)* Reconcile archived runtime leaks
- *(worker)* Classify ResourceQuota rejections as retryable capacity
- *(worker)* Roll back failed staged provisioning
- *(worker)* Report successful reconciliation at info level
- *(sandboxwich)* Harden restricted cache and kubectl bounds

### Other

- Merge branch 'main' into contract/openapi-export-for-mirrors
- Merge origin/main into compiler-cache-nonroot-redesign
- *(sandbox)* Move compiler-cache staging out of the guest mount namespace and drop root
- Merge branch 'main' into api-4xx-visibility
- Merge remote-tracking branch 'origin/main' into codex/provision-503
- Merge remote-tracking branch 'origin/main' into codex/provision-503
- Merge remote-tracking branch 'origin/main' into feat/trace-sandbox-lifecycle
- Merge pull request #237 from evalops/pvc-orphan-reaper-v2
- Merge remote-tracking branch 'origin/main' into pvc-orphan-reaper-v2
- Merge branch 'main' into quota-retryable-capacity

## 0.1.6 - 2026-08-02
### Added

- *(secrets)* Deliver secret references as read-only CSI mounts
- *(secrets)* Tenant-scoped secret-reference store
- *(kubernetes)* Host WIF-bound Maestro runners
- *(kubernetes)* Host generation-fenced Maestro runners
- *(worker)* Render an enforceable Cilium FQDN egress policy

### Fixed

- *(secrets)* Negotiate secret-delivery placement, harden spec validation
- *(secrets)* Bound delivery names, revalidate at the worker, stabilize mount order
- *(kubernetes)* Mount durable Maestro workspace
- *(identity)* Isolate Maestro workload fence
- *(identity)* Pin Maestro exchange trust
- *(identity)* Preserve projected-token rotation
- Give bootstrap handoff migration a unique version
- *(snapshots)* Carry secret mount fields through resume
- *(identity)* Classify stale Maestro generations
- *(worker)* Delete the Cilium policy on teardown and make the port case load-bearing

### Other

- Merge branch 'main' into devin/1785659573-brokered-desktop-transport
- Merge origin/main into brokered desktop transport
- Merge branch 'main' into devin/1785659399-shared-bootstrap-handoff
- Merge branch 'main' into devin/1785659399-shared-bootstrap-handoff
- Merge origin/main into snapshot-backed resume
- Revert "feat(kubernetes): host generation-fenced Maestro runners"
- Merge remote-tracking branch 'origin/main' into codex/sandboxwich-pr223
- Merge origin/main into Kata conformance gate
- Merge remote-tracking branch 'origin/main' into codex/sandboxwich-pr223

## 0.1.5 - 2026-07-28
### Other

- Update Cargo.lock dependencies

## 0.1.4 - 2026-07-26
### Added

- Stage bounded compiler cache archives

### Fixed

- Complete compiler cache materialization
- Isolate compiler cache activation
- Harden compiler cache archive boundaries

### Other

- Merge branch 'main' into agent/compiler-cache-staging
- Update Cargo.lock dependencies

## 0.1.3 - 2026-07-26
### Added

- Stage bounded compiler cache archives

### Fixed

- Complete compiler cache materialization
- Isolate compiler cache activation
- Harden compiler cache archive boundaries

### Other

- Merge branch 'main' into agent/compiler-cache-staging
- The Kubernetes provider now independently rejects `virtual_machine`
  execution-class provisioning unless it is configured with the `kata`
  isolation profile and a nonempty RuntimeClass. This mirrors the existing
  APEX/gVisor provider-boundary check so VM-class (hostile-workload) work
  fails closed at provision time rather than relying only on placement-time
  capability matching.

## 0.1.2 - 2026-07-19

- Release automation moved from the cargo-release bump/tag workflow pair to
  release-plz: a standing release PR now carries the version bump and
  generated changelog, and merging it pushes the release tag. All crates
  inherit the workspace version, workflow files are linted in CI, and the
  release build gained a manual dispatch fallback.

## 0.1.1 - 2026-07-19
- APEX trusted-supervisor sandboxes now require the typed
  sandboxed_container execution class end to end. Worker registration,
  provider dispatch, snapshot restore, materialization, and lease claims all
  enforce both the exact APEX profile/image and the gVisor isolation class.


- Sandbox creation now carries a durable typed `execution_class` HTTP field.
  Callers choose the provider-neutral workload class, while operators configure
  the worker isolation profile, RuntimeClass, compatible nodes, CNI, storage,
  and live conformance. VM-class execution remains experimental pending SW-3
  live certification.
- Provisioning progress is fenced by active lease identity and persists observed
  Kubernetes resource UIDs, allowing interrupted provisioning to adopt matching
  resources without duplicating them.
- Apply-mode workers have a bounded orphan-reconciliation loop. It is dry-run by
  default; deletion requires a CLI and environment double opt-in and uses UID
  preconditions while database, discovery, scope, or pagination uncertainty fails
  closed.

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
