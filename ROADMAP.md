# Roadmap and support gates

## Shipped in 0.1

- Typed `/v1` HTTP control plane with SQLite development mode and PostgreSQL shared-deployment contracts.
- Durable worker registration, capacity reports, leases, renewal, retry, cancellation requests, and typed completion.
- Guest command streaming, file operations, health, SSH metadata, sandbox-bound tokens, token refresh, and terminal guest-auth handling.
- Snapshot, fork, resume, retention, cleanup, desktop-session, managed-home, and runtime-resource records.
- Kubernetes dry-run and guarded apply providers with RuntimeClass, ingress, CIDR egress, and optional Cilium FQDN policy.
- Provider-isolated resident sidecars with atomic bootstrap acknowledgment, typed capability negotiation, fail-closed gating, and bounded telemetry.
- Independent worker heartbeat, concurrent ordinary leases, serial provision-like work, and reserved control capacity.
- Worker resource envelopes, create-time impossible-tier rejection, and bounded claim scanning beyond the original 25-candidate window.
- Signed API, worker, and Ubuntu runtime images plus attested CLI archives.

These capabilities remain Experimental until every gate below passes for a named provider and release.

## Promotion gates

### Authorization

- Tenant, operator, worker, and guest principals have separate credentials and route permissions.
- Guest credentials are bound to one sandbox, expire, rotate by revocation, and never appear in logs, provider metadata, process arguments, or stored response bodies.
- SQLite and PostgreSQL tests cover cross-tenant, cross-worker, cross-sandbox, expiry, revocation, and wrong-job-kind requests.
- Provider routing authority uses a dedicated credential and header; legacy ownership headers never become routing authority by inference.

### Isolation

- The supported provider uses gVisor, Kata, a microVM, or an equivalent documented boundary.
- Sandbox pods cannot reach Kubernetes, cloud metadata, control-plane namespaces, or another sandbox unless an explicit policy permits the destination.
- FQDN and CIDR allowlists have live allow, deny, DNS failure, redirect, IPv4, and IPv6 tests.

### Lifecycle recovery

- Provision, command, stop, snapshot, fork, resume, cancellation, lease loss, worker restart, API restart, response loss, and out-of-band resource deletion have deterministic convergent states.
- A transmitted provider request whose result cannot be proven becomes an explicit unknown outcome; callback-delivery loss is never reclassified as a provider failure.
- Snapshot-backed resume is deterministic in all three outcomes: `archived -> provisioning` on request, `provisioning -> ready` on provider success, and `provisioning -> archived` on permanent failure. Retryable and unknown outcomes stay reconcilable without destroying the source snapshot.
- Cleanup and reconciliation are idempotent and retain an operator-readable record of failures.

### Conformance

- The provider passes the disposable-cluster suite from a clean PostgreSQL database and empty cluster.
- SQLite development contracts and PostgreSQL production contracts pass on the release commit.
- Required Rust, Clippy, dependency audit, MSRV, container, and Kubernetes checks pass together on current `main`.
- Every release is blocked until `kubernetes-conformance.yml` has a successful run whose `head_sha` exactly equals the tagged commit, and the release publishes that attestation.

### Telemetry

- Metrics expose bounded-label sandbox, worker, job, lease, queue age, heartbeat age, retry, idempotency, cleanup, runtime-resource, guest-token, lifecycle-operation, unknown-outcome, and reconciliation state.
- Alerts cover queued-work age, stale workers, repeated lease expiry, cleanup failure, capacity exhaustion, and unknown outcomes older than two reconciliation intervals.
- Tenant credentials cannot read another tenant's metrics; the operator credential can read the global view.

### Documentation

- Every public `/v1` method and path appears in the released OpenAPI document.
- The capability matrix names the provider, backend, limitations, and support state.
- The release contains CLI archives, checksums, provenance attestations, OpenAPI, image digests, and exact-SHA conformance evidence.

## Landed hardening baseline

PR #268 implemented most of the August release-blocking baseline:

- guest-token refresh, terminal 401 handling, `restartPolicy: Never`, and optional active deadlines;
- stop-time cancellation requests, stable `lease_cancelled`, and queued-job cancellation;
- typed worker resource envelopes, claim-time filtering, and create-time `capacity_insufficient`;
- independent worker heartbeats, concurrent ordinary leases, serial provision-like work, and reserved control capacity;
- bounded candidate scanning beyond the original 25-job window;
- compiler-cache hardlink and identity hardening already landed through PR #264.

Open issues that still describe those baseline capabilities must be closed or narrowed to their actual residual work instead of remaining broad P0 trackers.

## Current hardening sequence

1. **Unknown provider outcomes.** Fix the live conformance failure where API restart or callback loss can turn provider progress into a failed lifecycle job. Introduce durable lifecycle-operation generations and an explicit `outcome_unknown` phase. Do not weaken the lost-response or API-restart chaos assertions.
2. **Exact-SHA release certification.** Block release jobs until the tagged commit has a successful live Kubernetes conformance run and publish a machine-readable attestation.
3. **Buildkite PostgreSQL parity.** Run the authoritative workspace test lane against digest-pinned PostgreSQL and use the aggregate Buildkite status as the core required check. GitHub Actions continues to own images, provenance, live provider conformance, and releases.
4. **Provider observation.** Separate provider `ensure`, `observe`, and `delete` from API state transitions so reconciliation can converge after response loss, worker death, and out-of-band deletion.
5. **Worker boundaries and protocol negotiation.** Split orchestration from provider adapters and continuously test N/N-1 API-worker compatibility. Protocol versions remain separate from capability labels.
6. **Production mode and doctor.** PostgreSQL is the production database contract; SQLite is local single-process development. `SANDBOXWICH_PRODUCTION_MODE=1` and `sandboxwich doctor --format=json` fail closed on SQLite, development auth, unpinned images, missing isolation, stale capacity evidence, disabled sweepers, and unbounded lifetime without acknowledgment.
7. **Atomic capacity reservations.** Replace non-binding admission estimates with a resource-vector reservation in the lease-claim transaction. Distinguish `capacity_unavailable`, `capacity_unknown`, `capability_unavailable`, and `quota_exhausted`.
8. **Extension boundary.** Move Foam, APEX, Orb, Maestro, and Agent Sandbox payloads behind versioned extensions so generic lifecycle, authority, and cleanup code no longer grows a permanent product-specific branch for every integration.

The approved architecture and task-level plan live in:

- `docs/superpowers/specs/2026-08-15-sandboxwich-control-plane-hardening-design.md`
- `docs/superpowers/plans/2026-08-15-sandboxwich-control-plane-hardening.md`

## Residual issue scope

- #182: keep open only for client deadline propagation and proving every provider wait/exec path terminates immediately on cancellation or unknown callback outcome.
- #206: keep open only for live node-allocatable probing, evidence freshness, and atomic capacity reservations. The typed envelope and create-time rejection baseline have landed.
- #160: close; independent heartbeat, concurrent ordinary jobs, serial provision-like work, and reserved control capacity landed in #268.
- #202 and #156: close or narrow only to a reproduced residual auth lifecycle defect; refresh, terminal auth, sandbox-bound claim authority, and restart bounding have landed.
- #181: either add a current-main same-attempt identity-rotation reproduction or close it; newer attempts already rotate durable provider identity.
- #265: replace the stale table with the residual hardening sequence above.

## Provider certification after hardening

After the sequence above is green:

1. Promote Cilium FQDN egress from Experimental on a named production target. The disposable suite already proves allow, deny, DNS failure, redirect, IPv4, IPv6, and port scope; production evidence is still missing.
2. Certify the `virtual_machine`/Kata execution class with the existing no-skip live gate on a Kata-capable disposable cluster.
3. Add live Secrets Store CSI conformance against a kubelet that mounts real external material.
4. Add live isolated-sidecar conformance across API and worker restart plus an explicit guest-to-sidecar network relay.
5. Finish the brokered desktop transport and public ingress.

## Expansion threshold

Do not add a microVM provider or another provider family until:

- 30 consecutive full conformance runs succeed on `main`;
- 10,000 fault-injected lifecycle operations produce zero false terminal failures;
- every unknown outcome converges within two reconciliation intervals;
- no provider resource remains orphaned beyond twice the reconciliation interval;
- N/N-1 API-worker compatibility is continuously green;
- every release contains exact-SHA conformance evidence.

## Non-goals for the current milestone

- Billing.
- A new microVM provider before the expansion threshold.
- Broader desktop ingress before lifecycle convergence.
- Secret backends other than operator-provisioned `SecretProviderClass` objects served by the Secrets Store CSI driver, and any path that accepts raw credential bytes into the control plane.
- Prompt or model execution inside Sandboxwich; Maestro remains the model-execution authority.
- Unsupported isolation claims for the dry-run provider.
