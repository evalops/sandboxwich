# Roadmap and support gates

## Shipped in 0.1

- Typed `/v1` HTTP control plane with SQLite and PostgreSQL contract tests.
- Durable worker registration, capacity, leases, renewal, retry, and typed completion.
- Guest command streaming, file operations, health, SSH metadata, and sandbox-bound tokens.
- Snapshot, fork, retention, cleanup, desktop-session, and runtime-resource records.
- Kubernetes dry-run and guarded apply providers with RuntimeClass, ingress, CIDR egress, and optional Cilium FQDN policy.
- Provider-isolated resident sidecars with atomic bootstrap acknowledgment, typed capability negotiation, fail-closed gating, and bounded telemetry.
- Signed API, worker, and Ubuntu runtime images plus attested CLI archives.

These capabilities remain Experimental until every gate below passes for a named provider and release.

## Promotion gates

### Authorization

- Tenant, operator, worker, and guest principals have separate credentials and route permissions.
- Guest credentials are bound to one sandbox, expire, rotate by revocation, and never appear in logs, provider metadata, process arguments, or stored response bodies.
- SQLite and PostgreSQL tests cover cross-tenant, cross-worker, cross-sandbox, expiry, revocation, and wrong-job-kind requests.

### Isolation

- The supported provider uses gVisor, Kata, a microVM, or an equivalent documented boundary.
- Sandbox pods cannot reach Kubernetes, cloud metadata, control-plane namespaces, or another sandbox unless an explicit policy permits the destination.
- FQDN and CIDR allowlists have live allow, deny, DNS failure, redirect, IPv4, and IPv6 tests.

### Lifecycle recovery

- Provision, command, stop, snapshot, fork, resume, cancellation, lease loss, worker restart, API restart, and out-of-band resource deletion have deterministic terminal states.
- Snapshot-backed resume is deterministic in all three outcomes: `archived -> provisioning` on request, `provisioning -> ready` on provider success, and `provisioning -> archived` on permanent failure (a retryable failure stays in `provisioning`). A failed resume leaves the snapshot intact and the sandbox resumable again.
- Cleanup and reconciliation are idempotent and retain an operator-readable record of failures.

### Conformance

- The provider passes the disposable-cluster suite from a clean database and empty cluster.
- SQLite and PostgreSQL contract suites pass on the release commit.
- Required Rust, Clippy, dependency audit, MSRV, container, and Kubernetes checks pass together on current `main`.

### Telemetry

- Metrics expose bounded-label sandbox, worker, job, lease, queue age, heartbeat age, retry, idempotency, cleanup, runtime-resource, and guest-token state.
- Alerts cover queued-work age, stale workers, repeated lease expiry, cleanup failure, and capacity exhaustion.
- Tenant credentials cannot read another tenant's metrics; the operator credential can read the global view.

### Documentation

- Every public `/v1` method and path appears in the released OpenAPI document.
- The capability matrix names the provider, backend, limitations, and support state.
- The release contains CLI archives, checksums, provenance attestations, OpenAPI, and image digests.

## Next work

1. Promote Cilium FQDN egress from Experimental. The live suite
   (`deploy/kubernetes/cilium-fqdn-conformance.sh`, `cilium-fqdn` job) now
   proves allow, deny, DNS failure, redirect, IPv4, and IPv6 against a
   Cilium-backed disposable cluster using the shipped policy rendering. What
   remains is a Cilium-backed *production* target: the deploy repo has no
   Cilium-managed cluster, so `SANDBOXWICH_CILIUM_FQDN_EGRESS=true` has no
   production evidence and the egress-gateway backend stays the default.
2. Add a microVM provider and compare its lifecycle and recovery behavior with RuntimeClass-backed Kubernetes.
3. Finish the brokered desktop transport. Desktop access now returns a typed `DesktopTransport` referencing the sandbox's persisted desktop `Service` runtime resource and a short-lived, sandbox-bound credential (returned once, stored only as a hash, rotated by revocation). Still outstanding: the external broker that validates the credential and relays clients onto the tunnel, and the public ingress/Gateway in front of the desktop `Service` in evalops/deploy.
4. Add live Secrets Store CSI conformance on a cluster with the driver installed. Reference storage, binding, and rendered read-only CSI mounts are covered by contract tests against the real API and provider surface, but no test asserts against a kubelet actually mounting material.
5. Add live sidecar conformance on a real cluster across worker restart and an explicit guest-to-sidecar network relay; the isolated Pod still does not share guest localhost. Resident bootstrap handoff is no longer process-local: with `SANDBOXWICH_BOOTSTRAP_HANDOFF_KEY` configured, sealed ephemeral rows carry it across API restart, replica failover, and cross-replica replay under the same generation/lease/digest fence, covered by SQLite and PostgreSQL contract tests.

## Non-goals for 0.1

- Billing.
- Secret backends other than operator-provisioned `SecretProviderClass` objects served by the Secrets Store CSI driver, and any path that accepts raw credential bytes into the control plane.
- Unsupported isolation claims for the dry-run provider.
